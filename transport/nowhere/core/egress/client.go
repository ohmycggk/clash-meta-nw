// Package egress is the Nowhere 3 exit client. Since Nowhere 3.3 it registers
// over QUIC or TLS, and only then serves the flows the Portal opens. QUIC
// registrations stay claimable and carry many Flows; TLS registrations carry
// exactly one Flow each, so the TLS side is a small supervisor that keeps a
// standby pool in step with demand.
package egress

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/metacubex/mihomo/transport/nowhere/core/dgram"
	"github.com/metacubex/mihomo/transport/nowhere/core/flowio"
	nwhandshake "github.com/metacubex/mihomo/transport/nowhere/core/handshake"
	"github.com/metacubex/mihomo/transport/nowhere/core/qio"
	"github.com/metacubex/mihomo/transport/nowhere/core/wire"
)

const (
	dialTimeout    = 15 * time.Second
	udpIdle        = 120 * time.Second
	flowSetupLimit = 20 * time.Second
	// egressTLSIdleTTL is the standby lifetime of one TLS registration. The
	// Egress and the Portal time it independently.
	egressTLSIdleTTL = 120 * time.Second
	// serviceCooldown is the delay before a fresh seed connection after a
	// failure. Expiry is not a failure, so it reseeds immediately.
	serviceCooldown = 3 * time.Second
	// egressTLSGrowth is how many standby connections one started Flow is
	// allowed to leave behind, before the pool cap is applied.
	egressTLSGrowth = 2
	// shutdownTimeout bounds how long the TLS supervisor waits for its Flow
	// goroutines after closing their connections.
	shutdownTimeout = 5 * time.Second

	// DefaultEgressTLSPoolMax is the default NOW_EGRESS_TLS_POOL_MAX.
	DefaultEgressTLSPoolMax = 128
)

// EgressTLSPoolMaxFromEnv reads NOW_EGRESS_TLS_POOL_MAX. Unset or empty yields
// DefaultEgressTLSPoolMax; anything below 1 is rejected.
func EgressTLSPoolMaxFromEnv() (int, error) {
	return readPoolMax("NOW_EGRESS_TLS_POOL_MAX", DefaultEgressTLSPoolMax)
}

// Config is one Egress process. Exactly one of DialQUIC and DialTLS is set: the
// carrier is chosen once and both are never mixed in one process.
type Config struct {
	SharedKey string
	DialQUIC  func(ctx context.Context) (qio.Conn, error)
	DialTLS   func(ctx context.Context) (net.Conn, error)
	Upstream  interface {
		DialTCP(ctx context.Context, target wire.Target) (net.Conn, error)
		DialUDP(ctx context.Context, target wire.Target) (net.Conn, error)
	}
	UploadMbps   int
	DownloadMbps int
	// HandshakeTimeout bounds one carrier dial, registration and
	// authentication. Zero derives it from the shared key, honouring
	// NOW_HANDSHAKE_TIMEOUT like the Portal does.
	HandshakeTimeout time.Duration
	// TLSPoolMax caps the TLS standby budget (NOW_EGRESS_TLS_POOL_MAX). Zero
	// reads NOW_EGRESS_TLS_POOL_MAX, and an unset value selects
	// DefaultEgressTLSPoolMax.
	TLSPoolMax int
}

// ErrBusy is returned when the Portal's pending TLS registration set is full.
// A TLS Egress treats it as a failed registration and retries after the
// service cooldown.
var ErrBusy = errors.New("nw3: egress registration busy")

// Run registers with Portal and serves flows until ctx ends or the connection
// drops. It dispatches on the carrier the caller configured.
func Run(ctx context.Context, cfg Config) error {
	if err := validateConfig(cfg); err != nil {
		return err
	}
	if cfg.HandshakeTimeout <= 0 {
		timeout, err := nwhandshake.TimeoutFromEnv(cfg.SharedKey)
		if err != nil {
			return err
		}
		cfg.HandshakeTimeout = timeout
	}
	if cfg.DialTLS != nil {
		if cfg.TLSPoolMax < 1 {
			poolMax, err := EgressTLSPoolMaxFromEnv()
			if err != nil {
				return err
			}
			cfg.TLSPoolMax = poolMax
		}
		return newTLSHydra(cfg).run(ctx)
	}
	return runQUIC(ctx, cfg)
}

func validateConfig(cfg Config) error {
	if err := wire.ValidateServiceKey(cfg.SharedKey); err != nil {
		return err
	}
	if cfg.Upstream == nil {
		return errors.New("nw3: egress requires an upstream")
	}
	quic := cfg.DialQUIC != nil
	tlsDial := cfg.DialTLS != nil
	if quic == tlsDial {
		return errors.New("nw3: egress requires exactly one carrier dialer")
	}
	return nil
}

// runQUIC is the QUIC registration loop. One connection is registered at a time
// and serves every Flow the Portal opens on it until the connection drops. Every
// drop returns here and waits out the cooldown before dialing again, matching the
// reference CLI.
func runQUIC(ctx context.Context, cfg Config) error {
	creds, err := wire.NewCredentials(cfg.SharedKey)
	if err != nil {
		return err
	}
	for {
		dialCtx, cancel := context.WithTimeout(ctx, cfg.HandshakeTimeout)
		conn, err := cfg.DialQUIC(dialCtx)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if !sleep(ctx, serviceCooldown) {
				return ctx.Err()
			}
			continue
		}
		// A registration failure (including BUSY from an older Portal) and a
		// clean disconnect both wait out the cooldown before the next dial.
		_ = serveQUIC(ctx, cfg, creds, conn)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !sleep(ctx, serviceCooldown) {
			return ctx.Err()
		}
	}
}

func serveQUIC(ctx context.Context, cfg Config, creds *wire.Credentials, conn qio.Conn) error {
	defer conn.CloseWithError(0, "")
	if conn.ALPN() != wire.ALPN || conn.TLSVersion() != tls.VersionTLS13 {
		return errors.New("nw3: QUIC handshake rejected")
	}
	st, err := conn.OpenStream(ctx)
	if err != nil {
		return err
	}
	if st.ID() != 0 {
		return errors.New("nw3: authentication stream was not stream 0")
	}
	exp, err := exporter(conn)
	if err != nil {
		return err
	}
	// The registration shares the handshake budget with the dial, so a Portal
	// that accepts the connection but never answers cannot pin the Egress.
	_ = st.SetDeadline(time.Now().Add(cfg.HandshakeTimeout))
	if err := wire.WriteAuthFrame(st, creds, wire.RoleEgress, wire.AuthQUIC, exp); err != nil {
		return err
	}
	if err := st.CloseWrite(); err != nil {
		return err
	}
	res, err := wire.ReadRegistrationResult(st)
	if err != nil {
		return err
	}
	_ = st.SetDeadline(time.Time{})
	if res == wire.RegistrationBusy {
		return ErrBusy
	}
	if res != wire.RegistrationAccepted {
		return errors.New("nw3: invalid registration result")
	}
	router := dgram.NewRouter(conn)
	go router.Run(ctx)
	up := flowio.NewMbps(cfg.UploadMbps)
	down := flowio.NewMbps(cfg.DownloadMbps)
	for {
		flow, err := conn.AcceptStream(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if flow.ID()&2 != 0 || flow.ID()&1 == 0 {
			_ = conn.CloseWithError(0, "direction")
			return errors.New("nw3: invalid business stream direction")
		}
		go serveFlow(ctx, cfg, router, flow, up, down)
	}
}

// tlsHydra is the TLS registration supervisor. Its budget counts connections
// being dialled, being registered, and standing by; a connection that has been
// handed a Flow has left the budget and is never counted against it again.
type tlsHydra struct {
	cfg     Config
	creds   *wire.Credentials
	poolMax int

	// handshake bounds one carrier dial, registration and authentication.
	handshake time.Duration
	// up and down are shared by every Flow this process carries, like the QUIC
	// supervisor's limiters.
	up   *flowio.Limiter
	down *flowio.Limiter

	mu      sync.Mutex
	pending int
	seedAt  time.Time
	// grow is how many extra standby connections started Flows have authorised.
	// The supervisor consumes it one spawn at a time, and a seed never carries
	// it: growth only ever follows a FlowStart.
	grow int
	// live is every TLS connection the supervisor owns, so shutdown can close
	// them and bound the wait for their goroutines.
	live map[net.Conn]struct{}
	wg   sync.WaitGroup

	// changed is closed and replaced on every state change that may let the
	// budget grow.
	changed chan struct{}
}

func newTLSHydra(cfg Config) *tlsHydra {
	poolMax := cfg.TLSPoolMax
	if poolMax < 1 {
		poolMax = DefaultEgressTLSPoolMax
	}
	return &tlsHydra{
		cfg:       cfg,
		poolMax:   poolMax,
		handshake: cfg.HandshakeTimeout,
		up:        flowio.NewMbps(cfg.UploadMbps),
		down:      flowio.NewMbps(cfg.DownloadMbps),
		live:      make(map[net.Conn]struct{}),
		seedAt:    time.Now(),
		changed:   make(chan struct{}),
	}
}

func (h *tlsHydra) run(ctx context.Context) error {
	creds, err := wire.NewCredentials(h.cfg.SharedKey)
	if err != nil {
		return err
	}
	h.creds = creds
	defer h.wake()
	for {
		h.mu.Lock()
		if !h.spawnAuthorisedLocked() {
			// Take the change channel in the same critical section as the
			// authorisation check: taking it after unlocking could miss a wake
			// that lands in between and stall the supervisor forever.
			changed := h.changed
			h.mu.Unlock()
			select {
			case <-ctx.Done():
				h.shutdown()
				return ctx.Err()
			case <-changed:
			}
			continue
		}
		if h.grow > 0 {
			h.grow--
		}
		h.spawnLocked(ctx)
		h.mu.Unlock()
	}
}

// spawnAuthorisedLocked reports whether one more standby connection may be
// dialled right now, mirroring the reference supervisor's two triggers: growth a
// started Flow authorised, or the single seed an empty budget is due for.
func (h *tlsHydra) spawnAuthorisedLocked() bool {
	if h.grow > 0 {
		return true
	}
	return h.pending == 0 && !time.Now().Before(h.seedAt)
}

func (h *tlsHydra) spawnLocked(ctx context.Context) {
	h.pending++
	h.wg.Add(1)
	go h.runPending(ctx)
}

func (h *tlsHydra) wake() {
	h.mu.Lock()
	// A zero-value hydra has no channel to close; newTLSHydra always makes one.
	if h.changed != nil {
		close(h.changed)
	}
	h.changed = make(chan struct{})
	h.mu.Unlock()
}

// finish records that one connection left the budget and reports how.
func (h *tlsHydra) finish(outcome pendingOutcome) {
	h.mu.Lock()
	if h.pending > 0 {
		h.pending--
	}
	switch outcome {
	case outcomeStarted:
		// A started Flow leaves the budget and authorises top-up growth, sized
		// from what is left of the pool after the budget was released.
		room := h.poolMax - h.pending
		if room > egressTLSGrowth {
			room = egressTLSGrowth
		}
		if room > 0 {
			h.grow += room
		}
	case outcomeExpired:
		if h.pending == 0 {
			// Expiry is not a failure, so the next seed goes out at once.
			h.seedAt = time.Now()
		}
	case outcomeFailed:
		if h.pending == 0 {
			h.seedAt = time.Now().Add(serviceCooldown)
			// Wake the supervisor when the cooldown ends, because nothing else
			// will report a change until then.
			time.AfterFunc(serviceCooldown, h.wake)
		}
	}
	h.mu.Unlock()
	h.wake()
}

type pendingOutcome int

const (
	outcomeStarted pendingOutcome = iota
	outcomeExpired
	outcomeFailed
)

// standbyOutcome classifies why a parked registration stopped waiting. Only the
// standby deadline expiring reseeds immediately; a disconnected carrier is a
// failure that waits out the cooldown, so a Portal that keeps dropping
// registrations is not reconnected to as fast as it drops them.
func standbyOutcome(err error) pendingOutcome {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return outcomeExpired
	}
	return outcomeFailed
}

// runPending dials, registers, and parks one TLS connection until it is handed
// a Flow or its standby lifetime ends.
func (h *tlsHydra) runPending(ctx context.Context) {
	defer h.wg.Done()
	outcome := outcomeFailed
	finished := false
	// finish records the outcome once and reports it. It is called explicitly
	// before a Flow starts, so the supervisor can replace this connection while
	// the Flow is still running; the deferred call covers the paths that return
	// before that.
	finish := func(next pendingOutcome) {
		if !finished {
			finished = true
			outcome = next
			h.finish(next)
		}
	}
	defer func() {
		if !finished {
			h.finish(outcome)
		}
	}()

	dialCtx, cancel := context.WithTimeout(ctx, h.handshake)
	conn, err := h.cfg.DialTLS(dialCtx)
	cancel()
	if err != nil {
		return
	}
	h.track(conn)
	defer h.untrack(conn)
	// Registration shares the handshake budget with the dial; a Portal that
	// accepts the TLS session but never answers cannot pin a standby slot.
	_ = conn.SetDeadline(time.Now().Add(h.handshake))
	if err := h.register(conn); err != nil {
		// A BUSY reply means the Portal's pending set is full. The supervisor
		// treats it like any other failure and reseeds after the cooldown.
		_ = conn.Close()
		return
	}
	_ = conn.SetDeadline(time.Time{})
	br := bufio.NewReader(conn)
	// Park until the Portal writes a FlowStart on this connection, or until the
	// standby lifetime ends. Peek leaves the byte buffered, so the Flow handler
	// below still reads the whole FlowStart+Target pair.
	_ = conn.SetReadDeadline(time.Now().Add(egressTLSIdleTTL))
	if _, err := br.Peek(1); err != nil {
		finish(standbyOutcome(err))
		_ = conn.Close()
		return
	}
	finish(outcomeStarted)
	_ = conn.SetDeadline(time.Time{})
	h.serveFlow(ctx, conn, br)
}

// track registers one live connection with the supervisor, so shutdown can
// close it and unblock its goroutine.
func (h *tlsHydra) track(conn net.Conn) {
	h.mu.Lock()
	h.live[conn] = struct{}{}
	h.mu.Unlock()
}

func (h *tlsHydra) untrack(conn net.Conn) {
	h.mu.Lock()
	delete(h.live, conn)
	h.mu.Unlock()
}

// shutdown closes every TLS connection the supervisor owns and bounds the wait
// for their goroutines. Stopping the Egress aborts its Flows, exactly as closing
// the QUIC carrier's connection aborts the Flows on that carrier.
func (h *tlsHydra) shutdown() {
	h.mu.Lock()
	for conn := range h.live {
		_ = conn.Close()
	}
	h.mu.Unlock()

	done := make(chan struct{})
	go func() {
		h.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(shutdownTimeout):
	}
}

// register writes the Egress AuthFrame and reads the one-byte reply.
func (h *tlsHydra) register(conn net.Conn) error {
	exp, err := exporterTLS(conn)
	if err != nil {
		return err
	}
	if err := wire.WriteAuthFrame(conn, h.creds, wire.RoleEgress, wire.AuthTLS, exp); err != nil {
		return err
	}
	res, err := wire.ReadRegistrationResult(conn)
	if err != nil {
		return err
	}
	if res == wire.RegistrationBusy {
		return ErrBusy
	}
	if res != wire.RegistrationAccepted {
		return errors.New("nw3: invalid registration result")
	}
	return nil
}

// serveFlow reads the FlowStart and target the Portal opens, dials the target,
// and relays. UDP over a TLS carrier is UoT framed, so both directions stay on
// the one connection.
func (h *tlsHydra) serveFlow(ctx context.Context, conn net.Conn, br *bufio.Reader) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(flowSetupLimit))
	kind, target, ok, err := wire.ReadFlowRequest(br)
	if err != nil || !ok {
		_ = wire.WriteSetupResult(conn, wire.SetupInvalidRequest)
		_ = conn.Close()
		return
	}
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	var peer net.Conn
	if kind == wire.FlowTCP {
		peer, err = h.cfg.Upstream.DialTCP(dialCtx, target)
	} else {
		peer, err = h.cfg.Upstream.DialUDP(dialCtx, target)
	}
	if err != nil {
		_ = wire.WriteSetupResult(conn, wire.SetupDialFailed)
		_ = conn.Close()
		return
	}
	defer peer.Close()
	if err := wire.WriteSetupResult(conn, wire.SetupReady); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	client := &pipe{Reader: br, write: conn, closer: conn}
	if kind == wire.FlowTCP {
		flowio.Relay(client, peer, h.up, h.down)
		return
	}
	// The carrier frames the UDP flow, the upstream socket does not, so the two
	// sides use different relays: UoT on the client side, bare datagrams on the
	// peer side. Framing both ends twice would nest the frames.
	flowio.RelayUoTRaw(client, &idleConn{Conn: peer, idle: udpIdle}, h.up, h.down)
}

// idleConn applies the UDP idle deadline to a raw datagram socket before every
// read, without adding any framing: the egress relay reads one datagram per
// Read and writes one datagram per Write.
type idleConn struct {
	net.Conn
	idle time.Duration
}

func (c *idleConn) Read(b []byte) (int, error) {
	_ = c.Conn.SetReadDeadline(time.Now().Add(c.idle))
	return c.Conn.Read(b)
}

// serveFlow is the QUIC-side flow handler. It is kept separate from the TLS one
// because the two carriers frame their UDP payloads differently.
func serveFlow(ctx context.Context, cfg Config, router *dgram.Router, st qio.Stream, up, down *flowio.Limiter) {
	defer st.Close()
	br := bufio.NewReader(st)
	kind, target, ok, err := wire.ReadFlowRequest(br)
	if err != nil || !ok {
		_ = wire.WriteSetupResult(st, wire.SetupInvalidRequest)
		return
	}
	// A UDP flow over this QUIC carrier needs DATAGRAM support. Reject it
	// before the target dial and before READY; Core forbids a fallback.
	if kind == wire.FlowUDP && router.MaxDatagramSize() <= 0 {
		_ = wire.WriteSetupResult(st, wire.SetupInternalError)
		return
	}
	var id uint32
	if kind == wire.FlowUDP {
		id, err = wire.UDPFlowID(st.ID(), true)
		if err != nil {
			_ = wire.WriteSetupResult(st, wire.SetupFlowLimit)
			return
		}
	}
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	var peer net.Conn
	if kind == wire.FlowTCP {
		peer, err = cfg.Upstream.DialTCP(dialCtx, target)
	} else {
		peer, err = cfg.Upstream.DialUDP(dialCtx, target)
	}
	if err != nil {
		_ = wire.WriteSetupResult(st, wire.SetupDialFailed)
		return
	}
	defer peer.Close()
	if err := wire.WriteSetupResult(st, wire.SetupReady); err != nil {
		return
	}
	client := &pipe{Reader: br, write: st, closer: st}
	if kind == wire.FlowTCP {
		flowio.Relay(client, peer, up, down)
		return
	}
	flow := router.Register(id)
	defer router.CloseFlow(id)
	done := make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(done) }) }
	go func() {
		var b [1]byte
		_, _ = br.Read(b[:])
		finish()
	}()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		for {
			_ = peer.SetReadDeadline(time.Now().Add(udpIdle))
			n, err := peer.Read(buf)
			if err != nil {
				finish()
				return
			}
			_ = down.WaitN(context.Background(), n)
			if err := router.Send(id, buf[:n]); err != nil {
				finish()
				return
			}
		}
	}()
	for {
		select {
		case <-done:
			_ = peer.Close()
			wg.Wait()
			return
		case <-flow.Done():
			_ = peer.Close()
			wg.Wait()
			return
		case pkt, ok := <-flow.C:
			if !ok {
				_ = peer.Close()
				wg.Wait()
				return
			}
			_ = up.WaitN(context.Background(), len(pkt))
			_ = peer.SetWriteDeadline(time.Now().Add(udpIdle))
			if _, err := peer.Write(pkt); err != nil {
				finish()
				_ = peer.Close()
				wg.Wait()
				return
			}
		}
	}
}

func exporter(conn qio.Conn) (wire.Exporter, error) {
	var out wire.Exporter
	b, err := conn.Exporter()
	if err != nil {
		return out, err
	}
	if copy(out[:], b) != wire.ExporterLen {
		return out, errors.New("nw3: short exporter")
	}
	return out, nil
}

func exporterTLS(conn net.Conn) (wire.Exporter, error) {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return wire.Exporter{}, errors.New("nw3: tls egress requires a tls connection")
	}
	state := tlsConn.ConnectionState()
	if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != wire.ALPN {
		return wire.Exporter{}, errors.New("nw3: tls handshake rejected")
	}
	var out wire.Exporter
	b, err := state.ExportKeyingMaterial(wire.ExporterLabel, []byte{}, wire.ExporterLen)
	if err != nil {
		return out, err
	}
	if copy(out[:], b) != wire.ExporterLen {
		return out, errors.New("nw3: short exporter")
	}
	return out, nil
}

func sleep(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func readPoolMax(name string, def int) (int, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return def, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q", name, raw)
	}
	if value < 1 {
		return 0, fmt.Errorf("%s must be at least 1, got %d", name, value)
	}
	return value, nil
}

type pipe struct {
	io.Reader
	write  io.Writer
	closer io.Closer
}

func (p *pipe) Read(b []byte) (int, error)  { return p.Reader.Read(b) }
func (p *pipe) Write(b []byte) (int, error) { return p.write.Write(b) }
func (p *pipe) Close() error {
	if p.closer != nil {
		return p.closer.Close()
	}
	return nil
}

func (p *pipe) CloseWrite() error {
	if cw, ok := p.write.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	if cw, ok := p.closer.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return p.Close()
}
