// Package portal is the Nowhere 3 server. A listener accepts only ALPN nw3.
package portal

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/transport/nowhere/core/dgram"
	"github.com/metacubex/mihomo/transport/nowhere/core/flowio"
	nwhandshake "github.com/metacubex/mihomo/transport/nowhere/core/handshake"
	"github.com/metacubex/mihomo/transport/nowhere/core/morph"
	"github.com/metacubex/mihomo/transport/nowhere/core/qio"
	"github.com/metacubex/mihomo/transport/nowhere/core/wire"
)

const (
	maxUnauth      = 256
	maxPerSource   = 32
	maxFlows       = 4096
	udpIdle        = 120 * time.Second
	flowSetupLimit = 20 * time.Second
)

// Config is a Portal. Egress mode ignores Upstream and bridges to the registered exits.
type Config struct {
	SharedKey    string
	Morph        bool
	TLS          *tls.Config
	Upstream     Upstream
	Egress       bool
	UploadMbps   int
	DownloadMbps int
	// EgressTLSMax caps the TLS Egress connection permits one Portal holds
	// (NOW_PORTAL_TLS_IDLE_MAX). Zero selects DefaultEgressTLSMax.
	EgressTLSMax int
}

// Server accepts Vector and, when Egress is set, any number of Egress
// registrations over both carriers.
type Server struct {
	creds    *wire.Credentials
	keys     *morph.Keys
	tls      *tls.Config
	up       Upstream
	egress   bool
	upload   *flowio.Limiter
	download *flowio.Limiter

	// handshake bounds transport establishment and authentication on every
	// connection. Since Nowhere 3.3 it is derived from the shared key unless
	// NOW_HANDSHAKE_TIMEOUT overrides it.
	handshake time.Duration

	admit admit
	flows gate

	// registry is the FIFO of Egress connections a Vector flow claims from. It
	// is nil unless Egress is set.
	registry *egressRegistry
}

// New checks the shared key and exit mode.
func New(cfg Config) (*Server, error) {
	if err := wire.ValidateServiceKey(cfg.SharedKey); err != nil {
		return nil, err
	}
	if cfg.TLS == nil {
		return nil, errors.New("nw3: missing portal TLS config")
	}
	if !cfg.Egress && cfg.Upstream == nil {
		return nil, errors.New("nw3: missing portal upstream")
	}
	handshake, err := nwhandshake.TimeoutFromEnv(cfg.SharedKey)
	if err != nil {
		return nil, err
	}
	egressTLSMax, err := EgressTLSMaxFromEnv()
	if err != nil {
		return nil, err
	}
	creds, err := wire.NewCredentials(cfg.SharedKey)
	if err != nil {
		return nil, err
	}
	tlsCfg := cfg.TLS.Clone()
	tlsCfg.MinVersion = tls.VersionTLS13
	tlsCfg.MaxVersion = tls.VersionTLS13
	tlsCfg.NextProtos = []string{wire.ALPN}
	tlsCfg.SessionTicketsDisabled = true
	s := &Server{
		creds:     creds,
		tls:       tlsCfg,
		up:        cfg.Upstream,
		egress:    cfg.Egress,
		upload:    flowio.NewMbps(cfg.UploadMbps),
		download:  flowio.NewMbps(cfg.DownloadMbps),
		admit:     admit{per: map[string]int{}},
		handshake: handshake,
	}
	if cfg.Egress {
		if cfg.EgressTLSMax > 0 {
			egressTLSMax = cfg.EgressTLSMax
		}
		s.registry = newEgressRegistry(egressTLSMax)
	}
	if cfg.Morph {
		keys := morph.Derive([]byte(cfg.SharedKey))
		s.keys = &keys
	}
	return s, nil
}

// Serve accepts TLS connections. The listener is closed when ctx ends.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		go s.serveTCP(ctx, conn)
	}
}

// ServeQUIC accepts QUIC connections that already negotiated ALPN nw3 inside the host stack.
// The host TLS config must offer only nw3; mismatched ALPNs are closed here as well.
func (s *Server) ServeQUIC(ctx context.Context, ln qio.Listener) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		go s.serveQUIC(ctx, conn)
	}
}

func (s *Server) serveTCP(ctx context.Context, raw net.Conn) {
	acceptedAt := time.Now()
	deadline := acceptedAt.Add(s.handshake)
	morphing := s.keys != nil
	if morphing {
		// Abortive close stays on until Vector authentication succeeds.
		if err := setZeroLinger(raw); err != nil {
			_ = raw.Close()
			return
		}
	}
	if !s.admit.take(raw.RemoteAddr()) {
		if !morphing {
			_ = raw.Close()
			return
		}
		// A Morph TCP connection waits for a slot until the handshake deadline
		// instead of being dropped. The wait does not read the socket.
		if !s.admit.wait(ctx, raw.RemoteAddr(), deadline) {
			_ = raw.Close()
			return
		}
	}
	held := true
	defer func() {
		if held {
			s.admit.release(raw.RemoteAddr())
		}
	}()
	if morphing {
		raw = morph.WrapTCPServer(raw, *s.keys)
	}
	tlsConn := tls.Server(raw, s.tls)
	_ = tlsConn.SetDeadline(deadline)
	if err := tlsConn.Handshake(); err != nil {
		// A rejected prelude or ClientHello is not drained: the Morph reader
		// stops returning socket bytes once admission fails. The slot is released
		// before the hold, because the connection will not authenticate. The
		// socket itself stays open until the deadline captured at accept.
		// crypto/tls does not preserve the admission error, so every Morph
		// failure before a TLS response takes this path.
		if morphing {
			s.admit.release(raw.RemoteAddr())
			held = false
			parkUntil(deadline)
		}
		_ = tlsConn.Close()
		return
	}
	state := tlsConn.ConnectionState()
	exp, err := exportState(state)
	if err != nil || state.NegotiatedProtocol != wire.ALPN || state.Version != tls.VersionTLS13 {
		_ = tlsConn.Close()
		return
	}
	br := bufio.NewReader(tlsConn)
	role, err := wire.ReadAuthFrame(br, s.creds, wire.AuthTLS, exp)
	s.admit.release(raw.RemoteAddr())
	held = false
	if err != nil {
		_ = tlsConn.Close()
		return
	}
	// Since Nowhere 3.3 an Egress tag is admitted on TLS as well as QUIC. A
	// complete, valid tag for an available role is what restores normal linger.
	if morphing {
		if err := morph.ReleaseAuthenticated(raw, deadline); err != nil {
			_ = tlsConn.Close()
			return
		}
	}
	switch role {
	case wire.RoleEgress:
		s.serveEgressTLS(ctx, tlsConn, br)
	case wire.RoleVector:
		s.serveVectorTCP(ctx, tlsConn, br)
	default:
		_ = tlsConn.Close()
	}
}

// serveVectorTCP reads the Vector's first Flow and hands it to serveFlow.
func (s *Server) serveVectorTCP(ctx context.Context, tlsConn *tls.Conn, br *bufio.Reader) {
	defer tlsConn.Close()
	_ = tlsConn.SetDeadline(time.Now().Add(flowSetupLimit))
	kind, target, ok, err := wire.ReadFlowRequest(br)
	rw := &pipe{Reader: br, write: tlsConn, closer: tlsConn}
	if err != nil || !ok {
		if ok || err != nil {
			_ = wire.WriteSetupResult(tlsConn, wire.SetupInvalidRequest)
		}
		_ = tlsConn.Close()
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})
	s.serveFlow(ctx, kind, target, rw, nil, 0, true)
}

func (s *Server) serveQUIC(ctx context.Context, conn qio.Conn) {
	defer conn.CloseWithError(0, "")
	if conn.ALPN() != wire.ALPN || conn.TLSVersion() != tls.VersionTLS13 {
		return
	}
	if !s.admit.take(conn.RemoteAddr()) {
		return
	}
	dropCtx, cancelDrop := context.WithCancel(ctx)
	dropDone := make(chan struct{})
	go func() {
		defer close(dropDone)
		for {
			if _, err := conn.ReceiveDatagram(dropCtx); err != nil {
				return
			}
		}
	}()
	authCtx, cancelAuth := context.WithTimeout(ctx, s.handshake)
	st, err := conn.AcceptStream(authCtx)
	cancelAuth()
	if err != nil || st.ID() != 0 {
		cancelDrop()
		<-dropDone
		s.admit.release(conn.RemoteAddr())
		return
	}
	exp, err := exportConn(conn)
	if err != nil {
		cancelDrop()
		<-dropDone
		s.admit.release(conn.RemoteAddr())
		return
	}
	_ = st.SetDeadline(time.Now().Add(s.handshake))
	br := bufio.NewReader(st)
	role, err := wire.ReadAuthFrame(br, s.creds, wire.AuthQUIC, exp)
	s.admit.release(conn.RemoteAddr())
	cancelDrop()
	<-dropDone
	if err != nil {
		return
	}
	_ = st.SetDeadline(time.Time{})
	router := dgram.NewRouter(conn)
	go router.Run(ctx)
	switch role {
	case wire.RoleVector:
		s.serveVectorConn(ctx, conn, router, st, br)
	case wire.RoleEgress:
		s.serveEgressQUIC(ctx, conn, router, st, br)
	default:
	}
}

func (s *Server) serveVectorConn(ctx context.Context, conn qio.Conn, router *dgram.Router, first qio.Stream, br *bufio.Reader) {
	go s.readAndServe(ctx, router, first, br, true)
	for {
		if !s.flows.try() {
			// The application flow cap is full. Stop accepting until one
			// finishes, so a peer cannot hold a goroutine per Stream on QUIC
			// credit alone.
			if !s.flows.wait(ctx, flowSetupLimit) {
				return
			}
		}
		st, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		if st.ID()&2 != 0 || st.ID()&1 != 0 {
			_ = conn.CloseWithError(0, "direction")
			return
		}
		go s.readAndServe(ctx, router, st, bufio.NewReader(st), true)
	}
}

func (s *Server) readAndServe(ctx context.Context, router *dgram.Router, st qio.Stream, br *bufio.Reader, client bool) {
	defer st.Close()
	_ = st.SetReadDeadline(time.Now().Add(flowSetupLimit))
	kind, target, ok, err := wire.ReadFlowRequest(br)
	_ = st.SetReadDeadline(time.Time{})
	if err != nil || !ok {
		if err != nil {
			_ = wire.WriteSetupResult(st, wire.SetupInvalidRequest)
		}
		_ = st.CloseWrite()
		return
	}
	rw := &pipe{Reader: br, write: st, closer: st}
	s.serveFlow(ctx, kind, target, rw, router, st.ID(), client)
}

func (s *Server) serveFlow(ctx context.Context, kind wire.FlowKind, target wire.Target, client *pipe, router *dgram.Router, streamID uint64, clientInitiated bool) {
	defer client.Close()
	if !s.flows.acquire() {
		_ = wire.WriteSetupResult(client, wire.SetupFlowLimit)
		_ = client.Close()
		return
	}
	defer s.flows.release()
	var udpID uint32
	if kind == wire.FlowUDP && router != nil {
		// A UDP flow over QUIC needs DATAGRAM support on the Vector connection.
		// Reject it before any target dial or READY; Core forbids a fallback.
		if router.MaxDatagramSize() <= 0 {
			_ = wire.WriteSetupResult(client, wire.SetupInternalError)
			_ = client.Close()
			return
		}
		// Derive the connection-local id before READY. An exhausted or invalid
		// stream id fails the flow with FLOW_LIMIT instead of authorizing
		// payload it cannot route.
		var err error
		udpID, err = wire.UDPFlowID(streamID, !clientInitiated)
		if err != nil {
			_ = wire.WriteSetupResult(client, wire.SetupFlowLimit)
			_ = client.Close()
			return
		}
	}
	setupCtx, cancel := context.WithTimeout(ctx, flowSetupLimit)
	defer cancel()
	if s.egress {
		s.serveViaEgress(setupCtx, kind, target, client, router, streamID)
		return
	}
	var peer net.Conn
	var err error
	if kind == wire.FlowTCP {
		peer, err = s.up.DialTCP(setupCtx, target)
	} else {
		peer, err = s.up.DialUDP(setupCtx, target)
	}
	if err != nil {
		_ = wire.WriteSetupResult(client, wire.SetupDialFailed)
		_ = client.Close()
		return
	}
	defer peer.Close()
	if err := wire.WriteSetupResult(client, wire.SetupReady); err != nil {
		return
	}
	if kind == wire.FlowTCP {
		flowio.Relay(client, peer, s.upload, s.download)
		return
	}
	if router == nil {
		relayUoT(client, peer, s.upload, s.download)
		return
	}
	relayQUICUDP(router, udpID, client, peer, s.upload, s.download)
}

// serveViaEgress claims one registered Egress connection and bridges the Vector
// flow onto it. Since Nowhere 3.3 the claim waits for an exit instead of failing
// outright, and the exit may be a QUIC or a TLS registration.
func (s *Server) serveViaEgress(ctx context.Context, kind wire.FlowKind, target wire.Target, client *pipe, router *dgram.Router, streamID uint64) {
	reg := s.registry.wait(ctx)
	if reg == nil {
		_ = wire.WriteSetupResult(client, wire.SetupDialFailed)
		_ = client.Close()
		return
	}
	if reg.tls != nil {
		s.serveViaTLSEgress(ctx, reg, kind, target, client, router, streamID)
		return
	}
	s.serveViaQUICEgress(ctx, reg, kind, target, client, router, streamID)
}

// serveViaQUICEgress opens a business stream on a claimed QUIC registration.
// The connection stays in the FIFO, so it can serve further Flows afterwards.
func (s *Server) serveViaQUICEgress(ctx context.Context, reg *egressRegistration, kind wire.FlowKind, target wire.Target, client *pipe, router *dgram.Router, streamID uint64) {
	// A Vector over TLS carries its UDP flows as UoT on the control stream,
	// while a QUIC Egress serves a UDP flow from DATAGRAMs on its connection.
	// Bridging the two needs a UoT-to-DATAGRAM relay this port does not have
	// (mihomo exposes one carrier per Portal, so the pair never occurs there).
	// Reject the flow rather than relaying frames the Egress would discard.
	if kind == wire.FlowUDP && router == nil {
		_ = wire.WriteSetupResult(client, wire.SetupInternalError)
		_ = client.Close()
		return
	}
	st, err := reg.quic.OpenStream(ctx)
	if err != nil {
		_ = wire.WriteSetupResult(client, wire.SetupDialFailed)
		_ = client.Close()
		return
	}
	defer st.Close()
	if err := wire.WriteFlowRequest(st, kind, target); err != nil {
		_ = wire.WriteSetupResult(client, wire.SetupDialFailed)
		_ = client.Close()
		return
	}
	_ = st.SetReadDeadline(time.Now().Add(flowSetupLimit))
	res, err := wire.ReadSetupResult(st)
	_ = st.SetReadDeadline(time.Time{})
	if err != nil {
		res = wire.SetupDialFailed
	}
	if res != wire.SetupReady {
		_ = wire.WriteSetupResult(client, res)
		_ = client.Close()
		return
	}
	// A UDP flow forwarded to a QUIC Egress needs DATAGRAM support on that
	// connection too, and its flow id must be valid before READY.
	if kind == wire.FlowUDP && reg.router.MaxDatagramSize() <= 0 {
		_ = wire.WriteSetupResult(client, wire.SetupInternalError)
		_ = client.Close()
		return
	}
	var vid, eid uint32
	if kind == wire.FlowUDP {
		vid, err = wire.UDPFlowID(streamID, false)
		if err == nil {
			eid, err = wire.UDPFlowID(st.ID(), true)
		}
		if err != nil {
			_ = wire.WriteSetupResult(client, wire.SetupFlowLimit)
			_ = client.Close()
			return
		}
	}
	if err := wire.WriteSetupResult(client, wire.SetupReady); err != nil {
		return
	}
	if kind == wire.FlowTCP {
		peer := &pipe{Reader: st, write: st, closer: st}
		flowio.Relay(client, peer, s.upload, s.download)
		return
	}
	bridgeUDP(router, vid, client, reg.router, eid, &pipe{Reader: st, write: st, closer: st})
}

// serveViaTLSEgress runs the one Flow a claimed TLS registration is allowed to
// carry. Authentication, registration and that Flow share the connection, so
// there is no second claim. UDP is UoT framed on that connection; a QUIC
// Vector's datagrams are bridged to the same framing.
func (s *Server) serveViaTLSEgress(ctx context.Context, reg *egressRegistration, kind wire.FlowKind, target wire.Target, client *pipe, router *dgram.Router, streamID uint64) {
	defer close(reg.done)
	defer func() { _ = reg.tls.Close() }()
	conn := reg.tls
	br := reg.reader
	if br == nil {
		br = bufio.NewReader(conn)
	}
	_ = conn.SetDeadline(time.Now().Add(flowSetupLimit))
	if err := wire.WriteFlowRequest(conn, kind, target); err != nil {
		_ = wire.WriteSetupResult(client, wire.SetupDialFailed)
		_ = client.Close()
		return
	}
	res, err := wire.ReadSetupResult(br)
	if err != nil {
		res = wire.SetupDialFailed
	}
	if res != wire.SetupReady {
		_ = conn.SetDeadline(time.Time{})
		_ = wire.WriteSetupResult(client, res)
		_ = client.Close()
		return
	}
	// Derive the Vector's connection-local UDP id before READY; the TLS Egress
	// side carries UoT, so only the Vector side needs this id.
	var vid uint32
	if kind == wire.FlowUDP && router != nil {
		vid, err = wire.UDPFlowID(streamID, false)
		if err != nil {
			_ = conn.SetDeadline(time.Time{})
			_ = wire.WriteSetupResult(client, wire.SetupFlowLimit)
			_ = client.Close()
			return
		}
	}
	if err := wire.WriteSetupResult(client, wire.SetupReady); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	peer := &pipe{Reader: br, write: conn, closer: conn}
	if kind == wire.FlowTCP {
		flowio.Relay(client, peer, s.upload, s.download)
		return
	}
	if router == nil {
		relayUoTStream(client, peer, s.upload, s.download)
		return
	}
	bridgeDatagramToUoT(router, vid, client, peer, s.upload, s.download)
}

// serveEgressQUIC registers a QUIC Egress connection. The AuthFrame stream is
// followed by FIN and carries no Flow bytes; the reply is one result byte and
// FIN. The registration lives as long as the connection, and several QUIC
// registrations may sit in the FIFO at once.
func (s *Server) serveEgressQUIC(ctx context.Context, conn qio.Conn, router *dgram.Router, st qio.Stream, br *bufio.Reader) {
	if !s.egress {
		return
	}
	_ = st.SetReadDeadline(time.Now().Add(s.handshake))
	var extra [1]byte
	if n, err := br.Read(extra[:]); n > 0 || (err != nil && !errors.Is(err, io.EOF)) {
		return
	}
	_ = st.SetReadDeadline(time.Now().Add(s.handshake))
	if err := wire.WriteRegistrationResult(st, wire.RegistrationAccepted); err != nil {
		return
	}
	if err := st.CloseWrite(); err != nil {
		return
	}
	reg := &egressRegistration{quic: conn, router: router}
	s.registry.add(reg)
	defer s.registry.remove(reg)
	// A client-initiated business stream on an Egress connection is a
	// role-direction violation and closes the whole connection.
	stray, err := conn.AcceptStream(ctx)
	if err != nil {
		return
	}
	_ = stray.Close()
	_ = conn.CloseWithError(0, "direction")
}

// serveEgressTLS registers a TLS Egress connection. Since Nowhere 3.3 the
// registration handshake exists on TLS too: one AuthFrame, one result byte, and
// then the single Flow this carrier is allowed to carry.
//
// NOTE: a parked registration is not watched for a peer close. A dead
// registration therefore stays claimable, and holds its pending permit, until
// its 120s standby TTL; the first claim consumes it and fails that one Flow.
// Detecting the disconnect earlier would need a reader handoff so the parked
// goroutine can read without racing the Flow for the same buffered reader.
func (s *Server) serveEgressTLS(ctx context.Context, conn *tls.Conn, br *bufio.Reader) {
	if !s.egress || s.registry == nil {
		_ = conn.Close()
		return
	}
	// A full pending set answers BUSY and drops the connection.
	if !s.registry.reserveTLS() {
		_ = conn.SetDeadline(time.Now().Add(s.handshake))
		_ = wire.WriteRegistrationResult(conn, wire.RegistrationBusy)
		_ = conn.Close()
		return
	}
	// One deferred cleanup owns the whole registration: the pending permit is
	// released by whichever of claim and teardown runs first, and the connection
	// is closed on every path.
	reg := &egressRegistration{tls: conn, reader: br, permitHeld: true}
	defer func() {
		s.registry.remove(reg)
		s.registry.releaseHeld(reg)
		_ = conn.Close()
	}()
	_ = conn.SetDeadline(time.Now().Add(s.handshake))
	if err := wire.WriteRegistrationResult(conn, wire.RegistrationAccepted); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	// A client that pipelines bytes before the result is not following the
	// registration handshake, so the connection is dropped rather than parked.
	if br.Buffered() > 0 {
		return
	}
	reg.standby = time.Now().Add(egressTLSIdleTTL)
	reg.done = make(chan struct{})
	claimed := s.registry.add(reg)
	select {
	case <-claimed:
		// The Flow that claimed this registration owns the connection and closes
		// reg.done when it finishes; the deferred cleanup then closes it.
		<-reg.done
	case <-time.After(time.Until(reg.standby)):
	case <-ctx.Done():
	}
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

// relayUoTStream relays a UoT-framed UDP flow between two stream peers. Unlike
// relayUoT it applies no read deadline, because a stream peer has no idle
// timeout of its own: either side closing the stream ends the flow.
func relayUoTStream(client *pipe, peer io.ReadWriteCloser, up, down *flowio.Limiter) {
	flowio.RelayUoT(client, peer, up, down)
}

func relayUoT(client *pipe, udp net.Conn, up, down *flowio.Limiter) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			pkt, err := wire.ReadUoT(client)
			if err != nil {
				break
			}
			_ = up.WaitN(context.Background(), len(pkt))
			if _, err := udp.Write(pkt); err != nil {
				break
			}
		}
		_ = udp.Close()
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		for {
			_ = udp.SetReadDeadline(time.Now().Add(udpIdle))
			n, err := udp.Read(buf)
			if err != nil {
				break
			}
			_ = down.WaitN(context.Background(), n)
			if err := wire.WriteUoT(client, buf[:n]); err != nil {
				break
			}
		}
		_ = client.CloseWrite()
	}()
	wg.Wait()
}

func relayQUICUDP(router *dgram.Router, id uint32, client *pipe, udp net.Conn, up, down *flowio.Limiter) {
	flow := router.Register(id)
	defer router.CloseFlow(id)
	done := make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(done) }) }
	go func() {
		var b [1]byte
		_, _ = client.Read(b[:])
		finish()
	}()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		for {
			_ = udp.SetReadDeadline(time.Now().Add(udpIdle))
			n, err := udp.Read(buf)
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
			_ = udp.Close()
			wg.Wait()
			return
		case <-flow.Done():
			_ = udp.Close()
			wg.Wait()
			return
		case pkt, ok := <-flow.C:
			if !ok {
				_ = udp.Close()
				wg.Wait()
				return
			}
			_ = up.WaitN(context.Background(), len(pkt))
			_ = udp.SetWriteDeadline(time.Now().Add(udpIdle))
			if _, err := udp.Write(pkt); err != nil {
				finish()
				_ = udp.Close()
				wg.Wait()
				return
			}
		}
	}
}

func bridgeUDP(from *dgram.Router, fromID uint32, fromCtl *pipe, to *dgram.Router, toID uint32, toCtl *pipe) {
	left := from.Register(fromID)
	right := to.Register(toID)
	defer from.CloseFlow(fromID)
	defer to.CloseFlow(toID)
	done := make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(done) }) }
	go func() {
		var b [1]byte
		_, _ = fromCtl.Read(b[:])
		finish()
	}()
	go func() {
		var b [1]byte
		_, _ = toCtl.Read(b[:])
		finish()
	}()
	for {
		select {
		case <-done:
			return
		case <-left.Done():
			return
		case <-right.Done():
			return
		case pkt, ok := <-left.C:
			if !ok || to.Send(toID, pkt) != nil {
				finish()
			}
		case pkt, ok := <-right.C:
			if !ok || from.Send(fromID, pkt) != nil {
				finish()
			}
		}
	}
}

// bridgeDatagramToUoT pipes one UDP flow between a QUIC DATAGRAM side (a Vector
// over the udp carrier) and a UoT-framed stream side (a TLS Egress
// registration). The control stream closing ends the flow, exactly as it does
// for a datagram-to-datagram bridge.
func bridgeDatagramToUoT(router *dgram.Router, id uint32, client *pipe, uot *pipe, up, down *flowio.Limiter) {
	flow := router.Register(id)
	defer router.CloseFlow(id)
	done := make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(done) }) }
	go func() {
		var b [1]byte
		_, _ = client.Read(b[:])
		finish()
	}()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			pkt, err := wire.ReadUoT(uot)
			if err != nil {
				finish()
				return
			}
			_ = down.WaitN(context.Background(), len(pkt))
			if err := router.Send(id, pkt); err != nil {
				finish()
				return
			}
		}
	}()
	for {
		select {
		case <-done:
			_ = uot.Close()
			wg.Wait()
			return
		case <-flow.Done():
			_ = uot.Close()
			wg.Wait()
			return
		case pkt, ok := <-flow.C:
			if !ok {
				_ = uot.Close()
				wg.Wait()
				return
			}
			_ = up.WaitN(context.Background(), len(pkt))
			if err := wire.WriteUoT(uot, pkt); err != nil {
				finish()
				_ = uot.Close()
				wg.Wait()
				return
			}
		}
	}
}

func exportState(state tls.ConnectionState) (wire.Exporter, error) {
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

func exportConn(conn qio.Conn) (wire.Exporter, error) {
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

type admit struct {
	mu   sync.Mutex
	cond *sync.Cond
	n    int
	per  map[string]int
}

func (a *admit) take(addr net.Addr) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.takeLocked(sourceKey(addr))
}

func (a *admit) takeLocked(key string) bool {
	if a.n >= maxUnauth || a.per[key] >= maxPerSource {
		return false
	}
	a.n++
	a.per[key]++
	return true
}

// wait blocks until a slot is taken, ctx ends, or deadline passes. The
// capacity check and the wait share one lock, so a release cannot pass
// unnoticed between them. It is used only for Morph TCP.
func (a *admit) wait(ctx context.Context, addr net.Addr, deadline time.Time) bool {
	a.mu.Lock()
	if a.cond == nil {
		a.cond = sync.NewCond(&a.mu)
	}
	key := sourceKey(addr)
	timer := time.NewTimer(time.Until(deadline))
	stop := make(chan struct{})
	defer func() {
		timer.Stop()
		close(stop)
	}()
	go func() {
		select {
		case <-timer.C:
		case <-ctx.Done():
		case <-stop:
			return
		}
		a.mu.Lock()
		a.cond.Broadcast()
		a.mu.Unlock()
	}()
	for {
		if a.takeLocked(key) {
			a.mu.Unlock()
			return true
		}
		if ctx.Err() != nil || !time.Now().Before(deadline) {
			a.mu.Unlock()
			return false
		}
		a.cond.Wait()
	}
}

func (a *admit) release(addr net.Addr) {
	key := sourceKey(addr)
	a.mu.Lock()
	if a.n > 0 {
		a.n--
	}
	if a.per[key] <= 1 {
		delete(a.per, key)
	} else {
		a.per[key]--
	}
	if a.cond != nil {
		a.cond.Broadcast()
	}
	a.mu.Unlock()
}

func setZeroLinger(conn net.Conn) error {
	type linger interface {
		SetLinger(int) error
	}
	if conn, ok := conn.(linger); ok {
		return conn.SetLinger(0)
	}
	return nil
}

func parkUntil(deadline time.Time) {
	if wait := time.Until(deadline); wait > 0 {
		time.Sleep(wait)
	}
}

func sourceKey(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return host
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	v6 := ip.To16()
	if v6 == nil {
		return host
	}
	return hex.EncodeToString(v6[:8])
}

type gate struct {
	mu sync.Mutex
	n  int
}

func (g *gate) acquire() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.n >= maxFlows {
		return false
	}
	g.n++
	return true
}

// try reports whether another flow would fit without taking the slot.
func (g *gate) try() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.n < maxFlows
}

// wait blocks until a flow slot is free, ctx ends, or the bound passes. The
// accept loop uses it before taking another business Stream, so a peer cannot
// hold a goroutine per Stream on QUIC credit alone.
func (g *gate) wait(ctx context.Context, bound time.Duration) bool {
	deadline := time.Now().Add(bound)
	for {
		if g.try() {
			return true
		}
		if ctx.Err() != nil || !time.Now().Before(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func (g *gate) release() {
	g.mu.Lock()
	if g.n > 0 {
		g.n--
	}
	g.mu.Unlock()
}
