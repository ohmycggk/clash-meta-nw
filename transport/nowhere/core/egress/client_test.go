package egress

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/nowhere/core/dgram"
	"github.com/metacubex/mihomo/transport/nowhere/core/qio"
	"github.com/metacubex/mihomo/transport/nowhere/core/wire"
)

const egressTestKey = "0123456789abcdef0123456789abcdef"

// TestRunRejectsBadConfig checks the startup validation: exactly one carrier
// dialer, a usable key, and an upstream to dial through.
func TestRunRejectsBadConfig(t *testing.T) {
	up := &fakeUpstream{}
	for name, cfg := range map[string]Config{
		"no dialer":     {SharedKey: egressTestKey, Upstream: up},
		"both dialers":  {SharedKey: egressTestKey, Upstream: up, DialQUIC: dialErr, DialTLS: dialTLSErr},
		"no upstream":   {SharedKey: egressTestKey, DialQUIC: dialErr},
		"short key":     {SharedKey: "abc", Upstream: up, DialQUIC: dialErr},
		"non-hex key":   {SharedKey: strings.Repeat("g", 32), Upstream: up, DialQUIC: dialErr},
		"uppercase key": {SharedKey: strings.ToUpper(egressTestKey), Upstream: up, DialQUIC: dialErr},
	} {
		t.Run(name, func(t *testing.T) {
			if err := Run(context.Background(), cfg); err == nil {
				t.Fatal("Run accepted an unusable config")
			}
		})
	}
}

// TestRunReportsContextCancellation checks that a cancelled context ends Run
// rather than looping forever, including on the retry sleep.
func TestRunReportsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := Run(ctx, Config{SharedKey: egressTestKey, DialQUIC: dialErr, Upstream: &fakeUpstream{}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v, want context.Canceled", err)
	}
}

// TestRunQUICRetriesAfterDialFailure checks that a failing QUIC dial backs off
// and keeps trying rather than giving up, so a Portal that is still starting up
// is reached on a later attempt instead of dropping the Egress.
func TestRunQUICRetriesAfterDialFailure(t *testing.T) {
	var attempts int
	var mu sync.Mutex
	dial := func(context.Context) (qio.Conn, error) {
		mu.Lock()
		attempts++
		mu.Unlock()
		return nil, errors.New("dial refused")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Config{SharedKey: egressTestKey, DialQUIC: dial, Upstream: &fakeUpstream{}})
	}()

	// The first dial goes out at once; the retry waits out serviceCooldown.
	deadline := time.Now().Add(serviceCooldown + 1500*time.Millisecond)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := attempts
		mu.Unlock()
		if got >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	mu.Lock()
	got := attempts
	mu.Unlock()
	if got < 2 {
		t.Fatalf("the dial was attempted %d times, want at least 2", got)
	}

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
}

// TestTLSHydraSpawnTriggers pins the two things that let the budget grow, and
// nothing else: growth a started Flow authorised, and the single seed an empty
// budget is due for. A failure holds the seed back for the cooldown, and a
// non-empty budget with no growth authorised spawns nothing.
func TestTLSHydraSpawnTriggers(t *testing.T) {
	for _, tc := range []struct {
		name     string
		poolMax  int
		pending  int
		grow     int
		cooldown bool
		want     bool
	}{
		{"empty budget is due its seed", DefaultEgressTLSPoolMax, 0, 0, false, true},
		{"empty budget in cooldown holds the seed", DefaultEgressTLSPoolMax, 0, 0, true, false},
		{"growth outranks the cooldown", DefaultEgressTLSPoolMax, 0, 1, true, true},
		{"growth is consumed while the budget is non-empty", DefaultEgressTLSPoolMax, 1, 1, false, true},
		{"non-empty budget with no growth spawns nothing", DefaultEgressTLSPoolMax, 1, 0, false, false},
		{"a full budget spawns nothing", DefaultEgressTLSPoolMax, DefaultEgressTLSPoolMax, 0, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTLSHydra(Config{TLSPoolMax: tc.poolMax})
			h.pending = tc.pending
			h.grow = tc.grow
			if tc.cooldown {
				h.seedAt = time.Now().Add(serviceCooldown)
			}
			h.mu.Lock()
			got := h.spawnAuthorisedLocked()
			h.mu.Unlock()
			if got != tc.want {
				t.Fatalf("spawnAuthorisedLocked() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestTLSHydraFinishOutcomes pins what each outcome authorises. A started Flow
// leaves the budget and sizes the top-up from the pool room that is left; an
// expiry reseeds at once; a failure waits out the cooldown. The budget itself
// never goes negative.
func TestTLSHydraFinishOutcomes(t *testing.T) {
	t.Run("started Flow sizes the top-up from the pool room", func(t *testing.T) {
		for _, tc := range []struct {
			poolMax  int
			pending  int
			wantGrow int
			wantPend int
		}{
			{DefaultEgressTLSPoolMax, 1, egressTLSGrowth, 0},
			{DefaultEgressTLSPoolMax, 3, egressTLSGrowth, 2},
			{1, 1, 1, 0},
			{2, 2, 1, 1},
			// At the cap a started Flow still refills the room it freed.
			{DefaultEgressTLSPoolMax, DefaultEgressTLSPoolMax, 1, DefaultEgressTLSPoolMax - 1},
		} {
			h := newTLSHydra(Config{TLSPoolMax: tc.poolMax})
			h.pending = tc.pending
			h.finish(outcomeStarted)
			h.mu.Lock()
			gotGrow, gotPending := h.grow, h.pending
			h.mu.Unlock()
			if gotGrow != tc.wantGrow || gotPending != tc.wantPend {
				t.Fatalf("poolMax=%d pending=%d: grow=%d pending=%d, want grow=%d pending=%d",
					tc.poolMax, tc.pending, gotGrow, gotPending, tc.wantGrow, tc.wantPend)
			}
		}
	})

	t.Run("expiry reseeds at once", func(t *testing.T) {
		h := newTLSHydra(Config{})
		h.pending = 1
		h.seedAt = time.Now().Add(serviceCooldown)
		h.finish(outcomeExpired)
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.pending != 0 {
			t.Fatalf("pending = %d, want 0", h.pending)
		}
		if time.Now().Before(h.seedAt) {
			t.Fatal("an expiry left the cooldown in place, want it cleared")
		}
		if !h.spawnAuthorisedLocked() {
			t.Fatal("an expired budget is not due a reseed")
		}
	})

	t.Run("failure waits out the cooldown", func(t *testing.T) {
		h := newTLSHydra(Config{})
		h.pending = 1
		h.finish(outcomeFailed)
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.pending != 0 {
			t.Fatalf("pending = %d, want 0", h.pending)
		}
		if !time.Now().Before(h.seedAt) {
			t.Fatal("a failure cleared the cooldown, want it held")
		}
		if h.spawnAuthorisedLocked() {
			t.Fatal("a failed budget is spawning during the cooldown")
		}
	})

	t.Run("a failure alongside a live standby holds no cooldown", func(t *testing.T) {
		h := newTLSHydra(Config{})
		h.pending = 2
		h.finish(outcomeFailed)
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.pending != 1 {
			t.Fatalf("pending = %d, want 1", h.pending)
		}
		if time.Now().Before(h.seedAt) {
			t.Fatal("a failure next to a live standby set a cooldown, want none")
		}
	})

	t.Run("the budget never goes negative", func(t *testing.T) {
		h := newTLSHydra(Config{})
		h.finish(outcomeFailed)
		h.finish(outcomeExpired)
		h.finish(outcomeStarted)
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.pending != 0 {
			t.Fatalf("pending = %d, want 0", h.pending)
		}
	})
}

// TestTLSHydraBudgetFollowsFlowStarts walks the supervisor through the shape the
// reference implementation produces for a pool cap of five: one seed, then a
// top-up of two per started Flow until the cap holds.
func TestTLSHydraBudgetFollowsFlowStarts(t *testing.T) {
	const poolMax = 5
	h := newTLSHydra(Config{TLSPoolMax: poolMax})

	// One seed, then nothing until a Flow starts. The bookkeeping is driven
	// directly here: spawnLocked only adds a goroutine on top of it, and a real
	// one would race these assertions.
	h.mu.Lock()
	if !h.spawnAuthorisedLocked() {
		t.Fatal("the empty budget is not due its seed")
	}
	h.pending++
	if h.spawnAuthorisedLocked() {
		t.Fatal("the budget spawned past its seed")
	}
	h.mu.Unlock()

	// pending after each started Flow, counting the top-up it authorises.
	for _, wantPending := range []int{2, 3, 4, 5, 5} {
		h.finish(outcomeStarted)
		h.mu.Lock()
		for h.grow > 0 {
			if h.pending >= poolMax {
				t.Fatalf("the budget grew to %d past the cap %d", h.pending, poolMax)
			}
			if !h.spawnAuthorisedLocked() {
				t.Fatal("authorised growth was not spawned")
			}
			h.grow--
			h.pending++
		}
		if h.pending != wantPending {
			t.Fatalf("pending = %d, want %d", h.pending, wantPending)
		}
		if h.spawnAuthorisedLocked() {
			t.Fatalf("the budget wants more at pending %d", h.pending)
		}
		h.mu.Unlock()
	}

	// The cap holds: a started Flow at the cap only refills the room it freed,
	// so the pool settles at the cap instead of growing past it.
	h.mu.Lock()
	h.pending = poolMax
	h.mu.Unlock()
	h.finish(outcomeStarted)
	h.mu.Lock()
	if h.pending != poolMax-1 {
		t.Fatalf("pending = %d, want %d", h.pending, poolMax-1)
	}
	if h.grow != 1 {
		t.Fatalf("grow = %d at the cap, want 1", h.grow)
	}
	// The supervisor consumes the authorisation as it spawns.
	h.grow--
	h.pending++
	if h.pending != poolMax {
		t.Fatalf("pending = %d after the refill, want %d", h.pending, poolMax)
	}
	if h.spawnAuthorisedLocked() {
		t.Fatal("a full budget is spawning")
	}
	h.mu.Unlock()
}

// TestExporterTLSRejectsNonTLS checks the carrier guard: the TLS side reaches
// the exporter through a *tls.Conn, so anything else is refused rather than
// silently producing a zero exporter.
func TestExporterTLSRejectsNonTLS(t *testing.T) {
	if _, err := exporterTLS(&fakeNetConn{}); err == nil {
		t.Fatal("exporterTLS accepted a plain connection")
	}
}

func dialErr(context.Context) (qio.Conn, error) { return nil, errors.New("unused") }

func dialTLSErr(context.Context) (net.Conn, error) { return nil, errors.New("unused") }

// fakeUpstream records the targets it was asked to dial.
type fakeUpstream struct {
	mu      sync.Mutex
	tcp     []wire.Target
	udp     []wire.Target
	dialErr error
}

func (u *fakeUpstream) DialTCP(_ context.Context, target wire.Target) (net.Conn, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.tcp = append(u.tcp, target)
	if u.dialErr != nil {
		return nil, u.dialErr
	}
	return &fakeNetConn{}, nil
}

func (u *fakeUpstream) DialUDP(_ context.Context, target wire.Target) (net.Conn, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.udp = append(u.udp, target)
	if u.dialErr != nil {
		return nil, u.dialErr
	}
	return &fakeNetConn{}, nil
}

// fakeNetConn is a net.Conn that accepts writes and reports EOF on reads.
type fakeNetConn struct {
	closed    chan struct{}
	closeOnce sync.Once
}

func (c *fakeNetConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *fakeNetConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *fakeNetConn) LocalAddr() net.Addr              { return nil }
func (c *fakeNetConn) RemoteAddr() net.Addr             { return nil }
func (c *fakeNetConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeNetConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeNetConn) SetWriteDeadline(time.Time) error { return nil }

func (c *fakeNetConn) Close() error {
	c.closeOnce.Do(func() {
		if c.closed == nil {
			c.closed = make(chan struct{})
		}
		close(c.closed)
	})
	return nil
}

// TestEgressTLSPoolMaxFromEnv pins the NOW_EGRESS_TLS_POOL_MAX bounds: unset
// and empty fall back to the default, and anything below 1 is rejected.
func TestEgressTLSPoolMaxFromEnv(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want int
	}{
		{"", DefaultEgressTLSPoolMax},
		{"1", 1},
		{"128", 128},
	} {
		t.Run("accepts "+tc.raw, func(t *testing.T) {
			t.Setenv("NOW_EGRESS_TLS_POOL_MAX", tc.raw)
			got, err := EgressTLSPoolMaxFromEnv()
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
		})
	}

	for _, raw := range []string{"0", "-1", "abc"} {
		t.Run("rejects "+raw, func(t *testing.T) {
			t.Setenv("NOW_EGRESS_TLS_POOL_MAX", raw)
			if _, err := EgressTLSPoolMaxFromEnv(); err == nil {
				t.Fatalf("NOW_EGRESS_TLS_POOL_MAX=%q was accepted", raw)
			}
		})
	}
}

// TestRunResolvesHandshakeTimeout checks that Run rejects an unusable budget and
// accepts an explicit one without reading the environment.
func TestRunResolvesHandshakeTimeout(t *testing.T) {
	t.Setenv("NOW_HANDSHAKE_TIMEOUT", "not-a-duration")
	err := Run(context.Background(), Config{
		SharedKey: egressTestKey, DialTLS: dialTLSErr, Upstream: &fakeUpstream{},
	})
	if err == nil {
		t.Fatal("Run accepted an unusable NOW_HANDSHAKE_TIMEOUT")
	}
}

// TestStandbyOutcome checks the standby classification: only the deadline
// expiring is an immediate reseed; any disconnect waits out the cooldown.
func TestStandbyOutcome(t *testing.T) {
	timeout := &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}
	if got := standbyOutcome(timeout); got != outcomeExpired {
		t.Fatalf("deadline error classified as %v, want outcomeExpired", got)
	}
	for _, err := range []error{io.EOF, net.ErrClosed, fmt.Errorf("wrapped: %w", io.ErrUnexpectedEOF)} {
		if got := standbyOutcome(err); got != outcomeFailed {
			t.Fatalf("%v classified as %v, want outcomeFailed", err, got)
		}
	}
}

// TestIdleConnAppliesReadDeadline checks the raw-datagram adapter sets the UDP
// idle deadline before each read instead of framing the payload.
func TestIdleConnAppliesReadDeadline(t *testing.T) {
	local, remote := net.Pipe()
	defer func() { _ = local.Close() }()
	defer func() { _ = remote.Close() }()

	conn := &idleConn{Conn: local, idle: 20 * time.Millisecond}
	buf := make([]byte, 8)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("a read without a datagram did not time out")
	}
	// The adapter passes datagrams through unchanged.
	go func() { _, _ = remote.Write([]byte("payload")) }()
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "payload" {
		t.Fatalf("read %q, want %q", buf[:n], "payload")
	}
}

// TestTLSHydraDialUsesHandshakeBudget checks that the dial context carries the
// resolved handshake budget, so a stalled Portal cannot pin a standby slot.
func TestTLSHydraDialUsesHandshakeBudget(t *testing.T) {
	h := newTLSHydra(Config{SharedKey: egressTestKey, HandshakeTimeout: 250 * time.Millisecond})
	deadline := make(chan time.Duration, 1)
	h.cfg.DialTLS = func(ctx context.Context) (net.Conn, error) {
		if dl, ok := ctx.Deadline(); ok {
			deadline <- time.Until(dl)
		} else {
			deadline <- -1
		}
		return nil, errors.New("stop")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.run(ctx) }()

	select {
	case got := <-deadline:
		if got <= 0 || got > 250*time.Millisecond {
			t.Fatalf("dial deadline is %v, want it inside the 250ms handshake budget", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the dialer was never called")
	}

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("run returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after cancellation")
	}
}

// TestTLSHydraReseedsAfterFailure checks the supervisor loop keeps reseeding
// after a failed seed, which is the wake path that used to be lost.
func TestTLSHydraReseedsAfterFailure(t *testing.T) {
	var attempts atomic.Int32
	dial := func(context.Context) (net.Conn, error) {
		attempts.Add(1)
		return nil, errors.New("refused")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Config{
			SharedKey: egressTestKey, DialTLS: dial, Upstream: &fakeUpstream{},
			HandshakeTimeout: time.Second, TLSPoolMax: 1,
		})
	}()

	deadline := time.Now().Add(serviceCooldown + 2*time.Second)
	for time.Now().Before(deadline) && attempts.Load() < 2 {
		time.Sleep(25 * time.Millisecond)
	}
	if got := attempts.Load(); got < 2 {
		t.Fatalf("the supervisor dialed %d times, want at least 2", got)
	}

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
}

// TestTLSHydraShutdownClosesTrackedConns checks that shutdown closes the
// connections it owns, unblocking their goroutines and bounding the wait.
func TestTLSHydraShutdownClosesTrackedConns(t *testing.T) {
	h := newTLSHydra(Config{})
	local, remote := net.Pipe()
	defer func() { _ = remote.Close() }()
	h.track(local)

	done := make(chan struct{})
	go func() {
		h.shutdown()
		close(done)
	}()

	_ = remote.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1)
	if _, err := remote.Read(buf); err == nil {
		t.Fatal("the peer was still open after shutdown")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not return")
	}
}

// fakeQIOStream feeds one FlowRequest and records the SetupResult written back.
type fakeQIOStream struct {
	id     uint64
	read   []byte
	writes []byte
}

func (s *fakeQIOStream) Read(p []byte) (int, error) {
	if len(s.read) == 0 {
		return 0, io.EOF
	}
	n := copy(p, s.read)
	s.read = s.read[n:]
	return n, nil
}

func (s *fakeQIOStream) Write(p []byte) (int, error) {
	s.writes = append(s.writes, p...)
	return len(p), nil
}
func (s *fakeQIOStream) CloseWrite() error                { return nil }
func (s *fakeQIOStream) Close() error                     { return nil }
func (s *fakeQIOStream) ID() uint64                       { return s.id }
func (s *fakeQIOStream) SetDeadline(time.Time) error      { return nil }
func (s *fakeQIOStream) SetReadDeadline(time.Time) error  { return nil }
func (s *fakeQIOStream) SetWriteDeadline(time.Time) error { return nil }

// fakeQIOConn is a QUIC connection stand-in for the router.
type fakeQIOConn struct {
	max int
}

func (c *fakeQIOConn) TLSVersion() uint16                               { return 0x0304 }
func (c *fakeQIOConn) ALPN() string                                     { return wire.ALPN }
func (c *fakeQIOConn) Exporter() ([]byte, error)                        { return make([]byte, 32), nil }
func (c *fakeQIOConn) AcceptStream(context.Context) (qio.Stream, error) { return nil, io.EOF }
func (c *fakeQIOConn) OpenStream(context.Context) (qio.Stream, error)   { return nil, io.EOF }
func (c *fakeQIOConn) ReceiveDatagram(context.Context) ([]byte, error)  { return nil, io.EOF }
func (c *fakeQIOConn) SendDatagram([]byte) error                        { return nil }
func (c *fakeQIOConn) MaxDatagramSize() int                             { return c.max }
func (c *fakeQIOConn) CloseWithError(uint64, string) error              { return nil }
func (c *fakeQIOConn) Context() context.Context                         { return context.Background() }
func (c *fakeQIOConn) RemoteAddr() net.Addr                             { return nil }

func flowRequestStream(t *testing.T, id uint64) *fakeQIOStream {
	t.Helper()
	target, err := wire.NewIPTarget(netip.MustParseAddr("1.2.3.4"), 53)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := wire.WriteFlowRequest(&buf, wire.FlowUDP, target); err != nil {
		t.Fatal(err)
	}
	return &fakeQIOStream{id: id, read: buf.Bytes()}
}

// TestServeFlowRejectsUDPWithoutDatagrams pins the Egress-side setup failure:
// a QUIC carrier without DATAGRAM support must get INTERNAL_ERROR before the
// target dial or READY.
func TestServeFlowRejectsUDPWithoutDatagrams(t *testing.T) {
	stream := flowRequestStream(t, 1)
	router := dgram.NewRouter(&fakeQIOConn{max: 0})
	serveFlow(context.Background(), Config{Upstream: &fakeUpstream{}}, router, stream, nil, nil)
	if len(stream.writes) != 1 || wire.SetupResult(stream.writes[0]) != wire.SetupInternalError {
		t.Fatalf("setup result = %x, want %v", stream.writes, wire.SetupInternalError)
	}
}

// TestServeFlowRejectsInvalidUDPFlowID pins the derived-id ordering: an invalid
// Egress business stream id fails with FLOW_LIMIT before READY.
func TestServeFlowRejectsInvalidUDPFlowID(t *testing.T) {
	// Even stream ids are client-initiated; Egress business streams are
	// server-initiated and must be odd.
	stream := flowRequestStream(t, 4)
	router := dgram.NewRouter(&fakeQIOConn{max: 1200})
	serveFlow(context.Background(), Config{Upstream: &fakeUpstream{}}, router, stream, nil, nil)
	if len(stream.writes) != 1 || wire.SetupResult(stream.writes[0]) != wire.SetupFlowLimit {
		t.Fatalf("setup result = %x, want %v", stream.writes, wire.SetupFlowLimit)
	}
}


type trackingHydraConn struct {
	net.Conn
	writeErr   error
	closeCount atomic.Int32
}

func (c *trackingHydraConn) Write(b []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return c.Conn.Write(b)
}

func (c *trackingHydraConn) Close() error {
	c.closeCount.Add(1)
	return c.Conn.Close()
}

type blockingEgressUDPConn struct {
	closed     chan struct{}
	closeOnce  sync.Once
	closeCount atomic.Int32
	writes     chan []byte
}

func newBlockingEgressUDPConn() *blockingEgressUDPConn {
	return &blockingEgressUDPConn{
		closed: make(chan struct{}),
		writes: make(chan []byte, 8),
	}
}

func (c *blockingEgressUDPConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}

func (c *blockingEgressUDPConn) Write(b []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	case c.writes <- append([]byte(nil), b...):
		return len(b), nil
	}
}

func (c *blockingEgressUDPConn) Close() error {
	c.closeCount.Add(1)
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *blockingEgressUDPConn) LocalAddr() net.Addr              { return nil }
func (c *blockingEgressUDPConn) RemoteAddr() net.Addr             { return nil }
func (c *blockingEgressUDPConn) SetDeadline(time.Time) error      { return nil }
func (c *blockingEgressUDPConn) SetReadDeadline(time.Time) error  { return nil }
func (c *blockingEgressUDPConn) SetWriteDeadline(time.Time) error { return nil }

type blockingEgressUpstream struct {
	udp net.Conn
}

func (u blockingEgressUpstream) DialTCP(context.Context, wire.Target) (net.Conn, error) {
	return &fakeNetConn{}, nil
}

func (u blockingEgressUpstream) DialUDP(context.Context, wire.Target) (net.Conn, error) {
	return u.udp, nil
}

type dgramFeedQIOConn struct {
	fakeQIOConn
	in chan []byte
}

func (c *dgramFeedQIOConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case b, ok := <-c.in:
		if !ok {
			return nil, io.EOF
		}
		return b, nil
	}
}

type pipeQIOStream struct {
	net.Conn
	id         uint64
	closeCount atomic.Int32
}

func (s *pipeQIOStream) ID() uint64        { return s.id }
func (s *pipeQIOStream) CloseWrite() error { return s.Conn.Close() }
func (s *pipeQIOStream) Close() error      { s.closeCount.Add(1); return s.Conn.Close() }

// TestTLSHydraServeFlowClosesConn verifies Patch A2: tlsHydra.serveFlow closes
// the claimed standby connection both when WriteSetupResult fails and when a
// normal flow relay completes.
func TestTLSHydraServeFlowClosesConn(t *testing.T) {
	target, err := wire.NewIPTarget(netip.MustParseAddr("127.0.0.1"), 80)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("WriteSetupResult failure", func(t *testing.T) {
		h := newTLSHydra(Config{SharedKey: egressTestKey, Upstream: &fakeUpstream{}})
		local, remote := net.Pipe()
		defer remote.Close()
		tc := &trackingHydraConn{Conn: local, writeErr: errors.New("broken pipe")}

		done := make(chan struct{})
		go func() {
			defer close(done)
			h.serveFlow(context.Background(), tc, bufio.NewReader(tc))
		}()
		if err := wire.WriteFlowRequest(remote, wire.FlowTCP, target); err != nil {
			t.Fatal(err)
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("tlsHydra.serveFlow did not finish")
		}
		if tc.closeCount.Load() == 0 {
			t.Fatal("conn.Close() was not called on WriteSetupResult failure")
		}
	})

	t.Run("normal TCP relay completion", func(t *testing.T) {
		h := newTLSHydra(Config{SharedKey: egressTestKey, Upstream: &fakeUpstream{}})
		local, remote := net.Pipe()
		tc := &trackingHydraConn{Conn: local}

		done := make(chan struct{})
		go func() {
			defer close(done)
			h.serveFlow(context.Background(), tc, bufio.NewReader(tc))
		}()
		if err := wire.WriteFlowRequest(remote, wire.FlowTCP, target); err != nil {
			t.Fatal(err)
		}
		if res, err := wire.ReadSetupResult(remote); err != nil || res != wire.SetupReady {
			t.Fatalf("ReadSetupResult = %v, %v", res, err)
		}
		_ = remote.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("tlsHydra.serveFlow did not finish")
		}
		if tc.closeCount.Load() == 0 {
			t.Fatal("conn.Close() was not called after relay finished")
		}
	})
}

// TestServeFlowQUICUDPUnblocksPeer verifies Patch A1 on QUIC Egress serveFlow:
// closing the business stream closes the UDP peer before wg.Wait().
func TestServeFlowQUICUDPUnblocksPeer(t *testing.T) {
	peer := newBlockingEgressUDPConn()
	qconn := &dgramFeedQIOConn{fakeQIOConn: fakeQIOConn{max: 1200}, in: make(chan []byte, 4)}
	router := dgram.NewRouter(qconn)
	rCtx, rCancel := context.WithCancel(context.Background())
	defer rCancel()
	go router.Run(rCtx)

	local, remote := net.Pipe()
	st := &pipeQIOStream{Conn: local, id: 1}
	target, err := wire.NewIPTarget(netip.MustParseAddr("127.0.0.1"), 53)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		serveFlow(context.Background(), Config{Upstream: blockingEgressUpstream{udp: peer}}, router, st, nil, nil)
	}()

	if err := wire.WriteFlowRequest(remote, wire.FlowUDP, target); err != nil {
		t.Fatal(err)
	}
	if res, err := wire.ReadSetupResult(remote); err != nil || res != wire.SetupReady {
		t.Fatalf("ReadSetupResult = %v, %v", res, err)
	}

	udpID, err := wire.UDPFlowID(1, true)
	if err != nil {
		t.Fatal(err)
	}
	frames, err := wire.EncodePacket(udpID, 1, []byte("egress-udp"), 1200)
	if err != nil {
		t.Fatal(err)
	}
	var received bool
	for i := 0; i < 50 && !received; i++ {
		for _, f := range frames {
			qconn.in <- f
		}
		select {
		case got := <-peer.writes:
			if string(got) != "egress-udp" {
				t.Fatalf("peer got %q, want %q", got, "egress-udp")
			}
			received = true
		case <-time.After(10 * time.Millisecond):
		}
	}
	if !received {
		t.Fatal("datagram did not reach UDP peer")
	}

	_ = remote.Close()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("serveFlow hung >100ms waiting on blocking peer.Read")
	}
	if peer.closeCount.Load() == 0 {
		t.Fatal("UDP peer Close() was not called")
	}
	if st.closeCount.Load() == 0 {
		t.Fatal("QUIC stream Close() was not called")
	}
}
