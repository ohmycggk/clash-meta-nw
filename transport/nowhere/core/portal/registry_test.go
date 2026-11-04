package portal

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/nowhere/core/qio"
)

// TestEgressTLSMaxFromEnv pins the NOW_PORTAL_TLS_IDLE_MAX bounds: 1..=1023,
// with unset and empty both falling back to the default.
func TestEgressTLSMaxFromEnv(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want int
	}{
		{"", DefaultEgressTLSMax},
		{"  ", DefaultEgressTLSMax},
		{" 8 ", 8},
		{"1", 1},
		{"1023", 1023},
	} {
		t.Run("accepts "+tc.raw, func(t *testing.T) {
			t.Setenv("NOW_PORTAL_TLS_IDLE_MAX", tc.raw)
			got, err := EgressTLSMaxFromEnv()
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
		})
	}

	for _, raw := range []string{"0", "-1", "1024", "abc"} {
		t.Run("rejects "+raw, func(t *testing.T) {
			t.Setenv("NOW_PORTAL_TLS_IDLE_MAX", raw)
			if _, err := EgressTLSMaxFromEnv(); err == nil {
				t.Fatalf("NOW_PORTAL_TLS_IDLE_MAX=%q was accepted", raw)
			}
		})
	}
}

// TestEgressRegistryReservesTLS checks the registration allowance: a full set
// refuses further reservations, and a permit is released exactly once.
func TestEgressRegistryReservesTLS(t *testing.T) {
	r := newEgressRegistry(2)
	for i := 0; i < 2; i++ {
		if !r.reserveTLS() {
			t.Fatalf("reservation %d was refused, want accepted", i)
		}
	}
	if r.reserveTLS() {
		t.Fatal("a third reservation was accepted past the cap")
	}
	if got := r.pendingTLS(); got != 2 {
		t.Fatalf("pending = %d, want 2", got)
	}
	held := &egressRegistration{permitHeld: true}
	r.releaseHeld(held)
	if got := r.pendingTLS(); got != 1 {
		t.Fatalf("pending after release = %d, want 1", got)
	}
	// Releasing the same registration again is a no-op, not a second decrement.
	r.releaseHeld(held)
	if got := r.pendingTLS(); got != 1 {
		t.Fatalf("pending after a repeated release = %d, want 1", got)
	}
	if !r.reserveTLS() {
		t.Fatal("a reservation after a release was refused")
	}
}

// TestNewEgressRegistryClampsMax rejects a nonsense cap rather than silently
// disabling TLS Egress admission.
func TestNewEgressRegistryClampsMax(t *testing.T) {
	r := newEgressRegistry(0)
	if r.maxPending != DefaultEgressTLSMax {
		t.Fatalf("maxPending = %d, want %d", r.maxPending, DefaultEgressTLSMax)
	}
	if !r.reserveTLS() {
		t.Fatal("the clamped registry refuses its first reservation")
	}
}

// TestEgressRegistryClaimRotatesQUIC pins the round-robin a QUIC registration
// gets: claiming one puts it straight back at the tail, so several exits share
// the load and none is starved.
func TestEgressRegistryClaimRotatesQUIC(t *testing.T) {
	r := newEgressRegistry(DefaultEgressTLSMax)
	first := &egressRegistration{quic: &fakeQIOConn{}}
	second := &egressRegistration{quic: &fakeQIOConn{}}
	r.add(first)
	r.add(second)

	for round, want := range []*egressRegistration{first, second, first, second} {
		got := r.claim()
		if got == nil {
			t.Fatalf("round %d: claim returned nil", round)
		}
		if got != want {
			t.Fatalf("round %d: claim returned the wrong registration", round)
		}
	}
	if got := len(r.queue); got != 2 {
		t.Fatalf("queue length = %d, want 2", got)
	}
}

// TestEgressRegistryClaimDropsDeadQUIC checks that a closed Egress connection is
// discarded instead of handed to a Vector flow.
func TestEgressRegistryClaimDropsDeadQUIC(t *testing.T) {
	r := newEgressRegistry(DefaultEgressTLSMax)
	dead, cancel := context.WithCancel(context.Background())
	r.add(&egressRegistration{quic: &fakeQIOConn{ctx: dead}})
	cancel()

	if reg := r.claim(); reg != nil {
		t.Fatalf("claim returned a dead registration: %+v", reg)
	}
	if got := len(r.queue); got != 0 {
		t.Fatalf("queue length = %d, want 0", got)
	}
}

// TestEgressRegistryClaimSkipsDeadToReachLive checks that one closed exit does
// not hide the healthy ones behind it in the FIFO.
func TestEgressRegistryClaimSkipsDeadToReachLive(t *testing.T) {
	r := newEgressRegistry(DefaultEgressTLSMax)
	dead, cancel := context.WithCancel(context.Background())
	cancel()
	r.add(&egressRegistration{quic: &fakeQIOConn{ctx: dead}})
	live := &egressRegistration{quic: &fakeQIOConn{}}
	r.add(live)

	if got := r.claim(); got != live {
		t.Fatalf("claim returned %+v, want the live registration", got)
	}
}

// TestEgressRegistryClaimDropsExpiredTLS checks the 120s non-renewable standby
// TTL: a TLS registration past it is dropped, not claimed. The teardown of the
// parked goroutine releases the permit it has held since registration.
func TestEgressRegistryClaimDropsExpiredTLS(t *testing.T) {
	r := newEgressRegistry(DefaultEgressTLSMax)
	if !r.reserveTLS() {
		t.Fatal("the registry refused the only permit")
	}
	reg := &egressRegistration{
		tls:        &fakeNetConn{},
		standby:    time.Now().Add(-time.Second),
		done:       make(chan struct{}),
		permitHeld: true,
	}
	claimed := r.add(reg)

	if got := r.claim(); got != nil {
		t.Fatalf("claim returned an expired registration: %+v", got)
	}
	// The parked goroutine must not be woken by an expiry, and the entry must
	// already be gone so a replacement takes its place.
	select {
	case <-claimed:
		t.Fatal("an expired registration woke its parked goroutine")
	default:
	}
	if got := len(r.queue); got != 0 {
		t.Fatalf("queue length = %d, want 0", got)
	}
	// The permit is released by the parked goroutine's teardown, so a
	// replacement can register.
	r.remove(reg)
	r.releaseHeld(reg)
	if got := r.pendingTLS(); got != 0 {
		t.Fatalf("pending after teardown = %d, want 0", got)
	}
	if !r.reserveTLS() {
		t.Fatal("the registry still refuses a permit after the teardown")
	}
}

// TestEgressRegistryClaimTLSIsSingleShot checks that a TLS registration leaves
// the FIFO when claimed and closes its claim channel, so the parked goroutine is
// woken. Claiming releases the pending allowance, and the claimed connection's
// later teardown must not release it a second time.
func TestEgressRegistryClaimTLSIsSingleShot(t *testing.T) {
	r := newEgressRegistry(DefaultEgressTLSMax)
	r.reserveTLS()
	reg := &egressRegistration{
		tls:        &fakeNetConn{},
		standby:    time.Now().Add(egressTLSIdleTTL),
		done:       make(chan struct{}),
		permitHeld: true,
	}
	claimed := r.add(reg)

	if got := r.claim(); got != reg {
		t.Fatalf("claim returned %+v, want the parked registration", got)
	}
	select {
	case <-claimed:
	default:
		t.Fatal("claiming a TLS registration did not wake its parked goroutine")
	}
	if got := r.pendingTLS(); got != 0 {
		t.Fatalf("pending after claim = %d, want 0", got)
	}
	// The Flow owning the claimed connection finishes: its teardown releases
	// the permit a second time unless the release is single-shot.
	r.releaseHeld(reg)
	if got := r.pendingTLS(); got != 0 {
		t.Fatalf("pending after the claimed Flow teardown = %d, want 0", got)
	}
	if again := r.claim(); again != nil {
		t.Fatalf("the FIFO still holds a claimed TLS registration: %+v", again)
	}
	if got := len(r.queue); got != 0 {
		t.Fatalf("queue length = %d, want 0", got)
	}
}

// TestEgressRegistryTLSPermitAccounting is the regression test for the double
// release: the Flow that claims one registration must not free the permit that
// another idle registration holds, in either teardown/claim order.
func TestEgressRegistryTLSPermitAccounting(t *testing.T) {
	t.Run("claimed Flow teardown leaves a later registration's permit alone", func(t *testing.T) {
		r := newEgressRegistry(1)
		if !r.reserveTLS() {
			t.Fatal("conn1 refused")
		}
		reg1 := &egressRegistration{
			tls:        &fakeNetConn{},
			standby:    time.Now().Add(egressTLSIdleTTL),
			done:       make(chan struct{}),
			permitHeld: true,
		}
		r.add(reg1)
		if got := r.claim(); got != reg1 {
			t.Fatal("conn1 was not claimed")
		}
		// conn2 registers while conn1's Flow is still running.
		if !r.reserveTLS() {
			t.Fatal("conn2 refused")
		}
		reg2 := &egressRegistration{
			tls:        &fakeNetConn{},
			standby:    time.Now().Add(egressTLSIdleTTL),
			done:       make(chan struct{}),
			permitHeld: true,
		}
		r.add(reg2)
		// conn1's Flow ends and its parked goroutine tears down.
		r.remove(reg1)
		r.releaseHeld(reg1)
		if got := r.pendingTLS(); got != 1 {
			t.Fatalf("pending after conn1 teardown = %d, want 1 (conn2 still holds its permit)", got)
		}
		if r.reserveTLS() {
			t.Fatal("a third reservation was accepted past the cap")
		}
		r.remove(reg2)
		r.releaseHeld(reg2)
	})

	t.Run("teardown that loses the claim race does not double release", func(t *testing.T) {
		r := newEgressRegistry(1)
		if !r.reserveTLS() {
			t.Fatal("reservation refused")
		}
		reg := &egressRegistration{
			tls:        &fakeNetConn{},
			standby:    time.Now().Add(egressTLSIdleTTL),
			done:       make(chan struct{}),
			permitHeld: true,
		}
		r.add(reg)
		// The teardown releases first, then an in-flight claim still finds the
		// entry (its remove lost the race) and must not release again.
		r.releaseHeld(reg)
		if got := r.claim(); got != reg {
			t.Fatal("claim did not find the in-flight registration")
		}
		if got := r.pendingTLS(); got != 0 {
			t.Fatalf("pending = %d, want 0", got)
		}
	})
}

// TestEgressRegistryRemove checks that a closed Egress leaves the FIFO without
// disturbing the registrations behind it.
func TestEgressRegistryRemove(t *testing.T) {
	r := newEgressRegistry(DefaultEgressTLSMax)
	head := &egressRegistration{quic: &fakeQIOConn{}}
	tail := &egressRegistration{quic: &fakeQIOConn{}}
	r.add(head)
	r.add(tail)

	r.remove(head)
	if got := len(r.queue); got != 1 || r.queue[0] != tail {
		t.Fatalf("queue = %+v, want only the tail registration", r.queue)
	}
	if got := r.claim(); got == nil || got.quic == nil {
		t.Fatal("the surviving registration is no longer claimable")
	}

	// Removing an already claimed or unknown registration is a no-op.
	r.remove(tail)
	r.remove(&egressRegistration{quic: &fakeQIOConn{}})
	if got := len(r.queue); got != 0 {
		t.Fatalf("queue length = %d, want 0", got)
	}
}

// TestEgressRegistryWaitWakesOnRegistration checks that a Vector flow blocked
// waiting for an exit is released the moment one registers.
func TestEgressRegistryWaitWakesOnRegistration(t *testing.T) {
	r := newEgressRegistry(DefaultEgressTLSMax)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	got := make(chan *egressRegistration, 1)
	go func() { got <- r.wait(ctx) }()

	// Give the waiter a chance to park before the registration arrives.
	time.Sleep(20 * time.Millisecond)
	r.add(&egressRegistration{quic: &fakeQIOConn{}})

	select {
	case reg := <-got:
		if reg == nil {
			t.Fatal("wait returned nil after a registration arrived")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("wait did not wake when a registration arrived")
	}
}

// TestEgressRegistryWaitEndsOnContext checks the timeout path: a Vector flow
// gives up rather than blocking forever when no exit ever registers.
func TestEgressRegistryWaitEndsOnContext(t *testing.T) {
	r := newEgressRegistry(DefaultEgressTLSMax)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if reg := r.wait(ctx); reg != nil {
		t.Fatalf("wait returned %+v, want nil", reg)
	}
}

// fakeQIOConn is a qio.Conn whose liveness the test controls through ctx.
type fakeQIOConn struct {
	ctx        context.Context
	noDatagram bool
}

func (c *fakeQIOConn) Context() context.Context {
	if c.ctx != nil {
		return c.ctx
	}
	return context.Background()
}

func (c *fakeQIOConn) TLSVersion() uint16 { return uint16(0x0304) }
func (c *fakeQIOConn) ALPN() string       { return "" }
func (c *fakeQIOConn) Exporter() ([]byte, error) {
	return make([]byte, 32), nil
}

func (c *fakeQIOConn) AcceptStream(context.Context) (qio.Stream, error) { return nil, nil }
func (c *fakeQIOConn) OpenStream(context.Context) (qio.Stream, error)   { return nil, nil }
func (c *fakeQIOConn) ReceiveDatagram(context.Context) ([]byte, error)  { return nil, nil }
func (c *fakeQIOConn) SendDatagram([]byte) error                        { return nil }
func (c *fakeQIOConn) MaxDatagramSize() int {
	if c.noDatagram {
		return 0
	}
	return 1000
}
func (c *fakeQIOConn) CloseWithError(uint64, string) error { return nil }
func (c *fakeQIOConn) RemoteAddr() net.Addr                { return nil }

// fakeNetConn is a net.Conn that records Close, so a test can assert the permit
// path released the connection.
type fakeNetConn struct {
	mu     sync.Mutex
	closed chan struct{}
}

func (c *fakeNetConn) Read(b []byte) (int, error)       { return 0, nil }
func (c *fakeNetConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *fakeNetConn) LocalAddr() net.Addr              { return nil }
func (c *fakeNetConn) RemoteAddr() net.Addr             { return nil }
func (c *fakeNetConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeNetConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeNetConn) SetWriteDeadline(time.Time) error { return nil }

func (c *fakeNetConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed == nil {
		c.closed = make(chan struct{})
		close(c.closed)
	}
	return nil
}
