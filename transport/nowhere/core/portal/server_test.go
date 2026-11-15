package portal

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/nowhere/core/dgram"
	"github.com/metacubex/mihomo/transport/nowhere/core/wire"
)

// TestServeViaQUICEgressRejectsTLSVectorUDP pins the mixed-carrier guard: a
// Vector over TLS carries UDP as UoT on its control stream, while a QUIC Egress
// reads UDP DATAGRAMs, so the flow is rejected before the egress stream is
// opened and before the client is told READY.
func TestServeViaQUICEgressRejectsTLSVectorUDP(t *testing.T) {
	local, remote := net.Pipe()
	client := &pipe{Reader: remote, write: local, closer: local}
	server := &Server{}
	reg := &egressRegistration{quic: &fakeQIOConn{}}

	done := make(chan struct{})
	go func() {
		defer close(done)
		server.serveViaQUICEgress(context.Background(), reg, wire.FlowUDP, wire.Target{}, client, nil, 1)
	}()

	_ = remote.SetReadDeadline(time.Now().Add(5 * time.Second))
	res, err := wire.ReadSetupResult(remote)
	if err != nil {
		t.Fatalf("read setup result: %v", err)
	}
	if res != wire.SetupInternalError {
		t.Fatalf("setup result = %v, want %v", res, wire.SetupInternalError)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serveViaQUICEgress did not return")
	}
}

// TestServeFlowRejectsUDPWithoutDatagrams pins the setup-time failure for a
// QUIC Vector connection that did not negotiate DATAGRAM support: the flow must
// get INTERNAL_ERROR before any target dial or READY.
func TestServeFlowRejectsUDPWithoutDatagrams(t *testing.T) {
	local, remote := net.Pipe()
	client := &pipe{Reader: remote, write: local, closer: local}
	router := dgram.NewRouter(&fakeQIOConn{noDatagram: true})
	srv := &Server{}

	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.serveFlow(context.Background(), wire.FlowUDP, wire.Target{}, client, router, 1, true)
	}()
	_ = remote.SetReadDeadline(time.Now().Add(5 * time.Second))
	res, err := wire.ReadSetupResult(remote)
	if err != nil {
		t.Fatalf("read setup result: %v", err)
	}
	if res != wire.SetupInternalError {
		t.Fatalf("setup result = %v, want %v", res, wire.SetupInternalError)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serveFlow did not return")
	}
}

// TestServeFlowRejectsInvalidUDPFlowID pins the pre-READY derived-id check: an
// invalid or exhausted stream id fails the flow with FLOW_LIMIT instead of
// authorizing payload it cannot route.
func TestServeFlowRejectsInvalidUDPFlowID(t *testing.T) {
	local, remote := net.Pipe()
	client := &pipe{Reader: remote, write: local, closer: local}
	router := dgram.NewRouter(&fakeQIOConn{})
	srv := &Server{}

	done := make(chan struct{})
	go func() {
		defer close(done)
		// A client unidirectional stream id (bit 1 set) is never a UDP control
		// stream, so UDPFlowID rejects it.
		srv.serveFlow(context.Background(), wire.FlowUDP, wire.Target{}, client, router, 2, true)
	}()
	_ = remote.SetReadDeadline(time.Now().Add(5 * time.Second))
	res, err := wire.ReadSetupResult(remote)
	if err != nil {
		t.Fatalf("read setup result: %v", err)
	}
	if res != wire.SetupFlowLimit {
		t.Fatalf("setup result = %v, want %v", res, wire.SetupFlowLimit)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serveFlow did not return")
	}
}

// TestGateTryAndWait checks the accept-loop admission helper: a full gate is
// not admitted, a released slot is, and a bounded wait gives up.
func TestGateTryAndWait(t *testing.T) {
	g := &gate{n: maxFlows}
	if g.try() {
		t.Fatal("a full gate reported a free slot")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if g.wait(ctx, 5*time.Millisecond) {
		t.Fatal("wait admitted a full gate")
	}
	g.release()
	if !g.try() {
		t.Fatal("a released gate reported no free slot")
	}
	if !g.wait(context.Background(), time.Second) {
		t.Fatal("wait did not admit a released slot")
	}
}


// blockingUDPConn simulates a host UDP peer whose SetReadDeadline is a no-op,
// blocking Read indefinitely until Close is called.
type blockingUDPConn struct {
	closed     chan struct{}
	closeOnce  sync.Once
	closeCount atomic.Int32
	writes     chan []byte
}

func newBlockingUDPConn() *blockingUDPConn {
	return &blockingUDPConn{
		closed: make(chan struct{}),
		writes: make(chan []byte, 8),
	}
}

func (c *blockingUDPConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}

func (c *blockingUDPConn) Write(b []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	case c.writes <- append([]byte(nil), b...):
		return len(b), nil
	}
}

func (c *blockingUDPConn) Close() error {
	c.closeCount.Add(1)
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *blockingUDPConn) LocalAddr() net.Addr              { return nil }
func (c *blockingUDPConn) RemoteAddr() net.Addr             { return nil }
func (c *blockingUDPConn) SetDeadline(time.Time) error      { return nil }
func (c *blockingUDPConn) SetReadDeadline(time.Time) error  { return nil }
func (c *blockingUDPConn) SetWriteDeadline(time.Time) error { return nil }

type stubPortalUpstream struct {
	tcp net.Conn
	udp net.Conn
}

func (u stubPortalUpstream) DialTCP(context.Context, wire.Target) (net.Conn, error) {
	if u.tcp != nil {
		return u.tcp, nil
	}
	l, r := net.Pipe()
	_ = r.Close()
	return l, nil
}

func (u stubPortalUpstream) DialUDP(context.Context, wire.Target) (net.Conn, error) {
	return u.udp, nil
}

type dgramFeedConn struct {
	fakeQIOConn
	in chan []byte
}

func (c *dgramFeedConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
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

type trackingStream struct {
	net.Conn
	id         uint64
	closeCount atomic.Int32
}

func (s *trackingStream) ID() uint64        { return s.id }
func (s *trackingStream) CloseWrite() error { return s.Conn.Close() }
func (s *trackingStream) Close() error      { s.closeCount.Add(1); return s.Conn.Close() }

type trackingRawConn struct {
	net.Conn
	closeCount atomic.Int32
}

func (c *trackingRawConn) Close() error {
	c.closeCount.Add(1)
	return c.Conn.Close()
}

// TestServeFlowQUICUDPUnblocksPeerWithoutReadDeadline verifies Patch A1:
// closing the Vector control stream closes the UDP peer before wg.Wait(),
// releasing s.flows and avoiding goroutine leaks even when SetReadDeadline is a no-op.
func TestServeFlowQUICUDPUnblocksPeerWithoutReadDeadline(t *testing.T) {
	runtime.GC()
	time.Sleep(10 * time.Millisecond)
	baseGoroutines := runtime.NumGoroutine()

	peer := newBlockingUDPConn()
	qconn := &dgramFeedConn{in: make(chan []byte, 4)}
	router := dgram.NewRouter(qconn)
	rCtx, rCancel := context.WithCancel(context.Background())
	go router.Run(rCtx)

	srv := &Server{up: stubPortalUpstream{udp: peer}}
	target, err := wire.NewIPTarget(netip.MustParseAddr("127.0.0.1"), 53)
	if err != nil {
		t.Fatal(err)
	}

	local, remote := net.Pipe()
	st := &trackingStream{Conn: local, id: 0}
	var req bytes.Buffer
	if err := wire.WriteFlowRequest(&req, wire.FlowUDP, target); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.readAndServe(context.Background(), router, st, bufio.NewReader(st), true)
	}()

	if _, err := remote.Write(req.Bytes()); err != nil {
		t.Fatal(err)
	}
	if res, err := wire.ReadSetupResult(remote); err != nil || res != wire.SetupReady {
		t.Fatalf("ReadSetupResult = %v, %v", res, err)
	}

	udpID, err := wire.UDPFlowID(0, false)
	if err != nil {
		t.Fatal(err)
	}
	frames, err := wire.EncodePacket(udpID, 1, []byte("ping"), 1000)
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
			if string(got) != "ping" {
				t.Fatalf("peer write = %q, want %q", got, "ping")
			}
			received = true
		case <-time.After(10 * time.Millisecond):
		}
	}
	if !received {
		t.Fatal("datagram was not written to UDP peer")
	}

	_ = remote.Close()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("readAndServe/serveFlow hung >100ms after control stream closed")
	}

	if peer.closeCount.Load() == 0 {
		t.Fatal("UDP peer Close was not called")
	}
	if st.closeCount.Load() == 0 {
		t.Fatal("QUIC stream Close was not called")
	}
	srv.flows.mu.Lock()
	flowsHeld := srv.flows.n
	srv.flows.mu.Unlock()
	if flowsHeld != 0 {
		t.Fatalf("srv.flows.n = %d, want 0", flowsHeld)
	}

	rCancel()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) && runtime.NumGoroutine() > baseGoroutines+1 {
		time.Sleep(10 * time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > baseGoroutines+1 {
		t.Fatalf("goroutines = %d, baseline = %d (leak detected)", got, baseGoroutines)
	}
}

// TestRelayQUICUDPExitsOnFlowClose verifies Patch A1's flow.Done() exit path.
func TestRelayQUICUDPExitsOnFlowClose(t *testing.T) {
	peer := newBlockingUDPConn()
	router := dgram.NewRouter(&fakeQIOConn{})
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	client := &pipe{Reader: local, write: local, closer: local}

	done := make(chan struct{})
	go func() {
		defer close(done)
		relayQUICUDP(router, 7, client, peer, nil, nil)
	}()

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		router.CloseFlow(7)
		select {
		case <-done:
			if peer.closeCount.Load() == 0 {
				t.Fatal("peer Close was not called on flow.Done()")
			}
			return
		case <-time.After(5 * time.Millisecond):
		}
	}
	t.Fatal("relayQUICUDP did not exit within 100ms after CloseFlow")
}

// TestBridgeDatagramToUoTFramesAndClosesOnExit verifies Patch A1 on bridgeDatagramToUoT:
// packets are UoT-framed and closing either the control stream or flow unblocks ReadUoT.
func TestBridgeDatagramToUoTFramesAndClosesOnExit(t *testing.T) {
	qconn := &dgramFeedConn{in: make(chan []byte, 4)}
	router := dgram.NewRouter(qconn)
	rCtx, rCancel := context.WithCancel(context.Background())
	defer rCancel()
	go router.Run(rCtx)

	ctlLocal, ctlRemote := net.Pipe()
	defer ctlRemote.Close()
	uotLocal, uotRemote := net.Pipe()
	defer uotRemote.Close()
	uotTracked := &trackingRawConn{Conn: uotLocal}

	done := make(chan struct{})
	go func() {
		defer close(done)
		bridgeDatagramToUoT(
			router, 11,
			&pipe{Reader: ctlLocal, write: ctlLocal, closer: ctlLocal},
			&pipe{Reader: uotTracked, write: uotTracked, closer: uotTracked},
			nil, nil,
		)
	}()

	// Wait until flow 11 is registered, then deliver one datagram.
	frames, err := wire.EncodePacket(11, 1, []byte("uot-framed"), 1000)
	if err != nil {
		t.Fatal(err)
	}
	var got []byte
	uotReadDone := make(chan error, 1)
	go func() {
		var rerr error
		got, rerr = wire.ReadUoT(uotRemote)
		uotReadDone <- rerr
	}()

	for i := 0; i < 20; i++ {
		for _, f := range frames {
			qconn.in <- f
		}
		select {
		case err := <-uotReadDone:
			if err != nil {
				t.Fatalf("ReadUoT: %v", err)
			}
			if string(got) != "uot-framed" {
				t.Fatalf("ReadUoT payload = %q, want %q", got, "uot-framed")
			}
			goto closedCheck
		case <-time.After(10 * time.Millisecond):
		}
	}
	t.Fatal("timed out waiting for UoT packet")

closedCheck:
	_ = ctlRemote.Close()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("bridgeDatagramToUoT hung >100ms after control stream closed")
	}
	if uotTracked.closeCount.Load() == 0 {
		t.Fatal("uot stream Close was not called")
	}
}

// TestServeVectorTCPClosesUnderlyingConn verifies Patch A2: serveVectorTCP and
// serveFlow close the underlying TCP connection rather than only sending TLS close_notify.
func TestServeVectorTCPClosesUnderlyingConn(t *testing.T) {
	cert := testCert(t)
	srvTLS := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{wire.ALPN},
	}
	cliTLS := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		NextProtos:         []string{wire.ALPN},
		ServerName:         "nowhere",
	}

	rawSrv, rawCli := net.Pipe()
	trackedSrv := &trackingRawConn{Conn: rawSrv}
	srvConn := tls.Server(trackedSrv, srvTLS)
	cliConn := tls.Client(rawCli, cliTLS)

	peerLocal, peerRemote := net.Pipe()
	_ = peerRemote.Close()
	srv := &Server{up: stubPortalUpstream{tcp: peerLocal}}

	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := srvConn.Handshake(); err != nil {
			return
		}
		srv.serveVectorTCP(context.Background(), srvConn, bufio.NewReader(srvConn))
	}()

	if err := cliConn.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	target, err := wire.NewIPTarget(netip.MustParseAddr("127.0.0.1"), 80)
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.WriteFlowRequest(cliConn, wire.FlowTCP, target); err != nil {
		t.Fatal(err)
	}
	if res, err := wire.ReadSetupResult(cliConn); err != nil || res != wire.SetupReady {
		t.Fatalf("ReadSetupResult = %v, %v", res, err)
	}
	// Half-close client TLS side only (close_notify without closing rawCli),
	// while draining the server's close_notify on the synchronous net.Pipe.
	go func() { _, _ = io.Copy(io.Discard, cliConn) }()
	_ = cliConn.CloseWrite()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("serveVectorTCP did not finish")
	}
	if trackedSrv.closeCount.Load() == 0 {
		t.Fatal("underlying server TCP connection Close() was never called")
	}
	_ = rawCli.Close()
}

// TestAdmitReleaseDeletesZeroCountKeys verifies Patch A3: admit.release deletes
// per-source map entries once their count reaches zero.
func TestAdmitReleaseDeletesZeroCountKeys(t *testing.T) {
	a := &admit{per: make(map[string]int)}
	for i := 0; i < 100; i++ {
		addr := &net.TCPAddr{IP: net.IPv4(198, 51, 100, byte(i)), Port: 10000 + i}
		if !a.take(addr) {
			t.Fatalf("take(%v) failed", addr)
		}
		if !a.take(addr) {
			t.Fatalf("second take(%v) failed", addr)
		}
		a.release(addr)
		if got := a.per[sourceKey(addr)]; got != 1 {
			t.Fatalf("count after first release = %d, want 1", got)
		}
		a.release(addr)
	}
	if len(a.per) != 0 {
		t.Fatalf("len(a.per) = %d, want 0", len(a.per))
	}
	if a.n != 0 {
		t.Fatalf("a.n = %d, want 0", a.n)
	}
}
