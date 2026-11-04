package flowio

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/nowhere/core/wire"
)

// relayPair wires a RelayUoT between two ends the test owns, so each side of the
// relay has exactly one reader and one writer. Sharing one net.Pipe end between
// the test and the relay would make the two readers race.
func relayPair(t *testing.T) (client, peer net.Conn, done func()) {
	t.Helper()
	clientTest, clientRelay := net.Pipe()
	peerTest, peerRelay := net.Pipe()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		RelayUoT(clientRelay, peerRelay, nil, nil)
	}()

	return clientTest, peerTest, func() {
		finished := make(chan struct{})
		go func() {
			wg.Wait()
			close(finished)
		}()
		select {
		case <-finished:
		case <-time.After(10 * time.Second):
			t.Error("the relay did not finish")
		}
	}
}

// TestRelayUoTBothDirections checks that a UDP-over-TCP flow relays framed
// packets in both directions.
func TestRelayUoTBothDirections(t *testing.T) {
	client, peer, done := relayPair(t)

	clientPackets := []string{"client to peer", "and again"}
	writeErr := make(chan error, 1)
	go func() {
		defer close(writeErr)
		for _, p := range clientPackets {
			if err := wire.WriteUoT(client, []byte(p)); err != nil {
				writeErr <- err
				return
			}
		}
	}()
	for _, want := range clientPackets {
		got, err := wire.ReadUoT(peer)
		if err != nil {
			t.Fatalf("peer read: %v", err)
		}
		if string(got) != want {
			t.Fatalf("peer read %q, want %q", got, want)
		}
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("client write: %v", err)
	}

	peerPackets := []string{"peer to client", "and back"}
	peerErr := make(chan error, 1)
	go func() {
		defer close(peerErr)
		for _, p := range peerPackets {
			if err := wire.WriteUoT(peer, []byte(p)); err != nil {
				peerErr <- err
				return
			}
		}
	}()
	for _, want := range peerPackets {
		got, err := wire.ReadUoT(client)
		if err != nil {
			t.Fatalf("client read: %v", err)
		}
		if string(got) != want {
			t.Fatalf("client read %q, want %q", got, want)
		}
	}
	if err := <-peerErr; err != nil {
		t.Fatalf("peer write: %v", err)
	}

	// Closing both ends finishes the relay.
	_ = client.Close()
	_ = peer.Close()
	done()
}

// TestRelayUoTPreservesFraming checks that packet boundaries survive the relay:
// several packets written back to back come out as separate packets, and a
// truncated frame yields no packet at all.
func TestRelayUoTPreservesFraming(t *testing.T) {
	client, peer, done := relayPair(t)

	packets := [][]byte{
		[]byte("a"),
		bytes.Repeat([]byte("b"), 600),
		{},
		[]byte("final"),
	}
	writeErr := make(chan error, 1)
	go func() {
		defer close(writeErr)
		for _, p := range packets {
			if err := wire.WriteUoT(client, p); err != nil {
				writeErr <- err
				return
			}
		}
	}()
	for i, want := range packets {
		got, err := wire.ReadUoT(peer)
		if err != nil {
			t.Fatalf("peer read %d: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("packet %d = %q, want %q", i, got, want)
		}
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("client write: %v", err)
	}

	// A header promising more bytes than follow must not deliver a packet.
	if _, err := client.Write([]byte{0x00, 0x40, 'x'}); err != nil {
		t.Fatalf("client write truncated frame: %v", err)
	}
	_ = client.Close()
	done()
}

// TestRelayUoTHalfCloses checks that a one-sided shutdown propagates: when the
// peer goes away the client sees the flow end, and the relay finishes once the
// client closes too, which is what a real Vector does when it is done.
func TestRelayUoTHalfCloses(t *testing.T) {
	client, peer, done := relayPair(t)

	if err := wire.WriteUoT(peer, []byte("only from peer")); err != nil {
		t.Fatalf("peer write: %v", err)
	}
	got, err := wire.ReadUoT(client)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(got) != "only from peer" {
		t.Fatalf("client read %q", got)
	}

	// The peer going away ends the client's reads.
	_ = peer.Close()
	if _, err := wire.ReadUoT(client); err == nil {
		t.Fatal("the client still reads after the peer closed")
	}

	// The relay only finishes once the client closes as well.
	_ = client.Close()
	done()
}

// TestRelayUoTRateLimited checks that a limiter slows the client-to-peer
// direction enough to be measurable without making the test slow.
func TestRelayUoTRateLimited(t *testing.T) {
	clientTest, clientRelay := net.Pipe()
	peerTest, peerRelay := net.Pipe()

	const mbps = 8
	limiter := NewMbps(mbps)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		RelayUoT(clientRelay, peerRelay, limiter, nil)
	}()

	// 8 Mbit/s is 1 MB/s with a 1 MB burst, so the first megabyte is free and
	// the next 200 KB costs about 200ms. The bound is loose enough to survive a
	// loaded machine but tight enough to catch a limiter that was silently
	// dropped. Each chunk stays under the 65535-byte ceiling the two-byte UoT
	// length header imposes.
	const chunk = 60000
	const chunks = 20
	payload := bytes.Repeat([]byte("x"), chunk)

	start := time.Now()
	written := make(chan struct{})
	go func() {
		defer close(written)
		for i := 0; i < chunks; i++ {
			if err := wire.WriteUoT(clientTest, payload); err != nil {
				t.Errorf("client write %d: %v", i, err)
				return
			}
		}
	}()

	for i := 0; i < chunks; i++ {
		if err := peerTest.SetReadDeadline(time.Now().Add(20 * time.Second)); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
		pkt, err := wire.ReadUoT(peerTest)
		if err != nil {
			t.Fatalf("peer read %d: %v", i, err)
		}
		if len(pkt) != chunk {
			t.Fatalf("peer read %d = %d bytes, want %d", i, len(pkt), chunk)
		}
	}
	<-written
	elapsed := time.Since(start)

	if min := 100 * time.Millisecond; elapsed < min {
		t.Fatalf("relayed %d KB in %v, want at least %v past the %d Mbit/s burst",
			chunks*chunk>>10, elapsed, min, mbps)
	}

	_ = clientTest.Close()
	_ = peerTest.Close()
	waitGroup(t, &wg)
}

// TestNewMbps checks the limiter factory: non-positive rates disable the limit.
func TestNewMbps(t *testing.T) {
	if NewMbps(0) != nil {
		t.Fatal("NewMbps(0) returned a limiter, want nil")
	}
	if NewMbps(-5) != nil {
		t.Fatal("NewMbps(-5) returned a limiter, want nil")
	}
	if NewMbps(100) == nil {
		t.Fatal("NewMbps(100) returned nil, want a limiter")
	}
	// A nil limiter never blocks.
	var nilLimiter *Limiter
	if err := nilLimiter.WaitN(context.Background(), 1<<20); err != nil {
		t.Fatalf("a nil limiter blocked: %v", err)
	}
}

// datagramConn is a message-oriented net.Conn: each Write is one datagram and
// each Read returns one datagram, like a *net.UDPConn.
type datagramConn struct {
	in     chan []byte
	out    chan []byte
	closed chan struct{}
	once   sync.Once
}

func newDatagramPair() (*datagramConn, *datagramConn) {
	aToB := make(chan []byte, 16)
	bToA := make(chan []byte, 16)
	return &datagramConn{in: aToB, out: bToA, closed: make(chan struct{})},
		&datagramConn{in: bToA, out: aToB, closed: make(chan struct{})}
}

func (c *datagramConn) Read(b []byte) (int, error) {
	select {
	case pkt := <-c.out:
		return copy(b, pkt), nil
	case <-c.closed:
		return 0, net.ErrClosed
	}
}

func (c *datagramConn) Write(b []byte) (int, error) {
	pkt := append([]byte(nil), b...)
	select {
	case c.in <- pkt:
		return len(b), nil
	case <-c.closed:
		return 0, net.ErrClosed
	}
}

func (c *datagramConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *datagramConn) LocalAddr() net.Addr              { return nil }
func (c *datagramConn) RemoteAddr() net.Addr             { return nil }
func (c *datagramConn) SetDeadline(time.Time) error      { return nil }
func (c *datagramConn) SetReadDeadline(time.Time) error  { return nil }
func (c *datagramConn) SetWriteDeadline(time.Time) error { return nil }

// TestRelayUoTRawBothDirections checks the raw relay used by a TLS Egress: UoT
// frames from the client become bare datagrams on the peer, and a bare peer
// datagram becomes one UoT frame on the client.
func TestRelayUoTRawBothDirections(t *testing.T) {
	clientTest, clientRelay := net.Pipe()
	peerTest, peerRelay := newDatagramPair()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		RelayUoTRaw(clientRelay, peerRelay, nil, nil)
	}()

	writeErr := make(chan error, 1)
	go func() { writeErr <- wire.WriteUoT(clientTest, []byte("outbound")) }()
	buf := make([]byte, 64)
	n, err := peerTest.Read(buf)
	if err != nil {
		t.Fatalf("peer read: %v", err)
	}
	if string(buf[:n]) != "outbound" {
		t.Fatalf("peer read %q, want %q", buf[:n], "outbound")
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("client write: %v", err)
	}

	if _, err := peerTest.Write([]byte("inbound")); err != nil {
		t.Fatalf("peer write: %v", err)
	}
	pkt, err := wire.ReadUoT(clientTest)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(pkt) != "inbound" {
		t.Fatalf("client read %q, want %q", pkt, "inbound")
	}

	_ = clientTest.Close()
	_ = peerTest.Close()
	waitGroup(t, &wg)
}

// TestRelayUoTRawEmitsOneDatagramPerPacket is the regression test for the
// double framing: one UoT frame must reach the raw peer as exactly one
// datagram, with no extra framing datagrams.
func TestRelayUoTRawEmitsOneDatagramPerPacket(t *testing.T) {
	clientTest, clientRelay := net.Pipe()
	peerTest, peerRelay := newDatagramPair()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		RelayUoTRaw(clientRelay, peerRelay, nil, nil)
	}()

	go func() { _ = wire.WriteUoT(clientTest, []byte("one-packet")) }()
	buf := make([]byte, 64)
	n, err := peerTest.Read(buf)
	if err != nil {
		t.Fatalf("peer read: %v", err)
	}
	if string(buf[:n]) != "one-packet" {
		t.Fatalf("peer read %q, want %q", buf[:n], "one-packet")
	}
	select {
	case extra := <-peerTest.out:
		t.Fatalf("the relay emitted an extra datagram %q", extra)
	case <-time.After(100 * time.Millisecond):
	}

	_ = clientTest.Close()
	_ = peerTest.Close()
	waitGroup(t, &wg)
}

func waitGroup(t *testing.T, wg *sync.WaitGroup) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the relay did not finish")
	}
}
