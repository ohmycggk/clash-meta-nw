package dgram

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"

	"github.com/metacubex/mihomo/transport/nowhere/core/qio"
	"github.com/metacubex/mihomo/transport/nowhere/core/wire"
)

type routerTestConn struct {
	recv chan []byte
	max  int
}

func (c *routerTestConn) TLSVersion() uint16        { return 0x0304 }
func (c *routerTestConn) ALPN() string              { return wire.ALPN }
func (c *routerTestConn) Exporter() ([]byte, error) { return make([]byte, 32), nil }
func (c *routerTestConn) AcceptStream(context.Context) (qio.Stream, error) {
	return nil, io.EOF
}
func (c *routerTestConn) OpenStream(context.Context) (qio.Stream, error) { return nil, io.EOF }
func (c *routerTestConn) ReceiveDatagram(context.Context) ([]byte, error) {
	pkt, ok := <-c.recv
	if !ok {
		return nil, io.EOF
	}
	return append([]byte(nil), pkt...), nil
}
func (c *routerTestConn) SendDatagram([]byte) error           { return nil }
func (c *routerTestConn) MaxDatagramSize() int                { return c.max }
func (c *routerTestConn) CloseWithError(uint64, string) error { return nil }
func (c *routerTestConn) Context() context.Context            { return context.Background() }
func (c *routerTestConn) RemoteAddr() net.Addr                { return nil }

// TestSendRejectsMissingDatagramSupport pins the Core rule that a missing
// DATAGRAM capability is not replaced by a fallback carrier or a guessed MTU.
func TestSendRejectsMissingDatagramSupport(t *testing.T) {
	r := NewRouter(&routerTestConn{max: 0})
	if err := r.Send(1, []byte("payload")); err == nil {
		t.Fatal("Send accepted a connection without DATAGRAM support")
	}
}

// TestFragmentsForUnknownFlowTakeNoSlot checks that a FRAGMENT for an
// unregistered flow is discarded before it reserves a reassembly slot. The byte
// budget holds one payload, so the known flow is only delivered if the unknown
// flow never reserved.
func TestFragmentsForUnknownFlowTakeNoSlot(t *testing.T) {
	const budget = 4000
	conn := &routerTestConn{recv: make(chan []byte, 16), max: 1200}
	r := NewRouter(conn)
	r.re = wire.NewReassembler(64, budget, 0)
	known := r.Register(8)

	payload := bytes.Repeat([]byte("z"), 3000)
	unknownFrames, err := wire.EncodePacket(7, 1, payload, 1200)
	if err != nil {
		t.Fatal(err)
	}
	knownFrames, err := wire.EncodePacket(8, 2, payload, 1200)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		r.Run(context.Background())
		close(done)
	}()
	for _, frame := range unknownFrames {
		conn.recv <- frame
	}
	for _, frame := range knownFrames {
		conn.recv <- frame
	}
	close(conn.recv)
	<-done

	select {
	case got := <-known.C:
		if !bytes.Equal(got, payload) {
			t.Fatalf("reassembled %d bytes, want %d", len(got), len(payload))
		}
	default:
		t.Fatal("the known flow was starved by an unknown flow's reassembly slot")
	}
}
