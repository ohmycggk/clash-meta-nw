package vector

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/nowhere/core/qio"
	"github.com/metacubex/mihomo/transport/nowhere/core/wire"
)

const vectorTestKey = "0123456789abcdef0123456789abcdef"

type fakeVectorStream struct {
	id uint64

	mu     sync.Mutex
	writes []byte
	read   []byte
}

func (s *fakeVectorStream) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.read) == 0 {
		return 0, errors.New("no more bytes")
	}
	n := copy(p, s.read)
	s.read = s.read[n:]
	return n, nil
}

func (s *fakeVectorStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	s.writes = append(s.writes, p...)
	s.mu.Unlock()
	return len(p), nil
}

func (s *fakeVectorStream) CloseWrite() error                { return nil }
func (s *fakeVectorStream) Close() error                     { return nil }
func (s *fakeVectorStream) ID() uint64                       { return s.id }
func (s *fakeVectorStream) SetDeadline(time.Time) error      { return nil }
func (s *fakeVectorStream) SetReadDeadline(time.Time) error  { return nil }
func (s *fakeVectorStream) SetWriteDeadline(time.Time) error { return nil }

func (s *fakeVectorStream) snapshot() (uint64, []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.id, append([]byte(nil), s.writes...)
}

type fakeVectorConn struct {
	mu       sync.Mutex
	next     uint64
	streams  []*fakeVectorStream
	max      int
	exporter wire.Exporter
	ctx      context.Context
	cancel   context.CancelFunc
	closed   bool
}

func newFakeVectorConn(maxDatagram int) *fakeVectorConn {
	ctx, cancel := context.WithCancel(context.Background())
	var exporter wire.Exporter
	for i := range exporter {
		exporter[i] = byte(0x40 + i)
	}
	return &fakeVectorConn{max: maxDatagram, exporter: exporter, ctx: ctx, cancel: cancel}
}

func (c *fakeVectorConn) TLSVersion() uint16 { return 0x0304 }
func (c *fakeVectorConn) ALPN() string       { return wire.ALPN }
func (c *fakeVectorConn) Exporter() ([]byte, error) {
	out := make([]byte, len(c.exporter))
	copy(out, c.exporter[:])
	return out, nil
}

func (c *fakeVectorConn) AcceptStream(context.Context) (qio.Stream, error) {
	return nil, errors.New("unused")
}

func (c *fakeVectorConn) OpenStream(context.Context) (qio.Stream, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errors.New("connection closed")
	}
	stream := &fakeVectorStream{id: c.next, read: []byte{byte(wire.SetupReady)}}
	c.next += 4
	c.streams = append(c.streams, stream)
	return stream, nil
}

func (c *fakeVectorConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (c *fakeVectorConn) SendDatagram([]byte) error { return nil }
func (c *fakeVectorConn) MaxDatagramSize() int      { return c.max }
func (c *fakeVectorConn) CloseWithError(uint64, string) error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	c.cancel()
	return nil
}
func (c *fakeVectorConn) Context() context.Context { return c.ctx }
func (c *fakeVectorConn) RemoteAddr() net.Addr     { return nil }

func (c *fakeVectorConn) snapshot() []*fakeVectorStream {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*fakeVectorStream, len(c.streams))
	copy(out, c.streams)
	return out
}

func newTestVectorClient(t *testing.T, dial func(context.Context) (qio.Conn, error)) *Client {
	t.Helper()
	client, err := New(Config{SharedKey: vectorTestKey, DialQUIC: dial})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// TestQUICAuthenticationUsesStreamZero checks that concurrent opens cannot put
// the AuthFrame on a business stream: only stream 0 carries the tag.
func TestQUICAuthenticationUsesStreamZero(t *testing.T) {
	conn := newFakeVectorConn(1200)
	client := newTestVectorClient(t, func(context.Context) (qio.Conn, error) {
		return conn, nil
	})
	target, err := wire.NewIPTarget(netip.MustParseAddr("1.2.3.4"), 80)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := client.OpenTCP(context.Background(), target)
			if err != nil {
				errs <- err
				return
			}
			_ = c.Close()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("OpenTCP: %v", err)
	}

	creds, err := wire.NewCredentials(vectorTestKey)
	if err != nil {
		t.Fatal(err)
	}
	roleKey, err := creds.RoleKey(wire.RoleVector)
	if err != nil {
		t.Fatal(err)
	}
	want, err := wire.EncodeAuthFrame(roleKey, wire.AuthQUIC, conn.exporter)
	if err != nil {
		t.Fatal(err)
	}

	streams := conn.snapshot()
	if len(streams) != 8 {
		t.Fatalf("opened %d streams, want 8", len(streams))
	}
	authStreams := 0
	for _, stream := range streams {
		id, writes := stream.snapshot()
		hasAuth := len(writes) >= wire.AuthFrameLen && bytes.Equal(writes[:wire.AuthFrameLen], want[:])
		if id == 0 {
			authStreams++
			if !hasAuth {
				t.Fatal("stream 0 does not start with the AuthFrame")
			}
			continue
		}
		if hasAuth {
			t.Fatalf("stream %d starts with the AuthFrame", id)
		}
	}
	if authStreams != 1 {
		t.Fatalf("AuthFrame found on %d streams, want exactly stream 0", authStreams)
	}
}

// TestOpenUDPRequiresDatagramSupport checks the client refuses a UDP flow on a
// connection that did not negotiate DATAGRAM support, before opening a stream.
func TestOpenUDPRequiresDatagramSupport(t *testing.T) {
	conn := newFakeVectorConn(0)
	client := newTestVectorClient(t, func(context.Context) (qio.Conn, error) {
		return conn, nil
	})
	if _, err := client.OpenUDP(context.Background(), wire.Target{}); err == nil {
		t.Fatal("OpenUDP accepted a connection without DATAGRAM support")
	}
	if got := len(conn.snapshot()); got != 0 {
		t.Fatalf("opened %d streams, want none", got)
	}
}

// TestQUICReconnectsAfterSessionLoss checks that a dead session is replaced on
// the next open instead of being reused forever.
func TestQUICReconnectsAfterSessionLoss(t *testing.T) {
	first := newFakeVectorConn(1200)
	second := newFakeVectorConn(1200)
	var dials int
	var mu sync.Mutex
	client := newTestVectorClient(t, func(context.Context) (qio.Conn, error) {
		mu.Lock()
		defer mu.Unlock()
		dials++
		if dials == 1 {
			return first, nil
		}
		return second, nil
	})
	target, err := wire.NewIPTarget(netip.MustParseAddr("1.2.3.4"), 80)
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.OpenTCP(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()

	first.cancel()
	c, err = client.OpenTCP(context.Background(), target)
	if err != nil {
		t.Fatalf("open after session loss: %v", err)
	}
	_ = c.Close()
	mu.Lock()
	got := dials
	mu.Unlock()
	if got != 2 {
		t.Fatalf("dials = %d, want 2", got)
	}
}
