package morph

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func TestDeriveMatchesRustVector(t *testing.T) {
	keys := Derive([]byte("test portal key"))
	assertHex(t, keys.TCPC2S[:], "f3d2fabc455a59c400d09d400b5a0b9b221e2b157589fc87674b902111ea1014")
	assertHex(t, keys.TCPS2C[:], "190cfc4c689b24d4bfc8431f46d9f2d1bcbf6222eed612a3ea12d04ff4e4af8c")
	assertHex(t, keys.UDPC2S[:], "20221bde5d70b44211a22c7e62967945d7d85bcde0d17a3b28d1fa686f8e5c1f")
	assertHex(t, keys.UDPS2C[:], "78938ee9245028e7de63ac27b0ab64c68df2961a2cf39da1394f0f242bf8b389")
}

func TestTCPRoundTrip(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	keys := Derive([]byte("0123456789abcdef0123456789abcdef"))
	client, err := WrapTCPClient(clientSide, keys)
	if err != nil {
		t.Fatal(err)
	}
	server := WrapTCPServer(serverSide, keys)
	payload := minimalClientHello()
	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, len(payload))
		_, err := io.ReadFull(server, buf)
		if err != nil {
			errCh <- err
			return
		}
		if !bytes.Equal(buf, payload) {
			errCh <- io.ErrUnexpectedEOF
			return
		}
		_, err = server.Write(payload)
		errCh <- err
	}()
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatalf("client read %q", buf)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func TestPreludePolicyDefaultsToFade(t *testing.T) {
	t.Setenv(preludeEnv, "sentinel")
	if err := os.Unsetenv(preludeEnv); err != nil {
		t.Fatal(err)
	}
	got, err := preludePolicyFromEnv()
	if err != nil || got != preludeFade {
		t.Fatalf("unset: got %d, err %v; want fade", got, err)
	}
	for _, tc := range []struct {
		value string
		want  preludePolicy
	}{
		{value: "fade", want: preludeFade},
		{value: "full8", want: preludeFull8},
		{value: "low7", want: preludeLow7},
	} {
		t.Run(tc.value, func(t *testing.T) {
			t.Setenv(preludeEnv, tc.value)
			got, err := preludePolicyFromEnv()
			if err != nil || got != tc.want {
				t.Fatalf("%s: got %d, err %v", tc.value, got, err)
			}
		})
	}
	for _, value := range []string{"", "FULL8", "FADE", " fade", "full8 ", "low7 ", "other"} {
		t.Run("reject "+value, func(t *testing.T) {
			t.Setenv(preludeEnv, value)
			if _, err := preludePolicyFromEnv(); err == nil {
				t.Fatalf("%q accepted", value)
			}
		})
	}
}

func TestSampleBelowRejectsBiasAndRetries(t *testing.T) {
	const upper = 95
	limit := 256 - 256%upper
	var draws []byte
	got, err := sampleBelow(255, upper, func(dst []byte) error {
		draws = append(draws, dst[0])
		dst[0] = 10
		return nil
	})
	if err != nil || got != 10 || len(draws) != 1 {
		t.Fatalf("retry: got %d draws %v err %v", got, draws, err)
	}
	if _, err := sampleBelow(byte(limit-1), upper, func([]byte) error {
		t.Fatal("accepted byte was redrawn")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("entropy")
	if _, err := sampleBelow(255, upper, func([]byte) error { return wantErr }); !errors.Is(err, wantErr) {
		t.Fatalf("redraw error: %v", err)
	}
}

func TestFadeCoversBoundaryPairs(t *testing.T) {
	for _, tc := range []struct {
		a, b   int
		bounds [2]byte
	}{
		{a: 8, b: 16, bounds: [2]byte{0, 0}},
		{a: 12, b: 32, bounds: [2]byte{4, 16}},
		{a: 10, b: 20, bounds: [2]byte{2, 4}},
	} {
		calls := 0
		prelude, err := generatePreludeWith(preludeFade, func(dst []byte) error {
			calls++
			if calls == 1 {
				for i := range dst {
					dst[i] = 0xff
				}
				return nil
			}
			if calls == 2 {
				copy(dst, tc.bounds[:])
				return nil
			}
			for i := range dst {
				dst[i] = 1
			}
			return nil
		})
		if err != nil {
			t.Fatalf("A=%d B=%d: %v", tc.a, tc.b, err)
		}
		for i := 0; i < tc.a; i++ {
			if prelude[i] != 0x21 {
				t.Fatalf("A=%d printable[%d]=%#x, want 0x21", tc.a, i, prelude[i])
			}
		}
		for i := tc.a; i < tc.b; i++ {
			if prelude[i] != 0x7f {
				t.Fatalf("A=%d B=%d low7[%d]=%#x, want 0x7f", tc.a, tc.b, i, prelude[i])
			}
		}
		for i := tc.b; i < preludeLen; i++ {
			if prelude[i] != 0xff {
				t.Fatalf("A=%d B=%d full8[%d]=%#x, want 0xff", tc.a, tc.b, i, prelude[i])
			}
		}
	}
}

func TestServerAcceptsEveryPreludePolicy(t *testing.T) {
	keys := Derive([]byte("0123456789abcdef0123456789abcdef"))
	payload := minimalClientHello()
	for _, policy := range []preludePolicy{preludeFade, preludeFull8, preludeLow7} {
		clientSide, serverSide := net.Pipe()
		client, err := wrapTCPClientPolicy(clientSide, keys, policy)
		if err != nil {
			t.Fatal(err)
		}
		server := WrapTCPServer(serverSide, keys)
		errCh := make(chan error, 1)
		go func() {
			buf := make([]byte, len(payload))
			_, err := io.ReadFull(server, buf)
			if err != nil {
				errCh <- err
				return
			}
			if !bytes.Equal(buf, payload) {
				errCh <- io.ErrUnexpectedEOF
				return
			}
			_, err = server.Write(payload)
			errCh <- err
		}()
		if _, err := client.Write(payload); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(client, buf); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buf, payload) {
			t.Fatalf("policy %d read %q", policy, buf)
		}
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
}

func TestServerDropsUnsupportedQUICVersions(t *testing.T) {
	if supportedQUICPacket(nil) || supportedQUICPacket([]byte{}) {
		t.Fatal("empty packet accepted")
	}
	for first := byte(0); first < 0x80; first += 17 {
		if !supportedQUICPacket([]byte{first}) {
			t.Fatalf("short header %#x rejected", first)
		}
	}
	for _, first := range []byte{0x80, 0xc0, 0xf0, 0xff} {
		for _, version := range quinnVersions {
			packet := append([]byte{first}, binary.BigEndian.AppendUint32(nil, version)...)
			if !supportedQUICPacket(packet) {
				t.Fatalf("version %#x rejected", version)
			}
			for n := 1; n < 5; n++ {
				if supportedQUICPacket(packet[:n]) {
					t.Fatalf("truncated long header of %d bytes accepted", n)
				}
			}
		}
		for _, version := range []uint32{0, 2, 0x0a1a2a3a, 0xffffffff, 0x6b3343cf} {
			packet := []byte{first, 0, 0, 0, 0}
			binary.BigEndian.PutUint32(packet[1:], version)
			if supportedQUICPacket(packet) {
				t.Fatalf("version %#x accepted", version)
			}
		}
	}
}

func TestServerReadFromSkipsUnsupportedThenReturnsNext(t *testing.T) {
	keys := Derive([]byte("0123456789abcdef0123456789abcdef"))
	rawClient, rawServer := packetPipe()
	defer rawClient.Close()
	defer rawServer.Close()
	server, err := WrapPacketConn(rawServer, keys, false)
	if err != nil {
		t.Fatal(err)
	}
	client, err := WrapPacketConn(rawClient, keys, true)
	if err != nil {
		t.Fatal(err)
	}

	rejected := []byte{0xc0, 0xff, 0xff, 0xff, 0xff, 1, 2, 3}
	accepted := []byte{0x40, 7, 8, 9}
	errCh := make(chan error, 1)
	go func() {
		if _, err := client.WriteTo(rejected, nil); err != nil {
			errCh <- err
			return
		}
		if _, err := client.WriteTo(accepted, nil); err != nil {
			errCh <- err
			return
		}
		errCh <- nil
	}()
	buf := make([]byte, 32)
	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := server.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], accepted) {
		t.Fatalf("got %x, want the short-header datagram", buf[:n])
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

type packetPipeConn struct {
	reader *io.PipeReader
	writer *io.PipeWriter
	peer   *packetPipeConn
}

func packetPipe() (*packetPipeConn, *packetPipeConn) {
	leftRead, rightWrite := io.Pipe()
	rightRead, leftWrite := io.Pipe()
	left := &packetPipeConn{reader: leftRead, writer: leftWrite}
	right := &packetPipeConn{reader: rightRead, writer: rightWrite}
	left.peer = right
	right.peer = left
	return left, right
}

func (c *packetPipeConn) ReadFrom(p []byte) (int, net.Addr, error) {
	var n uint16
	if err := binary.Read(c.reader, binary.BigEndian, &n); err != nil {
		return 0, nil, err
	}
	if int(n) > len(p) {
		return 0, nil, io.ErrShortBuffer
	}
	_, err := io.ReadFull(c.reader, p[:n])
	return int(n), nil, err
}

func (c *packetPipeConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if len(p) > 65535 {
		return 0, io.ErrShortWrite
	}
	var head [2]byte
	binary.BigEndian.PutUint16(head[:], uint16(len(p)))
	if _, err := c.writer.Write(head[:]); err != nil {
		return 0, err
	}
	return c.writer.Write(p)
}

func (c *packetPipeConn) Close() error {
	_ = c.reader.Close()
	return c.writer.Close()
}

func (c *packetPipeConn) LocalAddr() net.Addr              { return nil }
func (c *packetPipeConn) SetDeadline(time.Time) error      { return nil }
func (c *packetPipeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *packetPipeConn) SetWriteDeadline(time.Time) error { return nil }

func TestFadePropagatesRandomSourceErrors(t *testing.T) {
	want := errors.New("entropy")
	// Call 1 fills the prelude. Call 2 draws the two boundaries. The first
	// printable byte is 0xff, which is outside the unbiased range, so call 3
	// is the ASCII redraw.
	for _, stage := range []int{1, 2, 3} {
		calls := 0
		_, err := generatePreludeWith(preludeFade, func(dst []byte) error {
			calls++
			if calls == stage {
				return want
			}
			for i := range dst {
				dst[i] = 0xff
			}
			return nil
		})
		if !errors.Is(err, want) {
			t.Fatalf("stage %d: %v", stage, err)
		}
	}
}

func wrapTCPClientPolicy(conn net.Conn, keys Keys, policy preludePolicy) (net.Conn, error) {
	identity, counter, err := keys.state.allocate()
	if err != nil {
		return nil, err
	}
	prelude, err := generatePrelude(policy)
	if err != nil {
		return nil, err
	}
	var nonce [nonceLen]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}
	encodePrelude(keys.state, &prelude, &nonce, identity, counter)
	pref := make([]byte, 0, preludeLen+nonceLen)
	pref = append(pref, prelude[:]...)
	pref = append(pref, nonce[:]...)
	return &tcpConn{
		Conn:      conn,
		readKey:   keys.TCPS2C,
		writeKey:  keys.TCPC2S,
		nonce:     nonce,
		writePref: pref,
	}, nil
}

func assertHex(t *testing.T, got []byte, want string) {
	t.Helper()
	if hex.EncodeToString(got) != want {
		t.Fatalf("got %x want %s", got, want)
	}
}

// TestClientUDPPreludeShape pins the standalone prelude a Morph UDP client
// socket emits before its first datagram. It is 12 bytes — the nonce length, so
// the Portal drops it by length alone — and the fade default shapes its bytes
// the way Nowhere 3.3 does for that length.
func TestClientUDPPreludeShape(t *testing.T) {
	keys := Derive([]byte("0123456789abcdef0123456789abcdef"))
	rawClient, rawServer := packetPipe()
	defer rawClient.Close()
	defer rawServer.Close()
	client, err := WrapPacketConn(rawClient, keys, true)
	if err != nil {
		t.Fatal(err)
	}
	server, err := WrapPacketConn(rawServer, keys, false)
	if err != nil {
		t.Fatal(err)
	}
	// A server socket never carries a prelude.
	if pc, ok := server.(*packetConn); ok && pc.prelude != nil {
		t.Fatal("a server socket must not carry a UDP prelude")
	}
	pc, ok := client.(*packetConn)
	if !ok || pc.prelude == nil {
		t.Fatal("a client socket must carry a UDP prelude")
	}
	if len(pc.prelude) != udpPreludeLen {
		t.Fatalf("prelude is %d bytes, want %d", len(pc.prelude), udpPreludeLen)
	}
	if len(pc.prelude) != nonceLen {
		t.Fatalf("prelude is %d bytes, want the nonce length %d", len(pc.prelude), nonceLen)
	}
	for i := 0; i < 2; i++ {
		if pc.prelude[i] < 0x20 || pc.prelude[i] > 0x7e {
			t.Fatalf("prelude[%d]=%#x is not printable", i, pc.prelude[i])
		}
	}
	for i := 2; i < 10; i++ {
		if pc.prelude[i]&0x80 != 0 {
			t.Fatalf("prelude[%d]=%#x has the high bit set", i, pc.prelude[i])
		}
	}
}

// TestServerDropsUDPPrelude pins the Portal side of the Nowhere 3.3 prelude: a
// 12-byte datagram carries nothing but a nonce, so it is dropped without ever
// reaching the application. The client prelude travels ahead of the first real
// datagram, so it costs the application nothing.
func TestServerDropsUDPPrelude(t *testing.T) {
	keys := Derive([]byte("0123456789abcdef0123456789abcdef"))
	rawClient, rawServer := packetPipe()
	defer rawClient.Close()
	defer rawServer.Close()
	server, err := WrapPacketConn(rawServer, keys, false)
	if err != nil {
		t.Fatal(err)
	}
	client, err := WrapPacketConn(rawClient, keys, true)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte{0x40, 1, 2, 3, 4}
	errCh := make(chan error, 2)
	go func() {
		if _, err := client.WriteTo(payload, nil); err != nil {
			errCh <- err
			return
		}
		if _, err := client.WriteTo(payload, nil); err != nil {
			errCh <- err
			return
		}
		errCh <- nil
	}()
	for i := 0; i < 2; i++ {
		buf := make([]byte, 64)
		_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _, err := server.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buf[:n], payload) {
			t.Fatalf("datagram %d is %x, want %x", i, buf[:n], payload)
		}
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	// The prelude is spent: a third datagram is still delivered.
	go func() {
		if _, err := client.WriteTo(payload, nil); err != nil {
			errCh <- err
			return
		}
		errCh <- nil
	}()
	buf := make([]byte, 64)
	_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := server.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("third datagram is %x, want %x", buf[:n], payload)
	}
}

func TestUDPPreludePolicyShapes(t *testing.T) {
	full8, err := generateUDPPreludeWith(preludeFull8, func(b []byte) error {
		for i := range b {
			b[i] = 0xff
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for i, b := range full8 {
		if b != 0xff {
			t.Fatalf("full8[%d]=%#x, want every byte untouched", i, b)
		}
	}
	low7, err := generateUDPPreludeWith(preludeLow7, func(b []byte) error {
		for i := range b {
			b[i] = 0xff
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for i, b := range low7 {
		if b != 0x7f {
			t.Fatalf("low7[%d]=%#x, want every byte high bit cleared", i, b)
		}
	}
}

func TestUDPPreludePolicyFromEnv(t *testing.T) {
	for _, value := range []string{"fade", "full8", "low7"} {
		t.Setenv("NOW_MORPH_UDP_PRELUDE", value)
		if _, err := udpPreludePolicyFromEnv(); err != nil {
			t.Fatalf("%s: %v", value, err)
		}
	}
	t.Setenv("NOW_MORPH_UDP_PRELUDE", "nonsense")
	if _, err := udpPreludePolicyFromEnv(); err == nil {
		t.Fatal("an invalid NOW_MORPH_UDP_PRELUDE must be an error")
	}
	// Rust reads the variable with env::var, so an empty value is an explicit
	// invalid setting rather than an omission. Match that exactly.
	t.Setenv("NOW_MORPH_UDP_PRELUDE", "")
	if _, err := udpPreludePolicyFromEnv(); err == nil {
		t.Fatal("an empty value must be rejected, like Rust's env::var")
	}
}

func TestUDPPreludePolicyUnsetFallsBack(t *testing.T) {
	os.Unsetenv("NOW_MORPH_UDP_PRELUDE")
	policy, err := udpPreludePolicyFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if policy != preludeFade {
		t.Fatalf("policy is %v, want the fade default", policy)
	}
}
