package nowhere_test

import (
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	nwlisten "github.com/metacubex/mihomo/listener/nowhere"
	nwtransport "github.com/metacubex/mihomo/transport/nowhere"
)

// testNw3Password is a Nowhere 3 service key: exactly 32 lowercase hexadecimal
// characters. The nw2 keys in server_v2_test.go are deliberately not reused here:
// the two stacks have different key rules and must not be mixed.
const testNw3Password = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"

func TestSelectNowhereStack(t *testing.T) {
	for _, alpn := range [][]string{nil, {}, {"nw3"}} {
		nw3, err := nwtransport.SelectNowhereStack(alpn)
		if err != nil {
			t.Fatalf("SelectNowhereStack(%q): %v", alpn, err)
		}
		if !nw3 {
			t.Fatalf("SelectNowhereStack(%q) = Nowhere 2, want Nowhere 3", alpn)
		}
	}
	nw3, err := nwtransport.SelectNowhereStack([]string{"nw2"})
	if err != nil {
		t.Fatalf("SelectNowhereStack(nw2): %v", err)
	}
	if nw3 {
		t.Fatal("SelectNowhereStack(nw2) = Nowhere 3, want Nowhere 2")
	}
	for _, alpn := range [][]string{{""}, {"nw2", "nw3"}, {"now/1"}, {string(make([]byte, 256))}} {
		if _, err := nwtransport.SelectNowhereStack(alpn); err == nil {
			t.Fatalf("SelectNowhereStack(%q) = nil error, want an alpn error", alpn)
		}
	}
}

func TestResolveNowhereMorph(t *testing.T) {
	// Nowhere 2 leaves Morph off when omitted, Nowhere 3 turns it on.
	if nwtransport.ResolveNowhereMorph(nil, false) {
		t.Fatal("omitted morph resolved on for Nowhere 2")
	}
	if !nwtransport.ResolveNowhereMorph(nil, true) {
		t.Fatal("omitted morph resolved off for Nowhere 3")
	}
	on, off := true, false
	if !nwtransport.ResolveNowhereMorph(&on, false) {
		t.Fatal("explicit morph=true ignored for Nowhere 2")
	}
	if nwtransport.ResolveNowhereMorph(&off, true) {
		t.Fatal("explicit morph=false ignored for Nowhere 3")
	}
}

func TestNowhereV3Net(t *testing.T) {
	for _, testCase := range []struct {
		raw string
		net string
	}{
		{"", nwtransport.NowhereNetTCP},
		{"tcp", nwtransport.NowhereNetTCP},
		{"udp", nwtransport.NowhereNetUDP},
	} {
		netName, err := nwtransport.NowhereNet(testCase.raw)
		if err != nil {
			t.Fatalf("NowhereNet(%q): %v", testCase.raw, err)
		}
		if netName != testCase.net {
			t.Fatalf("NowhereNet(%q) = %q, want %q", testCase.raw, netName, testCase.net)
		}
	}
	for _, raw := range []string{"quic", "ws"} {
		if _, err := nwtransport.NowhereNet(raw); err == nil {
			t.Fatalf("NowhereNet(%q) = nil error, want a net error", raw)
		}
	}
}

func TestValidateNowhereV3ServiceKey(t *testing.T) {
	if err := nwtransport.ValidateNowhereServiceKey(testNw3Password); err != nil {
		t.Fatalf("ValidateNowhereServiceKey(%q): %v", testNw3Password, err)
	}
	for _, key := range []string{
		"",
		"xyz",
		// 32–64 is the Nowhere 2 rule; Nowhere 3 wants exactly 32.
		"0123456789abcdef0123456789abcdef01234567",
		"0123456789ABCDEF0123456789ABCDEF",
	} {
		if err := nwtransport.ValidateNowhereServiceKey(key); err == nil {
			t.Fatalf("ValidateNowhereServiceKey(%q) = nil error, want a key error", key)
		}
	}
}

// startNw3TestServer binds 127.0.0.1:0 with the Nowhere 3 Portal on the given
// transport and reports the port the vendored stack actually listens on.
func startNw3TestServer(t *testing.T, netName string, morph bool) int {
	t.Helper()
	return startNw3TestServerWithCipher(t, netName, morph, "")
}

func startNw3TestServerWithCipher(t *testing.T, netName string, morph bool, cipher string) int {
	t.Helper()
	return startNw3TestServerWithOptions(t, netName, morph, cipher, "")
}

func startNw3TestServerWithOptions(t *testing.T, netName string, morph bool, cipher, grade string) int {
	t.Helper()
	server, err := nwlisten.New(LC.NowhereServer{
		Enable:               true,
		Listen:               "127.0.0.1:0",
		Password:             testNw3Password,
		Certificate:          testCertificate,
		PrivateKey:           testPrivateKey,
		CongestionController: "bbr",
		Net:                  netName,
		Morph:                morph,
		Cipher:               cipher,
		Grade:                grade,
	}, inbound.NewListenConfig(), fakeTunnel{})
	if err != nil {
		t.Fatalf("nowhere.New: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	addrList := server.AddrList()
	if len(addrList) != 1 {
		t.Fatalf("AddrList = %v, want one address", addrList)
	}
	_, portStr, err := net.SplitHostPort(addrList[0])
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addrList[0], err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port %q: %v", portStr, err)
	}
	return port
}

func newNw3TestClient(t *testing.T, port int, netName string, morph bool) *outbound.Nowhere {
	t.Helper()
	return newNw3TestClientWithCipher(t, port, netName, morph, "")
}

func newNw3TestClientWithCipher(t *testing.T, port int, netName string, morph bool, cipher string) *outbound.Nowhere {
	t.Helper()
	return newNw3TestClientWithOptions(t, port, netName, morph, cipher, "")
}

func newNw3TestClientWithOptions(t *testing.T, port int, netName string, morph bool, cipher, grade string) *outbound.Nowhere {
	t.Helper()
	client, err := outbound.NewNowhere(outbound.NowhereOption{
		Name: "nowhere-nw3-test-client", Server: "127.0.0.1", Port: port,
		Password: testNw3Password, SkipCertVerify: true,
		Net:    netName,
		Morph:  &morph,
		Cipher: cipher,
		Grade:  grade,
		UDP:    true,
	})
	if err != nil {
		t.Fatalf("outbound.NewNowhere: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// testNw3Forwarding drives one TCP flow and one UDP flow through a Nowhere 3
// endpoint pair and asserts both round-trip through the echo tunnel.
func testNw3Forwarding(t *testing.T, client *outbound.Nowhere) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := client.DialContext(ctx, &C.Metadata{Host: "example.com", DstPort: 80})
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	payload := []byte("nowhere nw3 tcp echo")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("tcp echo = %q, want %q", buf, payload)
	}

	pc, err := client.ListenPacketContext(ctx, &C.Metadata{Host: "example.com", DstPort: 80})
	if err != nil {
		t.Fatalf("ListenPacketContext: %v", err)
	}
	defer func() { _ = pc.Close() }()
	_ = pc.SetDeadline(time.Now().Add(5 * time.Second))

	udpPayload := []byte("nowhere nw3 udp echo")
	if _, err := pc.WriteTo(udpPayload, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 80}); err != nil {
		t.Fatalf("udp write: %v", err)
	}
	udpBuf := make([]byte, len(udpPayload)+1)
	n, _, err := pc.ReadFrom(udpBuf)
	if err != nil {
		t.Fatalf("udp read: %v", err)
	}
	if string(udpBuf[:n]) != string(udpPayload) {
		t.Fatalf("udp echo = %q, want %q", udpBuf[:n], udpPayload)
	}
}

// TestNowhereV3TCPForwarding runs a full Nowhere 3 endpoint pair over the TCP
// carrier with Morph on (the Nowhere 3 default): Portal -> echo tunnel and back,
// for a TCP flow and for a UDP flow carried as UoT inside the TLS connection.
func TestNowhereV3TCPForwarding(t *testing.T) {
	port := startNw3TestServer(t, nwtransport.NowhereNetTCP, true)
	client := newNw3TestClient(t, port, nwtransport.NowhereNetTCP, true)
	testNw3Forwarding(t, client)
}

// TestNowhereV3TCPForwardingMorphOff is the same pair with Morph explicitly
// disabled on both ends, which is the escape hatch when a middlebox dislikes
// the transform.
func TestNowhereV3TCPForwardingMorphOff(t *testing.T) {
	port := startNw3TestServer(t, nwtransport.NowhereNetTCP, false)
	client := newNw3TestClient(t, port, nwtransport.NowhereNetTCP, false)
	testNw3Forwarding(t, client)
}

// TestNowhereV3TCPForwardingAES runs a Nowhere 3.4 TCP endpoint pair using the
// AES-128-CTR Morph cipher on both peers.
func TestNowhereV3TCPForwardingAES(t *testing.T) {
	port := startNw3TestServerWithCipher(t, nwtransport.NowhereNetTCP, true, "aes")
	client := newNw3TestClientWithCipher(t, port, nwtransport.NowhereNetTCP, true, "aes")
	testNw3Forwarding(t, client)
}

// TestNowhereV3TCPCipherMismatchRejected verifies that mismatched Morph ciphers
// fail handshake rather than silently falling back.
func TestNowhereV3TCPCipherMismatchRejected(t *testing.T) {
	t.Setenv("NOW_HANDSHAKE_TIMEOUT", "300ms")
	port := startNw3TestServerWithCipher(t, nwtransport.NowhereNetTCP, true, "chacha")
	client := newNw3TestClientWithCipher(t, port, nwtransport.NowhereNetTCP, true, "aes")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, &C.Metadata{Host: "example.com", DstPort: 80})
	if err == nil {
		_ = conn.Close()
		t.Fatal("DialContext succeeded across chacha/aes cipher mismatch")
	}
}

func TestParseNowhereMorphCipher(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want string
	}{
		{"", "chacha"},
		{"chacha", "chacha"},
		{"aes", "aes"},
	} {
		got, err := nwtransport.ParseNowhereMorphCipher(tc.raw)
		if err != nil {
			t.Fatalf("ParseNowhereMorphCipher(%q): %v", tc.raw, err)
		}
		if got.String() != tc.want {
			t.Fatalf("ParseNowhereMorphCipher(%q) = %q, want %q", tc.raw, got.String(), tc.want)
		}
	}
	for _, bad := range []string{"AES", "ChaCha", "chacha20", "aes-128-ctr", "none"} {
		if _, err := nwtransport.ParseNowhereMorphCipher(bad); err == nil {
			t.Fatalf("ParseNowhereMorphCipher(%q) = nil error, want error", bad)
		}
	}
}

// TestNowhereV3TCPForwardingCoreGrade runs Nowhere 3.5 TCP endpoint pairs using
// Core Morph with both ChaCha20-IETF and AES-128-CTR.
func TestNowhereV3TCPForwardingCoreGrade(t *testing.T) {
	for _, cipher := range []string{"chacha", "aes"} {
		t.Run(cipher, func(t *testing.T) {
			port := startNw3TestServerWithOptions(t, nwtransport.NowhereNetTCP, true, cipher, "core")
			client := newNw3TestClientWithOptions(t, port, nwtransport.NowhereNetTCP, true, cipher, "core")
			testNw3Forwarding(t, client)
		})
	}
}

// TestNowhereV3TCPGradeMismatchRejected verifies that mismatched Morph grades
// (full vs core) fail handshake rather than silently falling back.
func TestNowhereV3TCPGradeMismatchRejected(t *testing.T) {
	t.Setenv("NOW_HANDSHAKE_TIMEOUT", "300ms")
	for _, tc := range []struct {
		name        string
		cipher      string
		serverGrade string
		clientGrade string
	}{
		{"chacha-full-vs-core", "chacha", "full", "core"},
		{"chacha-core-vs-full", "chacha", "core", "full"},
		{"aes-full-vs-core", "aes", "full", "core"},
		{"aes-core-vs-full", "aes", "core", "full"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port := startNw3TestServerWithOptions(t, nwtransport.NowhereNetTCP, true, tc.cipher, tc.serverGrade)
			client := newNw3TestClientWithOptions(t, port, nwtransport.NowhereNetTCP, true, tc.cipher, tc.clientGrade)

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			conn, err := client.DialContext(ctx, &C.Metadata{Host: "example.com", DstPort: 80})
			if err == nil {
				_ = conn.Close()
				t.Fatalf("DialContext succeeded across %s grade mismatch", tc.name)
			}
		})
	}
}

func TestParseNowhereMorphGrade(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want string
	}{
		{"", "full"},
		{"full", "full"},
		{"core", "core"},
	} {
		got, err := nwtransport.ParseNowhereMorphGrade(tc.raw)
		if err != nil {
			t.Fatalf("ParseNowhereMorphGrade(%q): %v", tc.raw, err)
		}
		if got.String() != tc.want {
			t.Fatalf("ParseNowhereMorphGrade(%q) = %q, want %q", tc.raw, got.String(), tc.want)
		}
	}
	for _, bad := range []string{"FULL", "CORE", "Full", "Core", "light", "none"} {
		if _, err := nwtransport.ParseNowhereMorphGrade(bad); err == nil {
			t.Fatalf("ParseNowhereMorphGrade(%q) = nil error, want error", bad)
		}
	}
}
