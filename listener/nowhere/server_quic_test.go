package nowhere_test

import (
	"context"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	nwtransport "github.com/metacubex/mihomo/transport/nowhere"
)

// TestNowhereV3QUICForwarding runs the same endpoint pair as
// TestNowhereV3TCPForwarding over the QUIC carrier, with Morph on (the Nowhere 3
// default). Unlike the TCP carrier — where the vendored stack wraps Morph itself
// — the host seals the QUIC packet socket below QUIC on both ends, so this test
// exercises nwtransport.ListenNowhereQUIC / DialNowhereQUIC and the
// nw3MorphPacketDialer.
func TestNowhereV3QUICForwarding(t *testing.T) {
	port := startNw3TestServer(t, nwtransport.NowhereNetUDP, true)
	client := newNw3TestClient(t, port, nwtransport.NowhereNetUDP, true)
	testNw3Forwarding(t, client)
}

// TestNowhereV3QUICForwardingMorphOff is the QUIC pair with Morph disabled, the
// escape hatch when the transform breaks a path.
func TestNowhereV3QUICForwardingMorphOff(t *testing.T) {
	port := startNw3TestServer(t, nwtransport.NowhereNetUDP, false)
	client := newNw3TestClient(t, port, nwtransport.NowhereNetUDP, false)
	testNw3Forwarding(t, client)
}

// TestNowhereV3QUICForwardingAES runs a Nowhere 3.4 QUIC endpoint pair using
// AES-128-CTR Morph on both peers.
func TestNowhereV3QUICForwardingAES(t *testing.T) {
	port := startNw3TestServerWithCipher(t, nwtransport.NowhereNetUDP, true, "aes")
	client := newNw3TestClientWithCipher(t, port, nwtransport.NowhereNetUDP, true, "aes")
	testNw3Forwarding(t, client)
}

// TestNowhereV3QUICCipherMismatchRejected verifies that QUIC Morph peers with
// mismatched ciphers cannot establish a session.
func TestNowhereV3QUICCipherMismatchRejected(t *testing.T) {
	port := startNw3TestServerWithCipher(t, nwtransport.NowhereNetUDP, true, "chacha")
	client := newNw3TestClientWithCipher(t, port, nwtransport.NowhereNetUDP, true, "aes")

	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	conn, err := client.DialContext(ctx, &C.Metadata{Host: "example.com", DstPort: 80})
	if err == nil {
		_ = conn.Close()
		t.Fatal("DialContext succeeded across QUIC chacha/aes cipher mismatch")
	}
}

// TestNowhereV3QUICForwardingCoreGrade runs Nowhere 3.5 QUIC endpoint pairs
// using Core Morph with both ChaCha20-IETF and AES-128-CTR.
func TestNowhereV3QUICForwardingCoreGrade(t *testing.T) {
	for _, cipher := range []string{"chacha", "aes"} {
		t.Run(cipher, func(t *testing.T) {
			port := startNw3TestServerWithOptions(t, nwtransport.NowhereNetUDP, true, cipher, "core")
			client := newNw3TestClientWithOptions(t, port, nwtransport.NowhereNetUDP, true, cipher, "core")
			testNw3Forwarding(t, client)
		})
	}
}

// TestNowhereV3QUICGradeMismatchRejected verifies that QUIC Morph peers with
// mismatched grades (full vs core) cannot establish a session.
func TestNowhereV3QUICGradeMismatchRejected(t *testing.T) {
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
			port := startNw3TestServerWithOptions(t, nwtransport.NowhereNetUDP, true, tc.cipher, tc.serverGrade)
			client := newNw3TestClientWithOptions(t, port, nwtransport.NowhereNetUDP, true, tc.cipher, tc.clientGrade)

			ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
			defer cancel()
			conn, err := client.DialContext(ctx, &C.Metadata{Host: "example.com", DstPort: 80})
			if err == nil {
				_ = conn.Close()
				t.Fatalf("DialContext succeeded across QUIC %s grade mismatch", tc.name)
			}
		})
	}
}
