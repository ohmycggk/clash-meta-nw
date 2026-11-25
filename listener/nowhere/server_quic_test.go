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
