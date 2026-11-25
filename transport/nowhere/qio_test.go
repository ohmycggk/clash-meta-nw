package nowhere

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/transport/nowhere/core/morph"
	nwruntime "github.com/metacubex/mihomo/transport/nowhere/core/runtime"
	"github.com/metacubex/mihomo/transport/nowhere/core/wire"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

func TestNowhereV3QUICConfigMemoryProfiles(t *testing.T) {
	tests := []struct {
		profile  string
		wantStrm uint64
		wantConn uint64
	}{
		{"", 4 << 20, 32 << 20},
		{"throughput", 4 << 20, 32 << 20},
		{"balanced", 4 << 20, 16 << 20},
		{"memory", 4 << 20, 16 << 20},
	}
	for _, tc := range tests {
		t.Run("profile_"+tc.profile, func(t *testing.T) {
			if tc.profile != "" {
				t.Setenv(nwruntime.EnvMemoryProfile, tc.profile)
			}
			rt, err := nwruntime.Load("", false)
			if err != nil {
				t.Fatalf("runtime.Load: %v", err)
			}

			clientCfg := nowhereV3QUICConfig(true, rt, nil)
			if clientCfg.InitialStreamReceiveWindow != tc.wantStrm || clientCfg.MaxStreamReceiveWindow != tc.wantStrm {
				t.Fatalf("client stream window = %d/%d, want %d", clientCfg.InitialStreamReceiveWindow, clientCfg.MaxStreamReceiveWindow, tc.wantStrm)
			}
			if clientCfg.InitialConnectionReceiveWindow != tc.wantConn || clientCfg.MaxConnectionReceiveWindow != tc.wantConn {
				t.Fatalf("client conn window = %d/%d, want %d", clientCfg.InitialConnectionReceiveWindow, clientCfg.MaxConnectionReceiveWindow, tc.wantConn)
			}
			if !clientCfg.DisablePathMTUDiscovery || clientCfg.InitialPacketSize != 1200 {
				t.Fatalf("morph QUIC MTU settings not pinned: DisablePathMTUDiscovery=%v InitialPacketSize=%d", clientCfg.DisablePathMTUDiscovery, clientCfg.InitialPacketSize)
			}
			if clientCfg.AllowConnectionWindowIncrease != nil {
				t.Fatal("client QUIC config unexpectedly set AllowConnectionWindowIncrease")
			}

			gate := newPreAuthGate()
			serverCfg := nowhereV3QUICConfig(false, rt, gate)
			if serverCfg.InitialConnectionReceiveWindow != nwruntime.PreAuthConnWindow {
				t.Fatalf("server pre-auth conn window = %d, want %d", serverCfg.InitialConnectionReceiveWindow, nwruntime.PreAuthConnWindow)
			}
			if serverCfg.MaxConnectionReceiveWindow != tc.wantConn {
				t.Fatalf("server max conn window = %d, want %d", serverCfg.MaxConnectionReceiveWindow, tc.wantConn)
			}
			if serverCfg.AllowConnectionWindowIncrease == nil {
				t.Fatal("server QUIC config missing AllowConnectionWindowIncrease")
			}
			// Verify per-connection isolation on preAuthGate.
			c1 := new(quic.Conn)
			c2 := new(quic.Conn)
			if serverCfg.AllowConnectionWindowIncrease(c1, 1024) {
				t.Fatal("unauthenticated c1 allowed to grow connection window")
			}
			gate.release(c1)
			if !serverCfg.AllowConnectionWindowIncrease(c1, 1024) {
				t.Fatal("authenticated c1 not allowed to grow connection window")
			}
			if serverCfg.AllowConnectionWindowIncrease(c2, 1024) {
				t.Fatal("authenticating c1 leaked window release to c2")
			}
			gate.forget(c1)
			if serverCfg.AllowConnectionWindowIncrease(c1, 1024) {
				t.Fatal("forgotten c1 still marked released")
			}
		})
	}
}

func TestNowhereV3QUICConfigIdleTimeoutFromEnv(t *testing.T) {
	t.Setenv(nwruntime.EnvUDPIdleTimeout, "45s")
	rt, err := nwruntime.Load("", false)
	if err != nil {
		t.Fatalf("runtime.Load: %v", err)
	}
	cfg := nowhereV3QUICConfig(false, rt, nil)
	if cfg.MaxIdleTimeout != 45*time.Second {
		t.Fatalf("MaxIdleTimeout = %v, want 45s", cfg.MaxIdleTimeout)
	}
}

func TestPreAuthGateDoesNotLeakClosedConnAndClearsOnClose(t *testing.T) {
	certPEM, keyPEM, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatalf("NewRandomTLSKeyPair: %v", err)
	}
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	srvPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer srvPC.Close()

	srvTLS := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{wire.ALPN},
	}
	lnCtx, lnCancel := context.WithCancel(context.Background())
	defer lnCancel()
	qlnIface, err := ListenNowhereQUIC(lnCtx, srvPC, srvTLS, nil, nil, "bbr", 32)
	if err != nil {
		t.Fatalf("ListenNowhereQUIC: %v", err)
	}
	qln := qlnIface.(*QIOListener)
	defer qln.Close()

	acceptedCh := make(chan *QIOConn, 1)
	acceptErrCh := make(chan error, 1)
	go func() {
		c, err := qln.Accept(lnCtx)
		if err != nil {
			acceptErrCh <- err
			return
		}
		acceptedCh <- c.(*QIOConn)
	}()

	cliPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client ListenPacket: %v", err)
	}
	defer cliPC.Close()
	cliTLS := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "localhost",
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		NextProtos:         []string{wire.ALPN},
	}
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()
	cliConn, err := quic.Dial(dialCtx, cliPC, srvPC.LocalAddr(), cliTLS, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatalf("quic.Dial: %v", err)
	}

	var srvConn *QIOConn
	select {
	case err := <-acceptErrCh:
		t.Fatalf("Accept: %v", err)
	case srvConn = <-acceptedCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server Accept")
	}

	// Close the connection first, then call ReleasePreAuth: gate must not insert
	// a dead *quic.Conn into released.
	_ = cliConn.CloseWithError(0, "bye")
	_ = srvConn.CloseWithError(0, "bye")
	select {
	case <-srvConn.Context().Done():
	case <-time.After(2 * time.Second):
		t.Fatal("server connection context did not cancel after close")
	}
	srvConn.ReleasePreAuth()

	qln.gate.mu.RLock()
	leaked := len(qln.gate.released)
	qln.gate.mu.RUnlock()
	if leaked != 0 {
		t.Fatalf("preAuthGate retained %d closed connections, want 0", leaked)
	}

	// Verify QIOListener.Close clears any remaining entries in gate.
	qln.gate.mu.Lock()
	qln.gate.released[new(quic.Conn)] = struct{}{}
	qln.gate.mu.Unlock()
	if err := qln.Close(); err != nil {
		t.Fatalf("QIOListener.Close: %v", err)
	}
	qln.gate.mu.RLock()
	remaining := len(qln.gate.released)
	qln.gate.mu.RUnlock()
	if remaining != 0 {
		t.Fatalf("preAuthGate retained %d entries after QIOListener.Close, want 0", remaining)
	}
}

type trackingPacketConn struct {
	net.PacketConn
	closed bool
}

func (c *trackingPacketConn) Close() error {
	c.closed = true
	return nil
}

type fakePacketDialer struct {
	pc net.PacketConn
}

func (d fakePacketDialer) ListenPacket(context.Context, string, string, netip.AddrPort) (net.PacketConn, error) {
	return d.pc, nil
}

func TestNW3MorphPacketDialerClosesSocketOnWrapError(t *testing.T) {
	tracked := &trackingPacketConn{}
	d := &nw3MorphPacketDialer{
		inner: fakePacketDialer{pc: tracked},
		keys:  morph.Keys{Cipher: morph.Cipher(255)},
	}
	if _, err := d.ListenPacket(context.Background(), "udp", "", netip.MustParseAddrPort("127.0.0.1:443")); err == nil {
		t.Fatal("ListenPacket accepted invalid morph cipher")
	}
	if !tracked.closed {
		t.Fatal("inner PacketConn was leaked when morph.WrapPacketConn failed")
	}
}
