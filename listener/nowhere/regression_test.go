package nowhere

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/transport/nowhere"
)

type stubUDPTunnel struct {
	C.Tunnel
	received atomic.Int32
}

func (t *stubUDPTunnel) HandleUDPPacket(pkt C.UDPPacket, _ *C.Metadata) {
	t.received.Add(1)
	pkt.Drop()
}

// TestV3PacketConnDeadlinesAndServeUDPExit verifies Patch B1:
// 1. v3PacketConn honors read and write deadlines with os.ErrDeadlineExceeded.
// 2. v3Upstream.serveUDP terminates promptly when v3PacketConn.Close() is called.
func TestV3PacketConnDeadlinesAndServeUDPExit(t *testing.T) {
	pipe := newV3PacketPipe()
	conn := pipe.netConn()

	// Past read deadline fails immediately with os.ErrDeadlineExceeded.
	if err := conn.SetReadDeadline(time.Now().Add(-time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	if _, err := conn.Read(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read with past deadline err = %v, want os.ErrDeadlineExceeded", err)
	}

	// Clearing read deadline allows normal Read once data arrives, and future timer expires.
	if err := conn.SetReadDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := conn.Read(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read with 25ms deadline err = %v, want os.ErrDeadlineExceeded", err)
	}
	if time.Since(start) < 15*time.Millisecond {
		t.Fatalf("Read timed out too early: %v", time.Since(start))
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}

	// Fill c.in (capacity 64), then verify SetWriteDeadline unblocks Write.
	for i := 0; i < cap(pipe.in); i++ {
		if _, err := conn.Write([]byte{byte(i)}); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}
	if err := conn.SetWriteDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("overflow")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Write on full pipe err = %v, want os.ErrDeadlineExceeded", err)
	}
	if err := conn.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}

	// Verify serveUDP drains queued packets and exits promptly when conn.Close() runs.
	tun := &stubUDPTunnel{}
	up := &v3Upstream{tunnel: tun}
	done := make(chan struct{})
	go func() {
		defer close(done)
		up.serveUDP(pipe, &C.Metadata{NetWork: C.UDP, Type: C.NOWHERE, DstPort: 53})
	}()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && tun.received.Load() < int32(cap(pipe.in)) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := tun.received.Load(); got != int32(cap(pipe.in)) {
		t.Fatalf("drained %d packets, want %d", got, cap(pipe.in))
	}

	_ = conn.Close()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("serveUDP leaked / did not return within 100ms of v3PacketConn.Close()")
	}
	if _, err := conn.Read(buf); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Read after Close err = %v, want net.ErrClosed", err)
	}
}

// TestNw3ServerTLSConfigsSingleStack verifies Patch B2:
// TCP builds only the stdlib TLS config (quicTLSConfig == nil), while UDP builds
// only the QUIC TLS config and passes an empty shell *crypto/tls.Config to portal.New.
func TestNw3ServerTLSConfigsSingleStack(t *testing.T) {
	dir := t.TempDir()
	prevHome := C.Path.HomeDir()
	C.SetHomeDir(dir)
	t.Cleanup(func() { C.SetHomeDir(prevHome) })

	certPEM, keyPEM, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	if err := os.WriteFile(certPath, []byte(certPEM), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0o600); err != nil {
		t.Fatal(err)
	}

	udpCfg := LC.NowhereServer{Certificate: certPath, PrivateKey: keyPath, Net: nowhere.NowhereNetUDP}
	stdOnUDP, quicOnUDP, err := nw3ServerTLSConfigs(udpCfg, nowhere.NowhereNetUDP)
	if err != nil {
		t.Fatalf("nw3ServerTLSConfigs(udp): %v", err)
	}
	if quicOnUDP == nil || quicOnUDP.GetCertificate == nil {
		t.Fatal("UDP carrier must populate quicTLSConfig.GetCertificate")
	}
	if stdOnUDP == nil || stdOnUDP.GetCertificate != nil || len(stdOnUDP.Certificates) != 0 {
		t.Fatal("UDP carrier must return an empty shell stdtls.Config without stdLoader")
	}
	stdTLSKeyPairCacheMu.Lock()
	_, stdCachedForUDP := stdTLSKeyPairCache[[2]string{certPath, keyPath}]
	stdTLSKeyPairCacheMu.Unlock()
	if stdCachedForUDP {
		t.Fatal("UDP carrier unexpectedly populated stdTLSKeyPairCache")
	}

	tcpCfg := LC.NowhereServer{Certificate: certPath, PrivateKey: keyPath, Net: nowhere.NowhereNetTCP}
	stdOnTCP, quicOnTCP, err := nw3ServerTLSConfigs(tcpCfg, nowhere.NowhereNetTCP)
	if err != nil {
		t.Fatalf("nw3ServerTLSConfigs(tcp): %v", err)
	}
	if quicOnTCP != nil {
		t.Fatal("TCP carrier must leave quicTLSConfig == nil")
	}
	if stdOnTCP == nil || stdOnTCP.GetCertificate == nil {
		t.Fatal("TCP carrier must populate stdtls.Config.GetCertificate")
	}
	_ = quicOnUDP
	_ = stdOnTCP
}

// TestStdTLSKeyPairLoaderSharedCacheReloadAndGC verifies Patch B2:
// identical (certPath, keyPath) pairs share one cache entry & watcher, reload
// updated certificates on disk, and evict cleanly once all loaders are GC'd.
func TestStdTLSKeyPairLoaderSharedCacheReloadAndGC(t *testing.T) {
	dir := t.TempDir()
	prevHome := C.Path.HomeDir()
	C.SetHomeDir(dir)
	t.Cleanup(func() { C.SetHomeDir(prevHome) })

	cert1, key1, fp1, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")
	if err := os.WriteFile(certPath, []byte(cert1), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(key1), 0o600); err != nil {
		t.Fatal(err)
	}
	cacheKey := [2]string{certPath, keyPath}

	func() {
		loaders := make([]func() (*struct{}, error), 0)
		_ = loaders
		l1, err := newStdTLSKeyPairLoader(certPath, keyPath)
		if err != nil {
			t.Fatal(err)
		}
		l2, err := newStdTLSKeyPairLoader(certPath, keyPath)
		if err != nil {
			t.Fatal(err)
		}
		c1, err := l1()
		if err != nil {
			t.Fatal(err)
		}
		c2, err := l2()
		if err != nil {
			t.Fatal(err)
		}
		if c1 != c2 {
			t.Fatal("expected shared *tls.Certificate pointer across identical paths")
		}
		if gotFP := ca.CalculateFingerprint(c1.Certificate[0]); gotFP != fp1 {
			t.Fatalf("initial fingerprint = %s, want %s", gotFP, fp1)
		}

		stdTLSKeyPairCacheMu.Lock()
		_, exists := stdTLSKeyPairCache[cacheKey]
		stdTLSKeyPairCacheMu.Unlock()
		if !exists {
			t.Fatal("expected cacheKey to be present in stdTLSKeyPairCache")
		}

		// Renew certificate on disk and verify fswatch reloads the shared state.
		cert2, key2, fp2, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath, []byte(key2), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(certPath, []byte(cert2), 0o644); err != nil {
			t.Fatal(err)
		}

		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			cur, _ := l1()
			if cur != nil && len(cur.Certificate) > 0 && ca.CalculateFingerprint(cur.Certificate[0]) == fp2 {
				break
			}
			time.Sleep(25 * time.Millisecond)
		}
		cur2, _ := l2()
		if gotFP := ca.CalculateFingerprint(cur2.Certificate[0]); gotFP != fp2 {
			t.Fatalf("reloaded fingerprint = %s, want %s", gotFP, fp2)
		}
	}()

	// All loader closures are now out of scope; GC + AddCleanup must evict cacheKey.
	evicted := false
	for i := 0; i < 20; i++ {
		runtime.GC()
		stdTLSKeyPairCacheMu.Lock()
		_, exists := stdTLSKeyPairCache[cacheKey]
		stdTLSKeyPairCacheMu.Unlock()
		if !exists {
			evicted = true
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	if !evicted {
		t.Fatal("stdTLSKeyPairCache entry was not evicted after all loaders became unreachable")
	}
}
