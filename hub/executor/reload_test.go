package executor_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/component/geodata/router"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/tunnel"

	"golang.org/x/crypto/curve25519"
	"google.golang.org/protobuf/proto"
)

func generateWGKeyPair(t *testing.T) (privB64, pubB64 string) {
	t.Helper()
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(priv[:]), base64.StdEncoding.EncodeToString(pub)
}

func setupTestHomeWithGeositeAndProviders(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	prevHome := C.Path.HomeDir()
	C.SetHomeDir(dir)
	geodata.ClearGeoSiteCache()
	t.Cleanup(func() {
		executor.Shutdown()
		geodata.ClearGeoSiteCache()
		C.SetHomeDir(prevHome)
	})

	// Build a valid local geosite.dat so GEOSITE rules never touch the network.
	list := &router.GeoSiteList{
		Entry: []*router.GeoSite{
			{
				CountryCode: "CN",
				Domain: []*router.Domain{
					{Type: router.Domain_Domain, Value: "baidu.com"},
					{Type: router.Domain_Domain, Value: "qq.com"},
				},
			},
			{
				CountryCode: "GOOGLE",
				Domain: []*router.Domain{
					{Type: router.Domain_Domain, Value: "google.com"},
					{Type: router.Domain_Domain, Value: "googleapis.com"},
				},
			},
		},
	}
	rawGeo, err := proto.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(C.Path.GeoSite(), rawGeo, 0o644); err != nil {
		t.Fatal(err)
	}

	// File-backed proxy provider containing an anytls outbound (spawns sessionManager goroutine).
	providerYAML := `proxies:
  - name: provider-anytls
    type: anytls
    server: 127.0.0.1
    port: 18443
    password: secret
    skip-cert-verify: true
    udp: true
`
	if err := os.WriteFile(filepath.Join(dir, "prov-proxies.yaml"), []byte(providerYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	rulesetYAML := `payload:
  - '+.example.org'
`
	if err := os.WriteFile(filepath.Join(dir, "prov-rules.yaml"), []byte(rulesetYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestConfigCloseAndParseRollback verifies Patch B3:
// 1. Parsing a config and calling cfg.Close() without ApplyConfig tears down all
//    background goroutines (anytls sessionManager, nw2 CarrierBundle, provider tickers).
// 2. A mid-batch parse failure in parseProxies rolls back already-created proxies.
func TestConfigCloseAndParseRollback(t *testing.T) {
	_ = setupTestHomeWithGeositeAndProviders(t)
	wgPriv, _ := generateWGKeyPair(t)
	_, wgPeerPub := generateWGKeyPair(t)

	runtime.GC()
	time.Sleep(30 * time.Millisecond)
	baseGoroutines := runtime.NumGoroutine()

	validYAML := fmt.Sprintf(`
log-level: silent
proxies:
  - name: atls-1
    type: anytls
    server: 127.0.0.1
    port: 1443
    password: secret
    skip-cert-verify: true
  - name: nw2-1
    type: nowhere
    server: 127.0.0.1
    port: 2443
    password: 0123456789abcdef0123456789abcdef
    alpn: [nw2]
    up: tcp
    down: tcp
    skip-cert-verify: true
  - name: wg-1
    type: wireguard
    server: 127.0.0.1
    port: 51820
    ip: 10.0.0.2/32
    private-key: %s
    public-key: %s
    udp: true
proxy-providers:
  p1:
    type: file
    path: prov-proxies.yaml
    interval: 60
    health-check:
      enable: true
      url: http://127.0.0.1:1/generate_204
      interval: 60
      lazy: true
rule-providers:
  r1:
    type: file
    behavior: domain
    path: prov-rules.yaml
    interval: 60
rules:
  - RULE-SET,r1,atls-1
  - GEOSITE,cn,DIRECT
  - MATCH,nw2-1
`, wgPriv, wgPeerPub)

	for i := 0; i < 10; i++ {
		cfg, err := executor.ParseWithBytes([]byte(validYAML))
		if err != nil {
			t.Fatalf("ParseWithBytes iter %d: %v", i, err)
		}
		if err := cfg.Close(); err != nil {
			t.Fatalf("cfg.Close iter %d: %v", i, err)
		}
	}

	// Partial parse failure: atls-ok and nw2-ok are constructed first, then bad-nw3 fails.
	partialFailYAML := `
log-level: silent
proxies:
  - name: atls-ok
    type: anytls
    server: 127.0.0.1
    port: 1443
    password: secret
    skip-cert-verify: true
  - name: nw2-ok
    type: nowhere
    server: 127.0.0.1
    port: 2443
    password: 0123456789abcdef0123456789abcdef
    alpn: [nw2]
    up: tcp
    down: tcp
    skip-cert-verify: true
  - name: bad-nw3
    type: nowhere
    server: 127.0.0.1
    port: 3443
    password: invalid-uppercase-KEY
`
	for i := 0; i < 10; i++ {
		if _, err := executor.ParseWithBytes([]byte(partialFailYAML)); err == nil {
			t.Fatal("expected ParseWithBytes to fail on invalid nw3 service key")
		}
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && runtime.NumGoroutine() > baseGoroutines+6 {
		runtime.GC()
		time.Sleep(25 * time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > baseGoroutines+6 {
		t.Fatalf("goroutine leak after Config.Close + parse rollback: got %d, baseline %d", got, baseGoroutines)
	}
}

// TestReloadConvergence50Cycles verifies Patches B3 & B4:
// 50 consecutive ParseWithBytes + ApplyConfig cycles with anytls, nowhere (nw2 & nw3),
// initialized wireguard (device + GVisor stack started via ListenPacketContext),
// file-backed ProxyProvider + RuleProvider, and GEOSITE rules converge in both
// runtime.NumGoroutine() and HeapInuse without linear growth, and Shutdown() cleans up.
func TestReloadConvergence50Cycles(t *testing.T) {
	_ = setupTestHomeWithGeositeAndProviders(t)
	wgPriv, _ := generateWGKeyPair(t)
	_, wgPeerPub := generateWGKeyPair(t)

	buildConfig := func(iter int) []byte {
		return []byte(fmt.Sprintf(`
log-level: silent
dns:
  enable: false
proxies:
  - name: atls-%d
    type: anytls
    server: 127.0.0.1
    port: %d
    password: secret
    skip-cert-verify: true
    udp: true
  - name: nw2-%d
    type: nowhere
    server: 127.0.0.1
    port: %d
    password: 0123456789abcdef0123456789abcdef
    alpn: [nw2]
    up: tcp
    down: tcp
    skip-cert-verify: true
    udp: true
  - name: nw3-%d
    type: nowhere
    server: 127.0.0.1
    port: %d
    password: 0f1e2d3c4b5a69788796a5b4c3d2e1f0
    net: udp
    skip-cert-verify: true
    udp: true
  - name: wg-%d
    type: wireguard
    server: 127.0.0.1
    port: 51820
    ip: 10.0.0.2/32
    private-key: %s
    public-key: %s
    udp: true
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - atls-%d
      - nw2-%d
      - nw3-%d
      - wg-%d
    use:
      - p1
proxy-providers:
  p1:
    type: file
    path: prov-proxies.yaml
    interval: 60
    health-check:
      enable: true
      url: http://127.0.0.1:1/generate_204
      interval: 60
      lazy: true
rule-providers:
  r1:
    type: file
    behavior: domain
    path: prov-rules.yaml
    interval: 60
rules:
  - RULE-SET,r1,PROXY
  - GEOSITE,google,PROXY
  - GEOSITE,cn,DIRECT
  - MATCH,PROXY
`, iter, 20000+iter, iter, 21000+iter, iter, 22000+iter, iter, wgPriv, wgPeerPub, iter, iter, iter, iter))
	}

	var warmupGoroutines int
	var warmupHeap uint64

	const totalCycles = 50
	for i := 0; i < totalCycles; i++ {
		cfg, err := executor.ParseWithBytes(buildConfig(i))
		if err != nil {
			t.Fatalf("cycle %d ParseWithBytes: %v", i, err)
		}
		executor.ApplyConfig(cfg, false)

		// Force WireGuard lazy init() so wireguard-go + GVisor worker goroutines
		// are actually running and must be reaped on the next ApplyConfig!
		wgProxy := tunnel.Proxies()[fmt.Sprintf("wg-%d", i)]
		if wgProxy == nil {
			t.Fatalf("cycle %d: missing wg-%d in tunnel.Proxies()", i, i)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		pc, err := wgProxy.ListenPacketContext(ctx, &C.Metadata{
			NetWork: C.UDP,
			DstIP:   netip.MustParseAddr("1.1.1.1"),
			DstPort: 53,
		})
		cancel()
		if err != nil {
			t.Fatalf("cycle %d wg ListenPacketContext: %v", i, err)
		}
		_ = pc.Close()

		if i == 4 {
			runtime.GC()
			runtime.GC()
			time.Sleep(30 * time.Millisecond)
			warmupGoroutines = runtime.NumGoroutine()
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			warmupHeap = ms.HeapInuse
		}
	}

	runtime.GC()
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	endGoroutines := runtime.NumGoroutine()
	var endMS runtime.MemStats
	runtime.ReadMemStats(&endMS)

	// Before Patch B3, 45 extra cycles leaked ~15+ goroutines PER cycle (>650 goroutines!).
	if endGoroutines > warmupGoroutines+20 {
		t.Fatalf("goroutines grew across 50 reloads: cycle 5 = %d, cycle 50 = %d", warmupGoroutines, endGoroutines)
	}
	// Allow bounded allocator fluctuation (< 24 MiB) across 45 cycles under -race.
	const maxHeapGrowth = 24 << 20
	if endMS.HeapInuse > warmupHeap+maxHeapGrowth {
		t.Fatalf("HeapInuse grew excessively across 50 reloads: cycle 5 = %d bytes, cycle 50 = %d bytes", warmupHeap, endMS.HeapInuse)
	}

	executor.Shutdown()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && runtime.NumGoroutine() > warmupGoroutines {
		runtime.GC()
		time.Sleep(25 * time.Millisecond)
	}
	if len(tunnel.Proxies()) != 0 {
		t.Fatalf("tunnel.Proxies() len after Shutdown = %d, want 0", len(tunnel.Proxies()))
	}
}
