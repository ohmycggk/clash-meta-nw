package provider

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resource"
	C "github.com/metacubex/mihomo/constant"
)

type mockClosableProxy struct {
	C.Proxy
	name       string
	closeCount atomic.Int32
}

func (m *mockClosableProxy) Name() string        { return m.name }
func (m *mockClosableProxy) Type() C.AdapterType { return C.Shadowsocks }
func (m *mockClosableProxy) Close() error {
	m.closeCount.Add(1)
	return nil
}

func TestCompatibleProviderDoesNotCloseBorrowedProxies(t *testing.T) {
	p1 := &mockClosableProxy{name: "borrowed-1"}
	p2 := &mockClosableProxy{name: "borrowed-2"}
	hc := NewHealthCheck([]C.Proxy{p1, p2}, "", 0, 0, true, nil)

	cp, err := NewCompatibleProvider(ReservedName, []C.Proxy{p1, p2}, hc)
	if err != nil {
		t.Fatal(err)
	}
	if err := cp.Close(); err != nil {
		t.Fatal(err)
	}
	if got := p1.closeCount.Load(); got != 0 {
		t.Fatalf("borrowed p1 closed %d times, want 0", got)
	}
	if got := p2.closeCount.Load(); got != 0 {
		t.Fatalf("borrowed p2 closed %d times, want 0", got)
	}
}

func TestOwnedProviderClosesReplacedAndLateProxies(t *testing.T) {
	dir := t.TempDir()
	provFile := filepath.Join(dir, "proxies.yaml")
	if err := os.WriteFile(provFile, []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}

	var batch atomic.Int32
	var created []*mockClosableProxy
	parser := func(_ []byte) ([]C.Proxy, error) {
		id := batch.Add(1)
		p := &mockClosableProxy{name: "owned"}
		_ = id
		created = append(created, p)
		return []C.Proxy{p}, nil
	}

	hc := NewHealthCheck(nil, "", 0, 0, true, nil)
	pp, err := NewProxySetProvider("owned-set", time.Minute, nil, parser, resource.NewFileVehicle(provFile), hc)
	if err != nil {
		t.Fatal(err)
	}
	if err := pp.Initial(); err != nil {
		t.Fatal(err)
	}
	if len(created) != 1 || created[0].closeCount.Load() != 0 {
		t.Fatalf("unexpected initial proxies state: len=%d", len(created))
	}

	// Replace proxies via setProxies -> first proxy must be closed once.
	pReplacement := &mockClosableProxy{name: "replacement"}
	pp.setProxies([]C.Proxy{pReplacement})
	if got := created[0].closeCount.Load(); got != 1 {
		t.Fatalf("replaced proxy closeCount = %d, want 1", got)
	}
	if got := pReplacement.closeCount.Load(); got != 0 {
		t.Fatalf("active replacement closeCount = %d, want 0", got)
	}

	// Close provider -> active replacement must be closed once.
	if err := pp.Close(); err != nil {
		t.Fatal(err)
	}
	if got := pReplacement.closeCount.Load(); got != 1 {
		t.Fatalf("replacement closeCount after Close() = %d, want 1", got)
	}

	// Late async setProxies arriving after Close() must immediately close incoming proxies.
	pLate := &mockClosableProxy{name: "late"}
	pp.setProxies([]C.Proxy{pLate})
	if got := pLate.closeCount.Load(); got != 1 {
		t.Fatalf("late proxy closeCount after closed provider setProxies = %d, want 1", got)
	}
}
