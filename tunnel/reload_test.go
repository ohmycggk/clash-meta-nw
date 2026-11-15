package tunnel

import (
	"sync/atomic"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
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

type mockClosableProxyProvider struct {
	P.ProxyProvider
	proxies    []C.Proxy
	closeCount atomic.Int32
}

func (m *mockClosableProxyProvider) Version() uint32    { return 1 }
func (m *mockClosableProxyProvider) Proxies() []C.Proxy { return m.proxies }
func (m *mockClosableProxyProvider) Close() error {
	m.closeCount.Add(1)
	return nil
}

type mockClosableRuleProvider struct {
	P.RuleProvider
	closeCount atomic.Int32
}

func (m *mockClosableRuleProvider) Close() error {
	m.closeCount.Add(1)
	return nil
}

// TestUpdateProxiesClosesReplacedAndPreservesReused verifies Patch B3 in tunnel:
// 1. Replaced proxies & providers are closed outside configMux.
// 2. Reused proxy/provider instances are NOT closed.
// 3. CompatibleProvider (borrowsProxies == true) does not close borrowed proxies.
// 4. UpdateProxies(nil, nil) closes remaining entries and leaves Proxies() non-nil.
func TestUpdateProxiesClosesReplacedAndPreservesReused(t *testing.T) {
	t.Cleanup(func() {
		UpdateProxies(nil, nil)
		UpdateRules(nil, nil, nil)
	})

	pOld := &mockClosableProxy{name: "old"}
	pKeep := &mockClosableProxy{name: "keep"}
	pdOld := &mockClosableProxyProvider{}
	pdKeep := &mockClosableProxyProvider{}

	UpdateProxies(
		map[string]C.Proxy{"old": pOld, "keep": pKeep},
		map[string]P.ProxyProvider{"old-pd": pdOld, "keep-pd": pdKeep},
	)
	_ = AllProxies()

	pNew := &mockClosableProxy{name: "new"}
	UpdateProxies(
		map[string]C.Proxy{"keep": pKeep, "new": pNew},
		map[string]P.ProxyProvider{"keep-pd": pdKeep},
	)

	if got := pOld.closeCount.Load(); got != 1 {
		t.Fatalf("pOld.closeCount = %d, want 1", got)
	}
	if got := pdOld.closeCount.Load(); got != 1 {
		t.Fatalf("pdOld.closeCount = %d, want 1", got)
	}
	// pKeep was borrowed by compat (now closed) AND reused in newProxies -> must remain open!
	if got := pKeep.closeCount.Load(); got != 0 {
		t.Fatalf("pKeep.closeCount = %d, want 0 (borrowed + reused)", got)
	}
	if got := pdKeep.closeCount.Load(); got != 0 {
		t.Fatalf("pdKeep.closeCount = %d, want 0 (reused)", got)
	}

	// Shutdown path: UpdateProxies(nil, nil) closes everything and keeps Proxies() non-nil.
	UpdateProxies(nil, nil)
	if Proxies() == nil {
		t.Fatal("Proxies() became nil after UpdateProxies(nil, nil)")
	}
	if got := pKeep.closeCount.Load(); got != 1 {
		t.Fatalf("pKeep.closeCount after nil reset = %d, want 1", got)
	}
	if got := pNew.closeCount.Load(); got != 1 {
		t.Fatalf("pNew.closeCount after nil reset = %d, want 1", got)
	}
	if got := pdKeep.closeCount.Load(); got != 1 {
		t.Fatalf("pdKeep.closeCount after nil reset = %d, want 1", got)
	}
}

func TestUpdateRulesClosesReplacedRuleProviders(t *testing.T) {
	t.Cleanup(func() { UpdateRules(nil, nil, nil) })

	rpOld := &mockClosableRuleProvider{}
	rpKeep := &mockClosableRuleProvider{}
	UpdateRules(nil, nil, map[string]P.RuleProvider{"old": rpOld, "keep": rpKeep})

	UpdateRules(nil, nil, map[string]P.RuleProvider{"keep": rpKeep})
	if got := rpOld.closeCount.Load(); got != 1 {
		t.Fatalf("rpOld.closeCount = %d, want 1", got)
	}
	if got := rpKeep.closeCount.Load(); got != 0 {
		t.Fatalf("rpKeep.closeCount = %d, want 0", got)
	}

	UpdateRules(nil, nil, nil)
	if got := rpKeep.closeCount.Load(); got != 1 {
		t.Fatalf("rpKeep.closeCount after nil reset = %d, want 1", got)
	}
}
