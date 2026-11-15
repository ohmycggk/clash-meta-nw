package ca

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

// TestNewTLSKeyPairLoaderSharedCacheReloadAndGC verifies Patch B2 in component/ca:
// multiple callers referencing the same resolved (certPath, keyPath) share one
// cached key pair & fswatch.Watcher, observe live certificate renewals, and
// evict the cache entry + watcher once all loader closures are garbage-collected.
func TestNewTLSKeyPairLoaderSharedCacheReloadAndGC(t *testing.T) {
	dir := t.TempDir()
	prevHome := C.Path.HomeDir()
	C.SetHomeDir(dir)
	t.Cleanup(func() { C.SetHomeDir(prevHome) })

	cert1, key1, fp1, err := NewRandomTLSKeyPair(KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, []byte(cert1), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(key1), 0o600); err != nil {
		t.Fatal(err)
	}
	cacheKey := [2]string{certPath, keyPath}

	func() {
		l1, err := NewTLSKeyPairLoader(certPath, keyPath)
		if err != nil {
			t.Fatal(err)
		}
		l2, err := NewTLSKeyPairLoader("cert.pem", "key.pem") // relative path resolves to same cacheKey
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
			t.Fatal("expected shared *tls.Certificate across identical resolved paths")
		}
		if got := CalculateFingerprint(c1.Certificate[0]); got != fp1 {
			t.Fatalf("fingerprint = %s, want %s", got, fp1)
		}

		tlsKeyPairCacheMu.Lock()
		_, cached := tlsKeyPairCache[cacheKey]
		tlsKeyPairCacheMu.Unlock()
		if !cached {
			t.Fatal("expected cacheKey in tlsKeyPairCache")
		}

		cert2, key2, fp2, err := NewRandomTLSKeyPair(KeyPairTypeP256)
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
			if cur != nil && len(cur.Certificate) > 0 && CalculateFingerprint(cur.Certificate[0]) == fp2 {
				break
			}
			time.Sleep(25 * time.Millisecond)
		}
		cur2, _ := l2()
		if got := CalculateFingerprint(cur2.Certificate[0]); got != fp2 {
			t.Fatalf("reloaded fingerprint = %s, want %s", got, fp2)
		}
	}()

	evicted := false
	for i := 0; i < 20; i++ {
		runtime.GC()
		tlsKeyPairCacheMu.Lock()
		_, cached := tlsKeyPairCache[cacheKey]
		tlsKeyPairCacheMu.Unlock()
		if !cached {
			evicted = true
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	if !evicted {
		t.Fatal("tlsKeyPairCache entry was not evicted after GC")
	}
}
