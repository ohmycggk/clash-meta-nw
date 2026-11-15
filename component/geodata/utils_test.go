package geodata

import (
	"errors"
	"runtime"
	"sync/atomic"
	"testing"
	"weak"

	"github.com/metacubex/mihomo/component/geodata/router"
)

type fakeGeoLoader struct {
	siteCalls *atomic.Int32
	lastElem  *weak.Pointer[router.Domain]
}

func (f *fakeGeoLoader) LoadIPByPath(string, string) ([]*router.CIDR, error) {
	return nil, errors.New("unused")
}

func (f *fakeGeoLoader) LoadIPByBytes([]byte, string) ([]*router.CIDR, error) {
	return nil, errors.New("unused")
}

func (f *fakeGeoLoader) LoadSiteByPath(_, list string) ([]*router.Domain, error) {
	f.siteCalls.Add(1)
	if list != "cn" {
		return nil, errors.New("not found")
	}
	d1 := &router.Domain{Type: router.Domain_Domain, Value: "example.cn"}
	d2 := &router.Domain{
		Type:  router.Domain_Domain,
		Value: "ads.example.cn",
		Attribute: []*router.Domain_Attribute{
			{Key: "ads", TypedValue: &router.Domain_Attribute_BoolValue{BoolValue: true}},
		},
	}
	if f.lastElem != nil {
		*f.lastElem = weak.Make(d1)
	}
	return []*router.Domain{d1, d2}, nil
}

func (f *fakeGeoLoader) LoadSiteByBytes([]byte, string) ([]*router.Domain, error) {
	return nil, errors.New("unused")
}

// TestLoadGeoSiteMatcherDoesNotRetainRawDomainAST verifies Patch B4:
// loadGeoSiteMatcherListSF has StoreResult == false so the raw []*router.Domain
// protobuf slice is eligible for GC right after compilation, while
// loadGeoSiteMatcherSF (StoreResult == true) still caches compiled DomainMatchers.
func TestLoadGeoSiteMatcherDoesNotRetainRawDomainAST(t *testing.T) {
	if loadGeoSiteMatcherListSF.StoreResult {
		t.Fatal("loadGeoSiteMatcherListSF.StoreResult = true, want false")
	}
	if !loadGeoSiteMatcherSF.StoreResult {
		t.Fatal("loadGeoSiteMatcherSF.StoreResult = false, want true")
	}

	var calls atomic.Int32
	var wp weak.Pointer[router.Domain]
	RegisterGeoDataLoaderImplementationCreator("unit-test-loader", func() LoaderImplementation {
		return &fakeGeoLoader{siteCalls: &calls, lastElem: &wp}
	})
	prevLoader := LoaderName()
	SetLoader("unit-test-loader")
	ClearGeoSiteCache()
	t.Cleanup(func() {
		SetLoader(prevLoader)
		ClearGeoSiteCache()
	})

	var m1 router.DomainMatcher
	func() {
		var err error
		m1, err = LoadGeoSiteMatcher("CN")
		if err != nil {
			t.Fatalf("LoadGeoSiteMatcher(CN): %v", err)
		}
		if !m1.ApplyDomain("www.example.cn") {
			t.Fatal("compiled matcher failed to match www.example.cn")
		}
		if calls.Load() != 1 {
			t.Fatalf("LoadSiteByPath calls = %d, want 1", calls.Load())
		}
	}()

	// Repeated lookup of the same matcher hits loadGeoSiteMatcherSF without re-decoding.
	m1Cached, err := LoadGeoSiteMatcher("cn")
	if err != nil {
		t.Fatalf("cached LoadGeoSiteMatcher(cn): %v", err)
	}
	if m1Cached != m1 {
		t.Fatal("expected compiled DomainMatcher to remain cached in loadGeoSiteMatcherSF")
	}
	if calls.Load() != 1 {
		t.Fatalf("LoadSiteByPath calls after cached hit = %d, want 1", calls.Load())
	}

	// Raw *router.Domain AST must NOT be pinned by loadGeoSiteMatcherListSF.
	for i := 0; i < 10; i++ {
		runtime.GC()
		if wp.Value() == nil {
			break
		}
	}
	if wp.Value() != nil {
		t.Fatal("raw *router.Domain slice remained reachable in loadGeoSiteMatcherListSF")
	}
	if !m1.ApplyDomain("sub.example.cn") {
		t.Fatal("compiled matcher stopped working after raw AST GC")
	}

	// Attribute-filtered variant ("cn@ads") compiles cleanly by re-reading list "cn"
	// rather than holding the full list permanently in RAM.
	mAds, err := LoadGeoSiteMatcher("cn@ads")
	if err != nil {
		t.Fatalf("LoadGeoSiteMatcher(cn@ads): %v", err)
	}
	if !mAds.ApplyDomain("ads.example.cn") || mAds.ApplyDomain("www.example.cn") {
		t.Fatal("attribute-filtered matcher produced wrong result")
	}
	if calls.Load() != 2 {
		t.Fatalf("LoadSiteByPath calls after @ads load = %d, want 2", calls.Load())
	}
}
