package adapter

import (
	"strings"
	"testing"
)

// TestParseNowhereProxy drives the public ParseProxy entry point to confirm the
// "nowhere" type is wired into the registry and produces a C.Nowhere proxy.
func TestParseNowhereProxy(t *testing.T) {
	// An omitted ALPN selects Nowhere 3, which requires a 32-hex key.
	mapping := map[string]any{
		"type":     "nowhere",
		"name":     "nw",
		"server":   "example.com",
		"port":     2077,
		"password": "0123456789abcdef0123456789abcdef",
	}
	proxy, err := ParseProxy(mapping)
	if err != nil {
		t.Fatalf("ParseProxy: %v", err)
	}
	if proxy.Type().String() != "Nowhere" {
		t.Fatalf("type = %q, want Nowhere", proxy.Type().String())
	}
	if !proxy.SupportUDP() {
		t.Fatalf("SupportUDP = false, want true when udp key omitted")
	}
	if _, err := ParseProxy(map[string]any{
		"type": "nowhere", "name": "nw", "server": "example.com",
		"port": 2077, "password": "secret",
	}); err == nil {
		t.Fatal("ParseProxy accepted a non-32-hex key on the default Nowhere 3 stack")
	}

	// up/down select the Nowhere 2 carrier matrix and require alpn nw2.
	upDownMapping := map[string]any{
		"type":     "nowhere",
		"name":     "nw-tcp",
		"server":   "example.com",
		"port":     2077,
		"password": "secret",
		"alpn":     []string{"nw2"},
		"up":       "tcp",
		"down":     "tcp",
	}
	if _, err := ParseProxy(upDownMapping); err != nil {
		t.Fatalf("ParseProxy up/down: %v", err)
	}

	// An unknown carrier value must be rejected at parse time.
	badMapping := map[string]any{
		"type": "nowhere", "name": "nw", "server": "example.com",
		"port": 2077, "password": "secret", "alpn": []string{"nw2"},
		"up": "carrier-pigeon", "down": "udp",
	}
	if _, err := ParseProxy(badMapping); err == nil {
		t.Fatalf("ParseProxy accepted invalid carrier")
	}

	// A missing shared secret must be rejected.
	noPasswordMapping := map[string]any{
		"type": "nowhere", "name": "nw", "server": "example.com", "port": 2077,
	}
	if _, err := ParseProxy(noPasswordMapping); err == nil {
		t.Fatalf("ParseProxy accepted missing password")
	}

	// The legacy key/network/net aliases are gone: a mapping that only sets
	// them decodes with an empty password and must be rejected.
	legacyMapping := map[string]any{
		"type": "nowhere", "name": "nw-legacy", "server": "example.com",
		"port": 2077, "key": "secret", "network": "udp",
	}
	if _, err := ParseProxy(legacyMapping); err == nil {
		t.Fatalf("ParseProxy accepted legacy key/network aliases")
	}

	udpDisabledMapping := map[string]any{
		"type": "nowhere", "name": "nw", "server": "example.com",
		"port": 2077, "password": "0123456789abcdef0123456789abcdef", "udp": false,
	}
	udpDisabled, err := ParseProxy(udpDisabledMapping)
	if err != nil {
		t.Fatalf("ParseProxy udp disabled: %v", err)
	}
	if udpDisabled.SupportUDP() {
		t.Fatalf("SupportUDP = true, want false when udp: false")
	}

	mixMapping := map[string]any{
		"type": "nowhere", "name": "nw-mix", "server": "example.com",
		"port": 2077, "password": "secret", "alpn": []string{"nw2"},
		"up": "mix", "down": "mix", "mux": 1,
	}
	// mix is not a carrier since Nowhere 2.2: up/down must be tcp or udp.
	if _, err := ParseProxy(mixMapping); err == nil {
		t.Fatalf("ParseProxy accepted mix carrier")
	} else if !strings.Contains(err.Error(), "must be tcp or udp") {
		t.Fatalf("ParseProxy mix error = %v, want \"must be tcp or udp\"", err)
	}

	morphMapping := map[string]any{
		"type": "nowhere", "name": "nw-morph", "server": "example.com",
		"port": 2077, "password": "secret", "alpn": []string{"nw2"}, "morph": 1,
	}
	if _, err := ParseProxy(morphMapping); err != nil {
		t.Fatalf("ParseProxy morph: %v", err)
	}
	if _, err := ParseProxy(map[string]any{
		"type": "nowhere", "name": "nw-net", "server": "example.com",
		"port": 2077, "password": "secret", "alpn": []string{"nw2"}, "net": "udp",
	}); err == nil {
		t.Fatal("ParseProxy accepted net on the Nowhere 2 stack")
	}
	if _, err := ParseProxy(map[string]any{
		"type": "nowhere", "name": "nw-quic", "server": "example.com",
		"port": 2077, "password": "0123456789abcdef0123456789abcdef", "net": "quic",
	}); err == nil {
		t.Fatal("ParseProxy accepted net quic")
	}

	// Nowhere 3.5 Morph Cipher & Grade extensions: chacha/aes and full/core are
	// valid; invalid values are rejected even when morph is disabled; nw2 rejects
	// both cipher and grade.
	for _, cipher := range []string{"chacha", "aes"} {
		for _, grade := range []string{"full", "core"} {
			for _, netName := range []string{"tcp", "udp"} {
				if _, err := ParseProxy(map[string]any{
					"type": "nowhere", "name": "nw-" + netName + "-" + cipher + "-" + grade, "server": "example.com",
					"port": 2077, "password": "0123456789abcdef0123456789abcdef",
					"net": netName, "cipher": cipher, "grade": grade,
				}); err != nil {
					t.Fatalf("ParseProxy(%s, %s, %s): %v", netName, cipher, grade, err)
				}
			}
		}
	}
	for _, bad := range []map[string]any{
		{
			"type": "nowhere", "name": "nw-bad-cipher", "server": "example.com",
			"port": 2077, "password": "0123456789abcdef0123456789abcdef", "cipher": "AES",
		},
		{
			"type": "nowhere", "name": "nw-bad-cipher-morph-off", "server": "example.com",
			"port": 2077, "password": "0123456789abcdef0123456789abcdef", "morph": false, "cipher": "rc4",
		},
		{
			"type": "nowhere", "name": "nw2-cipher", "server": "example.com",
			"port": 2077, "password": "secret", "alpn": []string{"nw2"}, "cipher": "aes",
		},
		{
			"type": "nowhere", "name": "nw-bad-grade", "server": "example.com",
			"port": 2077, "password": "0123456789abcdef0123456789abcdef", "grade": "CORE",
		},
		{
			"type": "nowhere", "name": "nw-bad-grade-morph-off", "server": "example.com",
			"port": 2077, "password": "0123456789abcdef0123456789abcdef", "morph": false, "grade": "light",
		},
		{
			"type": "nowhere", "name": "nw2-grade", "server": "example.com",
			"port": 2077, "password": "secret", "alpn": []string{"nw2"}, "grade": "core",
		},
		{
			"type": "nowhere", "name": "nw-tcp-bad-pin", "server": "example.com",
			"port": 2077, "password": "0123456789abcdef0123456789abcdef", "net": "tcp", "pin": "not-a-pin",
		},
		{
			"type": "nowhere", "name": "nw-udp-bad-pin", "server": "example.com",
			"port": 2077, "password": "0123456789abcdef0123456789abcdef", "net": "udp", "pin": "not-a-pin",
		},
	} {
		if _, err := ParseProxy(bad); err == nil {
			t.Fatalf("ParseProxy(%v) = nil error, want rejection", bad["name"])
		}
	}
}

func TestParseNowhereProxyPreludeEnvValidation(t *testing.T) {
	base := func(netName string, morph bool) map[string]any {
		return map[string]any{
			"type":     "nowhere",
			"name":     "nw-prelude-" + netName,
			"server":   "example.com",
			"port":     2077,
			"password": "0123456789abcdef0123456789abcdef",
			"net":      netName,
			"morph":    morph,
		}
	}
	t.Run("bad tcp prelude rejects tcp morph only", func(t *testing.T) {
		t.Setenv("NOW_MORPH_TCP_PRELUDE", "bogus")
		if _, err := ParseProxy(base("tcp", true)); err == nil {
			t.Fatal("ParseProxy(tcp, morph=true) accepted invalid NOW_MORPH_TCP_PRELUDE")
		}
		if _, err := ParseProxy(base("tcp", false)); err != nil {
			t.Fatalf("ParseProxy(tcp, morph=false) rejected inactive NOW_MORPH_TCP_PRELUDE: %v", err)
		}
		if _, err := ParseProxy(base("udp", true)); err != nil {
			t.Fatalf("ParseProxy(udp, morph=true) rejected inactive NOW_MORPH_TCP_PRELUDE: %v", err)
		}
	})
	t.Run("bad udp prelude rejects udp morph only", func(t *testing.T) {
		t.Setenv("NOW_MORPH_UDP_PRELUDE", "bogus")
		if _, err := ParseProxy(base("udp", true)); err == nil {
			t.Fatal("ParseProxy(udp, morph=true) accepted invalid NOW_MORPH_UDP_PRELUDE")
		}
		if _, err := ParseProxy(base("udp", false)); err != nil {
			t.Fatalf("ParseProxy(udp, morph=false) rejected inactive NOW_MORPH_UDP_PRELUDE: %v", err)
		}
		if _, err := ParseProxy(base("tcp", true)); err != nil {
			t.Fatalf("ParseProxy(tcp, morph=true) rejected inactive NOW_MORPH_UDP_PRELUDE: %v", err)
		}
	})
}
