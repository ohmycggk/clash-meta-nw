package handshake

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"
)

const testKey = "0123456789abcdef0123456789abcdef"

// TestTimeoutDerivedFromKey pins the derivation a Vector and the Portal it
// dials must agree on without configuring it twice.
func TestTimeoutDerivedFromKey(t *testing.T) {
	if got := Timeout(testKey); got != 9100*time.Millisecond {
		t.Fatalf("Timeout(%q) = %v, want 9100ms", testKey, got)
	}
	// Recomputed from the documented formula, so the test does not merely
	// restate the implementation.
	for _, key := range []string{
		testKey,
		"00000000000000000000000000000000",
		"ffffffffffffffffffffffffffffffff",
		"a1b2c3d4e5f60718293a4b5c6d7e8f90",
	} {
		mac := hmac.New(sha256.New, []byte(key))
		_, _ = mac.Write([]byte(timeoutLabel))
		value := binary.BigEndian.Uint64(mac.Sum(nil)[:8])
		want := time.Duration(3000+100*(value%271)) * time.Millisecond
		if got := Timeout(key); got != want {
			t.Fatalf("Timeout(%q) = %v, want %v", key, got, want)
		}
	}
}

// TestTimeoutStaysInsideRange guards the bounds the derivation claims: the 271
// possible values span 3.0s-30.0s in 100ms steps.
func TestTimeoutStaysInsideRange(t *testing.T) {
	for i := 0; i < 512; i++ {
		key := makeKey(i)
		got := Timeout(key)
		if got < 3000*time.Millisecond || got > 30000*time.Millisecond {
			t.Fatalf("Timeout(%q) = %v, want 3s..30s", key, got)
		}
		if remainder := got % (100 * time.Millisecond); remainder != 0 {
			t.Fatalf("Timeout(%q) = %v, want a 100ms step", key, got)
		}
	}
}

// TestTimeoutIsStable checks that the budget is a pure function of the key: the
// same key always yields the same budget, and different keys spread.
func TestTimeoutIsStable(t *testing.T) {
	first := Timeout(makeKey(7))
	for i := 0; i < 32; i++ {
		if got := Timeout(makeKey(7)); got != first {
			t.Fatalf("Timeout is not stable: %v then %v", first, got)
		}
	}
	distinct := 0
	for i := 0; i < 512; i++ {
		if Timeout(makeKey(i)) != first {
			distinct++
		}
	}
	if distinct < 100 {
		t.Fatalf("only %d of 512 keys differ from the reference budget; want spread", distinct)
	}
}

// TestTimeoutFromEnv checks the explicit override. An unusable value is an
// error rather than a silent fallback, so a typo fails at startup.
func TestTimeoutFromEnv(t *testing.T) {
	t.Run("unset derives from the key", func(t *testing.T) {
		t.Setenv("NOW_HANDSHAKE_TIMEOUT", "")
		got, err := TimeoutFromEnv(testKey)
		if err != nil {
			t.Fatal(err)
		}
		if want := Timeout(testKey); got != want {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("explicit value wins and may sit outside the range", func(t *testing.T) {
		t.Setenv("NOW_HANDSHAKE_TIMEOUT", "2m")
		got, err := TimeoutFromEnv(testKey)
		if err != nil {
			t.Fatal(err)
		}
		if got != 2*time.Minute {
			t.Fatalf("got %v, want 2m", got)
		}
	})

	for _, raw := range []string{"0", "-1s", "abc", "5"} {
		t.Run("rejects "+raw, func(t *testing.T) {
			t.Setenv("NOW_HANDSHAKE_TIMEOUT", raw)
			if _, err := TimeoutFromEnv(testKey); err == nil {
				t.Fatalf("NOW_HANDSHAKE_TIMEOUT=%q was accepted", raw)
			}
		})
	}
}

// makeKey derives a distinct 32-hex-character key from an index, so a sweep
// never repeats a key.
func makeKey(i int) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 32)
	for j := range out {
		out[j] = hex[(i+j)&0xf]
	}
	out[0] = hex[i&0xf]
	out[1] = hex[(i>>4)&0xf]
	out[2] = hex[(i>>8)&0xf]
	return string(out)
}
