// Package handshake derives the transport/authentication budget shared by the
// Portal, the Vector and the Egress. Since Nowhere 3.3 an unset budget is
// derived once from the shared key rather than sampled randomly, so two peers
// agree on the same budget without configuring it twice.
package handshake

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"time"
)

// timeoutLabel is the exact HMAC message Nowhere 3.3 binds into the derived
// transport/authentication budget. It has no suffix and no NUL.
const timeoutLabel = "nowhere/handshake-timeout"

// Timeout is the transport/authentication budget one process applies to every
// connection:
//
//	digest  = HMAC-SHA256(key = SharedKey, data = "nowhere/handshake-timeout")
//	value   = BE64(digest[0..8])
//	timeout = (3000 + 100 * (value % 271)) ms
//
// The key is used as ASCII text bytes, never hex-decoded. The 271 possible
// values span 3.0s-30.0s in 100ms steps. For example the shared key
// 0123456789abcdef0123456789abcdef yields 9100ms.
func Timeout(sharedKey string) time.Duration {
	mac := hmac.New(sha256.New, []byte(sharedKey))
	_, _ = mac.Write([]byte(timeoutLabel))
	value := binary.BigEndian.Uint64(mac.Sum(nil)[:8])
	return time.Duration(3000+100*(value%271)) * time.Millisecond
}

// TimeoutFromEnv resolves the budget, preferring an explicit
// NOW_HANDSHAKE_TIMEOUT. An explicit value must be a positive duration and may
// sit outside the derived range; an unusable value is an error so a typo fails
// at startup instead of silently falling back.
func TimeoutFromEnv(sharedKey string) (time.Duration, error) {
	raw := os.Getenv("NOW_HANDSHAKE_TIMEOUT")
	if raw == "" {
		return Timeout(sharedKey), nil
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid NOW_HANDSHAKE_TIMEOUT %q: %w", raw, err)
	}
	if parsed <= 0 {
		return 0, errors.New("NOW_HANDSHAKE_TIMEOUT must be positive")
	}
	return parsed, nil
}
