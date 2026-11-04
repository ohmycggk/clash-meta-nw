package portal

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/transport/nowhere/core/dgram"
	"github.com/metacubex/mihomo/transport/nowhere/core/qio"
)

// Nowhere 3.3 replaced the single-exit rule with one FIFO of registered Egress
// connections that every Vector flow draws from. Claiming a QUIC connection puts
// it straight back at the tail, so it keeps serving further Flows; claiming a
// TLS connection removes it for good, because that carrier carries exactly one
// Flow. Closed and expired entries are discarded on the way past.
const (
	// egressTLSIdleTTL is the fixed standby lifetime of an unclaimed TLS Egress
	// registration. Activity does not renew it, and the Portal and the Egress
	// time it independently.
	egressTLSIdleTTL = 120 * time.Second

	// DefaultEgressTLSMax is the default NOW_PORTAL_TLS_IDLE_MAX.
	DefaultEgressTLSMax = 128
	// MaxEgressTLSMax is the largest accepted NOW_PORTAL_TLS_IDLE_MAX.
	MaxEgressTLSMax = 1023
)

// EgressTLSMaxFromEnv reads NOW_PORTAL_TLS_IDLE_MAX. Unset or empty yields
// DefaultEgressTLSMax; anything outside 1..=MaxEgressTLSMax is rejected so a
// typo fails at startup instead of silently disabling TLS Egress admission.
func EgressTLSMaxFromEnv() (int, error) {
	raw := strings.TrimSpace(os.Getenv("NOW_PORTAL_TLS_IDLE_MAX"))
	if raw == "" {
		return DefaultEgressTLSMax, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid NOW_PORTAL_TLS_IDLE_MAX %q", raw)
	}
	if value < 1 || value > MaxEgressTLSMax {
		return 0, fmt.Errorf("NOW_PORTAL_TLS_IDLE_MAX must be in 1..=%d, got %d", MaxEgressTLSMax, value)
	}
	return value, nil
}

// egressRegistration is one registered Egress connection. A QUIC registration
// carries a datagram router and stays claimable; a TLS registration carries the
// buffered reader that consumed its AuthFrame and is claimable exactly once.
type egressRegistration struct {
	quic   qio.Conn
	tls    net.Conn
	reader *bufio.Reader
	router *dgram.Router

	// standby is the absolute expiry of an unclaimed TLS registration.
	standby time.Time
	// permitHeld reports whether the pending-registration permit taken at
	// accept is still the registration's. Claiming a TLS registration transfers
	// the Flow but releases the permit, so the teardown that follows must not
	// release it again. The flag is guarded by egressRegistry.mu.
	permitHeld bool
	// done is closed by the Flow that claimed a TLS registration.
	done chan struct{}
	// claimed is closed by claim, waking the goroutine that parked this
	// registration. Only TLS registrations wait on it, and claimedClosed keeps
	// the close single-shot.
	claimed       chan struct{}
	claimedClosed bool
}

// egressRegistry is the Portal-wide FIFO of registered Egress connections.
type egressRegistry struct {
	mu    sync.Mutex
	queue []*egressRegistration

	// pending counts the outstanding TLS registration allowance. A permit is
	// taken when a TLS registration is accepted and released exactly once:
	// claiming the registration frees it for the next standby connection, or
	// the teardown of an unclaimed registration frees it when the connection
	// closes. releaseHeld makes the two paths single-shot.
	pending    int
	maxPending int

	// waiters is closed and replaced whenever a registration arrives, which
	// wakes a Vector flow waiting for an exit.
	waiters chan struct{}
}

func newEgressRegistry(maxPending int) *egressRegistry {
	if maxPending < 1 {
		maxPending = DefaultEgressTLSMax
	}
	return &egressRegistry{maxPending: maxPending, waiters: make(chan struct{})}
}

// reserveTLS takes one TLS connection permit. It reports false when the Portal
// already holds maxPending of them, which is the BUSY answer.
func (r *egressRegistry) reserveTLS() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending >= r.maxPending {
		return false
	}
	r.pending++
	return true
}

// releaseHeld returns one TLS connection permit, but only if reg still holds
// it. Claiming a TLS registration clears permitHeld, so a teardown that runs
// after the claim (or a claim that runs after the teardown) cannot release the
// same permit twice.
func (r *egressRegistry) releaseHeld(reg *egressRegistration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !reg.permitHeld {
		return
	}
	reg.permitHeld = false
	r.releasePendingLocked()
}

func (r *egressRegistry) releasePendingLocked() {
	if r.pending > 0 {
		r.pending--
	}
}

// pendingTLS reports how many TLS connection permits are currently held.
func (r *egressRegistry) pendingTLS() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.pending
}

// add appends a registration and returns the channel that claim closes.
func (r *egressRegistry) add(reg *egressRegistration) <-chan struct{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	reg.claimed = make(chan struct{})
	r.queue = append(r.queue, reg)
	close(r.waiters)
	r.waiters = make(chan struct{})
	return reg.claimed
}

// claim removes the head registration and returns it. A QUIC head that is still
// live is rotated to the tail first; a TLS head past its standby TTL is
// dropped. It returns nil when nothing is usable.
//
// Only a TLS registration has a parked goroutine waiting on claimed, and a TLS
// registration leaves the queue when it is claimed, so claimed is closed exactly
// once per TLS registration. A QUIC registration is claimable many times and has
// no waiter, so its claimed channel is never closed here.
func (r *egressRegistry) claim() *egressRegistration {
	r.mu.Lock()
	defer r.mu.Unlock()
	for len(r.queue) > 0 {
		reg := r.queue[0]
		r.queue = append(r.queue[:0], r.queue[1:]...)
		if reg.tls != nil {
			if !time.Now().Before(reg.standby) {
				continue
			}
			if reg.permitHeld {
				reg.permitHeld = false
				r.releasePendingLocked()
			}
			if !reg.claimedClosed {
				reg.claimedClosed = true
				close(reg.claimed)
			}
			return reg
		}
		if reg.quic == nil || reg.quic.Context().Err() != nil {
			continue
		}
		r.queue = append(r.queue, reg)
		return reg
	}
	return nil
}

// remove drops a registration that has not been claimed, which is how a closed
// or expired Egress connection leaves the FIFO.
func (r *egressRegistry) remove(reg *egressRegistration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, entry := range r.queue {
		if entry == reg {
			r.queue = append(r.queue[:i], r.queue[i+1:]...)
			return
		}
	}
}

// wait blocks until a registration can be claimed or ctx ends. It reports nil
// when ctx ends first.
func (r *egressRegistry) wait(ctx context.Context) *egressRegistration {
	for {
		waiters := r.snapshotWaiters()
		if reg := r.claim(); reg != nil {
			return reg
		}
		select {
		case <-ctx.Done():
			return nil
		case <-waiters:
		}
	}
}

func (r *egressRegistry) snapshotWaiters() chan struct{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.waiters
}
