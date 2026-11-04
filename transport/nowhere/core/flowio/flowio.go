// Package flowio copies bounded streams and applies optional rate limits.
package flowio

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/metacubex/mihomo/transport/nowhere/core/wire"
)

const copyBuf = 32 << 10

// Limiter is a token bucket in bytes per second. A nil or zero limiter is unlimited.
type Limiter struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

// NewMbps returns a limiter for the given megabits per second. Zero disables it.
func NewMbps(mbps int) *Limiter {
	if mbps <= 0 {
		return nil
	}
	rate := float64(mbps) * 1_000_000 / 8
	return &Limiter{rate: rate, burst: rate, tokens: rate, last: time.Now()}
}

// WaitN blocks until n bytes are allowed or ctx ends.
func (l *Limiter) WaitN(ctx context.Context, n int) error {
	if l == nil || l.rate <= 0 || n <= 0 {
		return nil
	}
	for {
		l.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(l.last).Seconds()
		l.last = now
		l.tokens += elapsed * l.rate
		if l.tokens > l.burst {
			l.tokens = l.burst
		}
		if float64(n) <= l.tokens {
			l.tokens -= float64(n)
			l.mu.Unlock()
			return nil
		}
		need := float64(n) - l.tokens
		wait := time.Duration(need / l.rate * float64(time.Second))
		l.mu.Unlock()
		if wait < time.Millisecond {
			wait = time.Millisecond
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// Relay copies both directions until one side ends, then half-closes the other.
func Relay(left, right io.ReadWriteCloser, leftToRight, rightToLeft *Limiter) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = Copy(right, left, leftToRight)
		closeWrite(right)
	}()
	go func() {
		defer wg.Done()
		_, _ = Copy(left, right, rightToLeft)
		closeWrite(left)
	}()
	wg.Wait()
}

// RelayUoT relays a UDP-over-TCP framed flow between two stream peers. Both ends
// speak the UoT framing, which is what makes the flow symmetric: a Portal talking
// to an Egress over a carrier frames on both sides. Unlike a datagram relay it
// applies no idle deadline, because a stream peer has none of its own: either
// side closing the stream ends the flow. A raw datagram peer must use RelayUoTRaw
// instead: framing it on top of this relay would nest the frames.
func RelayUoT(client, peer io.ReadWriteCloser, clientToPeer, peerToClient *Limiter) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			pkt, err := wire.ReadUoT(client)
			if err != nil {
				break
			}
			_ = clientToPeer.WaitN(context.Background(), len(pkt))
			if err := wire.WriteUoT(peer, pkt); err != nil {
				break
			}
		}
		_ = peer.Close()
	}()
	go func() {
		defer wg.Done()
		for {
			pkt, err := wire.ReadUoT(peer)
			if err != nil {
				break
			}
			_ = peerToClient.WaitN(context.Background(), len(pkt))
			if err := wire.WriteUoT(client, pkt); err != nil {
				break
			}
		}
		closeWrite(client)
	}()
	wg.Wait()
}

// RelayUoTRaw relays a UDP flow between a UoT-framed stream and a raw datagram
// peer. The client side is framed; the peer side moves exactly one datagram per
// Read and per Write. A stream peer must use RelayUoT: this relay does not add
// framing to the peer side, so wrapping a framed peer here would parse a payload
// as a length header.
func RelayUoTRaw(client, peer io.ReadWriteCloser, clientToPeer, peerToClient *Limiter) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			pkt, err := wire.ReadUoT(client)
			if err != nil {
				break
			}
			_ = clientToPeer.WaitN(context.Background(), len(pkt))
			if _, err := peer.Write(pkt); err != nil {
				break
			}
		}
		_ = peer.Close()
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		for {
			n, err := peer.Read(buf)
			if err != nil {
				break
			}
			_ = peerToClient.WaitN(context.Background(), n)
			if err := wire.WriteUoT(client, buf[:n]); err != nil {
				break
			}
		}
		closeWrite(client)
	}()
	wg.Wait()
}

// Copy copies src to dst, optionally rate-limited.
func Copy(dst io.Writer, src io.Reader, lim *Limiter) (int64, error) {
	buf := make([]byte, copyBuf)
	var total int64
	ctx := context.Background()
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			if err := lim.WaitN(ctx, n); err != nil {
				return total, err
			}
			wn, werr := dst.Write(buf[:n])
			total += int64(wn)
			if werr != nil {
				return total, werr
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				return total, nil
			}
			return total, rerr
		}
	}
}

func closeWrite(c io.Closer) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}
