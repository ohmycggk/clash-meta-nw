package nowhere

import (
	stdtls "crypto/tls"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"weak"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/fswatch"
)

type stdTLSKeyPairHandle struct {
	state *atomic.Pointer[stdtls.Certificate]
}

type stdTLSKeyPairCleanup struct {
	key     [2]string
	wp      weak.Pointer[stdTLSKeyPairHandle]
	watcher *fswatch.Watcher
}

var (
	stdTLSKeyPairCacheMu sync.Mutex
	stdTLSKeyPairCache   = make(map[[2]string]weak.Pointer[stdTLSKeyPairHandle])
)

// newStdTLSKeyPairLoader parses a PEM pair once and hands out the same
// certificate for every handshake. The vendored Portal performs its own
// standard-library handshakes, so it cannot use Mihomo's metacubex/tls loader.
// Like ca.NewTLSKeyPairLoader, the pair accepts inline PEM or file paths:
// inline parsing runs first, then the pair loads from disk and is reloaded
// when the files change (certificate renewal rewrites them in place).
// File-backed loaders sharing (certPath, keyPath) share one parsed certificate
// and one fswatch.Watcher until all referencing listeners are garbage-collected.
func newStdTLSKeyPairLoader(certificate, privateKey string) (func() (*stdtls.Certificate, error), error) {
	cert, inlineErr := stdtls.X509KeyPair([]byte(certificate), []byte(privateKey))
	if inlineErr == nil {
		return func() (*stdtls.Certificate, error) {
			return &cert, nil
		}, nil
	}

	certPath := C.Path.Resolve(certificate)
	keyPath := C.Path.Resolve(privateKey)
	if !C.Path.IsSafePath(certPath) {
		return nil, fmt.Errorf("parse certificate failed, maybe format error:%s, or path error: %s", inlineErr.Error(), C.Path.ErrNotSafePath(certPath).Error())
	}
	if !C.Path.IsSafePath(keyPath) {
		return nil, fmt.Errorf("parse certificate failed, maybe format error:%s, or path error: %s", inlineErr.Error(), C.Path.ErrNotSafePath(keyPath).Error())
	}

	cacheKey := [2]string{certPath, keyPath}
	stdTLSKeyPairCacheMu.Lock()
	if wp, ok := stdTLSKeyPairCache[cacheKey]; ok {
		if handle := wp.Value(); handle != nil {
			stdTLSKeyPairCacheMu.Unlock()
			state := handle.state
			return func() (*stdtls.Certificate, error) {
				c := state.Load()
				runtime.KeepAlive(handle)
				return c, nil
			}, nil
		}
		delete(stdTLSKeyPairCache, cacheKey)
	}

	loaded, loadErr := stdtls.LoadX509KeyPair(certPath, keyPath)
	if loadErr != nil {
		stdTLSKeyPairCacheMu.Unlock()
		return nil, fmt.Errorf("parse certificate failed, maybe format error:%s, or path error: %s", inlineErr.Error(), loadErr.Error())
	}

	state := new(atomic.Pointer[stdtls.Certificate])
	state.Store(&loaded)

	var activeWatcher *fswatch.Watcher
	if watcher, err := fswatch.NewWatcher(fswatch.Options{Path: []string{certPath, keyPath}, Callback: func(path string) {
		if newCert, err := stdtls.LoadX509KeyPair(certPath, keyPath); err == nil {
			state.Store(&newCert)
		}
	}}); err == nil {
		if err = watcher.Start(); err == nil {
			activeWatcher = watcher
		} else {
			_ = watcher.Close()
		}
	}

	handle := &stdTLSKeyPairHandle{state: state}
	wp := weak.Make(handle)
	stdTLSKeyPairCache[cacheKey] = wp
	runtime.AddCleanup(handle, func(c stdTLSKeyPairCleanup) {
		if c.watcher != nil {
			_ = c.watcher.Close()
		}
		stdTLSKeyPairCacheMu.Lock()
		if cur, ok := stdTLSKeyPairCache[c.key]; ok && cur == c.wp {
			delete(stdTLSKeyPairCache, c.key)
		}
		stdTLSKeyPairCacheMu.Unlock()
	}, stdTLSKeyPairCleanup{key: cacheKey, wp: wp, watcher: activeWatcher})
	stdTLSKeyPairCacheMu.Unlock()

	return func() (*stdtls.Certificate, error) {
		c := state.Load()
		runtime.KeepAlive(handle)
		return c, nil
	}, nil
}

type pipeDeadline struct {
	mu     sync.Mutex
	timer  *time.Timer
	cancel chan struct{} // Must be non-nil
}

func makePipeDeadline() pipeDeadline {
	return pipeDeadline{cancel: make(chan struct{})}
}

func (d *pipeDeadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil && !d.timer.Stop() {
		<-d.cancel
	}
	d.timer = nil
	closed := isClosedChan(d.cancel)
	if t.IsZero() {
		if closed {
			d.cancel = make(chan struct{})
		}
		return
	}
	if dur := time.Until(t); dur > 0 {
		if closed {
			d.cancel = make(chan struct{})
		}
		cancel := d.cancel
		d.timer = time.AfterFunc(dur, func() { close(cancel) })
		return
	}
	if !closed {
		close(d.cancel)
	}
}

func (d *pipeDeadline) wait() chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cancel
}

func isClosedChan(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

var v3PacketFlowSeq atomic.Uint64

// v3PacketPipe is an in-memory datagram pair: the Nowhere 3 protocol side sees a
// connected net.Conn while the tunnel side sees one C.UDPPacket per datagram.
// Its directions are opposite on the two views — a Write on the protocol side
// hands a user-to-target packet to the tunnel, and a Read takes a
// target-to-user packet the tunnel wrote back.
type v3PacketPipe struct {
	in     chan []byte
	out    chan []byte
	closed chan struct{}
	lAddr  net.Addr

	readDeadline  pipeDeadline
	writeDeadline pipeDeadline

	closeOnce sync.Once
}

func newV3PacketPipe() *v3PacketPipe {
	id := strconv.FormatUint(v3PacketFlowSeq.Add(1), 36)
	return &v3PacketPipe{
		in:            make(chan []byte, 64),
		out:           make(chan []byte, 64),
		closed:        make(chan struct{}),
		lAddr:         N.NewCustomAddr(C.NOWHERE.String(), id, &net.UDPAddr{}),
		readDeadline:  makePipeDeadline(),
		writeDeadline: makePipeDeadline(),
	}
}

// v3PacketConn is the datagram-oriented net.Conn facade the Nowhere 3 Portal and
// Egress upstreams use. One Read/Write moves exactly one packet.
type v3PacketConn struct {
	*v3PacketPipe
}

func (p *v3PacketPipe) netConn() net.Conn {
	return &v3PacketConn{v3PacketPipe: p}
}

func (c *v3PacketConn) Read(b []byte) (int, error) {
	if isClosedChan(c.closed) {
		return 0, net.ErrClosed
	}
	wait := c.readDeadline.wait()
	if isClosedChan(wait) {
		return 0, os.ErrDeadlineExceeded
	}
	select {
	case payload := <-c.out:
		return copy(b, payload), nil
	case <-c.closed:
		return 0, net.ErrClosed
	case <-wait:
		return 0, os.ErrDeadlineExceeded
	}
}

func (c *v3PacketConn) Write(b []byte) (int, error) {
	if isClosedChan(c.closed) {
		return 0, net.ErrClosed
	}
	wait := c.writeDeadline.wait()
	if isClosedChan(wait) {
		return 0, os.ErrDeadlineExceeded
	}
	payload := make([]byte, len(b))
	copy(payload, b)
	select {
	case c.in <- payload:
		return len(b), nil
	case <-c.closed:
		return 0, net.ErrClosed
	case <-wait:
		return 0, os.ErrDeadlineExceeded
	}
}

func (c *v3PacketConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.readDeadline.set(time.Time{})
		c.writeDeadline.set(time.Time{})
	})
	return nil
}

func (c *v3PacketConn) LocalAddr() net.Addr  { return v3PipeAddr{} }
func (c *v3PacketConn) RemoteAddr() net.Addr { return v3PipeAddr{} }

func (c *v3PacketConn) SetDeadline(t time.Time) error {
	c.readDeadline.set(t)
	c.writeDeadline.set(t)
	return nil
}

func (c *v3PacketConn) SetReadDeadline(t time.Time) error  { c.readDeadline.set(t); return nil }
func (c *v3PacketConn) SetWriteDeadline(t time.Time) error { c.writeDeadline.set(t); return nil }

type v3PipeAddr struct{}

func (v3PipeAddr) Network() string { return "nw3" }
func (v3PipeAddr) String() string  { return "nw3" }

// v3Packet adapts one Nowhere 3 datagram to C.UDPPacket. The flow is bound to a
// single target, so WriteBack passes addr through to the pipe, which ignores it.
type v3Packet struct {
	pc       *v3PacketPipe
	data     []byte
	metadata *C.Metadata
}

var _ C.UDPPacketInAddr = (*v3Packet)(nil)

func (p *v3Packet) Data() []byte {
	return p.data
}

func (p *v3Packet) WriteBack(b []byte, _ net.Addr) (int, error) {
	payload := make([]byte, len(b))
	copy(payload, b)
	select {
	case p.pc.out <- payload:
		return len(b), nil
	case <-p.pc.closed:
		return 0, net.ErrClosed
	}
}

func (p *v3Packet) Drop() {}

// LocalAddr returns the flow-scoped address used to isolate NAT table entries
// per Nowhere 3 UDP association.
func (p *v3Packet) LocalAddr() net.Addr {
	return p.pc.lAddr
}

// InAddr returns the address the packet arrived on.
func (p *v3Packet) InAddr() net.Addr {
	return &net.UDPAddr{}
}
