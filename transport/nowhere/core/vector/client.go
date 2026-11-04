// Package vector is the Nowhere 3 client. One process uses either TLS or QUIC,
// and the TLS/QUIC handshake offers only ALPN nw3.
package vector

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/transport/nowhere/core/dgram"
	"github.com/metacubex/mihomo/transport/nowhere/core/flowio"
	"github.com/metacubex/mihomo/transport/nowhere/core/morph"
	"github.com/metacubex/mihomo/transport/nowhere/core/qio"
	"github.com/metacubex/mihomo/transport/nowhere/core/wire"
)

// Config opens a Vector. Set DialQUIC for a QUIC carrier; otherwise DialTCP and
// TLS are required. Exactly one carrier is used.
type Config struct {
	SharedKey    string
	Morph        bool
	PortalAddr   string
	TLS          *tls.Config
	DialTCP      func(ctx context.Context, addr string) (net.Conn, error)
	DialQUIC     func(ctx context.Context) (qio.Conn, error)
	UploadMbps   int
	DownloadMbps int
}

// vectorDrainTimeout bounds the drain after the connection-local UDP ids are
// exhausted, before the session is closed and the next dial starts a new one.
const vectorDrainTimeout = 5 * time.Second

// Client opens TCP and UDP flows.
type Client struct {
	creds *wire.Credentials
	keys  *morph.Keys
	cfg   Config
	up    *flowio.Limiter
	down  *flowio.Limiter
	mu    sync.Mutex
	// openMu serializes OpenStream until the authentication stream exists, so
	// the AuthFrame cannot land on a stream other than stream 0.
	openMu   sync.Mutex
	quic     qio.Conn
	router   *dgram.Router
	used0    bool
	draining bool
	cancel   context.CancelFunc
}

// New validates the shared key and carrier selection.
func New(cfg Config) (*Client, error) {
	if err := wire.ValidateServiceKey(cfg.SharedKey); err != nil {
		return nil, err
	}
	creds, err := wire.NewCredentials(cfg.SharedKey)
	if err != nil {
		return nil, err
	}
	if cfg.DialQUIC != nil {
		if cfg.DialTCP != nil {
			return nil, errors.New("nw3: vector requires exactly one carrier")
		}
	} else if cfg.DialTCP == nil || cfg.TLS == nil {
		return nil, errors.New("nw3: vector requires exactly one carrier")
	}
	c := &Client{creds: creds, cfg: cfg, up: flowio.NewMbps(cfg.UploadMbps), down: flowio.NewMbps(cfg.DownloadMbps)}
	if cfg.Morph {
		keys := morph.Derive([]byte(cfg.SharedKey))
		c.keys = &keys
	}
	if cfg.TLS != nil {
		tlsCfg := cfg.TLS.Clone()
		tlsCfg.MinVersion = tls.VersionTLS13
		tlsCfg.MaxVersion = tls.VersionTLS13
		tlsCfg.NextProtos = []string{wire.ALPN}
		tlsCfg.ClientSessionCache = nil
		c.cfg.TLS = tlsCfg
	}
	return c, nil
}

// OpenTCP opens one TCP flow.
func (c *Client) OpenTCP(ctx context.Context, target wire.Target) (net.Conn, error) {
	return c.open(ctx, wire.FlowTCP, target)
}

// OpenUDP opens one UDP association. Each Read/Write is one datagram.
func (c *Client) OpenUDP(ctx context.Context, target wire.Target) (net.Conn, error) {
	return c.open(ctx, wire.FlowUDP, target)
}

// Close releases the QUIC connection, if any.
func (c *Client) Close() error {
	c.mu.Lock()
	conn := c.quic
	cancel := c.cancel
	c.quic = nil
	c.router = nil
	c.cancel = nil
	c.used0 = false
	c.draining = false
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if conn != nil {
		return conn.CloseWithError(0, "")
	}
	return nil
}

func (c *Client) open(ctx context.Context, kind wire.FlowKind, target wire.Target) (net.Conn, error) {
	if c.cfg.DialQUIC != nil {
		return c.openQUIC(ctx, kind, target)
	}
	return c.openTLS(ctx, kind, target)
}

func (c *Client) openTLS(ctx context.Context, kind wire.FlowKind, target wire.Target) (net.Conn, error) {
	raw, err := c.cfg.DialTCP(ctx, c.cfg.PortalAddr)
	if err != nil {
		return nil, err
	}
	if c.keys != nil {
		wrapped, wrapErr := morph.WrapTCPClient(raw, *c.keys)
		if wrapErr != nil {
			_ = raw.Close()
			return nil, wrapErr
		}
		raw = wrapped
	}
	tlsConn := tls.Client(raw, c.cfg.TLS)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	state := tlsConn.ConnectionState()
	exp, err := exportTLS(state)
	if err != nil || state.NegotiatedProtocol != wire.ALPN || state.Version != tls.VersionTLS13 {
		_ = tlsConn.Close()
		if err == nil {
			err = errors.New("nw3: TLS handshake rejected")
		}
		return nil, err
	}
	if err := wire.WriteAuthFrame(tlsConn, c.creds, wire.RoleVector, wire.AuthTLS, exp); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	if err := wire.WriteFlowRequest(tlsConn, kind, target); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	result, err := wire.ReadSetupResult(tlsConn)
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	if result != wire.SetupReady {
		_ = tlsConn.Close()
		return nil, wire.SetupError{Result: result}
	}
	var conn net.Conn = tlsConn
	if kind == wire.FlowUDP {
		conn = &uotConn{Conn: tlsConn}
	}
	return &limitedConn{Conn: conn, up: c.up, down: c.down}, nil
}

func (c *Client) openQUIC(ctx context.Context, kind wire.FlowKind, target wire.Target) (net.Conn, error) {
	conn, router, err := c.session(ctx)
	if err != nil {
		return nil, err
	}
	// A UDP flow needs DATAGRAM support; fail before opening a stream rather
	// than falling back to another carrier. Core forbids that fallback.
	if kind == wire.FlowUDP && conn.MaxDatagramSize() <= 0 {
		return nil, errors.New("nw3: portal does not support UDP DATAGRAMs")
	}

	// Stream 0 is the authentication stream. Serialize opens until it exists so
	// a concurrent opener cannot take stream 0 and put AuthFrame on a later one.
	c.openMu.Lock()
	st, err := conn.OpenStream(ctx)
	if err != nil {
		c.openMu.Unlock()
		return nil, err
	}
	if err := c.authenticate(conn, st); err != nil {
		c.openMu.Unlock()
		_ = st.Close()
		c.failSession()
		return nil, err
	}
	var id uint32
	if kind == wire.FlowUDP {
		id, err = wire.UDPFlowID(st.ID(), false)
		if err != nil {
			c.openMu.Unlock()
			_ = st.Close()
			// The derived ids are exhausted. Stop admitting on this session,
			// drain for a bounded deadline, then close it; the next open dials.
			go c.drainAndDrop(vectorDrainTimeout)
			return nil, err
		}
	}
	c.openMu.Unlock()

	if err := wire.WriteFlowRequest(st, kind, target); err != nil {
		_ = st.Close()
		c.failSession()
		return nil, err
	}
	br := bufio.NewReader(st)
	result, err := wire.ReadSetupResult(br)
	if err != nil {
		_ = st.Close()
		c.failSession()
		return nil, err
	}
	if result != wire.SetupReady {
		_ = st.Close()
		return nil, wire.SetupError{Result: result}
	}
	rw := &streamConn{Reader: br, Stream: st, local: addr("quic-local"), remote: conn.RemoteAddr()}
	if kind == wire.FlowTCP {
		return &limitedConn{Conn: rw, up: c.up, down: c.down}, nil
	}
	flow := router.Register(id)
	done := make(chan struct{})
	pc := &udpConn{PacketConn: &dgram.PacketConn{Router: router, Flow: flow, Done: done}, st: st}
	go func() {
		var b [1]byte
		_, _ = br.Read(b[:])
		_ = pc.Close()
	}()
	return &limitedConn{Conn: pc, up: c.up, down: c.down}, nil
}

// authenticate writes the AuthFrame on the first stream of a session. The
// caller holds openMu, so only the first stream can be stream 0.
func (c *Client) authenticate(conn qio.Conn, st qio.Stream) error {
	c.mu.Lock()
	first := !c.used0
	c.mu.Unlock()
	if !first {
		return nil
	}
	if st.ID() != 0 {
		return errors.New("nw3: authentication stream was not stream 0")
	}
	exp, err := connExporter(conn)
	if err != nil {
		return err
	}
	if err := wire.WriteAuthFrame(st, c.creds, wire.RoleVector, wire.AuthQUIC, exp); err != nil {
		return err
	}
	c.mu.Lock()
	c.used0 = true
	c.mu.Unlock()
	return nil
}

// failSession drops a broken QUIC session so the next open dials again.
func (c *Client) failSession() {
	c.mu.Lock()
	conn := c.quic
	cancel := c.cancel
	c.quic = nil
	c.router = nil
	c.cancel = nil
	c.used0 = false
	c.draining = false
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if conn != nil {
		_ = conn.CloseWithError(0, "session")
	}
}

// drainAndDrop stops admitting on this session, waits out a bounded drain and
// then closes it. A later open dials again and starts new Flows only.
func (c *Client) drainAndDrop(bound time.Duration) {
	c.mu.Lock()
	c.draining = true
	c.mu.Unlock()
	timer := time.NewTimer(bound)
	defer timer.Stop()
	<-timer.C
	c.failSession()
}

func (c *Client) session(ctx context.Context) (qio.Conn, *dgram.Router, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.draining {
		return nil, nil, errors.New("nw3: session draining")
	}
	if c.quic != nil {
		select {
		case <-c.quic.Context().Done():
			if c.cancel != nil {
				c.cancel()
			}
			_ = c.quic.CloseWithError(0, "idle")
			c.quic = nil
			c.router = nil
			c.cancel = nil
			c.used0 = false
			c.draining = false
		default:
			return c.quic, c.router, nil
		}
	}
	conn, err := c.cfg.DialQUIC(ctx)
	if err != nil {
		return nil, nil, err
	}
	if conn.ALPN() != wire.ALPN || conn.TLSVersion() != tls.VersionTLS13 {
		_ = conn.CloseWithError(0, "alpn")
		return nil, nil, errors.New("nw3: QUIC handshake rejected")
	}
	runCtx, cancel := context.WithCancel(context.Background())
	router := dgram.NewRouter(conn)
	go router.Run(runCtx)
	c.quic = conn
	c.router = router
	c.cancel = cancel
	c.used0 = false
	c.draining = false
	return conn, router, nil
}

func exportTLS(state tls.ConnectionState) (wire.Exporter, error) {
	var out wire.Exporter
	b, err := state.ExportKeyingMaterial(wire.ExporterLabel, []byte{}, wire.ExporterLen)
	if err != nil {
		return out, err
	}
	if copy(out[:], b) != wire.ExporterLen {
		return out, errors.New("nw3: short exporter")
	}
	return out, nil
}

func connExporter(conn qio.Conn) (wire.Exporter, error) {
	var out wire.Exporter
	b, err := conn.Exporter()
	if err != nil {
		return out, err
	}
	if copy(out[:], b) != wire.ExporterLen {
		return out, errors.New("nw3: short exporter")
	}
	return out, nil
}

type addr string

func (a addr) Network() string { return "nw3" }
func (a addr) String() string  { return string(a) }

type streamConn struct {
	io.Reader
	qio.Stream
	local, remote net.Addr
}

func (c *streamConn) Read(p []byte) (int, error) { return c.Reader.Read(p) }
func (c *streamConn) LocalAddr() net.Addr        { return c.local }
func (c *streamConn) RemoteAddr() net.Addr       { return c.remote }

type limitedConn struct {
	net.Conn
	up, down *flowio.Limiter
}

func (c *limitedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		_ = c.down.WaitN(context.Background(), n)
	}
	return n, err
}

func (c *limitedConn) Write(p []byte) (int, error) {
	if err := c.up.WaitN(context.Background(), len(p)); err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}

type uotConn struct{ net.Conn }

func (c *uotConn) Read(p []byte) (int, error) {
	pkt, err := wire.ReadUoT(c.Conn)
	if err != nil {
		return 0, err
	}
	n := copy(p, pkt)
	return n, nil
}

func (c *uotConn) Write(p []byte) (int, error) {
	if err := wire.WriteUoT(c.Conn, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

type udpConn struct {
	*dgram.PacketConn
	st qio.Stream
}

func (c *udpConn) Read(p []byte) (int, error) { return c.PacketConn.Read(p) }
func (c *udpConn) Write(p []byte) (int, error) {
	n, err := c.PacketConn.Write(p)
	return n, err
}

func (c *udpConn) Close() error {
	_ = c.PacketConn.Close()
	_ = c.st.Close()
	return nil
}
func (c *udpConn) LocalAddr() net.Addr                { return addr("udp") }
func (c *udpConn) RemoteAddr() net.Addr               { return addr("udp") }
func (c *udpConn) SetDeadline(t time.Time) error      { return c.st.SetDeadline(t) }
func (c *udpConn) SetReadDeadline(t time.Time) error  { return c.st.SetReadDeadline(t) }
func (c *udpConn) SetWriteDeadline(t time.Time) error { return c.st.SetWriteDeadline(t) }

// Ensure limitedConn is a net.Conn at compile time.
var _ net.Conn = (*limitedConn)(nil)
