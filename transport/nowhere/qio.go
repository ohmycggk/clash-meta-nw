package nowhere

import (
	"context"
	stdtls "crypto/tls"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/metacubex/mihomo/transport/nowhere/core/morph"
	"github.com/metacubex/mihomo/transport/nowhere/core/qio"
	nwruntime "github.com/metacubex/mihomo/transport/nowhere/core/runtime"
	"github.com/metacubex/mihomo/transport/nowhere/core/wire"
	"github.com/metacubex/mihomo/transport/tuic/common"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

// NowhereV3MaxDatagramSize is the conservative upper bound the vendored core
// uses when it splits a UDP payload across QUIC DATAGRAM frames. Pinning it
// below quic-go's smallest path-MTU-derived payload limit avoids rejecting the
// first datagram with "DATAGRAM frame too large (maximum: 1163 bytes)". If
// quic-go ever reports a smaller limit via DatagramTooLargeError, QIOConn
// lowers MaxDatagramSize dynamically.
const NowhereV3MaxDatagramSize = 1000

// NowhereV3ExporterLabel and NowhereV3ExporterLen are the TLS exporter
// parameters the vendored stack binds into every nw3 authentication tag.
const (
	NowhereV3ExporterLabel = wire.ExporterLabel
	NowhereV3ExporterLen   = wire.ExporterLen
)

var errNowhereNilTLS = errors.New("nowhere: missing tls config")

// QIOStream adapts *quic.Stream to the vendored qio.Stream. quic-go's Close
// sends FIN and keeps the receive side open, which is exactly CloseWrite; a
// full Close additionally aborts the receive side, like the reference CLI.
type QIOStream struct {
	*quic.Stream
}

var _ qio.Stream = (*QIOStream)(nil)

func (s *QIOStream) CloseWrite() error { return s.Stream.Close() }

func (s *QIOStream) Close() error {
	s.CancelRead(0)
	return s.Stream.Close()
}

func (s *QIOStream) ID() uint64 { return uint64(s.Stream.StreamID()) }

// QIOConn adapts *quic.Conn to the vendored qio.Conn and qio.PreAuth.
type QIOConn struct {
	conn *quic.Conn
	// datagrams records whether the peer negotiated QUIC DATAGRAM support.
	// MaxDatagramSize reports zero when it did not.
	datagrams bool
	// maxData remembers a smaller path payload limit reported by quic-go.
	maxData atomic.Int64
	// releasePreAuth lets a Portal connection's receive window grow past
	// PreAuthConnWindow once AuthFrame succeeds.
	releasePreAuth func()
}

var (
	_ qio.Conn    = (*QIOConn)(nil)
	_ qio.PreAuth = (*QIOConn)(nil)
)

func NewQIOConn(conn *quic.Conn) *QIOConn {
	return newQIOConn(conn, nil)
}

func newQIOConn(conn *quic.Conn, releasePreAuth func()) *QIOConn {
	return &QIOConn{
		conn:           conn,
		datagrams:      conn.ConnectionState().SupportsDatagrams.Remote,
		releasePreAuth: releasePreAuth,
	}
}

// ReleasePreAuth implements qio.PreAuth.
func (c *QIOConn) ReleasePreAuth() {
	if c.releasePreAuth != nil {
		c.releasePreAuth()
	}
}

func (c *QIOConn) TLSVersion() uint16 { return c.conn.ConnectionState().TLS.Version }
func (c *QIOConn) ALPN() string       { return c.conn.ConnectionState().TLS.NegotiatedProtocol }

func (c *QIOConn) Exporter() ([]byte, error) {
	state := c.conn.ConnectionState().TLS
	return (&state).ExportKeyingMaterial(NowhereV3ExporterLabel, []byte{}, NowhereV3ExporterLen)
}

func (c *QIOConn) AcceptStream(ctx context.Context) (qio.Stream, error) {
	stream, err := c.conn.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return &QIOStream{Stream: stream}, nil
}

func (c *QIOConn) OpenStream(ctx context.Context) (qio.Stream, error) {
	stream, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return &QIOStream{Stream: stream}, nil
}

func (c *QIOConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return c.conn.ReceiveDatagram(ctx)
}

func (c *QIOConn) SendDatagram(b []byte) error {
	err := c.conn.SendDatagram(b)
	var tooLarge *quic.DatagramTooLargeError
	if errors.As(err, &tooLarge) && tooLarge.MaxDatagramPayloadSize > 0 {
		c.maxData.Store(tooLarge.MaxDatagramPayloadSize)
	}
	return err
}

func (c *QIOConn) MaxDatagramSize() int {
	if !c.datagrams {
		return 0
	}
	if n := c.maxData.Load(); n > 0 && int(n) < NowhereV3MaxDatagramSize {
		return int(n)
	}
	return NowhereV3MaxDatagramSize
}

func (c *QIOConn) CloseWithError(code uint64, message string) error {
	return c.conn.CloseWithError(quic.ApplicationErrorCode(code), message)
}

func (c *QIOConn) Context() context.Context { return c.conn.Context() }
func (c *QIOConn) RemoteAddr() net.Addr     { return c.conn.RemoteAddr() }

// preAuthGate tracks per-connection authentication state for a Portal QUIC
// listener so unauthenticated peers stay capped at nwruntime.PreAuthConnWindow.
type preAuthGate struct {
	mu       sync.RWMutex
	released map[*quic.Conn]struct{}
}

func newPreAuthGate() *preAuthGate {
	return &preAuthGate{released: make(map[*quic.Conn]struct{})}
}

func (g *preAuthGate) allow(conn *quic.Conn, _ uint64) bool {
	g.mu.RLock()
	_, ok := g.released[conn]
	g.mu.RUnlock()
	return ok
}

func (g *preAuthGate) release(conn *quic.Conn) {
	if conn == nil {
		return
	}
	g.mu.Lock()
	// Checking conn.Context().Err() under g.mu linearizes with forget(conn)
	// invoked by context.AfterFunc: if the connection closed before we lock,
	// we never insert an orphaned entry into released.
	if ctx := conn.Context(); ctx == nil || ctx.Err() == nil {
		g.released[conn] = struct{}{}
	}
	g.mu.Unlock()
}

func (g *preAuthGate) forget(conn *quic.Conn) {
	g.mu.Lock()
	delete(g.released, conn)
	g.mu.Unlock()
}

func (g *preAuthGate) clear() {
	g.mu.Lock()
	for k := range g.released {
		delete(g.released, k)
	}
	g.mu.Unlock()
}

// QIOListener adapts *quic.Listener to the vendored qio.Listener and applies
// the configured congestion controller to every accepted connection, mirroring
// the nw2 listener's quicListenerAdapter.
type QIOListener struct {
	listener             *quic.Listener
	congestionController string
	cwnd                 int
	gate                 *preAuthGate
	stopCtx              func() bool
}

var _ qio.Listener = (*QIOListener)(nil)

func NewQIOListener(listener *quic.Listener, congestionController string, cwnd int) *QIOListener {
	return newQIOListener(listener, congestionController, cwnd, nil, nil)
}

func newQIOListener(listener *quic.Listener, congestionController string, cwnd int, gate *preAuthGate, stopCtx func() bool) *QIOListener {
	return &QIOListener{
		listener:             listener,
		congestionController: congestionController,
		cwnd:                 cwnd,
		gate:                 gate,
		stopCtx:              stopCtx,
	}
}

func (l *QIOListener) Accept(ctx context.Context) (qio.Conn, error) {
	conn, err := l.listener.Accept(ctx)
	if err != nil {
		return nil, err
	}
	common.SetCongestionController(conn, l.congestionController, l.cwnd, "")
	var release func()
	if l.gate != nil {
		gate := l.gate
		release = func() {
			gate.release(conn)
		}
		context.AfterFunc(conn.Context(), func() {
			gate.forget(conn)
		})
	}
	return newQIOConn(conn, release), nil
}

func (l *QIOListener) Close() error {
	if l.stopCtx != nil {
		l.stopCtx()
	}
	if l.gate != nil {
		l.gate.clear()
	}
	return l.listener.Close()
}

// DialNowhereQUIC opens the QUIC carrier for the Vector/Egress client. Morph
// seals the packet socket below QUIC on the host side; the TCP carrier is
// wrapped inside the vendored stack, so only QUIC needs this. The TLS config
// already pins TLS 1.3 and ALPN nw3 with session resumption disabled.
func DialNowhereQUIC(ctx context.Context, packetDialer common.PacketDialer, addr string, tlsConfig *tls.Config, quicConfig *quic.Config, keys *morph.Keys, congestionController string, cwnd int) (qio.Conn, error) {
	if tlsConfig == nil {
		return nil, errNowhereNilTLS
	}
	if quicConfig == nil {
		rt, err := nwruntime.Load("", false)
		if err != nil {
			return nil, err
		}
		quicConfig = nowhereV3QUICConfig(keys != nil, rt, nil)
	}
	dialer := packetDialer
	if keys != nil {
		dialer = &nw3MorphPacketDialer{inner: packetDialer, keys: *keys}
	}
	_, qconn, err := common.DialQuic(ctx, addr, nil, dialer, tlsConfig, quicConfig, common.DialQuicOption{})
	if err != nil {
		return nil, err
	}
	if congestionController != "" || cwnd != 0 {
		common.SetCongestionController(qconn, congestionController, cwnd, "")
	}
	return NewQIOConn(qconn), nil
}

// DialNowhereTLS opens the Nowhere 3 TLS-over-TCP carrier towards a Portal.
// Morph, when enabled, seals the socket below TLS using keys.Cipher and
// keys.Grade. The returned connection is a completed TLS 1.3 session with ALPN
// nw3; the caller still writes its own AuthFrame on top.
func DialNowhereTLS(ctx context.Context, addr string, tlsConfig *stdtls.Config, keys *morph.Keys) (net.Conn, error) {
	if tlsConfig == nil {
		return nil, errNowhereNilTLS
	}
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if keys != nil {
		wrapped, wrapErr := morph.WrapTCPClient(raw, *keys)
		if wrapErr != nil {
			_ = raw.Close()
			return nil, wrapErr
		}
		raw = wrapped
	}
	tlsConn := stdtls.Client(raw, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	state := tlsConn.ConnectionState()
	if state.Version != stdtls.VersionTLS13 || state.NegotiatedProtocol != wire.ALPN {
		_ = tlsConn.Close()
		return nil, errors.New("nowhere: TLS handshake rejected")
	}
	return tlsConn, nil
}

// ListenNowhereQUIC starts the QUIC listener for the Portal. Morph seals the
// listening socket below QUIC when enabled.
func ListenNowhereQUIC(ctx context.Context, packetConn net.PacketConn, tlsConfig *tls.Config, quicConfig *quic.Config, keys *morph.Keys, congestionController string, cwnd int) (qio.Listener, error) {
	if tlsConfig == nil {
		return nil, errNowhereNilTLS
	}
	if keys != nil {
		wrapped, wrapErr := morph.WrapPacketConn(packetConn, *keys, false)
		if wrapErr != nil {
			return nil, wrapErr
		}
		packetConn = wrapped
	}
	var gate *preAuthGate
	if quicConfig == nil {
		rt, err := nwruntime.Load("", false)
		if err != nil {
			return nil, err
		}
		gate = newPreAuthGate()
		quicConfig = nowhereV3QUICConfig(keys != nil, rt, gate)
	}
	// quic.Listen (not ListenEarly): Accept must return connections whose
	// handshake has completed, otherwise the TLS exporter the vendored Portal
	// binds into every auth frame is not yet available.
	listener, err := quic.Listen(packetConn, tlsConfig, quicConfig)
	if err != nil {
		return nil, err
	}
	stopCtx := context.AfterFunc(ctx, func() {
		_ = listener.Close()
	})
	return newQIOListener(listener, congestionController, cwnd, gate, stopCtx), nil
}

// nowhereV3MaxIncomingStreams bounds the streams the peer may open. quic-go maps
// a negative MaxIncomingStreams to zero, which would forbid the peer from
// opening any stream at all, so the bound must be positive.
const nowhereV3MaxIncomingStreams = (1 << 32) - 1

// nowhereV3QUICConfig builds the Nowhere 3.5 QUIC transport config from the
// active runtime memory profile and idle timeout. 0-RTT stays off because the
// vendored stack binds the TLS exporter of a completed handshake into every
// authentication frame.
func nowhereV3QUICConfig(morph bool, rt nwruntime.Settings, gate *preAuthGate) *quic.Config {
	idle := rt.UDPIdleTimeout
	if idle <= 0 {
		idle = nwruntime.DefaultUDPIdleTimeout
	}
	profile := rt.Profile
	if profile.Stream == 0 || profile.Connection == 0 {
		profile = nwruntime.Profile{Name: "throughput", Stream: 4 << 20, Connection: 32 << 20, Send: 32 << 20}
	}
	connWindow := profile.Connection
	if gate != nil {
		connWindow = nwruntime.PreAuthConnWindow
	}
	cfg := &quic.Config{
		EnableDatagrams:                true,
		Allow0RTT:                      false,
		KeepAlivePeriod:                0,
		MaxIdleTimeout:                 idle,
		MaxIncomingStreams:             nowhereV3MaxIncomingStreams,
		MaxIncomingUniStreams:          nowhereV3MaxIncomingStreams,
		InitialStreamReceiveWindow:     profile.Stream,
		MaxStreamReceiveWindow:         profile.Stream,
		InitialConnectionReceiveWindow: connWindow,
		MaxConnectionReceiveWindow:     profile.Connection,
	}
	if gate != nil {
		cfg.AllowConnectionWindowIncrease = gate.allow
	}
	if morph {
		// Morph seals every datagram with a 12-byte nonce below QUIC. Pin the
		// packet size at the QUIC minimum and skip path-MTU discovery so the
		// UDP payload stays inside a 1212-byte path instead of growing to the
		// link MTU and getting IP-fragmented.
		cfg.DisablePathMTUDiscovery = true
		cfg.InitialPacketSize = 1200
	}
	return cfg
}

// nw3MorphPacketDialer seals every packet socket the QUIC client opens with the
// Nowhere 3 Morph transform.
type nw3MorphPacketDialer struct {
	inner common.PacketDialer
	keys  morph.Keys
}

func (d *nw3MorphPacketDialer) ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
	pc, err := d.inner.ListenPacket(ctx, network, address, rAddrPort)
	if err != nil {
		return nil, err
	}
	wrapped, err := morph.WrapPacketConn(pc, d.keys, true)
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	return wrapped, nil
}
