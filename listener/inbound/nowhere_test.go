package inbound_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener"
	"github.com/metacubex/mihomo/listener/inbound"
)

// testNw3Key is a Nowhere 3 service key: exactly 32 lowercase hexadecimal
// characters. The nw2 keys in nowhere_v2_test.go are deliberately not reused here:
// the two stacks have different key rules and must not be mixed.
const testNw3Key = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"

// testNw2Key is a Portal-admissible Nowhere 2 key: 32 lowercase hexadecimal
// characters. It is deliberately longer than the Nowhere 3 rule allows, so it
// doubles as the "wrong length" case for the nw3 validators.
const testNw2Key = "0123456789abcdef0123456789abcdef01234567"

func nw3BaseOption() inbound.BaseOption {
	return inbound.BaseOption{NameStr: "nowhere-nw3", Listen: "127.0.0.1", Port: "0"}
}

func TestParseListenerNowhereALPN(t *testing.T) {
	t.Run("omitted alpn selects nw3", func(t *testing.T) {
		parsed, err := listener.ParseListener(map[string]any{
			"type": "nowhere", "name": "nowhere-nw3", "listen": "127.0.0.1", "port": 0, "password": testNw3Key,
		})
		if err != nil {
			t.Fatalf("ParseListener: %v", err)
		}
		if _, ok := parsed.(*inbound.Nowhere); !ok {
			t.Fatalf("parsed = %T, want *inbound.Nowhere", parsed)
		}
	})
	t.Run("alpn nw3 selects nw3", func(t *testing.T) {
		parsed, err := listener.ParseListener(map[string]any{
			"type": "nowhere", "name": "nowhere-nw3", "listen": "127.0.0.1", "port": 0, "password": testNw3Key,
			"alpn": []string{"nw3"},
		})
		if err != nil {
			t.Fatalf("ParseListener: %v", err)
		}
		if _, ok := parsed.(*inbound.Nowhere); !ok {
			t.Fatalf("parsed = %T, want *inbound.Nowhere", parsed)
		}
	})
	t.Run("alpn nw2 selects nw2", func(t *testing.T) {
		parsed, err := listener.ParseListener(map[string]any{
			"type": "nowhere", "name": "nowhere-nw2", "listen": "127.0.0.1", "port": 0, "password": testNw2Key,
			"alpn": []string{"nw2"},
		})
		if err != nil {
			t.Fatalf("ParseListener: %v", err)
		}
		if _, ok := parsed.(*inbound.Nowhere); ok {
			t.Fatal("parsed = *inbound.Nowhere, want the Nowhere 2 listener")
		}
		if _, ok := parsed.Config().(*inbound.NowhereOption); !ok {
			t.Fatalf("Config() = %T, want *inbound.NowhereOption", parsed.Config())
		}
	})
	t.Run("custom alpn fails", func(t *testing.T) {
		if _, err := listener.ParseListener(map[string]any{
			"type": "nowhere", "name": "nowhere-nw2", "listen": "127.0.0.1", "port": 0, "password": testNw2Key,
			"alpn": []string{"now/1"},
		}); err == nil {
			t.Fatal("ParseListener(now/1) = nil error, want an alpn error")
		}
	})
	t.Run("multiple alpn fails", func(t *testing.T) {
		if _, err := listener.ParseListener(map[string]any{
			"type": "nowhere", "name": "nowhere-bad", "listen": "127.0.0.1", "port": 0, "password": testNw3Key,
			"alpn": []string{"nw2", "nw3"},
		}); err == nil {
			t.Fatal("ParseListener(multiple alpn) = nil error, want an alpn error")
		}
	})
	t.Run("nw2 rejects net", func(t *testing.T) {
		if _, err := listener.ParseListener(map[string]any{
			"type": "nowhere", "name": "nowhere-nw2", "listen": "127.0.0.1", "port": 0, "password": testNw2Key,
			"alpn": []string{"nw2"}, "net": "tcp",
		}); err == nil {
			t.Fatal("ParseListener(nw2 net) = nil error, want a net error")
		}
	})
	t.Run("quic net fails", func(t *testing.T) {
		if _, err := listener.ParseListener(map[string]any{
			"type": "nowhere", "name": "nowhere-nw3", "listen": "127.0.0.1", "port": 0, "password": testNw3Key,
			"net": "quic",
		}); err == nil {
			t.Fatal("ParseListener(net: quic) = nil error, want a net error")
		}
	})
	t.Run("nw3 accepts aes and chacha cipher", func(t *testing.T) {
		for _, cipher := range []string{"chacha", "aes"} {
			parsed, err := listener.ParseListener(map[string]any{
				"type": "nowhere", "name": "nowhere-nw3-" + cipher, "listen": "127.0.0.1", "port": 0,
				"password": testNw3Key, "cipher": cipher,
			})
			if err != nil {
				t.Fatalf("ParseListener(cipher: %s): %v", cipher, err)
			}
			if _, ok := parsed.(*inbound.Nowhere); !ok {
				t.Fatalf("parsed = %T, want *inbound.Nowhere", parsed)
			}
		}
	})
	t.Run("nw3 rejects invalid cipher even with morph off", func(t *testing.T) {
		if _, err := listener.ParseListener(map[string]any{
			"type": "nowhere", "name": "nowhere-nw3-bad-cipher", "listen": "127.0.0.1", "port": 0,
			"password": testNw3Key, "morph": false, "cipher": "AES",
		}); err == nil {
			t.Fatal("ParseListener(cipher: AES, morph: false) = nil error, want cipher error")
		}
	})
	t.Run("nw2 rejects cipher", func(t *testing.T) {
		if _, err := listener.ParseListener(map[string]any{
			"type": "nowhere", "name": "nowhere-nw2", "listen": "127.0.0.1", "port": 0,
			"password": testNw2Key, "alpn": []string{"nw2"}, "cipher": "aes",
		}); err == nil {
			t.Fatal("ParseListener(nw2 cipher) = nil error, want a cipher error")
		}
	})
	t.Run("nowhere-egress validates cipher", func(t *testing.T) {
		if _, err := listener.ParseListener(map[string]any{
			"type": "nowhere-egress", "name": "egress-aes", "server": "127.0.0.1", "server-port": 443,
			"password": testNw3Key, "cipher": "aes",
		}); err != nil {
			t.Fatalf("ParseListener(nowhere-egress aes): %v", err)
		}
		if _, err := listener.ParseListener(map[string]any{
			"type": "nowhere-egress", "name": "egress-bad", "server": "127.0.0.1", "server-port": 443,
			"password": testNw3Key, "morph": false, "cipher": "invalid",
		}); err == nil {
			t.Fatal("ParseListener(nowhere-egress invalid cipher) = nil error, want cipher error")
		}
	})
}

func TestNewNowhereV3RejectsUnsupportedFields(t *testing.T) {
	base := func() *inbound.NowhereOption {
		return &inbound.NowhereOption{BaseOption: nw3BaseOption(), Password: testNw3Key}
	}
	for name, mutate := range map[string]func(*inbound.NowhereOption){
		"key":        func(o *inbound.NowhereOption) { o.Password = "xyz" },
		"key-length": func(o *inbound.NowhereOption) { o.Password = testNw2Key },
		"net":        func(o *inbound.NowhereOption) { o.Net = "quic" },
		"next":       func(o *inbound.NowhereOption) { o.Next = &inbound.NowhereNextOption{} },
		"ech-key":    func(o *inbound.NowhereOption) { o.EchKey = "not-a-real-key" },
		"alpn":       func(o *inbound.NowhereOption) { o.ALPN = []string{"nw2"} },
	} {
		t.Run(name, func(t *testing.T) {
			options := base()
			mutate(options)
			if _, err := inbound.NewNowhere(options); err == nil {
				t.Fatalf("NewNowhere(%s) = nil error, want a rejection", name)
			}
		})
	}
	// Since Nowhere 3.3 the Egress registration handshake exists on TLS as well
	// as QUIC, so an egress Portal is accepted on either net value.
	for _, net := range []string{"", "tcp", "udp"} {
		options := base()
		options.Egress = true
		options.Net = net
		if _, err := inbound.NewNowhere(options); err != nil {
			t.Fatalf("NewNowhere with egress on net %q: %v", net, err)
		}
	}
	// The same fields on Nowhere 2 keep working, because that listener still
	// accepts next chaining, an ECH key and an explicit ALPN.
	options := base()
	options.ALPN = []string{"nw2"}
	if _, err := inbound.NewNowhereV2(options); err != nil {
		t.Fatalf("NewNowhereV2 with nw2 fields: %v", err)
	}
}

func TestNewNowhereEgressValidation(t *testing.T) {
	base := func() *inbound.NowhereEgressOption {
		return &inbound.NowhereEgressOption{
			BaseOption: inbound.BaseOption{NameStr: "nowhere-egress", Listen: "127.0.0.1", Port: "0"},
			Server:     "127.0.0.1", Port: 2080, Password: testNw3Key,
		}
	}
	for name, mutate := range map[string]func(*inbound.NowhereEgressOption){
		"password":   func(o *inbound.NowhereEgressOption) { o.Password = "" },
		"key":        func(o *inbound.NowhereEgressOption) { o.Password = "xyz" },
		"key-length": func(o *inbound.NowhereEgressOption) { o.Password = testNw2Key },
		"server":     func(o *inbound.NowhereEgressOption) { o.Server = "" },
		"port":       func(o *inbound.NowhereEgressOption) { o.Port = 0 },
		"port-range": func(o *inbound.NowhereEgressOption) { o.Port = 70000 },
		"pin":        func(o *inbound.NowhereEgressOption) { o.Pin = "not-a-pin" },
		"net":        func(o *inbound.NowhereEgressOption) { o.Net = "quic" },
	} {
		t.Run(name, func(t *testing.T) {
			options := base()
			mutate(options)
			if _, err := inbound.NewNowhereEgress(options); err == nil {
				t.Fatalf("NewNowhereEgress(%s) = nil error, want a rejection", name)
			}
		})
	}
	// "none" is the Rust sentinel for an omitted sni/pin, and skip-cert-verify
	// is the documented insecure escape hatch.
	options := base()
	options.SNI = "none"
	options.Pin = "none"
	options.SkipCertVerify = true
	if _, err := inbound.NewNowhereEgress(options); err != nil {
		t.Fatalf("NewNowhereEgress with none sentinels: %v", err)
	}
	// Both carriers are accepted; an omitted net is QUIC, the Nowhere 3 default.
	for _, net := range []string{"", "tcp", "udp"} {
		options := base()
		options.Net = net
		built, err := inbound.NewNowhereEgress(options)
		if err != nil {
			t.Fatalf("NewNowhereEgress with net %q: %v", net, err)
		}
		if net == "" && built.Config().(*inbound.NowhereEgressOption).Net != "" {
			t.Fatalf("an omitted net must stay omitted, got %q", built.Config().(*inbound.NowhereEgressOption).Net)
		}
	}
	// The protocol knobs are read when the listener is built, so a typo fails
	// the inbound at startup instead of logging forever from the reconnect loop.
	for name, env := range map[string][2]string{
		"tls-pool-max":      {"NOW_EGRESS_TLS_POOL_MAX", "0"},
		"handshake-timeout": {"NOW_HANDSHAKE_TIMEOUT", "not-a-duration"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(env[0], env[1])
			built, err := inbound.NewNowhereEgress(base())
			if err != nil {
				t.Fatalf("NewNowhereEgress: %v", err)
			}
			if err := built.Listen(newRecordingTunnel()); err == nil {
				_ = built.Close()
				t.Fatalf("Listen accepted %s=%q", env[0], env[1])
			}
		})
	}
}

func TestParseListenerNowhereEgress(t *testing.T) {
	parsed, err := listener.ParseListener(map[string]any{
		"type": "nowhere-egress", "name": "nowhere-egress", "listen": "127.0.0.1", "port": 0,
		"server": "portal.example.com", "server-port": 443, "password": testNw3Key,
		"net": "tcp",
	})
	if err != nil {
		t.Fatalf("ParseListener: %v", err)
	}
	options, ok := parsed.Config().(*inbound.NowhereEgressOption)
	if !ok {
		t.Fatalf("Config() = %T, want *inbound.NowhereEgressOption", parsed.Config())
	}
	if options.Server != "portal.example.com" || options.Port != 443 {
		t.Fatalf("egress portal = %s:%d, want portal.example.com:443", options.Server, options.Port)
	}
	if options.Net != "tcp" {
		t.Fatalf("egress net = %q, want tcp", options.Net)
	}
	if parsed.Address() != "" {
		t.Fatalf("Address() = %q, want empty (the Egress never listens)", parsed.Address())
	}
}

// recordingTunnel echoes every TCP flow and every UDP datagram back to the
// client and records what it saw, so a test can tell which side of an egress
// chain served a flow.
type recordingTunnel struct {
	tcp  chan string
	udp  chan string
	seen chan string
}

func newRecordingTunnel() *recordingTunnel {
	return &recordingTunnel{tcp: make(chan string, 8), udp: make(chan string, 8), seen: make(chan string, 16)}
}

func (r *recordingTunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata) {
	r.record("tcp", metadata)
	defer func() { _ = conn.Close() }()
	_, _ = io.Copy(conn, conn)
}

func (r *recordingTunnel) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) {
	r.record("udp", metadata)
	_, _ = packet.WriteBack(packet.Data(), nil)
}

func (r *recordingTunnel) NatTable() C.NatTable {
	return nil
}

func (r *recordingTunnel) record(kind string, metadata *C.Metadata) {
	select {
	case r.seen <- kind + " " + metadata.String():
	default:
	}
}

// nw3UDPReplyPayload is what a real UDP target answers with in the UDP forwarding
// test.
const nw3UDPReplyPayload = "nowhere nw3 egress reply"

// replyTunnel behaves like a real UDP target: it records every datagram it is
// handed and answers only a payload longer than the 2-byte UoT framing noise.
// A relay that emits framing datagrams therefore cannot receive the reply, and
// the recorded datagrams expose the stray frames.
type replyTunnel struct {
	mu   sync.Mutex
	seen [][]byte
}

func newReplyTunnel() *replyTunnel {
	return &replyTunnel{}
}

func (r *replyTunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata) {
	_ = conn.Close()
}

func (r *replyTunnel) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) {
	data := append([]byte(nil), packet.Data()...)
	r.mu.Lock()
	r.seen = append(r.seen, data)
	r.mu.Unlock()
	if len(data) <= 2 {
		return
	}
	_, _ = packet.WriteBack([]byte(nw3UDPReplyPayload), nil)
}

func (r *replyTunnel) NatTable() C.NatTable { return nil }

func (r *replyTunnel) datagrams() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([][]byte, len(r.seen))
	copy(out, r.seen)
	return out
}

// dialNw3Flow retries one client dial until the Portal can serve it. The Egress
// registration is asynchronous (egress.Run owns its own reconnect loop), so a
// client that starts right after the exit may race the registration and be told
// the flow cannot be dialed. A real client sees the same window, and the retry
// below is what it takes to cross it.
func dialNw3Flow(ctx context.Context, client *outbound.Nowhere, metadata *C.Metadata) (net.Conn, error) {
	for {
		conn, err := client.DialContext(ctx, metadata)
		if err == nil || ctx.Err() != nil {
			return conn, err
		}
		select {
		case <-ctx.Done():
			return nil, err
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// TestNowhereV3EgressForwarding wires the full Nowhere 3 exit chain: a Portal in
// egress mode (QUIC carrier), one Egress client registered to it, and one Vector
// client dialing the Portal. A flow must be served by the Egress side, never by
// the Portal's own tunnel.
func TestNowhereV3EgressForwarding(t *testing.T) {
	portalTunnel := newRecordingTunnel()
	egressTunnel := newRecordingTunnel()

	portal, err := inbound.NewNowhere(&inbound.NowhereOption{
		BaseOption: nw3BaseOption(),
		Password:   testNw3Key,
		Net:        "udp",
		Egress:     true,
	})
	if err != nil {
		t.Fatalf("NewNowhere egress portal: %v", err)
	}
	if err := portal.Listen(portalTunnel); err != nil {
		t.Fatalf("portal Listen: %v", err)
	}
	defer func() { _ = portal.Close() }()
	_, portalPortStr, err := net.SplitHostPort(portal.Address())
	if err != nil {
		t.Fatalf("portal address %q: %v", portal.Address(), err)
	}
	portalPort, err := strconv.Atoi(portalPortStr)
	if err != nil {
		t.Fatalf("portal port %q: %v", portalPortStr, err)
	}

	egress, err := inbound.NewNowhereEgress(&inbound.NowhereEgressOption{
		BaseOption: inbound.BaseOption{NameStr: "nowhere-egress-test", Listen: "127.0.0.1", Port: "0"},
		Server:     "127.0.0.1", Port: portalPort, Password: testNw3Key,
		SkipCertVerify: true,
	})
	if err != nil {
		t.Fatalf("NewNowhereEgress: %v", err)
	}
	if err := egress.Listen(egressTunnel); err != nil {
		t.Fatalf("egress Listen: %v", err)
	}
	defer func() { _ = egress.Close() }()

	client, err := outbound.NewNowhere(outbound.NowhereOption{
		Name: "nowhere-nw3-egress-client", Server: "127.0.0.1", Port: portalPort,
		Password: testNw3Key, SkipCertVerify: true,
		Net: "udp", UDP: true,
	})
	if err != nil {
		t.Fatalf("NewNowhere client: %v", err)
	}
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := dialNw3Flow(ctx, client, &C.Metadata{Host: "example.com", DstPort: 80})
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	payload := []byte("nowhere nw3 egress echo")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("echo = %q, want %q", buf, payload)
	}

	select {
	case seen := <-egressTunnel.seen:
		if got := seen[:4]; got != "tcp " {
			t.Fatalf("egress tunnel saw %q, want a tcp flow", seen)
		}
	default:
		t.Fatal("egress tunnel served no flow")
	}
	select {
	case seen := <-portalTunnel.seen:
		t.Fatalf("portal tunnel served a flow it should have bridged: %q", seen)
	default:
	}
}

// TestNowhereV3EgressMultipleExits checks the Nowhere 3.3 exit rule. The
// single-exit cap is gone: every registered Egress joins one FIFO, and a QUIC
// registration is put back at the tail after each Flow so it keeps serving.
// Several exits therefore share the load, and losing one leaves the others
// serving.
func TestNowhereV3EgressMultipleExits(t *testing.T) {
	portalTunnel := newRecordingTunnel()
	ownerTunnel := newRecordingTunnel()
	waiterTunnel := newRecordingTunnel()

	portal, err := inbound.NewNowhere(&inbound.NowhereOption{
		BaseOption: nw3BaseOption(),
		Password:   testNw3Key,
		Net:        "udp",
		Egress:     true,
	})
	if err != nil {
		t.Fatalf("NewNowhere egress portal: %v", err)
	}
	if err := portal.Listen(portalTunnel); err != nil {
		t.Fatalf("portal Listen: %v", err)
	}
	defer func() { _ = portal.Close() }()
	portalPort := nw3PortalPort(t, portal.Address())

	client, err := outbound.NewNowhere(outbound.NowhereOption{
		Name: "nowhere-nw3-multi-client", Server: "127.0.0.1", Port: portalPort,
		Password: testNw3Key, SkipCertVerify: true,
		Net: "udp", UDP: true,
	})
	if err != nil {
		t.Fatalf("NewNowhere client: %v", err)
	}
	defer func() { _ = client.Close() }()

	owner, err := newNw3TestEgress(t, "nw3-egress-multi-owner", portalPort, ownerTunnel)
	if err != nil {
		t.Fatalf("NewNowhereEgress owner: %v", err)
	}
	defer func() { _ = owner.Close() }()
	if err := echoOneFlowOn(t, client, ownerTunnel, "owner alone"); err != nil {
		t.Fatalf("flow with the owner alone: %v", err)
	}

	// A second exit is accepted, not told the exit is taken: since 3.3 there is
	// no single owner to preempt.
	waiter, err := newNw3TestEgress(t, "nw3-egress-multi-waiter", portalPort, waiterTunnel)
	if err != nil {
		t.Fatalf("NewNowhereEgress waiter: %v", err)
	}
	defer func() { _ = waiter.Close() }()

	// The waiter registers asynchronously, so drive flows until the FIFO has
	// handed at least one to each exit. A fixed number of flows would race the
	// registration; the deadline bounds the wait.
	served := map[*recordingTunnel]int{ownerTunnel: 0, waiterTunnel: 0}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && (served[ownerTunnel] == 0 || served[waiterTunnel] == 0) {
		tunnel, err := echoOneFlowAny(t, client, "shared", ownerTunnel, waiterTunnel)
		if err != nil {
			t.Fatalf("shared flow: %v", err)
		}
		served[tunnel]++
	}
	if served[ownerTunnel] == 0 || served[waiterTunnel] == 0 {
		t.Fatalf("the FIFO starved an exit: owner served %d, waiter served %d",
			served[ownerTunnel], served[waiterTunnel])
	}
	if got := drainTunnelSeen(portalTunnel); got != "" {
		t.Fatalf("the portal tunnel served %q, want nothing", got)
	}

	// Losing one exit leaves the other serving on its own.
	if err := owner.Close(); err != nil {
		t.Fatalf("owner Close: %v", err)
	}
	if err := echoOneFlowOn(t, client, waiterTunnel, "after handover"); err != nil {
		t.Fatalf("flow after handover: %v", err)
	}
}

// TestNowhereV3EgressTLSShared checks that a TLS-carrier Egress serves a flow
// and that its single-Flow registration is replaced afterwards, so a second TLS
// exit can register once the first Flow has released the pending allowance. The
// pending-cap accounting itself is pinned by the portal registry unit tests.
func TestNowhereV3EgressTLSShared(t *testing.T) {
	t.Setenv("NOW_PORTAL_TLS_IDLE_MAX", "1")
	portalTunnel := newRecordingTunnel()
	ownerTunnel := newRecordingTunnel()

	portal, err := inbound.NewNowhere(&inbound.NowhereOption{
		BaseOption: nw3BaseOption(),
		Password:   testNw3Key,
		Net:        "tcp",
		Egress:     true,
	})
	if err != nil {
		t.Fatalf("NewNowhere tls egress portal: %v", err)
	}
	if err := portal.Listen(portalTunnel); err != nil {
		t.Fatalf("portal Listen: %v", err)
	}
	defer func() { _ = portal.Close() }()
	portalPort := nw3PortalPort(t, portal.Address())

	client, err := outbound.NewNowhere(outbound.NowhereOption{
		Name: "nowhere-nw3-tls-client", Server: "127.0.0.1", Port: portalPort,
		Password: testNw3Key, SkipCertVerify: true,
		Net: "tcp",
	})
	if err != nil {
		t.Fatalf("NewNowhere client: %v", err)
	}
	defer func() { _ = client.Close() }()

	owner, err := newNw3TestEgressNet(t, "nw3-egress-tls-owner", portalPort, ownerTunnel, "tcp")
	if err != nil {
		t.Fatalf("NewNowhereEgress owner: %v", err)
	}
	defer func() { _ = owner.Close() }()
	if err := echoOneFlowOn(t, client, ownerTunnel, "tls owner alone"); err != nil {
		t.Fatalf("flow with the owner alone: %v", err)
	}

	// The owner's Flow has ended, so its permit is free again and the second
	// exit is accepted rather than told the pending set is full. With the
	// pending cap at one, the two supervisors race to refill the single pending
	// slot, so the next Flow may be served by either exit; both are valid.
	waiterTunnel := newRecordingTunnel()
	waiter, err := newNw3TestEgressNet(t, "nw3-egress-tls-waiter", portalPort, waiterTunnel, "tcp")
	if err != nil {
		t.Fatalf("NewNowhereEgress waiter: %v", err)
	}
	defer func() { _ = waiter.Close() }()
	if _, err := echoOneFlowAny(t, client, "tls shared", ownerTunnel, waiterTunnel); err != nil {
		t.Fatalf("flow with both exits: %v", err)
	}
}

// TestNowhereV3EgressUDPForwarding exercises one UDP request/response flow
// across both Egress carriers. The target only answers a real payload, so a
// relay that doubles the UoT framing is caught: the client times out and the
// target reports the stray framing datagrams.
func TestNowhereV3EgressUDPForwarding(t *testing.T) {
	for _, carrier := range []string{"udp", "tcp"} {
		t.Run(carrier, func(t *testing.T) {
			portalTunnel := newRecordingTunnel()
			portal, err := inbound.NewNowhere(&inbound.NowhereOption{
				BaseOption: nw3BaseOption(),
				Password:   testNw3Key,
				Net:        carrier,
				Egress:     true,
			})
			if err != nil {
				t.Fatalf("NewNowhere egress portal: %v", err)
			}
			if err := portal.Listen(portalTunnel); err != nil {
				t.Fatalf("portal Listen: %v", err)
			}
			defer func() { _ = portal.Close() }()
			portalPort := nw3PortalPort(t, portal.Address())

			client, err := outbound.NewNowhere(outbound.NowhereOption{
				Name: "nowhere-nw3-udp-" + carrier, Server: "127.0.0.1", Port: portalPort,
				Password: testNw3Key, SkipCertVerify: true,
				Net: carrier, UDP: true,
			})
			if err != nil {
				t.Fatalf("NewNowhere client: %v", err)
			}
			defer func() { _ = client.Close() }()

			tunnel := newReplyTunnel()
			egress, err := inbound.NewNowhereEgress(&inbound.NowhereEgressOption{
				BaseOption: inbound.BaseOption{NameStr: "nw3-udp-egress-" + carrier, Listen: "127.0.0.1", Port: "0"},
				Server:     "127.0.0.1", Port: portalPort, Password: testNw3Key,
				Net: carrier, SkipCertVerify: true,
			})
			if err != nil {
				t.Fatalf("NewNowhereEgress: %v", err)
			}
			if err := egress.Listen(tunnel); err != nil {
				t.Fatalf("egress Listen: %v", err)
			}
			defer func() { _ = egress.Close() }()

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			pc, err := client.ListenPacketContext(ctx, &C.Metadata{Host: "example.com", DstPort: 53})
			if err != nil {
				t.Fatalf("open udp flow: %v", err)
			}
			defer func() { _ = pc.Close() }()
			_ = pc.SetReadDeadline(time.Now().Add(10 * time.Second))

			payload := []byte("nowhere nw3 egress udp")
			if _, err := pc.WriteTo(payload, nil); err != nil {
				t.Fatalf("udp write: %v", err)
			}
			buf := make([]byte, 256)
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				t.Fatalf("udp read: %v (target saw %q)", err, tunnel.datagrams())
			}
			if string(buf[:n]) != nw3UDPReplyPayload {
				t.Fatalf("udp read %q from %v, want %q", buf[:n], from, nw3UDPReplyPayload)
			}
			seen := tunnel.datagrams()
			if len(seen) != 1 || string(seen[0]) != string(payload) {
				t.Fatalf("target saw %q, want only the %q payload", seen, payload)
			}
		})
	}
}

// TestCleanupReleasesNowhereEgress guards the shutdown path. An Egress holds a
// live QUIC session to its Portal, and only closing the listener sends the
// CONNECTION_CLOSE that releases the registration. Without it a stopped Egress
// leaves a dead entry at its place in the Portal's FIFO (until a claim discards
// it), so the test also checks that a replacement exit serves the next flow.
func TestCleanupReleasesNowhereEgress(t *testing.T) {
	portalTunnel := newRecordingTunnel()
	ownerTunnel := newRecordingTunnel()
	waiterTunnel := newRecordingTunnel()

	portal, err := inbound.NewNowhere(&inbound.NowhereOption{
		BaseOption: nw3BaseOption(),
		Password:   testNw3Key,
		Net:        "udp",
		Egress:     true,
	})
	if err != nil {
		t.Fatalf("NewNowhere egress portal: %v", err)
	}
	if err := portal.Listen(portalTunnel); err != nil {
		t.Fatalf("portal Listen: %v", err)
	}
	defer func() { _ = portal.Close() }()
	portalPort := nw3PortalPort(t, portal.Address())

	// Registered the way the config path registers it, so Cleanup can find it.
	owner, err := inbound.NewNowhereEgress(&inbound.NowhereEgressOption{
		BaseOption: inbound.BaseOption{NameStr: "nw3-egress-shutdown", Listen: "127.0.0.1", Port: "0"},
		Server:     "127.0.0.1", Port: portalPort, Password: testNw3Key,
		SkipCertVerify: true,
	})
	if err != nil {
		t.Fatalf("NewNowhereEgress owner: %v", err)
	}
	listener.PatchInboundListeners(map[string]C.InboundListener{"nw3-egress-shutdown": owner}, ownerTunnel, false)
	t.Cleanup(func() { _ = owner.Close() })

	client, err := outbound.NewNowhere(outbound.NowhereOption{
		Name: "nowhere-nw3-shutdown-client", Server: "127.0.0.1", Port: portalPort,
		Password: testNw3Key, SkipCertVerify: true,
		Net: "udp", UDP: true,
	})
	if err != nil {
		t.Fatalf("NewNowhere client: %v", err)
	}
	defer func() { _ = client.Close() }()

	if err := echoOneFlow(t, client, ownerTunnel, "before shutdown"); err != nil {
		t.Fatalf("flow before shutdown: %v", err)
	}

	listener.Cleanup()

	// The exit must be free now: a fresh Egress registers without being told the
	// exit is taken, and serves the next flow.
	waiter, err := newNw3TestEgress(t, "nw3-egress-shutdown-waiter", portalPort, waiterTunnel)
	if err != nil {
		t.Fatalf("NewNowhereEgress waiter: %v", err)
	}
	defer func() { _ = waiter.Close() }()
	if err := echoOneFlow(t, client, waiterTunnel, "after shutdown"); err != nil {
		t.Fatalf("flow after shutdown: %v", err)
	}
}

func newNw3TestEgress(t *testing.T, name string, portalPort int, tunnel *recordingTunnel) (*inbound.NowhereEgress, error) {
	t.Helper()
	return newNw3TestEgressNet(t, name, portalPort, tunnel, "")
}

// newNw3TestEgressNet builds a test Egress on an explicit carrier. An empty
// carrier keeps the QUIC default.
func newNw3TestEgressNet(t *testing.T, name string, portalPort int, tunnel *recordingTunnel, net string) (*inbound.NowhereEgress, error) {
	t.Helper()
	egress, err := inbound.NewNowhereEgress(&inbound.NowhereEgressOption{
		BaseOption: inbound.BaseOption{NameStr: name, Listen: "127.0.0.1", Port: "0"},
		Server:     "127.0.0.1", Port: portalPort, Password: testNw3Key,
		Net:            net,
		SkipCertVerify: true,
	})
	if err != nil {
		return nil, err
	}
	if err := egress.Listen(tunnel); err != nil {
		_ = egress.Close()
		return nil, err
	}
	return egress, nil
}

func nw3PortalPort(t *testing.T, address string) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("portal address %q: %v", address, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("portal port %q: %v", portStr, err)
	}
	return port
}

// echoOneFlow dials one flow and expects the echo to come back, then reports
// which tunnel served it. The dial retries because an exit registration is
// asynchronous and the handover above leaves a cooldown window.
func echoOneFlow(t *testing.T, client *outbound.Nowhere, tunnel *recordingTunnel, stage string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := dialNw3Flow(ctx, client, &C.Metadata{Host: "example.com", DstPort: 80})
	if err != nil {
		return fmt.Errorf("dial %s: %w", stage, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	payload := []byte("nowhere nw3 egress " + stage)
	if _, err := conn.Write(payload); err != nil {
		return fmt.Errorf("write %s: %w", stage, err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("read %s: %w", stage, err)
	}
	if string(buf) != string(payload) {
		return fmt.Errorf("echo %s = %q, want %q", stage, buf, payload)
	}

	select {
	case seen := <-tunnel.seen:
		if got := seen[:4]; got != "tcp " {
			return fmt.Errorf("%s tunnel saw %q, want a tcp flow", stage, seen)
		}
	default:
		return fmt.Errorf("%s tunnel served no flow", stage)
	}
	return nil
}

// echoOneFlowOn dials one flow and requires the named tunnel to serve it.
func echoOneFlowOn(t *testing.T, client *outbound.Nowhere, tunnel *recordingTunnel, stage string) error {
	t.Helper()
	_, err := echoOneFlowAny(t, client, stage, tunnel)
	return err
}

// echoOneFlowAny dials one flow and accepts any of the given tunnels as the
// server, reporting which one served it.
func echoOneFlowAny(t *testing.T, client *outbound.Nowhere, stage string, tunnels ...*recordingTunnel) (*recordingTunnel, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := dialNw3Flow(ctx, client, &C.Metadata{Host: "example.com", DstPort: 80})
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", stage, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	payload := []byte("nowhere nw3 egress " + stage)
	if _, err := conn.Write(payload); err != nil {
		return nil, fmt.Errorf("write %s: %w", stage, err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, fmt.Errorf("read %s: %w", stage, err)
	}
	if string(buf) != string(payload) {
		return nil, fmt.Errorf("echo %s = %q, want %q", stage, buf, payload)
	}

	for _, tunnel := range tunnels {
		select {
		case seen := <-tunnel.seen:
			if got := seen[:4]; got != "tcp " {
				return nil, fmt.Errorf("%s tunnel saw %q, want a tcp flow", stage, seen)
			}
			return tunnel, nil
		default:
		}
	}
	return nil, fmt.Errorf("%s: no tunnel served the flow", stage)
}

func drainTunnelSeen(tunnel *recordingTunnel) string {
	select {
	case seen := <-tunnel.seen:
		return seen
	default:
		return ""
	}
}

// TestNowhereV3EgressAESForwarding exercises the full Portal (egress: true) +
// Egress + Vector trio under Nowhere 3.4 Morph AES-128-CTR on both TCP (TLS,
// verifying morph.WrapTCPClient inside core/egress) and UDP (QUIC).
func TestNowhereV3EgressAESForwarding(t *testing.T) {
	for _, netName := range []string{"tcp", "udp"} {
		t.Run(netName, func(t *testing.T) {
			portalTunnel := newRecordingTunnel()
			egressTunnel := newRecordingTunnel()

			portal, err := inbound.NewNowhere(&inbound.NowhereOption{
				BaseOption: nw3BaseOption(),
				Password:   testNw3Key,
				Net:        netName,
				Egress:     true,
				Cipher:     "aes",
			})
			if err != nil {
				t.Fatalf("NewNowhere portal(%s): %v", netName, err)
			}
			if err := portal.Listen(portalTunnel); err != nil {
				t.Fatalf("portal Listen(%s): %v", netName, err)
			}
			defer func() { _ = portal.Close() }()
			portalPort := nw3PortalPort(t, portal.Address())

			egress, err := inbound.NewNowhereEgress(&inbound.NowhereEgressOption{
				BaseOption:     inbound.BaseOption{NameStr: "nw3-egress-aes-" + netName, Listen: "127.0.0.1", Port: "0"},
				Server:         "127.0.0.1",
				Port:           portalPort,
				Password:       testNw3Key,
				Net:            netName,
				Cipher:         "aes",
				SkipCertVerify: true,
			})
			if err != nil {
				t.Fatalf("NewNowhereEgress(%s): %v", netName, err)
			}
			if err := egress.Listen(egressTunnel); err != nil {
				_ = egress.Close()
				t.Fatalf("egress Listen(%s): %v", netName, err)
			}
			defer func() { _ = egress.Close() }()

			client, err := outbound.NewNowhere(outbound.NowhereOption{
				Name:           "nw3-vector-aes-" + netName,
				Server:         "127.0.0.1",
				Port:           portalPort,
				Password:       testNw3Key,
				Net:            netName,
				Cipher:         "aes",
				SkipCertVerify: true,
				UDP:            true,
			})
			if err != nil {
				t.Fatalf("NewNowhere client(%s): %v", netName, err)
			}
			defer func() { _ = client.Close() }()

			if err := echoOneFlow(t, client, egressTunnel, "aes-"+netName); err != nil {
				t.Fatalf("echoOneFlow(%s): %v", netName, err)
			}
			if leaked := drainTunnelSeen(portalTunnel); leaked != "" {
				t.Fatalf("portal local tunnel handled %q in egress mode", leaked)
			}
		})
	}
}
