package portal

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/nowhere/core/dgram"
	"github.com/metacubex/mihomo/transport/nowhere/core/wire"
)

// TestServeViaQUICEgressRejectsTLSVectorUDP pins the mixed-carrier guard: a
// Vector over TLS carries UDP as UoT on its control stream, while a QUIC Egress
// reads UDP DATAGRAMs, so the flow is rejected before the egress stream is
// opened and before the client is told READY.
func TestServeViaQUICEgressRejectsTLSVectorUDP(t *testing.T) {
	local, remote := net.Pipe()
	client := &pipe{Reader: remote, write: local, closer: local}
	server := &Server{}
	reg := &egressRegistration{quic: &fakeQIOConn{}}

	done := make(chan struct{})
	go func() {
		defer close(done)
		server.serveViaQUICEgress(context.Background(), reg, wire.FlowUDP, wire.Target{}, client, nil, 1)
	}()

	_ = remote.SetReadDeadline(time.Now().Add(5 * time.Second))
	res, err := wire.ReadSetupResult(remote)
	if err != nil {
		t.Fatalf("read setup result: %v", err)
	}
	if res != wire.SetupInternalError {
		t.Fatalf("setup result = %v, want %v", res, wire.SetupInternalError)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serveViaQUICEgress did not return")
	}
}

// TestServeFlowRejectsUDPWithoutDatagrams pins the setup-time failure for a
// QUIC Vector connection that did not negotiate DATAGRAM support: the flow must
// get INTERNAL_ERROR before any target dial or READY.
func TestServeFlowRejectsUDPWithoutDatagrams(t *testing.T) {
	local, remote := net.Pipe()
	client := &pipe{Reader: remote, write: local, closer: local}
	router := dgram.NewRouter(&fakeQIOConn{noDatagram: true})
	srv := &Server{}

	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.serveFlow(context.Background(), wire.FlowUDP, wire.Target{}, client, router, 1, true)
	}()
	_ = remote.SetReadDeadline(time.Now().Add(5 * time.Second))
	res, err := wire.ReadSetupResult(remote)
	if err != nil {
		t.Fatalf("read setup result: %v", err)
	}
	if res != wire.SetupInternalError {
		t.Fatalf("setup result = %v, want %v", res, wire.SetupInternalError)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serveFlow did not return")
	}
}

// TestServeFlowRejectsInvalidUDPFlowID pins the pre-READY derived-id check: an
// invalid or exhausted stream id fails the flow with FLOW_LIMIT instead of
// authorizing payload it cannot route.
func TestServeFlowRejectsInvalidUDPFlowID(t *testing.T) {
	local, remote := net.Pipe()
	client := &pipe{Reader: remote, write: local, closer: local}
	router := dgram.NewRouter(&fakeQIOConn{})
	srv := &Server{}

	done := make(chan struct{})
	go func() {
		defer close(done)
		// A client unidirectional stream id (bit 1 set) is never a UDP control
		// stream, so UDPFlowID rejects it.
		srv.serveFlow(context.Background(), wire.FlowUDP, wire.Target{}, client, router, 2, true)
	}()
	_ = remote.SetReadDeadline(time.Now().Add(5 * time.Second))
	res, err := wire.ReadSetupResult(remote)
	if err != nil {
		t.Fatalf("read setup result: %v", err)
	}
	if res != wire.SetupFlowLimit {
		t.Fatalf("setup result = %v, want %v", res, wire.SetupFlowLimit)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serveFlow did not return")
	}
}

// TestGateTryAndWait checks the accept-loop admission helper: a full gate is
// not admitted, a released slot is, and a bounded wait gives up.
func TestGateTryAndWait(t *testing.T) {
	g := &gate{n: maxFlows}
	if g.try() {
		t.Fatal("a full gate reported a free slot")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if g.wait(ctx, 5*time.Millisecond) {
		t.Fatal("wait admitted a full gate")
	}
	g.release()
	if !g.try() {
		t.Fatal("a released gate reported no free slot")
	}
	if !g.wait(context.Background(), time.Second) {
		t.Fatal("wait did not admit a released slot")
	}
}
