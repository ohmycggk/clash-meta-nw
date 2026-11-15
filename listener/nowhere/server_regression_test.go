package nowhere_test

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	nwlisten "github.com/metacubex/mihomo/listener/nowhere"
	nwtransport "github.com/metacubex/mihomo/transport/nowhere"
)

type addrRecordingTunnel struct {
	C.Tunnel
	mu    sync.Mutex
	addrs map[string]struct{}
}

func (t *addrRecordingTunnel) HandleUDPPacket(packet C.UDPPacket, _ *C.Metadata) {
	if addr := packet.LocalAddr(); addr != nil {
		t.mu.Lock()
		t.addrs[addr.String()] = struct{}{}
		t.mu.Unlock()
	}
	_, _ = packet.WriteBack(packet.Data(), nil)
	packet.Drop()
}

// TestNowhereV3ConcurrentUDPNoGoroutineLeakAndDistinctLocalAddr verifies Patches B1 & B5:
// 200 concurrent nw3 UDP flows (100 over TCP UoT + 100 over QUIC DATAGRAM) each
// receive a distinct v3Packet.LocalAddr() NAT key and leave zero leaked serveUDP
// goroutines once closed.
func TestNowhereV3ConcurrentUDPNoGoroutineLeakAndDistinctLocalAddr(t *testing.T) {
	tun := &addrRecordingTunnel{addrs: make(map[string]struct{}, 200)}

	startPortal := func(netName string) *nwlisten.Server {
		srv, err := nwlisten.New(LC.NowhereServer{
			Enable:               true,
			Listen:               "127.0.0.1:0",
			Password:             testNw3Password,
			Certificate:          testCertificate,
			PrivateKey:           testPrivateKey,
			CongestionController: "bbr",
			Net:                  netName,
			Morph:                false,
		}, inbound.NewListenConfig(), tun)
		if err != nil {
			t.Fatalf("nowhere.New(%s): %v", netName, err)
		}
		return srv
	}

	parsePort := func(srv *nwlisten.Server) int {
		addrs := srv.AddrList()
		if len(addrs) != 1 {
			t.Fatalf("AddrList = %v", addrs)
		}
		_, pStr, err := net.SplitHostPort(addrs[0])
		if err != nil {
			t.Fatal(err)
		}
		p, err := strconv.Atoi(pStr)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}

	tcpSrv := startPortal(nwtransport.NowhereNetTCP)
	defer func() { _ = tcpSrv.Close() }()
	udpSrv := startPortal(nwtransport.NowhereNetUDP)
	defer func() { _ = udpSrv.Close() }()

	tcpPort := parsePort(tcpSrv)
	udpPort := parsePort(udpSrv)

	morphOff := false
	tcpClient, err := outbound.NewNowhere(outbound.NowhereOption{
		Name: "nw3-tcp-bench", Server: "127.0.0.1", Port: tcpPort,
		Password: testNw3Password, SkipCertVerify: true,
		Net: nwtransport.NowhereNetTCP, Morph: &morphOff, UDP: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tcpClient.Close() }()

	udpClient, err := outbound.NewNowhere(outbound.NowhereOption{
		Name: "nw3-udp-bench", Server: "127.0.0.1", Port: udpPort,
		Password: testNw3Password, SkipCertVerify: true,
		Net: nwtransport.NowhereNetUDP, Morph: &morphOff, UDP: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = udpClient.Close() }()

	// Warm up 1 flow on each carrier so the shared QUIC session & pools settle
	// before capturing the goroutine baseline.
	runOneFlow := func(cli *outbound.Nowhere, id int) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		pc, err := cli.ListenPacketContext(ctx, &C.Metadata{Host: "example.com", DstPort: 53})
		if err != nil {
			return fmt.Errorf("flow %d ListenPacketContext: %w", id, err)
		}
		defer func() { _ = pc.Close() }()
		_ = pc.SetDeadline(time.Now().Add(5 * time.Second))
		msg := []byte(fmt.Sprintf("pkt-%03d", id))
		if _, err := pc.WriteTo(msg, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}); err != nil {
			return fmt.Errorf("flow %d WriteTo: %w", id, err)
		}
		buf := make([]byte, 32)
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			return fmt.Errorf("flow %d ReadFrom: %w", id, err)
		}
		if string(buf[:n]) != string(msg) {
			return fmt.Errorf("flow %d echo = %q, want %q", id, buf[:n], msg)
		}
		return nil
	}

	if err := runOneFlow(tcpClient, -1); err != nil {
		t.Fatal(err)
	}
	if err := runOneFlow(udpClient, -2); err != nil {
		t.Fatal(err)
	}
	tun.mu.Lock()
	tun.addrs = make(map[string]struct{}, 200)
	tun.mu.Unlock()

	runtime.GC()
	time.Sleep(30 * time.Millisecond)
	baseGoroutines := runtime.NumGoroutine()

	const totalFlows = 200
	errCh := make(chan error, totalFlows)
	sem := make(chan struct{}, 32)
	var wg sync.WaitGroup
	for i := 0; i < totalFlows; i++ {
		wg.Add(1)
		cli := tcpClient
		if i%2 == 1 {
			cli = udpClient
		}
		go func(idx int, c *outbound.Nowhere) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if err := runOneFlow(c, idx); err != nil {
				errCh <- err
			}
		}(i, cli)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}

	tun.mu.Lock()
	distinct := len(tun.addrs)
	tun.mu.Unlock()
	if distinct != totalFlows {
		t.Fatalf("distinct v3Packet.LocalAddr() count = %d, want %d", distinct, totalFlows)
	}

	// Without Patch B1, 200 serveUDP goroutines would remain leaked forever.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && runtime.NumGoroutine() > baseGoroutines+8 {
		runtime.GC()
		time.Sleep(25 * time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > baseGoroutines+8 {
		t.Fatalf("goroutine leak after %d UDP flows: got %d, baseline %d", totalFlows, got, baseGoroutines)
	}
}
