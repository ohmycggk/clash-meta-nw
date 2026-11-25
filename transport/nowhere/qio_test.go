package nowhere

import (
	"testing"
	"time"

	nwruntime "github.com/metacubex/mihomo/transport/nowhere/core/runtime"
	"github.com/metacubex/quic-go"
)

func TestNowhereV3QUICConfigMemoryProfiles(t *testing.T) {
	tests := []struct {
		profile  string
		wantStrm uint64
		wantConn uint64
	}{
		{"", 4 << 20, 32 << 20},
		{"throughput", 4 << 20, 32 << 20},
		{"balanced", 4 << 20, 16 << 20},
		{"memory", 4 << 20, 16 << 20},
	}
	for _, tc := range tests {
		t.Run("profile_"+tc.profile, func(t *testing.T) {
			if tc.profile != "" {
				t.Setenv(nwruntime.EnvMemoryProfile, tc.profile)
			}
			rt, err := nwruntime.Load("", false)
			if err != nil {
				t.Fatalf("runtime.Load: %v", err)
			}

			clientCfg := nowhereV3QUICConfig(true, rt, nil)
			if clientCfg.InitialStreamReceiveWindow != tc.wantStrm || clientCfg.MaxStreamReceiveWindow != tc.wantStrm {
				t.Fatalf("client stream window = %d/%d, want %d", clientCfg.InitialStreamReceiveWindow, clientCfg.MaxStreamReceiveWindow, tc.wantStrm)
			}
			if clientCfg.InitialConnectionReceiveWindow != tc.wantConn || clientCfg.MaxConnectionReceiveWindow != tc.wantConn {
				t.Fatalf("client conn window = %d/%d, want %d", clientCfg.InitialConnectionReceiveWindow, clientCfg.MaxConnectionReceiveWindow, tc.wantConn)
			}
			if !clientCfg.DisablePathMTUDiscovery || clientCfg.InitialPacketSize != 1200 {
				t.Fatalf("morph QUIC MTU settings not pinned: DisablePathMTUDiscovery=%v InitialPacketSize=%d", clientCfg.DisablePathMTUDiscovery, clientCfg.InitialPacketSize)
			}
			if clientCfg.AllowConnectionWindowIncrease != nil {
				t.Fatal("client QUIC config unexpectedly set AllowConnectionWindowIncrease")
			}

			gate := newPreAuthGate()
			serverCfg := nowhereV3QUICConfig(false, rt, gate)
			if serverCfg.InitialConnectionReceiveWindow != nwruntime.PreAuthConnWindow {
				t.Fatalf("server pre-auth conn window = %d, want %d", serverCfg.InitialConnectionReceiveWindow, nwruntime.PreAuthConnWindow)
			}
			if serverCfg.MaxConnectionReceiveWindow != tc.wantConn {
				t.Fatalf("server max conn window = %d, want %d", serverCfg.MaxConnectionReceiveWindow, tc.wantConn)
			}
			if serverCfg.AllowConnectionWindowIncrease == nil {
				t.Fatal("server QUIC config missing AllowConnectionWindowIncrease")
			}
			// Verify per-connection isolation on preAuthGate.
			c1 := new(quic.Conn)
			c2 := new(quic.Conn)
			if serverCfg.AllowConnectionWindowIncrease(c1, 1024) {
				t.Fatal("unauthenticated c1 allowed to grow connection window")
			}
			gate.release(c1)
			if !serverCfg.AllowConnectionWindowIncrease(c1, 1024) {
				t.Fatal("authenticated c1 not allowed to grow connection window")
			}
			if serverCfg.AllowConnectionWindowIncrease(c2, 1024) {
				t.Fatal("authenticating c1 leaked window release to c2")
			}
			gate.forget(c1)
			if serverCfg.AllowConnectionWindowIncrease(c1, 1024) {
				t.Fatal("forgotten c1 still marked released")
			}
		})
	}
}

func TestNowhereV3QUICConfigIdleTimeoutFromEnv(t *testing.T) {
	t.Setenv(nwruntime.EnvUDPIdleTimeout, "45s")
	rt, err := nwruntime.Load("", false)
	if err != nil {
		t.Fatalf("runtime.Load: %v", err)
	}
	cfg := nowhereV3QUICConfig(false, rt, nil)
	if cfg.MaxIdleTimeout != 45*time.Second {
		t.Fatalf("MaxIdleTimeout = %v, want 45s", cfg.MaxIdleTimeout)
	}
}
