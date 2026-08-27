package usquebind

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestGetStatsShape verifies the stats JSON schema Kotlin parses.
func TestGetStatsShape(t *testing.T) {
	s := GetStats()
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("stats not valid JSON: %v", err)
	}
	for _, k := range []string{"running", "connected", "tx_bytes", "rx_bytes", "uptime_sec", "has_network", "connect_count"} {
		if _, ok := m[k]; !ok {
			t.Errorf("stats missing key %q", k)
		}
	}
	if _, ok := m["running"].(bool); !ok {
		t.Errorf("running must be bool, got %T", m["running"])
	}
	if _, ok := m["tx_bytes"].(float64); !ok {
		t.Errorf("tx_bytes must be number, got %T", m["tx_bytes"])
	}
}

// TestStartTunnelInvalidConfig verifies config validation happens before any network I/O.
func TestStartTunnelInvalidConfig(t *testing.T) {
	err := StartTunnel("{not json", 0, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "invalid config JSON") {
		t.Fatalf("expected invalid config JSON error, got %v", err)
	}
}

// TestIsDNSQuery verifies DNS query detection (extracted pure function).
func TestIsDNSQuery(t *testing.T) {
	// DNS query: header with QR=0, opcode=0, one question
	q := []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // flags: RD set, QR=0
		0x00, 0x01, // QDCOUNT=1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // AN/NS/AR = 0
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, // name
		0x00, 0x01, 0x00, 0x01, // A, IN
	}
	if !isDNSQuery(q) {
		t.Error("expected DNS query to be detected")
	}
	// Non-DNS: short garbage
	if isDNSQuery([]byte{0x00, 0x01, 0x02, 0x03}) {
		t.Error("expected short/garbage packet to not be a DNS query")
	}
}
