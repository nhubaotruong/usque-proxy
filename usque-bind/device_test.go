package usquebind

import (
	"os"
	"testing"
)

// TestFilterDevicePassthrough verifies non-DNS, non-excluded packets pass
// through unchanged and tx_bytes is counted.
func TestFilterDevicePassthrough(t *testing.T) {
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	defer pw.Close()

	fd := &filterDevice{file: pr}
	txBytes.Store(0)

	// Fake IPv4 UDP packet (not port 53): 20B IP + 8B UDP + 4B payload
	pkt := []byte{
		0x45, 0x00, 0x00, 0x20, 0x00, 0x01, 0x00, 0x00,
		0x40, 0x11, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01,
		0x08, 0x08, 0x08, 0x08, 0x00, 0x50, 0x01, 0xbb,
		0x00, 0x08, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef,
	}
	go pw.Write(pkt)

	buf := make([]byte, 1500)
	n, err := fd.ReadPacket(buf)
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if n != len(pkt) {
		t.Fatalf("ReadPacket returned %d bytes, want %d", n, len(pkt))
	}
	for i := range pkt {
		if buf[i] != pkt[i] {
			t.Fatalf("byte %d: got %#x, want %#x", i, buf[i], pkt[i])
		}
	}
	if got := txBytes.Load(); got != int64(len(pkt)) {
		t.Fatalf("tx_bytes = %d, want %d", got, len(pkt))
	}
}

// TestFilterDeviceWritePacket verifies rx_bytes counting.
func TestFilterDeviceWritePacket(t *testing.T) {
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	defer pw.Close()

	fd := &filterDevice{file: pw}
	rxBytes.Store(0)

	pkt := []byte{0x45, 0x00, 0x00, 0x10}
	if err := fd.WritePacket(pkt); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	if got := rxBytes.Load(); got != int64(len(pkt)) {
		t.Fatalf("rx_bytes = %d, want %d", got, len(pkt))
	}
}
