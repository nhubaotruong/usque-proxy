package usquebind

import (
	"bytes"
	"encoding/binary"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"log"
	"net"
	"testing"
	"time"
)

// TestDirectInject proves the gVisor demux + TCP forwarder + protected dial
// chain: a crafted SYN to an excluded prefix must reach handleTCP and relay
// to the real destination (host flask listener on :8000). Uses the host's
// outbound IP because gVisor drops loopback (martian) destinations.
func TestDirectInject(t *testing.T) {
	hostIP := outboundIP(t)
	df, err := newDirectForwarder(
		[]string{hostIP + "/32"},
		1280,
		func(pkt []byte) error { return nil }, // outbound pump sink
	)
	if err != nil {
		t.Fatalf("newDirectForwarder: %v", err)
	}
	if df == nil {
		t.Fatal("forwarder is nil")
	}
	defer df.close()

	// Watch the outbound pump: a successful relay produces a reply packet
	// (SYN-ACK or RST) addressed back to the source.
	gotPump := make(chan []byte, 16)
	df.writePkt = func(pkt []byte) error {
		select {
		case gotPump <- pkt:
		default:
		}
		return nil
	}

	// Craft SYN: 100.96.0.1:54321 -> <hostIP>:8000 (host flask listener).
	src := net.ParseIP("100.96.0.1").To4()
	dst := net.ParseIP(hostIP).To4()
	pkt := make([]byte, 40)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = 6
	copy(pkt[12:16], src)
	copy(pkt[16:20], dst)
	tcpHdr := pkt[20:40]
	binary.BigEndian.PutUint16(tcpHdr[0:2], 54321)
	binary.BigEndian.PutUint16(tcpHdr[2:4], 8000)
	binary.BigEndian.PutUint32(tcpHdr[4:8], 1)
	tcpHdr[12] = 0x50 // data offset 5 (20-byte header)
	tcpHdr[13] = 0x02 // SYN flag
	binary.BigEndian.PutUint16(tcpHdr[14:16], 65535)
	binary.BigEndian.PutUint16(pkt[10:12], testIpChecksum(pkt[0:20]))
	// Compute the TCP checksum with gVisor's own functions so the segment is
	// guaranteed to pass csumValid in the forwarder.
	csum := ^checksum.Checksum(tcpHdr, header.PseudoHeaderChecksum(header.TCPProtocolNumber, tcpip.AddrFrom4Slice(src), tcpip.AddrFrom4Slice(dst), uint16(len(tcpHdr))))
	binary.BigEndian.PutUint16(tcpHdr[16:18], csum)

	if !df.shouldForward(pkt) {
		t.Fatalf("shouldForward rejected %s with %s/32 excluded", hostIP, hostIP)
	}

	df.inject(pkt)
	// Give the stack a local address so FindRoute can pick a source for replies.
	if err := df.stack.AddProtocolAddress(df.nicID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4Slice(src), PrefixLen: 32},
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress: %v", err)
	}

	// 1. Expect the SYN-ACK from the stack.
	var iss uint32
	select {
	case out := <-gotPump:
		proto := out[0] >> 4
		if proto != 4 {
			t.Fatalf("pump returned non-IPv4 packet: %x", out[0])
		}
		gotDst := net.IP(out[16:20]).String()
		if gotDst != "100.96.0.1" {
			t.Fatalf("reply dst = %s, want 100.96.0.1 (flags %02x)", gotDst, out[33])
		}
		if out[33]&0x12 != 0x12 {
			t.Fatalf("expected SYN-ACK, got flags %02x", out[33])
		}
		iss = binary.BigEndian.Uint32(out[24:28])
	case <-time.After(5 * time.Second):
		t.Fatalf("no SYN-ACK from gVisor stack within 5s — forwarder chain broken")
	}

	// 2. Complete the handshake: ACK with a GET payload for the host flask
	// server. The relayed response must come back through the pump.
	payload := []byte("GET / HTTP/1.0\r\n\r\n")
	total := 20 + 20 + len(payload)
	ack := make([]byte, total)
	copy(ack, pkt[:20])
	binary.BigEndian.PutUint16(ack[2:4], uint16(total))
	ack[10] = 0 // zero checksum field before computing
	ack[11] = 0
	tcp := ack[20:]
	binary.BigEndian.PutUint16(tcp[0:2], 54321)
	binary.BigEndian.PutUint16(tcp[2:4], 8000)
	binary.BigEndian.PutUint32(tcp[4:8], 2) // seq 2 (after SYN)
	binary.BigEndian.PutUint32(tcp[8:12], iss+1)
	tcp[12] = 0x50
	tcp[13] = 0x19 // FIN|PSH|ACK — toybox nc shuts down its write side after
	// stdin EOF, coalescing the data and FIN into one segment
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	copy(tcp[20:], payload)
	binary.BigEndian.PutUint16(ack[10:12], testIpChecksum(ack[:20]))
	tcpCsum := checksum.Checksum(tcp, header.PseudoHeaderChecksum(header.TCPProtocolNumber, tcpip.AddrFrom4Slice(src), tcpip.AddrFrom4Slice(dst), uint16(len(tcp))))
	binary.BigEndian.PutUint16(tcp[16:18], ^tcpCsum)
	df.inject(ack)

	// 3. The relayed flask response must arrive through the pump.
	deadline := time.After(5 * time.Second)
	for {
		select {
		case out := <-gotPump:
			if bytes.Contains(out, []byte("LAN-OK-42")) {
				log.Printf("PASS: relayed response received (%d-byte segment)", len(out))
				return
			}
		case <-deadline:
			st := df.stack.Stats()
			log.Printf("drop stats: NIC.disabled=%d IP.received=%d IP.malformed=%d IP.invalidSrc=%d IP.invalidDst=%d L4.malformed=%d TCP.invalidSeg=%d TCP.checksum=%d",
				st.NICs.DisabledRx.Packets.Value(),
				st.IP.PacketsReceived.Value(),
				st.IP.MalformedPacketsReceived.Value(),
				st.IP.InvalidSourceAddressesReceived.Value(),
				st.IP.InvalidDestinationAddressesReceived.Value(),
				st.NICs.MalformedL4RcvdPackets.Value(),
				st.TCP.InvalidSegmentsReceived.Value(),
				st.TCP.ChecksumErrors.Value(),
			)
			t.Fatal("no relayed response within 5s — data path broken")
		}
	}
}

// outboundIP returns the host's outbound IPv4 (the interface used to reach
// the internet), so the test dial target is reachable and not loopback.
func outboundIP(t *testing.T) string {
	t.Helper()
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		t.Fatalf("outbound dial: %v", err)
	}
	defer conn.Close()
	ip := conn.LocalAddr().(*net.UDPAddr).IP.String()
	if ip == "127.0.0.1" {
		t.Fatal("no outbound IP")
	}
	return ip
}

func testIpChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
