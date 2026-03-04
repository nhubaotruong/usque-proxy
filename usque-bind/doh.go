package usquebind

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

const virtualDNSIP = "10.255.255.53"

// dohProxy resolves DNS queries over HTTPS (RFC 8484).
type dohProxy struct {
	url       string
	client    *http.Client
	protector VpnProtector
	cache     sync.Map // query content -> *cacheEntry
}

type cacheEntry struct {
	response []byte
	expiry   time.Time
}

func newDohProxy(url string, protector VpnProtector) *dohProxy {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := &http.Transport{
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        2,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			// Protect the socket from VPN routing
			if tc, ok := conn.(*net.TCPConn); ok {
				raw, err := tc.SyscallConn()
				if err == nil {
					raw.Control(func(fd uintptr) {
						protector.ProtectFd(int(fd))
					})
				}
			}
			return conn, nil
		},
	}
	return &dohProxy{
		url:       url,
		protector: protector,
		client: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
	}
}

// resolve sends a DNS query to the DoH server and returns the raw DNS response.
func (d *dohProxy) resolve(query []byte) ([]byte, error) {
	// Check cache
	cacheKey := string(query)
	if v, ok := d.cache.Load(cacheKey); ok {
		entry := v.(*cacheEntry)
		if time.Now().Before(entry.expiry) {
			return entry.response, nil
		}
		d.cache.Delete(cacheKey)
	}

	req, err := http.NewRequest("POST", d.url, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("DoH server returned " + resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil, err
	}

	// Cache with TTL from DNS response
	ttl := extractMinTTL(body)
	d.cache.Store(cacheKey, &cacheEntry{
		response: body,
		expiry:   time.Now().Add(ttl),
	})

	return body, nil
}

// isDNSPacket checks if pkt is an IPv4 UDP packet destined for the virtual DNS IP on port 53.
// Returns srcIP, srcPort, DNS payload, and true if it's a DNS packet; false otherwise.
func isDNSPacket(pkt []byte) (srcIP net.IP, srcPort uint16, payload []byte, ok bool) {
	// Minimum: 20 (IPv4) + 8 (UDP) + 12 (DNS header)
	if len(pkt) < 40 {
		return nil, 0, nil, false
	}
	// Check IPv4
	version := pkt[0] >> 4
	if version != 4 {
		return nil, 0, nil, false
	}
	// Check protocol = UDP (17)
	if pkt[9] != 17 {
		return nil, 0, nil, false
	}
	// Check destination IP = virtualDNSIP (10.255.255.53)
	if pkt[16] != 10 || pkt[17] != 255 || pkt[18] != 255 || pkt[19] != 53 {
		return nil, 0, nil, false
	}

	ihl := int(pkt[0]&0x0f) * 4
	if len(pkt) < ihl+8 {
		return nil, 0, nil, false
	}

	// Check destination port = 53
	dstPort := binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
	if dstPort != 53 {
		return nil, 0, nil, false
	}

	srcIP = net.IP(pkt[12:16]).To4()
	srcPort = binary.BigEndian.Uint16(pkt[ihl : ihl+2])
	payload = pkt[ihl+8:]
	ok = true
	return
}

// buildDNSResponse crafts an IPv4/UDP packet wrapping the DNS response back to the original sender.
func buildDNSResponse(srcIP net.IP, srcPort uint16, dnsResp []byte) []byte {
	udpLen := 8 + len(dnsResp)
	totalLen := 20 + udpLen
	pkt := make([]byte, totalLen)

	// IPv4 header
	pkt[0] = 0x45 // version=4, IHL=5
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[8] = 64  // TTL
	pkt[9] = 17  // UDP
	// Source IP: virtualDNSIP (10.255.255.53)
	pkt[12] = 10
	pkt[13] = 255
	pkt[14] = 255
	pkt[15] = 53
	// Destination IP
	copy(pkt[16:20], srcIP.To4())

	// IP header checksum
	binary.BigEndian.PutUint16(pkt[10:12], ipChecksum(pkt[:20]))

	// UDP header
	binary.BigEndian.PutUint16(pkt[20:22], 53)         // src port
	binary.BigEndian.PutUint16(pkt[22:24], srcPort)     // dst port
	binary.BigEndian.PutUint16(pkt[24:26], uint16(udpLen))
	// UDP checksum = 0 (optional for IPv4)
	copy(pkt[28:], dnsResp)

	return pkt
}

// ipChecksum computes the IPv4 header checksum.
func ipChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i < len(header)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// extractMinTTL parses a DNS response to find the minimum TTL, clamped to [60s, 300s].
func extractMinTTL(resp []byte) time.Duration {
	const minTTL = 60 * time.Second
	const maxTTL = 300 * time.Second

	if len(resp) < 12 {
		return minTTL
	}

	// Skip header (12 bytes), count questions and answers
	qdcount := binary.BigEndian.Uint16(resp[4:6])
	ancount := binary.BigEndian.Uint16(resp[6:8])

	offset := 12

	// Skip questions
	for i := 0; i < int(qdcount); i++ {
		offset = skipDNSName(resp, offset)
		if offset < 0 || offset+4 > len(resp) {
			return minTTL
		}
		offset += 4 // QTYPE + QCLASS
	}

	// Parse answers for minimum TTL
	var found bool
	result := maxTTL
	for i := 0; i < int(ancount); i++ {
		offset = skipDNSName(resp, offset)
		if offset < 0 || offset+10 > len(resp) {
			break
		}
		ttl := time.Duration(binary.BigEndian.Uint32(resp[offset+4:offset+8])) * time.Second
		rdlen := binary.BigEndian.Uint16(resp[offset+8 : offset+10])
		offset += 10 + int(rdlen)

		if ttl < result {
			result = ttl
			found = true
		}
	}

	if !found {
		return minTTL
	}
	if result < minTTL {
		return minTTL
	}
	if result > maxTTL {
		return maxTTL
	}
	return result
}

// skipDNSName skips a DNS name (with possible compression) and returns the new offset.
func skipDNSName(data []byte, offset int) int {
	for {
		if offset >= len(data) {
			return -1
		}
		length := int(data[offset])
		if length == 0 {
			return offset + 1
		}
		if length&0xC0 == 0xC0 {
			// Compression pointer: 2 bytes
			return offset + 2
		}
		offset += 1 + length
	}
}

// handleDNSPacket processes a DNS packet via DoH and writes the response to the TUN device.
func (d *dohProxy) handleDNSPacket(srcIP net.IP, srcPort uint16, query []byte, writeFunc func([]byte) error) {
	resp, err := d.resolve(query)
	if err != nil {
		log.Printf("DoH resolve error: %v", err)
		return
	}
	pkt := buildDNSResponse(srcIP, srcPort, resp)
	if err := writeFunc(pkt); err != nil {
		log.Printf("DoH write error: %v", err)
	}
}
