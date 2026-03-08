package usquebind

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

const virtualDNSIPStr = "10.255.255.53"

var virtualDNSIPv4 = net.IPv4(10, 255, 255, 53).To4()

// dnsResponsePool reuses buffers for building DNS response packets.
// Max size: 40 (IPv6) + 8 (UDP) + 4096 (DNS payload) = 4144.
var dnsResponsePool = sync.Pool{
	New: func() any { return make([]byte, 4144) },
}

// dohProxy resolves DNS queries over HTTPS (RFC 8484).
type dohProxy struct {
	url        string
	client     *http.Client
	clientMu   sync.Mutex           // protects client recreation
	protector  VpnProtector
	cache      sync.Map             // query content -> *cacheEntry
	makeClient func() *http.Client  // factory for recreating client on network errors
}

type cacheEntry struct {
	response []byte
	expiry   time.Time
}

func newDohProxy(url string, protector VpnProtector) *dohProxy {
	makeClient := func() *http.Client {
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		transport := &http.Transport{
			ForceAttemptHTTP2:   true,
			DisableCompression:  true,
			MaxConnsPerHost:     2,
			MaxIdleConns:        2,
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     5 * time.Minute,
			TLSHandshakeTimeout: 5 * time.Second,
			TLSClientConfig: &tls.Config{
				ClientSessionCache: tls.NewLRUClientSessionCache(0),
			},
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

		// Explicitly configure HTTP/2 with idle connection pinging
		h2transport, err := http2.ConfigureTransports(transport)
		if err == nil {
			h2transport.ReadIdleTimeout = 30 * time.Second
		}

		return &http.Client{
			Transport: transport,
			Timeout:   7 * time.Second,
		}
	}

	return &dohProxy{
		url:        url,
		protector:  protector,
		client:     makeClient(),
		makeClient: makeClient,
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

	// RFC 8484: Use GET with base64url-encoded query for cache friendliness
	encoded := base64.RawURLEncoding.EncodeToString(query)
	reqURL := d.url + "?dns=" + encoded
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")

	resp, err := d.client.Do(req)
	if err != nil {
		// On timeout/network errors, reset the client for next request
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			d.resetClient()
		}
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

// resetClient recreates the HTTP client, discarding stale connections.
func (d *dohProxy) resetClient() {
	d.clientMu.Lock()
	defer d.clientMu.Unlock()
	d.client = d.makeClient()
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

// dnsRequest represents a queued DNS interception request.
type dnsRequest struct {
	srcIP     net.IP
	srcPort   uint16
	dstIP     net.IP
	query     []byte
	writeFunc func([]byte) error
	isIPv6    bool
}

// dnsInterceptor is a unified DNS interception wrapper that works across all DNS modes.
type dnsInterceptor struct {
	resolver     func(query []byte) ([]byte, error)
	interceptAll bool // true = intercept all port 53 traffic, false = only virtualDNSIP
	reqCh        chan dnsRequest
	closeFunc    func() // called on shutdown to close pooled connections
}

// newDnsInterceptor creates a dnsInterceptor based on the tunnel config.
func newDnsInterceptor(ctx context.Context, cfg *tunnelConfig, protector VpnProtector) *dnsInterceptor {
	var resolver func(query []byte) ([]byte, error)
	var interceptAll bool
	var closeFunc func()
	var caches []*sync.Map

	if cfg.DoHURL != "" {
		doh := newDohProxy(cfg.DoHURL, protector)
		resolver = doh.resolve
		interceptAll = cfg.PreventDnsLeak
		caches = append(caches, &doh.cache)
	} else if cfg.PreventDnsLeak && len(cfg.DnsServers) > 0 {
		plain := newPlainDnsProxy(cfg.DnsServers, protector)
		resolver = plain.resolve
		interceptAll = true
		closeFunc = plain.close
		caches = append(caches, &plain.cache)
	} else {
		return nil
	}

	d := &dnsInterceptor{
		resolver:     resolver,
		interceptAll: interceptAll,
		reqCh:        make(chan dnsRequest, 256),
		closeFunc:    closeFunc,
	}

	// Bounded worker pool for DNS resolution.
	const numWorkers = 8
	for i := 0; i < numWorkers; i++ {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case req, ok := <-d.reqCh:
					if !ok {
						return
					}
					d.handleInterceptedDNS(req)
				}
			}
		}()
	}

	// Start cache eviction
	for _, c := range caches {
		startCacheEvictor(ctx, c, 60*time.Second)
	}

	return d
}

// forwardUp queues a DNS request for processing. Drops the request if the queue is full.
func (d *dnsInterceptor) forwardUp(req dnsRequest) {
	select {
	case d.reqCh <- req:
	default:
		log.Println("DNS queue full, dropping request")
	}
}

// close shuts down the interceptor, closing any pooled connections.
func (d *dnsInterceptor) close() {
	if d.closeFunc != nil {
		d.closeFunc()
	}
}

// handleInterceptedDNS resolves a DNS query and writes the response packet back.
func (d *dnsInterceptor) handleInterceptedDNS(req dnsRequest) {
	resp, err := d.resolver(req.query)
	if err != nil {
		log.Printf("DNS resolve error: %v", err)
		return
	}

	buf := dnsResponsePool.Get().([]byte)
	var pkt []byte

	if req.isIPv6 {
		pkt = buildDNSResponseIPv6(buf, req.dstIP, req.srcIP, req.srcPort, resp)
	} else {
		pkt = buildDNSResponseIPv4(buf, req.dstIP, req.srcIP, req.srcPort, resp)
	}

	err = req.writeFunc(pkt)
	dnsResponsePool.Put(buf)
	if err != nil {
		log.Printf("DNS write error: %v", err)
	}
}

// buildDNSResponseIPv4 builds an IPv4/UDP DNS response packet into buf.
func buildDNSResponseIPv4(buf []byte, responseIP, dstIP net.IP, dstPort uint16, dnsResp []byte) []byte {
	udpLen := 8 + len(dnsResp)
	totalLen := 20 + udpLen
	if totalLen > len(buf) {
		buf = make([]byte, totalLen)
	}
	pkt := buf[:totalLen]

	// IPv4 header
	pkt[0] = 0x45 // version=4, IHL=5
	pkt[1] = 0
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[4] = 0
	pkt[5] = 0
	pkt[6] = 0
	pkt[7] = 0
	pkt[8] = 64 // TTL
	pkt[9] = 17 // UDP
	pkt[10] = 0
	pkt[11] = 0
	copy(pkt[12:16], responseIP.To4())
	copy(pkt[16:20], dstIP.To4())

	// IP header checksum
	binary.BigEndian.PutUint16(pkt[10:12], ipChecksum(pkt[:20]))

	// UDP header
	binary.BigEndian.PutUint16(pkt[20:22], 53)      // src port
	binary.BigEndian.PutUint16(pkt[22:24], dstPort) // dst port
	binary.BigEndian.PutUint16(pkt[24:26], uint16(udpLen))
	pkt[26] = 0 // UDP checksum = 0 (optional for IPv4)
	pkt[27] = 0
	copy(pkt[28:], dnsResp)

	return pkt
}

// buildDNSResponseIPv6 builds an IPv6/UDP DNS response packet into buf.
func buildDNSResponseIPv6(buf []byte, responseIP, dstIP net.IP, dstPort uint16, dnsResp []byte) []byte {
	udpLen := 8 + len(dnsResp)
	totalLen := 40 + udpLen // 40-byte IPv6 header
	if totalLen > len(buf) {
		buf = make([]byte, totalLen)
	}
	pkt := buf[:totalLen]

	// IPv6 header
	pkt[0] = 0x60 // version=6, traffic class=0
	pkt[1] = 0
	pkt[2] = 0
	pkt[3] = 0
	binary.BigEndian.PutUint16(pkt[4:6], uint16(udpLen)) // payload length
	pkt[6] = 17                                          // Next Header = UDP
	pkt[7] = 64                                          // Hop Limit
	// Source IP (16 bytes)
	copy(pkt[8:24], responseIP.To16())
	// Destination IP (16 bytes)
	copy(pkt[24:40], dstIP.To16())

	// UDP header
	udp := pkt[40:]
	binary.BigEndian.PutUint16(udp[0:2], 53)      // src port
	binary.BigEndian.PutUint16(udp[2:4], dstPort) // dst port
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	udp[6] = 0 // checksum placeholder
	udp[7] = 0
	copy(udp[8:], dnsResp)

	// UDP checksum is mandatory for IPv6
	binary.BigEndian.PutUint16(udp[6:8], udp6Checksum(pkt[8:24], pkt[24:40], udp[:udpLen]))

	return pkt
}

// udp6Checksum computes the UDP checksum over the IPv6 pseudo-header and UDP segment.
func udp6Checksum(srcIP, dstIP, udpSegment []byte) uint16 {
	var sum uint32

	// Pseudo-header: src IP (16) + dst IP (16) + UDP length (4) + next header (4)
	for i := 0; i < 16; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(srcIP[i : i+2]))
	}
	for i := 0; i < 16; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(dstIP[i : i+2]))
	}
	sum += uint32(len(udpSegment)) // UDP length
	sum += 17                      // Next Header = UDP

	// UDP segment
	for i := 0; i < len(udpSegment)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(udpSegment[i : i+2]))
	}
	if len(udpSegment)%2 != 0 {
		sum += uint32(udpSegment[len(udpSegment)-1]) << 8
	}

	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}

	csum := ^uint16(sum)
	if csum == 0 {
		csum = 0xffff // RFC 2460: 0 means no checksum, use 0xffff instead
	}
	return csum
}

// serverConn wraps a UDP connection with a mutex to serialize queries per server.
// This prevents response mismatch when multiple workers query the same server.
type serverConn struct {
	mu   sync.Mutex
	conn *net.UDPConn
}

// plainDnsProxy forwards DNS queries via protected UDP sockets to upstream servers.
// Connections are pooled and reused across queries, one per server.
type plainDnsProxy struct {
	servers   []string
	protector VpnProtector
	cache     sync.Map // query content -> *cacheEntry
	mu        sync.Mutex
	conns     map[string]*serverConn
}

func newPlainDnsProxy(servers []string, protector VpnProtector) *plainDnsProxy {
	return &plainDnsProxy{
		servers:   servers,
		protector: protector,
		conns:     make(map[string]*serverConn),
	}
}

// getServerConn returns (or creates) the serverConn entry for the given server.
func (p *plainDnsProxy) getServerConn(server string) *serverConn {
	p.mu.Lock()
	defer p.mu.Unlock()
	sc, ok := p.conns[server]
	if !ok {
		sc = &serverConn{}
		p.conns[server] = sc
	}
	return sc
}

// dialConn creates a new protected UDP connection to the server.
func (p *plainDnsProxy) dialConn(server string) (*net.UDPConn, error) {
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(server, "53"))
	if err != nil {
		return nil, err
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}

	// Protect the socket from VPN routing
	rawConn, err := conn.SyscallConn()
	if err != nil {
		conn.Close()
		return nil, err
	}
	var protectErr error
	rawConn.Control(func(fd uintptr) {
		if !p.protector.ProtectFd(int(fd)) {
			protectErr = errors.New("VPN protect() failed")
		}
	})
	if protectErr != nil {
		conn.Close()
		return nil, protectErr
	}

	return conn, nil
}

// close closes all pooled connections.
func (p *plainDnsProxy) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for server, sc := range p.conns {
		sc.mu.Lock()
		if sc.conn != nil {
			sc.conn.Close()
			sc.conn = nil
		}
		sc.mu.Unlock()
		delete(p.conns, server)
	}
}

func (p *plainDnsProxy) resolve(query []byte) ([]byte, error) {
	// Check cache
	cacheKey := string(query)
	if v, ok := p.cache.Load(cacheKey); ok {
		entry := v.(*cacheEntry)
		if time.Now().Before(entry.expiry) {
			return entry.response, nil
		}
		p.cache.Delete(cacheKey)
	}

	var lastErr error
	for _, server := range p.servers {
		resp, err := p.queryServer(server, query)
		if err != nil {
			lastErr = err
			continue
		}
		// Cache with TTL
		ttl := extractMinTTL(resp)
		p.cache.Store(cacheKey, &cacheEntry{
			response: resp,
			expiry:   time.Now().Add(ttl),
		})
		return resp, nil
	}
	return nil, fmt.Errorf("all DNS servers failed: %v", lastErr)
}

func (p *plainDnsProxy) queryServer(server string, query []byte) ([]byte, error) {
	sc := p.getServerConn(server)

	// Hold per-server lock for the entire write+read cycle to prevent response mismatch
	sc.mu.Lock()
	defer sc.mu.Unlock()

	// Lazily create connection
	if sc.conn == nil {
		conn, err := p.dialConn(server)
		if err != nil {
			return nil, err
		}
		sc.conn = conn
	}

	sc.conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := sc.conn.Write(query); err != nil {
		sc.conn.Close()
		sc.conn = nil
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := sc.conn.Read(buf)
	if err != nil {
		sc.conn.Close()
		sc.conn = nil
		return nil, err
	}
	return buf[:n], nil
}

// isAnyDNSPacket checks if pkt is an IPv4 UDP packet destined for ANY IP on port 53.
// Returns srcIP, srcPort, dstIP, DNS payload, and true if it matches.
func isAnyDNSPacket(pkt []byte) (srcIP net.IP, srcPort uint16, dstIP net.IP, payload []byte, ok bool) {
	// Minimum: 20 (IPv4) + 8 (UDP) + 12 (DNS header)
	if len(pkt) < 40 {
		return nil, 0, nil, nil, false
	}
	if pkt[0]>>4 != 4 {
		return nil, 0, nil, nil, false
	}
	if pkt[9] != 17 {
		return nil, 0, nil, nil, false
	}

	ihl := int(pkt[0]&0x0f) * 4
	if len(pkt) < ihl+8 {
		return nil, 0, nil, nil, false
	}

	dstPort := binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
	if dstPort != 53 {
		return nil, 0, nil, nil, false
	}

	srcIP = net.IP(pkt[12:16]).To4()
	srcPort = binary.BigEndian.Uint16(pkt[ihl : ihl+2])
	dstIP = net.IP(pkt[16:20]).To4()
	payload = pkt[ihl+8:]
	ok = true
	return
}

// isAnyDNSv6Packet checks if pkt is an IPv6 UDP packet destined for ANY IP on port 53.
// Returns srcIP, srcPort, dstIP, DNS payload, and true if it matches.
// Only handles packets where Next Header is directly UDP (no extension headers).
func isAnyDNSv6Packet(pkt []byte) (srcIP net.IP, srcPort uint16, dstIP net.IP, payload []byte, ok bool) {
	// Minimum: 40 (IPv6) + 8 (UDP) + 12 (DNS header)
	if len(pkt) < 60 {
		return nil, 0, nil, nil, false
	}
	if pkt[0]>>4 != 6 {
		return nil, 0, nil, nil, false
	}
	// Next Header = UDP (17)
	if pkt[6] != 17 {
		return nil, 0, nil, nil, false
	}

	// UDP header starts at offset 40
	dstPort := binary.BigEndian.Uint16(pkt[42:44])
	if dstPort != 53 {
		return nil, 0, nil, nil, false
	}

	srcIP = make(net.IP, 16)
	copy(srcIP, pkt[8:24])
	srcPort = binary.BigEndian.Uint16(pkt[40:42])
	dstIP = make(net.IP, 16)
	copy(dstIP, pkt[24:40])
	payload = pkt[48:]
	ok = true
	return
}

// startCacheEvictor periodically scans a sync.Map and deletes expired cache entries.
func startCacheEvictor(ctx context.Context, cache *sync.Map, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := time.Now()
				cache.Range(func(key, value any) bool {
					if entry, ok := value.(*cacheEntry); ok {
						if now.After(entry.expiry) {
							cache.Delete(key)
						}
					}
					return true
				})
			}
		}
	}()
}
