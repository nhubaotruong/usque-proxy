package usquebind

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// globalTLSSessionCache is shared across all DoH clients to survive client resets.
var globalTLSSessionCache = tls.NewLRUClientSessionCache(2048)

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
	refreshing sync.Map             // cache keys currently being background-refreshed
	makeClient func() *http.Client  // factory for recreating client on network errors
	preferGET  bool                 // flip to true on HTTP 405, stay on GET
}

type cacheEntry struct {
	response      []byte
	expiry        time.Time
	staleDeadline time.Time
}

const staleGracePeriod = 5 * time.Minute

// warmupQuery is a minimal DNS query for "." (root) NS record, used to pre-warm the connection.
var warmupQuery = []byte{
	0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01,
}

func newDohProxy(url string, protector VpnProtector) *dohProxy {
	makeClient := func() *http.Client {
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		transport := &http.Transport{
			ForceAttemptHTTP2:     true,
			DisableCompression:    true,
			MaxConnsPerHost:       4,
			MaxIdleConns:          4,
			MaxIdleConnsPerHost:   4,
			IdleConnTimeout:       3 * time.Minute,
			TLSHandshakeTimeout:   7 * time.Second,
			ResponseHeaderTimeout: 8 * time.Second,
			TLSClientConfig: &tls.Config{
				MinVersion:             tls.VersionTLS12,
				SessionTicketsDisabled: false,
				ClientSessionCache:     globalTLSSessionCache,
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
			Timeout:   10 * time.Second,
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
	if len(query) < 12 {
		return nil, errors.New("DNS query too short")
	}

	// Save original transaction ID and zero it for cache key
	origID := [2]byte{query[0], query[1]}
	query[0], query[1] = 0, 0

	cacheKey := string(query)
	if v, ok := d.cache.Load(cacheKey); ok {
		entry := v.(*cacheEntry)
		now := time.Now()
		if now.Before(entry.expiry) {
			// Fresh hit — return immediately
			resp := make([]byte, len(entry.response))
			copy(resp, entry.response)
			resp[0], resp[1] = origID[0], origID[1]
			query[0], query[1] = origID[0], origID[1]
			return resp, nil
		}
		if now.Before(entry.staleDeadline) {
			// Stale hit — return immediately, refresh in background
			resp := make([]byte, len(entry.response))
			copy(resp, entry.response)
			resp[0], resp[1] = origID[0], origID[1]
			query[0], query[1] = origID[0], origID[1]
			// Trigger background refresh (deduped by cache key)
			if _, loaded := d.refreshing.LoadOrStore(cacheKey, struct{}{}); !loaded {
				queryCopy := make([]byte, len(query))
				copy(queryCopy, query)
				queryCopy[0], queryCopy[1] = 0, 0
				go d.backgroundRefresh(cacheKey, queryCopy)
			}
			return resp, nil
		}
		// Fully expired — delete and fall through to network fetch
		d.cache.Delete(cacheKey)
	}

	body, err := d.fetchFromServer(query)
	if err != nil {
		query[0], query[1] = origID[0], origID[1]
		return nil, err
	}

	// Cache with zeroed transaction ID
	cacheCopy := make([]byte, len(body))
	copy(cacheCopy, body)
	cacheCopy[0], cacheCopy[1] = 0, 0
	ttl := extractMinTTL(body)
	now := time.Now()
	d.cache.Store(cacheKey, &cacheEntry{
		response:      cacheCopy,
		expiry:        now.Add(ttl),
		staleDeadline: now.Add(ttl + staleGracePeriod),
	})

	// Patch caller's original ID into response
	body[0], body[1] = origID[0], origID[1]
	query[0], query[1] = origID[0], origID[1]
	return body, nil
}

// fetchFromServer sends a DNS query to the DoH server with retries and returns the raw response.
func (d *dohProxy) fetchFromServer(query []byte) ([]byte, error) {
	padded := padQuery(query)

	const maxRetries = 3
	var resp *http.Response
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		var req *http.Request
		var err error
		if d.preferGET {
			req, err = d.buildGETRequest(padded)
		} else {
			req, err = d.buildPOSTRequest(padded)
		}
		if err != nil {
			return nil, err
		}

		resp, err = d.client.Do(req)
		if err != nil {
			lastErr = err
			if isRetryableError(err) {
				continue
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				if attempt == maxRetries-1 {
					d.resetClient()
				}
				continue
			}
			return nil, err
		}

		// On 405 Method Not Allowed, switch to GET and retry
		if resp.StatusCode == http.StatusMethodNotAllowed && !d.preferGET {
			resp.Body.Close()
			d.preferGET = true
			continue
		}
		break
	}

	if resp == nil {
		return nil, fmt.Errorf("DoH request failed after retries: %v", lastErr)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("DoH server returned " + resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil, err
	}

	if len(body) < 2 {
		return nil, errors.New("DoH response too short")
	}

	return body, nil
}

// backgroundRefresh fetches a fresh response for the given cache key and updates the cache.
func (d *dohProxy) backgroundRefresh(cacheKey string, query []byte) {
	defer d.refreshing.Delete(cacheKey)

	body, err := d.fetchFromServer(query)
	if err != nil {
		log.Printf("DNS background refresh error: %v", err)
		return
	}

	cacheCopy := make([]byte, len(body))
	copy(cacheCopy, body)
	cacheCopy[0], cacheCopy[1] = 0, 0
	ttl := extractMinTTL(body)
	now := time.Now()
	d.cache.Store(cacheKey, &cacheEntry{
		response:      cacheCopy,
		expiry:        now.Add(ttl),
		staleDeadline: now.Add(ttl + staleGracePeriod),
	})
}

// warmConnection pre-establishes the TCP+TLS+HTTP/2 connection by sending a root NS query.
func (d *dohProxy) warmConnection() {
	go func() {
		_, _ = d.fetchFromServer(warmupQuery)
	}()
}

func (d *dohProxy) buildPOSTRequest(query []byte) (*http.Request, error) {
	req, err := http.NewRequest("POST", d.url, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	return req, nil
}

func (d *dohProxy) buildGETRequest(query []byte) (*http.Request, error) {
	encoded := base64RawURLEncode(query)
	reqURL := d.url + "?dns=" + encoded
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	return req, nil
}

// base64RawURLEncode encodes bytes to base64url without padding (RFC 4648 §5).
func base64RawURLEncode(src []byte) string {
	const encode = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	buf := make([]byte, ((len(src)+2)/3)*4)
	n := 0
	for i := 0; i < len(src); i += 3 {
		var val uint32
		remaining := len(src) - i
		switch {
		case remaining >= 3:
			val = uint32(src[i])<<16 | uint32(src[i+1])<<8 | uint32(src[i+2])
			buf[n] = encode[val>>18&0x3f]
			buf[n+1] = encode[val>>12&0x3f]
			buf[n+2] = encode[val>>6&0x3f]
			buf[n+3] = encode[val&0x3f]
			n += 4
		case remaining == 2:
			val = uint32(src[i])<<16 | uint32(src[i+1])<<8
			buf[n] = encode[val>>18&0x3f]
			buf[n+1] = encode[val>>12&0x3f]
			buf[n+2] = encode[val>>6&0x3f]
			n += 3
		case remaining == 1:
			val = uint32(src[i]) << 16
			buf[n] = encode[val>>18&0x3f]
			buf[n+1] = encode[val>>12&0x3f]
			n += 2
		}
	}
	return string(buf[:n])
}

// isRetryableError returns true for transient errors worth retrying (EOF, connection reset).
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "broken pipe")
}

// padQuery adds EDNS0 padding (RFC 8467) to a DNS query, padding to 128-byte blocks.
func padQuery(query []byte) []byte {
	query = ensureEDNS0(query)
	padLen := computePaddingSize(len(query))
	if padLen <= 0 {
		return query
	}
	// Append EDNS0 padding option: code=12, length=padLen, data=zeros
	opt := make([]byte, 4+padLen)
	binary.BigEndian.PutUint16(opt[0:2], 12)             // option code: padding
	binary.BigEndian.PutUint16(opt[2:4], uint16(padLen))  // option length
	// opt[4:] is already zeroed

	// Update OPT record RDLENGTH (last OPT record in additional section)
	// The OPT RDLENGTH is at the end of the fixed OPT fields, before RDATA
	// We need to find and update it
	result := make([]byte, len(query)+len(opt))
	copy(result, query)
	// Update RDLENGTH of the OPT record
	// OPT record ends at len(query), RDLENGTH is at len(query)-2 relative to RDATA start
	// Actually, we appended OPT in ensureEDNS0 with RDLENGTH=0 at the end
	// The RDLENGTH field is 2 bytes before the end of the current query (before any RDATA)
	rdlenOffset := len(query) - 2
	if rdlenOffset >= 12 {
		existingRDLen := binary.BigEndian.Uint16(query[rdlenOffset : rdlenOffset+2])
		binary.BigEndian.PutUint16(result[rdlenOffset:rdlenOffset+2], existingRDLen+uint16(len(opt)))
	}
	copy(result[len(query):], opt)
	return result
}

// ensureEDNS0 ensures the query has an OPT pseudo-record in the additional section.
// If one already exists, returns the query as-is.
func ensureEDNS0(query []byte) []byte {
	if len(query) < 12 {
		return query
	}

	arcount := binary.BigEndian.Uint16(query[10:12])

	// Check if OPT record already exists by scanning additional section
	qdcount := binary.BigEndian.Uint16(query[4:6])
	ancount := binary.BigEndian.Uint16(query[6:8])
	nscount := binary.BigEndian.Uint16(query[8:10])

	offset := 12
	// Skip questions
	for i := 0; i < int(qdcount); i++ {
		offset = skipDNSName(query, offset)
		if offset < 0 || offset+4 > len(query) {
			return query
		}
		offset += 4
	}
	// Skip answers
	for i := 0; i < int(ancount); i++ {
		offset = skipResourceRecord(query, offset)
		if offset < 0 {
			return query
		}
	}
	// Skip authority
	for i := 0; i < int(nscount); i++ {
		offset = skipResourceRecord(query, offset)
		if offset < 0 {
			return query
		}
	}
	// Check additional section for OPT (type 41)
	for i := 0; i < int(arcount); i++ {
		rrStart := offset
		offset = skipDNSName(query, offset)
		if offset < 0 || offset+10 > len(query) {
			return query
		}
		rrType := binary.BigEndian.Uint16(query[offset : offset+2])
		if rrType == 41 {
			// OPT record already exists
			return query
		}
		rdlen := binary.BigEndian.Uint16(query[offset+8 : offset+10])
		offset = offset + 10 + int(rdlen)
		_ = rrStart
	}

	// Append minimal OPT pseudo-record: name=0x00, type=41, class=4096(UDP size), TTL=0, RDLENGTH=0
	opt := []byte{
		0x00,       // root name
		0x00, 0x29, // type = OPT (41)
		0x10, 0x00, // class = 4096 (UDP payload size)
		0x00, 0x00, 0x00, 0x00, // TTL (extended RCODE + flags)
		0x00, 0x00, // RDLENGTH = 0
	}
	result := make([]byte, len(query)+len(opt))
	copy(result, query)
	copy(result[len(query):], opt)
	// Increment ARCOUNT
	binary.BigEndian.PutUint16(result[10:12], arcount+1)
	return result
}

// skipResourceRecord skips a DNS resource record and returns the new offset.
func skipResourceRecord(data []byte, offset int) int {
	offset = skipDNSName(data, offset)
	if offset < 0 || offset+10 > len(data) {
		return -1
	}
	rdlen := binary.BigEndian.Uint16(data[offset+8 : offset+10])
	return offset + 10 + int(rdlen)
}

// computePaddingSize returns the number of padding bytes needed to reach the next 128-byte block.
// Accounts for the 4-byte EDNS0 option header (code + length).
func computePaddingSize(currentLen int) int {
	// We'll add 4 bytes of option header + padLen bytes of padding
	// Want total = next multiple of 128
	total := currentLen + 4 // minimum: option header only
	remainder := total % 128
	if remainder == 0 {
		return 0
	}
	return 128 - remainder
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
		doh.warmConnection()
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
	if len(query) < 12 {
		return nil, errors.New("DNS query too short")
	}

	// Save original transaction ID and zero it for cache key
	origID := [2]byte{query[0], query[1]}
	query[0], query[1] = 0, 0

	cacheKey := string(query)
	if v, ok := p.cache.Load(cacheKey); ok {
		entry := v.(*cacheEntry)
		if time.Now().Before(entry.expiry) {
			resp := make([]byte, len(entry.response))
			copy(resp, entry.response)
			resp[0], resp[1] = origID[0], origID[1]
			query[0], query[1] = origID[0], origID[1]
			return resp, nil
		}
		p.cache.Delete(cacheKey)
	}

	// Restore original ID for wire query (UDP servers expect it)
	query[0], query[1] = origID[0], origID[1]

	var lastErr error
	for _, server := range p.servers {
		resp, err := p.queryServer(server, query)
		if err != nil {
			lastErr = err
			continue
		}
		// Cache with zeroed transaction ID
		cacheCopy := make([]byte, len(resp))
		copy(cacheCopy, resp)
		cacheCopy[0], cacheCopy[1] = 0, 0
		ttl := extractMinTTL(resp)
		p.cache.Store(cacheKey, &cacheEntry{
			response: cacheCopy,
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
						deadline := entry.staleDeadline
					if deadline.IsZero() {
						deadline = entry.expiry
					}
					if now.After(deadline) {
							cache.Delete(key)
						}
					}
					return true
				})
			}
		}
	}()
}
