package usquebind

import (
	"bytes"
	"container/list"
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
var globalTLSSessionCache = tls.NewLRUClientSessionCache(32)

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
	cache      *lruCache            // bounded LRU: query content -> *cacheEntry
	refreshing sync.Map             // cache keys currently being background-refreshed
	makeClient func() *http.Client  // factory for recreating client on network errors
	preferGET  bool                 // flip to true on HTTP 405, stay on GET
}

type cacheEntry struct {
	response      []byte
	expiry        time.Time
	staleDeadline time.Time
	originalTTL   time.Duration
}

const staleGracePeriod = 30 * time.Minute

// lruCache is a bounded, thread-safe LRU cache keyed by string.
type lruCache struct {
	mu       sync.Mutex
	capacity int
	items    map[string]*list.Element
	order    *list.List // front = most recently used
}

type lruItem struct {
	key   string
	value *cacheEntry
}

func newLRUCache(capacity int) *lruCache {
	return &lruCache{
		capacity: capacity,
		items:    make(map[string]*list.Element, capacity),
		order:    list.New(),
	}
}

func (c *lruCache) get(key string) (*cacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.order.MoveToFront(el)
		return el.Value.(*lruItem).value, true
	}
	return nil, false
}

func (c *lruCache) put(key string, entry *cacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.order.MoveToFront(el)
		el.Value.(*lruItem).value = entry
		return
	}
	if c.order.Len() >= c.capacity {
		back := c.order.Back()
		if back != nil {
			c.order.Remove(back)
			delete(c.items, back.Value.(*lruItem).key)
		}
	}
	el := c.order.PushFront(&lruItem{key: key, value: entry})
	c.items[key] = el
}

func (c *lruCache) delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.order.Remove(el)
		delete(c.items, key)
	}
}

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
			MaxConnsPerHost:       2,
			MaxIdleConns:          2,
			MaxIdleConnsPerHost:   2,
			IdleConnTimeout:       300 * time.Second,
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
		cache:      newLRUCache(1024),
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
	if entry, ok := d.cache.get(cacheKey); ok {
		now := time.Now()
		if now.Before(entry.expiry) {
			// Fresh hit — return immediately
			resp := make([]byte, len(entry.response))
			copy(resp, entry.response)
			resp[0], resp[1] = origID[0], origID[1]
			query[0], query[1] = origID[0], origID[1]
			// Proactive refresh at 75% TTL for popular entries
			if entry.originalTTL > 0 {
				refreshAt := entry.expiry.Add(-entry.originalTTL / 4)
				if now.After(refreshAt) {
					if _, loaded := d.refreshing.LoadOrStore(cacheKey, struct{}{}); !loaded {
						queryCopy := make([]byte, len(query))
						copy(queryCopy, query)
						queryCopy[0], queryCopy[1] = 0, 0
						go d.backgroundRefresh(cacheKey, queryCopy)
					}
				}
			}
			return resp, nil
		}
		if now.Before(entry.staleDeadline) {
			// Stale hit — return immediately, refresh in background
			resp := make([]byte, len(entry.response))
			copy(resp, entry.response)
			resp[0], resp[1] = origID[0], origID[1]
			query[0], query[1] = origID[0], origID[1]
			if _, loaded := d.refreshing.LoadOrStore(cacheKey, struct{}{}); !loaded {
				queryCopy := make([]byte, len(query))
				copy(queryCopy, query)
				queryCopy[0], queryCopy[1] = 0, 0
				go d.backgroundRefresh(cacheKey, queryCopy)
			}
			return resp, nil
		}
		// Fully expired — delete and fall through to network fetch
		d.cache.delete(cacheKey)
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
	d.cache.put(cacheKey, &cacheEntry{
		response:      cacheCopy,
		expiry:        now.Add(ttl),
		staleDeadline: now.Add(ttl + staleGracePeriod),
		originalTTL:   ttl,
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
	d.cache.put(cacheKey, &cacheEntry{
		response:      cacheCopy,
		expiry:        now.Add(ttl),
		staleDeadline: now.Add(ttl + staleGracePeriod),
		originalTTL:   ttl,
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

// extractMinTTL parses a DNS response to find the minimum TTL, clamped to [60s, 600s].
func extractMinTTL(resp []byte) time.Duration {
	const minTTL = 60 * time.Second
	const maxTTL = 1800 * time.Second

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
	poolBuf   *[]byte // if non-nil, return to dnsQueryPool after use
}

// dnsInterceptor intercepts all port 53 traffic and resolves via DoH.
type dnsInterceptor struct {
	resolver  func(query []byte) ([]byte, error)
	reqCh     chan dnsRequest
	resetFunc func() // called on network change to discard stale connections
}

// newDnsInterceptor creates a dnsInterceptor that resolves all DNS via DoH.
// Returns nil if no DoH URL is configured.
func newDnsInterceptor(ctx context.Context, cfg *tunnelConfig, protector VpnProtector) *dnsInterceptor {
	if cfg.DoHURL == "" {
		return nil
	}

	doh := newDohProxy(cfg.DoHURL, protector)
	doh.warmConnection()

	d := &dnsInterceptor{
		resolver: doh.resolve,
		reqCh:    make(chan dnsRequest, 256),
		resetFunc: func() {
			doh.resetClient()
			doh.warmConnection()
		},
	}

	// Bounded worker pool for DNS resolution.
	const numWorkers = 4
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

	return d
}

// systemDnsResolver forwards DNS queries via protected UDP sockets to system DNS servers.
type systemDnsResolver struct {
	servers   []string
	protector VpnProtector
	cache     *lruCache
	refreshing sync.Map
}

func newSystemDnsResolver(servers []string, protector VpnProtector) *systemDnsResolver {
	return &systemDnsResolver{
		servers:   servers,
		protector: protector,
		cache:     newLRUCache(1024),
	}
}

// resolve sends a DNS query to system DNS servers via protected UDP sockets.
func (s *systemDnsResolver) resolve(query []byte) ([]byte, error) {
	if len(query) < 12 {
		return nil, errors.New("DNS query too short")
	}

	// Save original transaction ID and zero it for cache key
	origID := [2]byte{query[0], query[1]}
	query[0], query[1] = 0, 0

	cacheKey := string(query)
	if entry, ok := s.cache.get(cacheKey); ok {
		now := time.Now()
		if now.Before(entry.expiry) {
			resp := make([]byte, len(entry.response))
			copy(resp, entry.response)
			resp[0], resp[1] = origID[0], origID[1]
			query[0], query[1] = origID[0], origID[1]
			// Proactive refresh at 75% TTL
			if entry.originalTTL > 0 {
				refreshAt := entry.expiry.Add(-entry.originalTTL / 4)
				if now.After(refreshAt) {
					if _, loaded := s.refreshing.LoadOrStore(cacheKey, struct{}{}); !loaded {
						queryCopy := make([]byte, len(query))
						copy(queryCopy, query)
						queryCopy[0], queryCopy[1] = 0, 0
						go s.backgroundRefresh(cacheKey, queryCopy)
					}
				}
			}
			return resp, nil
		}
		if now.Before(entry.staleDeadline) {
			resp := make([]byte, len(entry.response))
			copy(resp, entry.response)
			resp[0], resp[1] = origID[0], origID[1]
			query[0], query[1] = origID[0], origID[1]
			if _, loaded := s.refreshing.LoadOrStore(cacheKey, struct{}{}); !loaded {
				queryCopy := make([]byte, len(query))
				copy(queryCopy, query)
				queryCopy[0], queryCopy[1] = 0, 0
				go s.backgroundRefresh(cacheKey, queryCopy)
			}
			return resp, nil
		}
		s.cache.delete(cacheKey)
	}

	body, err := s.queryServers(query)
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
	s.cache.put(cacheKey, &cacheEntry{
		response:      cacheCopy,
		expiry:        now.Add(ttl),
		staleDeadline: now.Add(ttl + staleGracePeriod),
		originalTTL:   ttl,
	})

	body[0], body[1] = origID[0], origID[1]
	query[0], query[1] = origID[0], origID[1]
	return body, nil
}

// queryServers sends a DNS query to each configured server until one succeeds.
func (s *systemDnsResolver) queryServers(query []byte) ([]byte, error) {
	var lastErr error
	for _, server := range s.servers {
		resp, err := s.queryServer(server, query)
		if err != nil {
			lastErr = err
			continue
		}
		return resp, nil
	}
	return nil, fmt.Errorf("all system DNS servers failed: %v", lastErr)
}

// queryServer sends a DNS query to a single server via a protected UDP socket.
func (s *systemDnsResolver) queryServer(server string, query []byte) ([]byte, error) {
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(server, "53"))
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", server, err)
	}

	// Determine local address family to match the server
	localAddr := &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	if addr.IP.To4() == nil {
		localAddr = &net.UDPAddr{IP: net.IPv6zero, Port: 0}
	}

	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	defer conn.Close()

	// Protect socket from VPN routing
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("syscall conn: %w", err)
	}
	var protectErr error
	rawConn.Control(func(fd uintptr) {
		if !s.protector.ProtectFd(int(fd)) {
			protectErr = errors.New("VPN protect() failed for DNS socket")
		}
	})
	if protectErr != nil {
		return nil, protectErr
	}

	conn.SetDeadline(time.Now().Add(2 * time.Second))

	_, err = conn.WriteToUDP(query, addr)
	if err != nil {
		return nil, fmt.Errorf("write to %s: %w", server, err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read from %s: %w", server, err)
	}

	if n < 12 {
		return nil, fmt.Errorf("response from %s too short (%d bytes)", server, n)
	}

	resp := make([]byte, n)
	copy(resp, buf[:n])
	return resp, nil
}

func (s *systemDnsResolver) backgroundRefresh(cacheKey string, query []byte) {
	defer s.refreshing.Delete(cacheKey)

	body, err := s.queryServers(query)
	if err != nil {
		log.Printf("System DNS background refresh error: %v", err)
		return
	}

	cacheCopy := make([]byte, len(body))
	copy(cacheCopy, body)
	cacheCopy[0], cacheCopy[1] = 0, 0
	ttl := extractMinTTL(body)
	now := time.Now()
	s.cache.put(cacheKey, &cacheEntry{
		response:      cacheCopy,
		expiry:        now.Add(ttl),
		staleDeadline: now.Add(ttl + staleGracePeriod),
		originalTTL:   ttl,
	})
}

// newSystemDnsInterceptor creates a dnsInterceptor that forwards DNS queries
// to system DNS servers via protected UDP sockets (bypassing the VPN).
func newSystemDnsInterceptor(ctx context.Context, servers []string, protector VpnProtector) *dnsInterceptor {
	if len(servers) == 0 {
		return nil
	}

	resolver := newSystemDnsResolver(servers, protector)

	d := &dnsInterceptor{
		resolver:  resolver.resolve,
		reqCh:     make(chan dnsRequest, 256),
		resetFunc: nil, // no persistent connections to reset
	}

	const numWorkers = 4
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

// close is a no-op (DoH client is GC'd with the interceptor).
func (d *dnsInterceptor) close() {}

// resetConnections discards stale DNS connections after a network change.
func (d *dnsInterceptor) resetConnections() {
	if d.resetFunc != nil {
		d.resetFunc()
	}
}

// handleInterceptedDNS resolves a DNS query and writes the response packet back.
func (d *dnsInterceptor) handleInterceptedDNS(req dnsRequest) {
	if req.poolBuf != nil {
		defer dnsQueryPool.Put(req.poolBuf)
	}
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

// isAnyDNSResponsePacket checks if pkt is an IPv4 UDP packet FROM port 53 (DNS response).
func isAnyDNSResponsePacket(pkt []byte) (srcIP net.IP, srcPort uint16, dstIP net.IP, payload []byte, ok bool) {
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
	if binary.BigEndian.Uint16(pkt[ihl:ihl+2]) != 53 {
		return nil, 0, nil, nil, false
	}
	srcIP = net.IP(pkt[12:16]).To4()
	srcPort = 53
	dstIP = net.IP(pkt[16:20]).To4()
	payload = pkt[ihl+8:]
	ok = true
	return
}

// isAnyDNSResponseV6Packet checks if pkt is an IPv6 UDP packet FROM port 53 (DNS response).
func isAnyDNSResponseV6Packet(pkt []byte) (srcIP net.IP, srcPort uint16, dstIP net.IP, payload []byte, ok bool) {
	if len(pkt) < 60 {
		return nil, 0, nil, nil, false
	}
	if pkt[0]>>4 != 6 {
		return nil, 0, nil, nil, false
	}
	if pkt[6] != 17 {
		return nil, 0, nil, nil, false
	}
	if binary.BigEndian.Uint16(pkt[40:42]) != 53 {
		return nil, 0, nil, nil, false
	}
	srcIP = make(net.IP, 16)
	copy(srcIP, pkt[8:24])
	srcPort = 53
	dstIP = make(net.IP, 16)
	copy(dstIP, pkt[24:40])
	payload = pkt[48:]
	ok = true
	return
}

// dnsQuestionKey extracts the question section (QNAME+QTYPE+QCLASS) from a DNS message
// for use as a cache key. Works for both queries and responses.
func dnsQuestionKey(payload []byte) (string, bool) {
	if len(payload) < 12 {
		return "", false
	}
	qdcount := binary.BigEndian.Uint16(payload[4:6])
	if qdcount == 0 {
		return "", false
	}
	start := 12
	end := skipDNSName(payload, start)
	if end < 0 || end+4 > len(payload) {
		return "", false
	}
	end += 4 // QTYPE + QCLASS
	return string(payload[start:end]), true
}

// tunnelDnsCache caches DNS responses for non-DoH mode to avoid redundant tunnel round-trips.
type tunnelDnsCache struct {
	cache *lruCache
}

func newTunnelDnsCache(capacity int) *tunnelDnsCache {
	return &tunnelDnsCache{
		cache: newLRUCache(capacity),
	}
}

// checkAndRespond checks a DNS query packet against the cache.
// Returns true if a cached response was written to TUN (cache hit).
func (c *tunnelDnsCache) checkAndRespond(pkt []byte, writeFunc func([]byte) error) bool {
	var srcIP, dstIP net.IP
	var srcPort uint16
	var query []byte
	var isIPv6 bool

	if s, sp, d, q, ok := isAnyDNSPacket(pkt); ok {
		srcIP, srcPort, dstIP, query = s, sp, d, q
	} else if s, sp, d, q, ok := isAnyDNSv6Packet(pkt); ok {
		srcIP, srcPort, dstIP, query = s, sp, d, q
		isIPv6 = true
	} else {
		return false
	}

	if len(query) < 12 {
		return false
	}

	key, ok := dnsQuestionKey(query)
	if !ok {
		return false
	}

	entry, ok := c.cache.get(key)
	if !ok {
		return false
	}

	now := time.Now()
	if now.After(entry.staleDeadline) {
		c.cache.delete(key)
		return false
	}

	// Build response with original transaction ID
	resp := make([]byte, len(entry.response))
	copy(resp, entry.response)
	resp[0], resp[1] = query[0], query[1]

	buf := dnsResponsePool.Get().([]byte)
	var responsePkt []byte
	if isIPv6 {
		responsePkt = buildDNSResponseIPv6(buf, dstIP, srcIP, srcPort, resp)
	} else {
		responsePkt = buildDNSResponseIPv4(buf, dstIP, srcIP, srcPort, resp)
	}

	err := writeFunc(responsePkt)
	dnsResponsePool.Put(buf)
	return err == nil
}

// cacheResponse extracts DNS response data from an incoming packet and caches it.
func (c *tunnelDnsCache) cacheResponse(pkt []byte) {
	var payload []byte

	if _, _, _, p, ok := isAnyDNSResponsePacket(pkt); ok {
		payload = p
	} else if _, _, _, p, ok := isAnyDNSResponseV6Packet(pkt); ok {
		payload = p
	} else {
		return
	}

	if len(payload) < 12 {
		return
	}
	// Only cache responses (QR bit set)
	if payload[2]&0x80 == 0 {
		return
	}
	// Only cache successful responses (NOERROR=0 or NXDOMAIN=3)
	rcode := payload[3] & 0x0f
	if rcode != 0 && rcode != 3 {
		return
	}

	key, ok := dnsQuestionKey(payload)
	if !ok {
		return
	}

	ttl := extractMinTTL(payload)
	cacheCopy := make([]byte, len(payload))
	copy(cacheCopy, payload)
	cacheCopy[0], cacheCopy[1] = 0, 0

	now := time.Now()
	c.cache.put(key, &cacheEntry{
		response:      cacheCopy,
		expiry:        now.Add(ttl),
		staleDeadline: now.Add(ttl + staleGracePeriod),
		originalTTL:   ttl,
	})
}

