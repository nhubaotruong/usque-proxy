// Package usquebind provides gomobile-compatible bindings for the usque library,
// enabling Android VPN integration via MASQUE/Connect-IP.
package usquebind

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/models"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

const (
	defaultSNI    = "consumer-masque.cloudflareclient.com"
	ZeroTrustSNI  = "zt-masque.cloudflareclient.com"
	defaultURI    = "https://cloudflareaccess.com"
	defaultLocale = "en_US"
)

// quicSessionCache enables TLS session resumption across QUIC reconnects (1-RTT, not 0-RTT).
var quicSessionCache = tls.NewLRUClientSessionCache(8)

// taggedEndpoint pairs a resolved UDP address with a label for logging.
type taggedEndpoint struct {
	addr *net.UDPAddr
	tag  string
}

// connResult holds the outcome of a single tunnel connection attempt.
type connResult struct {
	udpConn *net.UDPConn
	tr      *http3.Transport
	ipConn  *connectip.Conn
	rsp     *http.Response
	err     error
	tag     string
}

// tunnelConfig extends config.Config with optional tunnel parameters.
type tunnelConfig struct {
	config.Config
	SNI         string   `json:"sni"`
	ConnectURI  string   `json:"connect_uri"`
	DoHURL      string   `json:"doh_url"`
	DoQURL      string   `json:"doq_url"`
	SystemDNS      []string `json:"system_dns"`
	PrivateDNS     bool     `json:"private_dns_active"`
}

func (t *tunnelConfig) sni() string {
	if t.SNI != "" {
		return t.SNI
	}
	return defaultSNI
}

func (t *tunnelConfig) connectUri() string {
	if t.ConnectURI != "" {
		return t.ConnectURI
	}
	return defaultURI
}

// VpnProtector is implemented by Android's VpnService to protect sockets
// from being routed through the VPN tunnel.
type VpnProtector interface {
	ProtectFd(fd int) bool
}

// FdAdapter wraps an OS file descriptor (from Android's VpnService TUN) to
// satisfy usque's api.TunnelDevice interface.
type FdAdapter struct {
	file *os.File
}

func (f *FdAdapter) ReadPacket(buf []byte) (int, error) {
	return f.file.Read(buf)
}

func (f *FdAdapter) WritePacket(pkt []byte) error {
	_, err := f.file.Write(pkt)
	return err
}

// dnsQueryPool reuses buffers for DNS query copies in forwardUp, reducing GC pressure.
var dnsQueryPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 0, 512) // typical DNS query size
		return &buf
	},
}

// tunnel state
var (
	mu          sync.Mutex
	cancel      context.CancelFunc
	running     atomic.Bool
	connected   atomic.Bool  // true when MASQUE tunnel is forwarding traffic
	done        chan struct{} // closed when maintainTunnel returns
	reconnectCh chan struct{}
	startTime   time.Time
	connectedAt atomic.Int64 // unix millis when last connected (0 if not connected)
	txBytes     atomic.Int64
	rxBytes     atomic.Int64
	lastError    atomic.Value // string: last connection error message
	hasNetwork   atomic.Bool  // set by Android via SetConnectivity
	connectCount atomic.Int64 // number of connection attempts since StartTunnel
)

// StartTunnel starts the MASQUE tunnel. Blocks until StopTunnel or error.
// If a previous tunnel is still winding down, waits up to 5s for it to finish.
func StartTunnel(configJSON string, tunFd int, protector VpnProtector) error {
	mu.Lock()
	if running.Load() {
		d := done
		mu.Unlock()
		// Previous tunnel still shutting down — wait up to 5s
		if d != nil {
			select {
			case <-d:
			case <-time.After(5 * time.Second):
				return errors.New("timeout waiting for previous tunnel to stop")
			}
		}
		mu.Lock()
		if running.Load() {
			mu.Unlock()
			return errors.New("tunnel already running")
		}
	}

	var tcfg tunnelConfig
	if err := json.Unmarshal([]byte(configJSON), &tcfg); err != nil {
		mu.Unlock()
		return fmt.Errorf("invalid config JSON: %w", err)
	}
	config.AppConfig = tcfg.Config
	config.ConfigLoaded = true

	ctx, c := context.WithCancel(context.Background())
	cancel = c
	done = make(chan struct{})
	reconnectCh = make(chan struct{}, 1)
	running.Store(true)
	connected.Store(false)
	hasNetwork.Store(true)
	lastError.Store("")
	startTime = time.Now()
	connectedAt.Store(0)
	connectCount.Store(0)
	txBytes.Store(0)
	rxBytes.Store(0)
	mu.Unlock()

	tunFile := os.NewFile(uintptr(tunFd), "tun")
	device := &FdAdapter{file: tunFile}

	err := maintainTunnel(ctx, &tcfg, device, protector)
	running.Store(false)
	close(done)
	return err
}

// StopTunnel cancels the running tunnel.
func StopTunnel() {
	mu.Lock()
	defer mu.Unlock()
	if cancel != nil {
		cancel()
		cancel = nil
	}
}

// SetConnectivity tells the tunnel whether the device has network.
// When false, the reconnect loop sleeps instead of hammering failed dials.
// Call from Kotlin: true on onAvailable, false on onLost (no active network).
func SetConnectivity(networkAvailable bool) {
	wasConnected := hasNetwork.Swap(networkAvailable)
	if networkAvailable && !wasConnected {
		// Network restored — trigger reconnect to pick up the new network
		Reconnect()
	}
}

// Reconnect tears down the current QUIC connection but keeps the reconnect
// loop alive so it re-establishes on the (possibly new) network.
func Reconnect() {
	mu.Lock()
	ch := reconnectCh
	mu.Unlock()
	if ch != nil {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// IsRunning returns whether the tunnel is currently active.
func IsRunning() bool {
	return running.Load()
}

// GetStats returns JSON with tunnel statistics.
func GetStats() string {
	stats := map[string]interface{}{
		"running":    running.Load(),
		"connected":  connected.Load(),
		"tx_bytes":   txBytes.Load(),
		"rx_bytes":   rxBytes.Load(),
		"uptime_sec": 0,
		"has_network":    hasNetwork.Load(),
		"connect_count":  connectCount.Load(),
	}
	if e, ok := lastError.Load().(string); ok && e != "" {
		stats["last_error"] = e
	}
	if running.Load() {
		stats["uptime_sec"] = int(time.Since(startTime).Seconds())
	}
	if t := connectedAt.Load(); t > 0 {
		stats["connected_since_ms"] = t
	}
	b, _ := json.Marshal(stats)
	return string(b)
}

// Register performs WARP device registration and returns config JSON to persist.
func Register(license string) (string, error) {
	accountData, err := api.Register("Android", defaultLocale, "", true)
	if err != nil {
		return "", fmt.Errorf("registration failed: %w", err)
	}
	return enrollAndBuildConfig(accountData, license)
}

// RegisterWithJWT performs ZeroTrust device registration using a JWT token
// obtained from https://<team-domain>/warp and returns config JSON to persist.
func RegisterWithJWT(jwt string) (string, error) {
	jwt = strings.TrimSpace(jwt)
	accountData, err := api.Register("Android", defaultLocale, jwt, true)
	if err != nil {
		return "", fmt.Errorf("registration failed: %w", err)
	}
	return enrollAndBuildConfig(accountData, "")
}

// enrollAndBuildConfig generates a key pair, enrolls it with the API, and
// returns the serialized config JSON.
func enrollAndBuildConfig(accountData models.AccountData, license string) (string, error) {
	privKeyDER, updatedAccount, err := generateAndEnroll(accountData)
	if err != nil {
		return "", err
	}

	cfg := config.Config{
		PrivateKey:  base64.StdEncoding.EncodeToString(privKeyDER),
		ID:          accountData.ID,
		AccessToken: accountData.Token,
		License:     license,
	}
	applyAccountToConfig(&cfg, updatedAccount)

	result, err := json.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("failed to serialize config: %w", err)
	}
	return string(result), nil
}

// Enroll re-enrolls an existing config with a new key pair, refreshing
// endpoints and addresses from the server. Useful for device migration,
// WireGuard→MASQUE switch, or updating ZeroTrust IPv6 addresses.
func Enroll(configJSON string) (string, error) {
	var cfg config.Config
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return "", fmt.Errorf("invalid config JSON: %w", err)
	}
	if cfg.ID == "" || cfg.AccessToken == "" {
		return "", errors.New("config must contain id and access_token")
	}

	accountData := models.AccountData{ID: cfg.ID, Token: cfg.AccessToken}
	privKeyDER, updatedAccount, err := generateAndEnroll(accountData)
	if err != nil {
		return "", err
	}

	cfg.PrivateKey = base64.StdEncoding.EncodeToString(privKeyDER)
	applyAccountToConfig(&cfg, updatedAccount)

	result, err := json.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("failed to serialize config: %w", err)
	}
	return string(result), nil
}

// generateAndEnroll creates a new EC key pair and enrolls it with the API.
func generateAndEnroll(accountData models.AccountData) (privKeyDER []byte, updatedAccount *models.AccountData, err error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("key generation failed: %w", err)
	}
	privKeyDER, err = x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("private key marshal failed: %w", err)
	}
	pubKeyPKIX, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("public key marshal failed: %w", err)
	}

	updated, apiErr, err := api.EnrollKey(accountData, pubKeyPKIX, "UsqueProxy")
	if err != nil {
		if apiErr != nil {
			return nil, nil, fmt.Errorf("enrollment failed: %s", apiErr.ErrorsAsString("; "))
		}
		return nil, nil, fmt.Errorf("enrollment failed: %w", err)
	}
	return privKeyDER, &updated, nil
}

// applyAccountToConfig updates a config with peer endpoints and addresses from the API response.
func applyAccountToConfig(cfg *config.Config, account *models.AccountData) {
	if len(account.Config.Peers) > 0 {
		peer := account.Config.Peers[0]
		cfg.EndpointPubKey = peer.PublicKey
		cfg.EndpointV4 = cleanEndpoint(peer.Endpoint.V4)
		cfg.EndpointV6 = cleanEndpoint(peer.Endpoint.V6)
	}
	cfg.IPv4 = account.Config.Interface.Addresses.V4
	cfg.IPv6 = account.Config.Interface.Addresses.V6
}

func cleanEndpoint(ep string) string {
	ep = strings.TrimPrefix(ep, "[")
	ep = strings.TrimSuffix(ep, "]")
	if host, _, err := net.SplitHostPort(ep); err == nil {
		return host
	}
	return ep
}

// maintainTunnel reconnects in a loop. We can't use api.MaintainTunnel
// directly because it calls ConnectTunnel without a protect() hook.
func maintainTunnel(ctx context.Context, cfg *tunnelConfig, device api.TunnelDevice, protector VpnProtector) error {
	const (
		mtu             = 1280
		connectPort     = 443
		reconnectDelay  = 1 * time.Second
		certRenewBefore = 1 * time.Hour // renew cert 1h before expiry
	)

	privKey, err := cfg.GetEcPrivateKey()
	if err != nil {
		return fmt.Errorf("private key: %w", err)
	}
	peerPubKey, err := cfg.GetEcEndpointPublicKey()
	if err != nil {
		return fmt.Errorf("endpoint public key: %w", err)
	}

	pool := api.NewNetBuffer(mtu)

	// Create DNS interceptor (DoH or System DNS) or tunnel DNS cache (fallback).
	// When Android Private DNS (DoT) is active with system DNS mode, skip our
	// system DNS interception — Android resolves DNS directly via DoT, so our
	// interceptor would just add latency for no benefit.
	var dns *dnsInterceptor
	var dnsCache *tunnelDnsCache
	if cfg.DoHURL != "" {
		dns = newDnsInterceptor(ctx, cfg, protector)
		if dns != nil {
			defer dns.close()
			log.Println("DNS interception enabled: all port 53 traffic via DoH")
		}
	} else if cfg.DoQURL != "" {
		dns = newDoqDnsInterceptor(ctx, cfg.DoQURL, protector)
		if dns != nil {
			defer dns.close()
			log.Println("DNS interception enabled: all port 53 traffic via DoQ")
		}
	} else if len(cfg.SystemDNS) > 0 && !cfg.PrivateDNS {
		dns = newSystemDnsInterceptor(ctx, cfg.SystemDNS, protector)
		if dns != nil {
			defer dns.close()
			log.Printf("System DNS interception enabled: forwarding via protected sockets to %v", cfg.SystemDNS)
		}
	} else if len(cfg.SystemDNS) > 0 && cfg.PrivateDNS {
		log.Println("Android Private DNS active — skipping system DNS interception, DNS handled by OS via DoT")
	} else {
		dnsCache = newTunnelDnsCache(512)
		log.Println("DNS tunnel cache enabled")
	}

	// Certificate cache: generate once, reuse until near expiry.
	var cachedCert [][]byte
	var certExpiry time.Time

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		// Reuse cached cert if still valid; regenerate only when near expiry.
		if cachedCert == nil || time.Now().After(certExpiry.Add(-certRenewBefore)) {
			cert, err := selfSignedCert(privKey)
			if err != nil {
				lastError.Store(err.Error())
				log.Printf("cert generation: %v", err)
				sleepCtx(ctx, reconnectDelay)
				continue
			}
			cachedCert = cert
			certExpiry = time.Now().Add(24 * time.Hour)
		}

		tlsCfg, err := api.PrepareTlsConfig(privKey, peerPubKey, cachedCert, cfg.sni())
		if err != nil {
			lastError.Store(err.Error())
			log.Printf("TLS config: %v", err)
			sleepCtx(ctx, reconnectDelay)
			continue
		}

		tlsCfg.ClientSessionCache = quicSessionCache // 1-RTT session resumption (not 0-RTT)

		quicCfg := &quic.Config{
			EnableDatagrams:         true,
			InitialPacketSize:       1280,
			KeepAlivePeriod:         30 * time.Second,
			MaxIdleTimeout:          120 * time.Second,
			DisablePathMTUDiscovery: true,
		}

		connectCount.Add(1)
		udpConn, tr, ipConn, rsp, err := connectHappyEyeballs(
			ctx, tlsCfg, quicCfg,
			cfg.EndpointV4, cfg.EndpointV6,
			connectPort, cfg.connectUri(), protector,
		)
		if err != nil {
			lastError.Store(err.Error())
			log.Printf("connect: %v", err)
			// If no network, wait for SetConnectivity(true) instead of hammering
			if !hasNetwork.Load() {
				log.Println("no network — waiting for connectivity")
				waitForNetwork(ctx)
			} else {
				sleepCtx(ctx, reconnectDelay)
			}
			continue
		}
		if rsp.StatusCode != 200 {
			lastError.Store(fmt.Sprintf("tunnel rejected: %s", rsp.Status))
			log.Printf("tunnel rejected: %s", rsp.Status)
			cleanup(ipConn, udpConn, tr)
			sleepCtx(ctx, reconnectDelay)
			continue
		}

		connected.Store(true)
		connectedAt.Store(time.Now().UnixMilli())
		lastError.Store("")
		log.Println("Connected to MASQUE server")

		errChan := make(chan error, 2)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); forwardUp(device, ipConn, pool, errChan, dns, dnsCache) }()
		go func() { defer wg.Done(); forwardDown(device, ipConn, pool, errChan, dnsCache) }()

		select {
		case err = <-errChan:
			connected.Store(false)
			connectedAt.Store(0)
			lastError.Store(err.Error())
			log.Printf("tunnel lost: %v", err)
		case <-reconnectCh:
			connected.Store(false)
			connectedAt.Store(0)
			log.Println("reconnect requested")
		case <-ctx.Done():
			connected.Store(false)
			connectedAt.Store(0)
		}

		cleanup(ipConn, udpConn, tr)
		wg.Wait() // wait for forwarding goroutines to exit before reconnecting
		if ctx.Err() != nil {
			return nil
		}

		// Reset DNS connections so stale sockets are discarded
		if dns != nil {
			dns.resetConnections()
		}

		sleepCtx(ctx, reconnectDelay)
	}
}

// connectHappyEyeballs implements Happy Eyeballs v3 (RFC 8305 / draft-ietf-happy-happyeyeballs-v3)
// for the QUIC/Connect-IP tunnel connection. It races IPv6 and IPv4 with a
// 250ms staggered delay, preferring IPv6 per the spec.
func connectHappyEyeballs(
	ctx context.Context,
	tlsConfig *tls.Config,
	quicConfig *quic.Config,
	endpointV4, endpointV6 string,
	connectPort int,
	connectUri string,
	protector VpnProtector,
) (*net.UDPConn, *http3.Transport, *connectip.Conn, *http.Response, error) {
	const connectionAttemptDelay = 150 * time.Millisecond

	// Build ordered endpoint list: IPv6 first, then IPv4.
	var endpoints []taggedEndpoint
	if ip := net.ParseIP(endpointV6); ip != nil {
		endpoints = append(endpoints, taggedEndpoint{&net.UDPAddr{IP: ip, Port: connectPort}, "IPv6"})
	}
	if ip := net.ParseIP(endpointV4); ip != nil {
		endpoints = append(endpoints, taggedEndpoint{&net.UDPAddr{IP: ip, Port: connectPort}, "IPv4"})
	}

	if len(endpoints) == 0 {
		return nil, nil, nil, nil, errors.New("no valid endpoints configured")
	}

	// Single endpoint — no racing needed.
	if len(endpoints) == 1 {
		ep := endpoints[0]
		log.Printf("Connecting to %s (%s)", ep.addr, ep.tag)
		udpConn, tr, ipConn, rsp, err := connectTunnelProtected(ctx, tlsConfig, quicConfig, ep.addr, connectUri, protector)
		if err != nil {
			if udpConn != nil {
				udpConn.Close()
			}
			return nil, nil, nil, nil, err
		}
		return udpConn, tr, ipConn, rsp, nil
	}

	// Dual-stack: race with staggered start.
	raceCtx, raceCancel := context.WithCancel(ctx)
	defer raceCancel()

	ch := make(chan connResult, 2)

	attempt := func(ep taggedEndpoint) {
		log.Printf("Connecting to %s (%s)", ep.addr, ep.tag)
		udpConn, tr, ipConn, rsp, err := connectTunnelProtected(raceCtx, tlsConfig, quicConfig, ep.addr, connectUri, protector)
		r := connResult{udpConn: udpConn, tr: tr, ipConn: ipConn, rsp: rsp, err: err, tag: ep.tag}
		// Treat non-200 as failure for racing purposes.
		if err == nil && rsp.StatusCode != 200 {
			r.err = fmt.Errorf("tunnel rejected: %s", rsp.Status)
		}
		ch <- r
	}

	// Start first attempt (IPv6) immediately.
	go attempt(endpoints[0])

	// Wait for delay or first failure before starting second attempt.
	timer := time.NewTimer(connectionAttemptDelay)
	defer timer.Stop()

	remaining := 0
	select {
	case r := <-ch:
		if r.err == nil {
			// First attempt won — no need to start second.
			return r.udpConn, r.tr, r.ipConn, r.rsp, nil
		}
		// First attempt failed — start fallback immediately.
		log.Printf("%s failed: %v", r.tag, r.err)
		if r.udpConn != nil {
			r.udpConn.Close()
		}
		go attempt(endpoints[1])
		remaining = 1 // only the fallback is in flight
	case <-timer.C:
		// Delay expired — start second attempt in parallel.
		go attempt(endpoints[1])
		remaining = 2 // both attempts in flight
	case <-ctx.Done():
		return nil, nil, nil, nil, ctx.Err()
	}

	// Collect results from in-flight attempts.
	var lastErr error
	for i := 0; i < remaining; i++ {
		select {
		case r := <-ch:
			if r.err == nil {
				// Winner — cancel the other attempt and return.
				raceCancel()
				return r.udpConn, r.tr, r.ipConn, r.rsp, nil
			}
			log.Printf("%s failed: %v", r.tag, r.err)
			if r.udpConn != nil {
				r.udpConn.Close()
			}
			lastErr = r.err
		case <-ctx.Done():
			return nil, nil, nil, nil, ctx.Err()
		}
	}
	return nil, nil, nil, nil, lastErr
}

// connectTunnelProtected mirrors api.ConnectTunnel but protects the UDP
// socket fd before QUIC handshake to prevent VPN routing loops.
func connectTunnelProtected(
	ctx context.Context,
	tlsConfig *tls.Config,
	quicConfig *quic.Config,
	endpoint *net.UDPAddr,
	connectUri string,
	protector VpnProtector,
) (*net.UDPConn, *http3.Transport, *connectip.Conn, *http.Response, error) {
	// Create UDP socket
	listenAddr := &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	if endpoint.IP.To4() == nil {
		listenAddr = &net.UDPAddr{IP: net.IPv6zero, Port: 0}
	}
	udpConn, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("UDP socket: %w", err)
	}

	// Protect before QUIC handshake
	if err := protectUDPConn(udpConn, protector); err != nil {
		udpConn.Close()
		return nil, nil, nil, nil, err
	}

	// QUIC + Connect-IP (mirrors api.ConnectTunnel logic)
	conn, err := quic.Dial(ctx, udpConn, endpoint, tlsConfig, quicConfig)
	if err != nil {
		udpConn.Close()
		return nil, nil, nil, nil, err
	}

	tr := &http3.Transport{
		EnableDatagrams:    true,
		AdditionalSettings: map[uint64]uint64{0x276: 1},
		DisableCompression: true,
	}
	hconn := tr.NewClientConn(conn)
	template := uritemplate.MustNew(connectUri)
	headers := http.Header{"User-Agent": {""}}

	ipConn, rsp, err := connectip.Dial(ctx, hconn, template, "cf-connect-ip", headers, true)
	if err != nil {
		tr.Close()
		udpConn.Close()
		return nil, nil, nil, nil, fmt.Errorf("connect-ip: %v", err)
	}
	return udpConn, tr, ipConn, rsp, nil
}

func forwardUp(device api.TunnelDevice, ipConn *connectip.Conn, pool *api.NetBuffer, errChan chan<- error, dns *dnsInterceptor, dnsCache *tunnelDnsCache) {
	for {
		buf := pool.Get()
		n, err := device.ReadPacket(buf)
		if err != nil {
			pool.Put(buf)
			errChan <- err
			return
		}
		pkt := buf[:n]
		txBytes.Add(int64(n))

		// Intercept DNS packets (IPv4 and IPv6)
		if srcIP, srcPort, dstIP, query, isIPv6, ok := detectDNSQuery(pkt); ok {
			if dns != nil {
				bufPtr := dnsQueryPool.Get().(*[]byte)
				queryCopy := append((*bufPtr)[:0], query...)
				pool.Put(buf)
				dns.forwardUp(dnsRequest{
					srcIP: srcIP, srcPort: srcPort, dstIP: dstIP,
					query: queryCopy, writeFunc: device.WritePacket,
					isIPv6: isIPv6, poolBuf: bufPtr,
				})
				continue
			}
			if dnsCache != nil && dnsCache.checkAndRespond(pkt, device.WritePacket) {
				pool.Put(buf)
				continue
			}
		}

		// Send via Connect-IP datagrams (UDP, ICMP, TCP, etc.)
		icmp, err := ipConn.WritePacket(pkt)
		pool.Put(buf)
		if err != nil {
			if errors.As(err, new(*connectip.CloseError)) {
				errChan <- fmt.Errorf("connection closed while writing to IP connection: %v", err)
				return
			}
			log.Printf("Error writing to IP connection: %v, continuing...", err)
			continue
		}
		if len(icmp) > 0 {
			if err := device.WritePacket(icmp); err != nil {
				if errors.As(err, new(*connectip.CloseError)) {
					errChan <- fmt.Errorf("connection closed while writing ICMP to TUN device: %v", err)
					return
				}
				log.Printf("Error writing ICMP to TUN device: %v, continuing...", err)
			}
		}
	}
}

func forwardDown(device api.TunnelDevice, ipConn *connectip.Conn, pool *api.NetBuffer, errChan chan<- error, dnsCache *tunnelDnsCache) {
	buf := pool.Get()
	defer pool.Put(buf)
	for {
		n, err := ipConn.ReadPacket(buf, true)
		if err != nil {
			if errors.As(err, new(*connectip.CloseError)) {
				errChan <- fmt.Errorf("connection closed while reading from IP connection: %v", err)
				return
			}
			log.Printf("Error reading from IP connection: %v, continuing...", err)
			continue
		}
		rxBytes.Add(int64(n))
		if dnsCache != nil {
			dnsCache.cacheResponse(buf[:n])
		}
		if err := device.WritePacket(buf[:n]); err != nil {
			errChan <- err
			return
		}
	}
}

func selfSignedCert(privKey *ecdsa.PrivateKey) ([][]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}, &x509.Certificate{}, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, err
	}
	return [][]byte{der}, nil
}

func cleanup(ipConn *connectip.Conn, udpConn *net.UDPConn, tr *http3.Transport) {
	if ipConn != nil {
		ipConn.Close()
	}
	if udpConn != nil {
		udpConn.Close()
	}
	if tr != nil {
		tr.Close()
	}
}

// protectUDPConn marks a UDP socket as protected from VPN routing.
func protectUDPConn(conn *net.UDPConn, protector VpnProtector) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("raw conn: %w", err)
	}
	var protectErr error
	rawConn.Control(func(fd uintptr) {
		if !protector.ProtectFd(int(fd)) {
			protectErr = errors.New("VPN protect() failed")
		}
	})
	return protectErr
}

// waitForNetwork blocks until hasNetwork becomes true or ctx is cancelled.
// Polls every 500ms — SetConnectivity(true) also triggers Reconnect() which
// will wake the select in maintainTunnel if we're past the connection phase.
func waitForNetwork(ctx context.Context) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if hasNetwork.Load() {
				return
			}
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}
