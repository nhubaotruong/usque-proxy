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
	mrand "math/rand/v2"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
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
	tunnelMTU     = 1280 // must match mtu constant in maintainTunnel
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
	NetworkType    string   `json:"network_type"`
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
	done           chan struct{} // closed when maintainTunnel returns
	reconnectCh    chan struct{}
	connectivityCh chan struct{} // signalled by SetConnectivity(true) to wake waitForNetwork
	startTime   time.Time
	connectedAt atomic.Int64 // unix millis when last connected (0 if not connected)
	txBytes     atomic.Int64
	rxBytes     atomic.Int64
	lastError    atomic.Value // string: last connection error message
	hasNetwork   atomic.Bool  // set by Android via SetConnectivity
	connectCount atomic.Int64 // number of connection attempts since StartTunnel
	// lastRxTime/lastTxTime track the most recent packet activity (Unix nanos).
	// Used by the liveness goroutine to detect one-way stalls where the server
	// stops forwarding (rx frozen) while the client is still sending (tx active).
	lastRxTime atomic.Int64 // Unix nanos of last received IP packet from tunnel
	lastTxTime atomic.Int64 // Unix nanos of last IP packet written to tunnel
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
	connectivityCh = make(chan struct{}, 1)
	running.Store(true)
	connected.Store(false)
	networkTriggered.Store(false)
	hasNetwork.Store(true)
	lastError.Store("")
	startTime = time.Now()
	connectedAt.Store(0)
	connectCount.Store(0)
	txBytes.Store(0)
	rxBytes.Store(0)
	lastRxTime.Store(0)
	lastTxTime.Store(0)
	mu.Unlock()

	// Dup the fd so Go owns an independent copy. Without this, Go's GC
	// finalizer can close the *original* fd after Kotlin hands it to a new
	// VPN interface (fd number reuse), killing the new tunnel on reconnect.
	// With dup, Go closes its copy and Kotlin closes the original — no race.
	dupFd, dupErr := syscall.Dup(tunFd)
	if dupErr != nil {
		mu.Lock()
		running.Store(false)
		close(done)
		mu.Unlock()
		return fmt.Errorf("dup tun fd: %w", dupErr)
	}
	tunFile := os.NewFile(uintptr(dupFd), "tun")
	device := &FdAdapter{file: tunFile}

	err := maintainTunnel(ctx, &tcfg, device, protector)
	tunFile.Close() // closes Go's dup'd fd, not Kotlin's original
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

// networkTriggered is set by Reconnect() to signal that the reconnect was
// caused by a network change, so maintainTunnel can skip the initial backoff.
var networkTriggered atomic.Bool

// networkHint stores the current network type ("wifi", "cellular", or "")
// for adaptive keepalive intervals. Updated from Kotlin via SetNetworkHint.
var networkHint atomic.Value

// SetNetworkHint updates the network type hint for adaptive keepalive.
// Call from Kotlin on network change: "wifi", "cellular", or "" (unknown).
func SetNetworkHint(hint string) {
	networkHint.Store(hint)
}

// SetConnectivity tells the tunnel whether the device has network.
// When false, the reconnect loop sleeps instead of hammering failed dials.
// Call from Kotlin: true on onAvailable, false on onLost (no active network).
func SetConnectivity(networkAvailable bool) {
	wasConnected := hasNetwork.Swap(networkAvailable)
	if networkAvailable && !wasConnected {
		// Network restored — wake waitForNetwork (if blocked) and trigger reconnect.
		mu.Lock()
		ch := connectivityCh
		mu.Unlock()
		if ch != nil {
			select {
			case ch <- struct{}{}:
			default:
			}
		}
		Reconnect()
	}
}

// Reconnect tears down the current QUIC connection but keeps the reconnect
// loop alive so it re-establishes on the (possibly new) network.
func Reconnect() {
	networkTriggered.Store(true)
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
	now := time.Now()
	stats := map[string]interface{}{
		"running":       running.Load(),
		"connected":     connected.Load(),
		"tx_bytes":      txBytes.Load(),
		"rx_bytes":      rxBytes.Load(),
		"uptime_sec":    0,
		"has_network":   hasNetwork.Load(),
		"connect_count": connectCount.Load(),
	}
	if e, ok := lastError.Load().(string); ok && e != "" {
		stats["last_error"] = e
	}
	if running.Load() {
		stats["uptime_sec"] = int(now.Sub(startTime).Seconds())
	}
	if t := connectedAt.Load(); t > 0 {
		stats["connected_since_ms"] = t
	}
	// Diagnostic fields for liveness/stall monitoring.
	if rxNs := lastRxTime.Load(); rxNs > 0 {
		stats["last_rx_time_ms"] = rxNs / int64(time.Millisecond)
		if connected.Load() {
			stats["rx_stall_sec"] = int(now.Sub(time.Unix(0, rxNs)).Seconds())
		}
	}
	if txNs := lastTxTime.Load(); txNs > 0 {
		stats["last_tx_time_ms"] = txNs / int64(time.Millisecond)
	}
	if v := networkHint.Load(); v != nil {
		stats["network_hint"] = v.(string)
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
		packetSize      = 1242
		connectPort     = 443
		minBackoff      = 1 * time.Second
		maxBackoff      = 60 * time.Second
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

	const networkGraceMax = 3 // attempts at minBackoff after network change before escalating

	// Seed network hint from config; Kotlin will update dynamically via SetNetworkHint.
	if cfg.NetworkType != "" {
		networkHint.Store(cfg.NetworkType)
	}

	backoff := minBackoff
	networkGraceAttempts := 0

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
				sleepCtx(ctx, backoff)
				backoff = nextBackoff(backoff, maxBackoff)
				continue
			}
			cachedCert = cert
			certExpiry = time.Now().Add(24 * time.Hour)
		}

		tlsCfg, err := api.PrepareTlsConfig(privKey, peerPubKey, cachedCert, cfg.sni())
		if err != nil {
			lastError.Store(err.Error())
			log.Printf("TLS config: %v", err)
			sleepCtx(ctx, backoff)
			backoff = nextBackoff(backoff, maxBackoff)
			continue
		}

		tlsCfg.ClientSessionCache = quicSessionCache // 1-RTT session resumption (not 0-RTT)

		// Adaptive keepalive and PMTU based on network type
		var hint string
		if v := networkHint.Load(); v != nil {
			hint = v.(string)
		}

		keepalive := 55 * time.Second
		switch hint {
		case "wifi":
			keepalive = 110 * time.Second
		case "cellular":
			keepalive = 50 * time.Second
		}

		disablePMTU := true
		pktSize := uint16(packetSize) // 1242
		if hint == "wifi" {
			disablePMTU = false
			pktSize = 1400
		}

		quicCfg := &quic.Config{
			EnableDatagrams:         true,
			InitialPacketSize:       pktSize,
			KeepAlivePeriod:         keepalive,
			MaxIdleTimeout:          300 * time.Second,
			DisablePathMTUDiscovery: disablePMTU,
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
				backoff = minBackoff
			} else {
				sleepCtx(ctx, backoff)
				backoff = nextBackoff(backoff, maxBackoff)
			}
			continue
		}
		if rsp.StatusCode != 200 {
			lastError.Store(fmt.Sprintf("tunnel rejected: %s", rsp.Status))
			log.Printf("tunnel rejected: %s", rsp.Status)
			cleanup(ipConn, udpConn, tr)
			sleepCtx(ctx, backoff)
			backoff = nextBackoff(backoff, maxBackoff)
			continue
		}

		// Connection succeeded — reset backoff.
		backoff = minBackoff
		connected.Store(true)
		connectedAt.Store(time.Now().UnixMilli())
		lastError.Store("")
		// Seed liveness timestamps so the check doesn't immediately fire.
		now := time.Now().UnixNano()
		lastRxTime.Store(now)
		lastTxTime.Store(now)
		log.Println("Connected to MASQUE server")

		// Per-connection context: cancelled when this connection ends, which stops
		// the liveness goroutine immediately without waiting for its next tick.
		connCtx, connCancel := context.WithCancel(ctx)

		errChan := make(chan error, 2)
		var wg sync.WaitGroup
		wg.Add(3)
		go func() { defer wg.Done(); forwardUp(device, ipConn, pool, errChan, dns, dnsCache) }()
		go func() { defer wg.Done(); forwardDown(device, ipConn, pool, errChan, dnsCache) }()
		go func() { defer wg.Done(); livenessCheck(connCtx) }()

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
			if networkTriggered.Swap(false) {
				backoff = 200 * time.Millisecond // micro-delay lets new network's routing stabilize
				networkGraceAttempts = networkGraceMax
			} else {
				backoff = minBackoff
			}
		case <-ctx.Done():
			connected.Store(false)
			connectedAt.Store(0)
		}

		connCancel() // stop liveness goroutine immediately
		cleanup(ipConn, udpConn, tr)
		wg.Wait() // wait for forwarding goroutines to exit before reconnecting
		if ctx.Err() != nil {
			return nil
		}

		// Always reset DNS connections on reconnect — DoH/DoQ maintain persistent
		// connections that go stale when the tunnel dies (e.g., screen off).
		if dns != nil {
			dns.resetConnections()
		}

		if backoff > 0 {
			sleepCtx(ctx, backoff)
		}
		if networkGraceAttempts > 0 {
			networkGraceAttempts--
			backoff = minBackoff // hold at minBackoff during grace period
		} else {
			backoff = nextBackoff(backoff, maxBackoff)
		}
	}
}

// nextBackoff doubles the current backoff, capped at max, with 0–25% random jitter.
func nextBackoff(current, max time.Duration) time.Duration {
	next := current * 2
	if next > max {
		next = max
	}
	if quarter := int64(next) / 4; quarter > 0 {
		next += time.Duration(mrand.Int64N(quarter))
	}
	return next
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

		// Fast path: cheap version+protocol+port check before the full IP-extracting parse.
		// ~95% of packets are not DNS — this avoids all allocations for that majority.
		if dns != nil || dnsCache != nil {
			if _, isDNS := isDNSPacketFast(pkt); !isDNS {
				goto sendPacket
			}
		}

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

	sendPacket:
		// Send via Connect-IP datagrams (UDP, ICMP, TCP, etc.)
		icmp, err := ipConn.WritePacket(pkt)
		pool.Put(buf)
		if err != nil {
			errChan <- err
			return
		}
		lastTxTime.Store(time.Now().UnixNano())
		if len(icmp) > 0 {
			_ = device.WritePacket(icmp)
		}
	}
}

func forwardDown(device api.TunnelDevice, ipConn *connectip.Conn, _ *api.NetBuffer, errChan chan<- error, dnsCache *tunnelDnsCache) {
	// Allocate directly instead of using the pool: this buffer lives for the
	// entire connection lifetime, so pool Get/Put mutex overhead is wasted.
	buf := make([]byte, tunnelMTU)
	for {
		n, err := ipConn.ReadPacket(buf, true)
		if err != nil {
			errChan <- err
			return
		}
		lastRxTime.Store(time.Now().UnixNano())
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

// livenessCheck periodically detects one-way tunnel stalls where the server
// has silently stopped forwarding (rx frozen) while the client is still
// sending traffic (tx active). This covers the case where the Cloudflare
// MASQUE session expires server-side but the QUIC connection remains alive
// (keepalives keep the transport up, so forwardDown never gets an error).
//
// Stall condition: no rx packet for >30s AND tx packet within last 30s.
// Idle connections (both rx and tx silent) do NOT trigger a reconnect.
//
// Exits immediately when ctx is cancelled (connection ended or reconnecting).
func livenessCheck(ctx context.Context) {
	const (
		rxStallTimeout = 30 * time.Second
		txActiveWindow = 30 * time.Second
		checkInterval  = 10 * time.Second
	)
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			rxAge := now.Sub(time.Unix(0, lastRxTime.Load()))
			txAge := now.Sub(time.Unix(0, lastTxTime.Load()))
			if rxAge > rxStallTimeout && txAge < txActiveWindow {
				log.Printf("liveness: rx stall detected (no rx for %.0fs, last tx %.0fs ago) — triggering reconnect",
					rxAge.Seconds(), txAge.Seconds())
				Reconnect()
				return // one reconnect signal is enough; exit so we don't spam
			}
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

// waitForNetwork blocks until SetConnectivity(true) is called or ctx is cancelled.
// Uses a channel signal instead of polling — zero CPU wakeups while waiting.
func waitForNetwork(ctx context.Context) {
	if hasNetwork.Load() {
		return // already have network, no need to block
	}
	mu.Lock()
	ch := connectivityCh
	mu.Unlock()
	if ch == nil {
		return
	}
	select {
	case <-ctx.Done():
	case <-ch:
	}
}

// isDNSPacketFast is a zero-allocation check for whether pkt is a UDP packet to port 53.
// Checks only version nibble, protocol byte, and destination port — no IP extraction.
// Call this before detectDNSQuery to skip allocations for the ~95% of non-DNS packets.
// Returns (isIPv6 bool, ok bool).
func isDNSPacketFast(pkt []byte) (isIPv6 bool, ok bool) {
	if len(pkt) < 8 {
		return false, false
	}
	version := pkt[0] >> 4
	switch version {
	case 4: // IPv4
		if len(pkt) < 28 || pkt[9] != 17 { // 17 = UDP
			return false, false
		}
		ihl := int(pkt[0]&0x0f) * 4
		if len(pkt) < ihl+4 {
			return false, false
		}
		// Destination port at ihl+2
		dstPort := uint16(pkt[ihl+2])<<8 | uint16(pkt[ihl+3])
		return false, dstPort == 53
	case 6: // IPv6
		if len(pkt) < 48 || pkt[6] != 17 { // next header must be UDP directly
			return false, false
		}
		// UDP header at offset 40; destination port at 42
		dstPort := uint16(pkt[42])<<8 | uint16(pkt[43])
		return true, dstPort == 53
	}
	return false, false
}

func sleepCtx(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}
