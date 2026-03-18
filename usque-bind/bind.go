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
	SNI            string   `json:"sni"`
	ConnectURI     string   `json:"connect_uri"`
	DoHURL         string   `json:"doh_url"`
	PreventDnsLeak bool     `json:"prevent_dns_leak"`
	DnsServers     []string `json:"dns_servers"`
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

// tunnel state
var (
	mu          sync.Mutex
	cancel      context.CancelFunc
	running     atomic.Bool
	done        chan struct{} // closed when maintainTunnel returns
	reconnectCh chan struct{}
	startTime   time.Time
	txBytes     atomic.Int64
	rxBytes     atomic.Int64
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
	networkTriggered.Store(false)
	startTime = time.Now()
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

// networkTriggered is set by Reconnect() to signal that the reconnect was
// caused by a network change, so maintainTunnel can skip the initial backoff.
var networkTriggered atomic.Bool

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
	stats := map[string]interface{}{
		"running":    running.Load(),
		"tx_bytes":   txBytes.Load(),
		"rx_bytes":   rxBytes.Load(),
		"uptime_sec": 0,
	}
	if running.Load() {
		stats["uptime_sec"] = int(time.Since(startTime).Seconds())
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

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("key generation failed: %w", err)
	}
	privKeyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return "", fmt.Errorf("private key marshal failed: %w", err)
	}
	pubKeyPKIX, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return "", fmt.Errorf("public key marshal failed: %w", err)
	}

	updatedAccount, apiErr, err := api.EnrollKey(accountData, pubKeyPKIX, "UsqueProxy")
	if err != nil {
		if apiErr != nil {
			return "", fmt.Errorf("key enrollment failed: %s", apiErr.ErrorsAsString("; "))
		}
		return "", fmt.Errorf("key enrollment failed: %w", err)
	}

	cfg := config.Config{
		PrivateKey:  base64.StdEncoding.EncodeToString(privKeyDER),
		ID:          accountData.ID,
		AccessToken: accountData.Token,
		License:     license,
	}
	if len(updatedAccount.Config.Peers) > 0 {
		peer := updatedAccount.Config.Peers[0]
		cfg.EndpointPubKey = peer.PublicKey
		cfg.EndpointV4 = cleanEndpoint(peer.Endpoint.V4)
		cfg.EndpointV6 = cleanEndpoint(peer.Endpoint.V6)
	}
	cfg.IPv4 = updatedAccount.Config.Interface.Addresses.V4
	cfg.IPv6 = updatedAccount.Config.Interface.Addresses.V6

	result, err := json.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("failed to serialize config: %w", err)
	}
	return string(result), nil
}

// RegisterWithJWT performs ZeroTrust device registration using a JWT token
// obtained from https://<team-domain>/warp and returns config JSON to persist.
func RegisterWithJWT(jwt string) (string, error) {
	jwt = strings.TrimSpace(jwt)
	accountData, err := api.Register("Android", defaultLocale, jwt, true)
	if err != nil {
		return "", fmt.Errorf("registration failed: %w", err)
	}

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("key generation failed: %w", err)
	}
	privKeyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return "", fmt.Errorf("private key marshal failed: %w", err)
	}
	pubKeyPKIX, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return "", fmt.Errorf("public key marshal failed: %w", err)
	}

	updatedAccount, apiErr, err := api.EnrollKey(accountData, pubKeyPKIX, "UsqueProxy")
	if err != nil {
		if apiErr != nil {
			return "", fmt.Errorf("key enrollment failed: %s", apiErr.ErrorsAsString("; "))
		}
		return "", fmt.Errorf("key enrollment failed: %w", err)
	}

	cfg := config.Config{
		PrivateKey:  base64.StdEncoding.EncodeToString(privKeyDER),
		ID:          accountData.ID,
		AccessToken: accountData.Token,
	}
	if len(updatedAccount.Config.Peers) > 0 {
		peer := updatedAccount.Config.Peers[0]
		cfg.EndpointPubKey = peer.PublicKey
		cfg.EndpointV4 = cleanEndpoint(peer.Endpoint.V4)
		cfg.EndpointV6 = cleanEndpoint(peer.Endpoint.V6)
	}
	cfg.IPv4 = updatedAccount.Config.Interface.Addresses.V4
	cfg.IPv6 = updatedAccount.Config.Interface.Addresses.V6

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

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("key generation failed: %w", err)
	}
	privKeyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return "", fmt.Errorf("private key marshal failed: %w", err)
	}
	pubKeyPKIX, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return "", fmt.Errorf("public key marshal failed: %w", err)
	}

	accountData := models.AccountData{ID: cfg.ID, Token: cfg.AccessToken}
	updatedAccount, apiErr, err := api.EnrollKey(accountData, pubKeyPKIX, "UsqueProxy")
	if err != nil {
		if apiErr != nil {
			return "", fmt.Errorf("re-enrollment failed: %s", apiErr.ErrorsAsString("; "))
		}
		return "", fmt.Errorf("re-enrollment failed: %w", err)
	}

	cfg.PrivateKey = base64.StdEncoding.EncodeToString(privKeyDER)
	if len(updatedAccount.Config.Peers) > 0 {
		peer := updatedAccount.Config.Peers[0]
		cfg.EndpointPubKey = peer.PublicKey
		cfg.EndpointV4 = cleanEndpoint(peer.Endpoint.V4)
		cfg.EndpointV6 = cleanEndpoint(peer.Endpoint.V6)
	}
	cfg.IPv4 = updatedAccount.Config.Interface.Addresses.V4
	cfg.IPv6 = updatedAccount.Config.Interface.Addresses.V6

	result, err := json.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("failed to serialize config: %w", err)
	}
	return string(result), nil
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
		keepalive       = 95 * time.Second // relaxed for battery; safe vs 120-300s server timeouts
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

	// Create DNS interceptor
	dns := newDnsInterceptor(ctx, cfg, protector)
	if dns != nil {
		defer dns.close()
		if dns.interceptAll {
			log.Println("DNS interception enabled: all port 53 traffic")
		} else {
			log.Println("DNS interception enabled: virtual DNS IP only")
		}
	}

	// Certificate cache: generate once, reuse until near expiry.
	var cachedCert [][]byte
	var certExpiry time.Time

	const networkGraceMax = 3 // attempts at minBackoff after network change before escalating

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
			log.Printf("TLS config: %v", err)
			sleepCtx(ctx, backoff)
			backoff = nextBackoff(backoff, maxBackoff)
			continue
		}

		quicCfg := &quic.Config{
			EnableDatagrams:         true,
			InitialPacketSize:       packetSize,
			KeepAlivePeriod:         keepalive,
			MaxIdleTimeout:          2 * keepalive, // must exceed keep-alive to avoid premature close
			DisablePathMTUDiscovery: true,           // saves probe traffic; MTU is fixed at 1280
		}

		udpConn, tr, ipConn, rsp, err := connectHappyEyeballs(
			ctx, tlsCfg, quicCfg,
			cfg.EndpointV4, cfg.EndpointV6,
			connectPort, cfg.connectUri(), protector,
		)
		if err != nil {
			log.Printf("connect: %v", err)
			sleepCtx(ctx, backoff)
			backoff = nextBackoff(backoff, maxBackoff)
			continue
		}
		if rsp.StatusCode != 200 {
			log.Printf("tunnel rejected: %s", rsp.Status)
			cleanup(ipConn, udpConn, tr)
			sleepCtx(ctx, backoff)
			backoff = nextBackoff(backoff, maxBackoff)
			continue
		}

		// Connection succeeded — reset backoff.
		backoff = minBackoff
		log.Println("Connected to MASQUE server")
		errChan := make(chan error, 2)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); forwardUp(device, ipConn, pool, errChan, dns) }()
		go func() { defer wg.Done(); forwardDown(device, ipConn, pool, errChan) }()

		isNetworkReconnect := false
		select {
		case err = <-errChan:
			log.Printf("tunnel lost: %v", err)
		case <-reconnectCh:
			log.Println("reconnect requested")
			if networkTriggered.Swap(false) {
				isNetworkReconnect = true
				backoff = 0
				networkGraceAttempts = networkGraceMax
			} else {
				backoff = minBackoff
			}
		case <-ctx.Done():
		}

		cleanup(ipConn, udpConn, tr)
		wg.Wait() // wait for forwarding goroutines to exit before reconnecting
		if ctx.Err() != nil {
			return nil
		}

		// Reset DNS connections on network change so stale sockets are discarded
		if isNetworkReconnect && dns != nil {
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

// nextBackoff doubles the current backoff, capped at max.
func nextBackoff(current, max time.Duration) time.Duration {
	next := current * 2
	if next > max {
		return max
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
	const connectionAttemptDelay = 50 * time.Millisecond

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
	case <-timer.C:
		// Delay expired — start second attempt in parallel.
		go attempt(endpoints[1])
	case <-ctx.Done():
		return nil, nil, nil, nil, ctx.Err()
	}

	// Collect results: up to 2 attempts may be in flight.
	var lastErr error
	for i := 0; i < 2; i++ {
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
	rawConn, err := udpConn.SyscallConn()
	if err != nil {
		udpConn.Close()
		return nil, nil, nil, nil, fmt.Errorf("raw conn: %w", err)
	}
	var protectErr error
	rawConn.Control(func(fd uintptr) {
		if !protector.ProtectFd(int(fd)) {
			protectErr = errors.New("VPN protect() failed")
		}
	})
	if protectErr != nil {
		udpConn.Close()
		return nil, nil, nil, nil, protectErr
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
		udpConn.Close()
		return nil, nil, nil, nil, fmt.Errorf("connect-ip: %v", err)
	}
	return udpConn, tr, ipConn, rsp, nil
}

func forwardUp(device api.TunnelDevice, ipConn *connectip.Conn, pool *api.NetBuffer, errChan chan<- error, dns *dnsInterceptor) {
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
		if dns != nil {
			if dns.interceptAll {
				if srcIP, srcPort, dstIP, query, ok := isAnyDNSPacket(pkt); ok {
					queryCopy := make([]byte, len(query))
					copy(queryCopy, query)
					pool.Put(buf)
					dns.forwardUp(dnsRequest{
						srcIP: srcIP, srcPort: srcPort, dstIP: dstIP,
						query: queryCopy, writeFunc: device.WritePacket,
					})
					continue
				}
				if srcIP, srcPort, dstIP, query, ok := isAnyDNSv6Packet(pkt); ok {
					queryCopy := make([]byte, len(query))
					copy(queryCopy, query)
					pool.Put(buf)
					dns.forwardUp(dnsRequest{
						srcIP: srcIP, srcPort: srcPort, dstIP: dstIP,
						query: queryCopy, writeFunc: device.WritePacket,
						isIPv6: true,
					})
					continue
				}
			} else {
				if srcIP, srcPort, query, ok := isDNSPacket(pkt); ok {
					queryCopy := make([]byte, len(query))
					copy(queryCopy, query)
					pool.Put(buf)
					dns.forwardUp(dnsRequest{
						srcIP: srcIP, srcPort: srcPort, dstIP: virtualDNSIPv4,
						query: queryCopy, writeFunc: device.WritePacket,
					})
					continue
				}
			}
		}

		icmp, err := ipConn.WritePacket(pkt)
		pool.Put(buf)
		if err != nil {
			errChan <- err
			return
		}
		if len(icmp) > 0 {
			_ = device.WritePacket(icmp)
		}
	}
}

func forwardDown(device api.TunnelDevice, ipConn *connectip.Conn, pool *api.NetBuffer, errChan chan<- error) {
	buf := pool.Get()
	defer pool.Put(buf)
	for {
		n, err := ipConn.ReadPacket(buf, true)
		if err != nil {
			errChan <- err
			return
		}
		rxBytes.Add(int64(n))
		if err := device.WritePacket(buf[:n]); err != nil {
			errChan <- err
			return
		}
	}
}

func selfSignedCert(privKey *ecdsa.PrivateKey) ([][]byte, error) {
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(0),
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

func sleepCtx(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}
