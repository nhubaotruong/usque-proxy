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
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/models"
)

const (
	defaultSNI    = "consumer-masque.cloudflareclient.com"
	ZeroTrustSNI  = "zt-masque.cloudflareclient.com"
	defaultURI    = "https://cloudflareaccess.com"
	defaultLocale = "en_US"
)

// quicSessionCache enables TLS session resumption across QUIC reconnects (1-RTT, not 0-RTT).
var quicSessionCache = tls.NewLRUClientSessionCache(8)

// tunnelConfig extends config.Config with optional tunnel parameters.
type tunnelConfig struct {
	config.Config
	SNI        string   `json:"sni"`
	ConnectURI string   `json:"connect_uri"`
	DoHURL     string   `json:"doh_url"`
	DoQURL     string   `json:"doq_url"`
	SystemDNS  []string `json:"system_dns"`
	PrivateDNS bool     `json:"private_dns_active"`
	UseHTTP2   bool     `json:"use_http2"`
	// ExcludePrefixes lists CIDRs whose traffic is relayed directly via
	// protected sockets (userspace route exclusion; Android API < 33, where
	// VpnService.Builder.excludeRoute does not exist).
	ExcludePrefixes []string `json:"exclude_prefixes"`
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

// TunnelListener receives tunnel state, stats, and error callbacks from Go.
// Implemented in Kotlin via gomobile; callbacks arrive on arbitrary goroutines.
type TunnelListener interface {
	OnStateChanged(state string)
	OnStats(stats string)
	OnError(err string)
}

// listenerBox keeps a single concrete type in atomic.Value (Store panics on type change).
type listenerBox struct {
	l TunnelListener // may be nil
}

var listenerHolder atomic.Value

func setListener(l TunnelListener) {
	listenerHolder.Store(&listenerBox{l: l})
}

func getListener() TunnelListener {
	v := listenerHolder.Load()
	if v == nil {
		return nil
	}
	return v.(*listenerBox).l
}

// safeNotify guards against a panicking Kotlin listener (gomobile callback
// threading risk) — a Java exception must not kill the tunnel goroutine.
func safeNotify(fn func()) {
	defer func() { recover() }()
	fn()
}

func notifyState(state string) {
	safeNotify(func() {
		if l := getListener(); l != nil {
			l.OnStateChanged(state)
		}
	})
}

func notifyStats() {
	safeNotify(func() {
		if l := getListener(); l != nil {
			l.OnStats(GetStats())
		}
	})
}

func notifyError(err string) {
	safeNotify(func() {
		if l := getListener(); l != nil {
			l.OnError(err)
		}
	})
}

// dnsQueryPool reuses buffers for DNS query copies, reducing GC pressure.
var dnsQueryPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 0, 512) // typical DNS query size
		return &buf
	},
}

// tunnel state
var (
	mu        sync.Mutex
	cancel    context.CancelFunc
	running   atomic.Bool
	connected atomic.Bool // true when MASQUE tunnel is forwarding traffic
	done      chan struct{}
	startTime time.Time
	txBytes   atomic.Int64
	rxBytes   atomic.Int64
)

// StartTunnel starts the MASQUE tunnel. Blocks until StopTunnel or error.
// If a previous tunnel is still winding down, waits up to 5s for it to finish.
func StartTunnel(configJSON string, tunFd int, listener TunnelListener) error {
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
	if tcfg.EndpointV4 == "" {
		mu.Unlock()
		return fmt.Errorf("no endpoint v4 in config")
	}

	ctx, c := context.WithCancel(context.Background())
	cancel = c
	done = make(chan struct{})
	running.Store(true)
	connected.Store(false)
	startTime = time.Now()
	txBytes.Store(0)
	rxBytes.Store(0)
	mu.Unlock()

	setListener(listener)
	defer setListener(nil)

	// dup() gives Go an unowned copy of the TUN fd (fdsan fix, see spec).
	dupFd, err := syscall.Dup(tunFd)
	if err != nil {
		return fmt.Errorf("dup tun fd: %w", err)
	}
	tunFile := os.NewFile(uintptr(dupFd), "tun")
	defer tunFile.Close()
	// On shutdown, unblock the TUN read in filterDevice.
	go func() {
		<-ctx.Done()
		tunFile.Close()
	}()

	device := &filterDevice{file: tunFile}

	// DNS interception (DoH, DoQ, or System DNS) or tunnel cache fallback.
	if tcfg.DoHURL != "" {
		device.dns = newDnsInterceptor(ctx, &tcfg)
		if device.dns != nil {
			defer device.dns.close()
			log.Println("DNS interception enabled: all port 53 traffic via DoH")
		}
	} else if tcfg.DoQURL != "" {
		device.dns = newDoqDnsInterceptor(ctx, tcfg.DoQURL)
		if device.dns != nil {
			defer device.dns.close()
			log.Println("DNS interception enabled: all port 53 traffic via DoQ")
		}
	} else if len(tcfg.SystemDNS) > 0 {
		device.dns = newSystemDnsInterceptor(ctx, tcfg.SystemDNS)
		if device.dns != nil {
			defer device.dns.close()
			if tcfg.PrivateDNS {
				log.Printf("System DNS interception enabled (Private DNS active): forwarding port-53 via sockets to %v", tcfg.SystemDNS)
			} else {
				log.Printf("System DNS interception enabled: forwarding via sockets to %v", tcfg.SystemDNS)
			}
		}
	} else {
		device.dnsCache = newTunnelDnsCache(512)
		log.Println("DNS tunnel cache enabled")
	}

	// Userspace route exclusion (Android < 13): only set when exclude_prefixes
	// arrive from Kotlin (API < 33 path).
	if len(tcfg.ExcludePrefixes) > 0 {
		df, derr := newDirectForwarder(tcfg.ExcludePrefixes, 1280, device.WritePacket)
		if derr != nil {
			log.Printf("Userspace route exclusion disabled: %v", derr)
		} else if df != nil {
			device.direct = df
			defer df.close()
			log.Printf("Userspace route exclusion enabled for %d prefixes", len(df.prefixes))
		}
	}

	privKey, err := tcfg.GetEcPrivateKey()
	if err != nil {
		return fmt.Errorf("private key: %w", err)
	}
	peerPubKey, err := tcfg.GetEcEndpointPublicKey()
	if err != nil {
		return fmt.Errorf("endpoint public key: %w", err)
	}
	cert, err := selfSignedCert(privKey)
	if err != nil {
		return fmt.Errorf("cert generation: %w", err)
	}
	tlsCfg, err := api.PrepareTlsConfig(privKey, peerPubKey, cert, tcfg.sni(), false)
	if err != nil {
		return fmt.Errorf("TLS config: %w", err)
	}
	tlsCfg.ClientSessionCache = quicSessionCache

	// Connected heuristic: upstream MaintainTunnel has no connect callback;
	// report connected shortly after start if the loop is still alive
	// (matches the reference usque-android pattern).
	go func() {
		select {
		case <-time.After(3 * time.Second):
			if running.Load() {
				connected.Store(true)
				notifyState("connected")
				notifyStats()
			}
		case <-ctx.Done():
		}
	}()

	// Stats ticker: one notifyStats() per ~5 min while connected.
	statsTicker := time.NewTicker(5 * time.Minute)
	defer statsTicker.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-statsTicker.C:
				if connected.Load() {
					notifyStats()
				}
			}
		}
	}()

	notifyState("connecting")
	api.MaintainTunnel(ctx, api.MaintainTunnelConfig{
		TLSConfig:         tlsCfg,
		KeepalivePeriod:   30 * time.Second,
		InitialPacketSize: 1242,
		Endpoint:          endpointFromConfig(&tcfg),
		Device:            device,
		MTU:               1280,
		ReconnectDelay:    1 * time.Second,
		AlwaysReconnect:   false,
		UseHTTP2:          tcfg.UseHTTP2,
	})

	running.Store(false)
	connected.Store(false)
	notifyState("stopped")
	close(done)
	return nil
}

// endpointFromConfig resolves the WARP endpoint. HTTP/2 uses TCP, H3 uses UDP.
func endpointFromConfig(cfg *tunnelConfig) net.Addr {
	hostport := net.JoinHostPort(cfg.EndpointV4, "443")
	if cfg.UseHTTP2 {
		addr, err := net.ResolveTCPAddr("tcp", hostport)
		if err != nil {
			log.Printf("resolve endpoint %q: %v", hostport, err)
			return nil
		}
		return addr
	}
	addr, err := net.ResolveUDPAddr("udp", hostport)
	if err != nil {
		log.Printf("resolve endpoint %q: %v", hostport, err)
		return nil
	}
	return addr
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
func enrollAndBuildConfig(accountData *models.AccountData, license string) (string, error) {
	privKeyDER, updatedAccount, err := generateAndEnroll(accountData)
	if err != nil {
		return "", err
	}

	cfg := config.Config{
		PrivateKey:  base64.StdEncoding.EncodeToString(privKeyDER),
		ID:          accountData.ID,
		AccessToken: accountData.Token,
	}
	applyAccountToConfig(&cfg, updatedAccount)

	// License is bound to the account server-side: config.Config.License was
	// removed upstream in favor of api.UpdateLicenceKey.
	if license != "" {
		if err := api.UpdateLicenceKey(accountData.ID, accountData.Token, license); err != nil {
			return "", fmt.Errorf("license update failed: %w", err)
		}
	}

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
	privKeyDER, updatedAccount, err := generateAndEnroll(&accountData)
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
func generateAndEnroll(accountData *models.AccountData) (privKeyDER []byte, updatedAccount *models.AccountData, err error) {
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

	updated, err := api.EnrollKey(accountData.ID, accountData.Token, pubKeyPKIX, "UsqueProxy")
	if err != nil {
		return nil, nil, fmt.Errorf("enrollment failed: %w", err)
	}
	return privKeyDER, updated, nil
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

// isDNSQuery reports whether pkt looks like a DNS query (QR=0, opcode=0, QDCOUNT>=1).
func isDNSQuery(pkt []byte) bool {
	if len(pkt) < 12 {
		return false
	}
	flags := uint16(pkt[2])<<8 | uint16(pkt[3])
	qr := flags >> 15
	opcode := (flags >> 11) & 0xF
	qdcount := uint16(pkt[4])<<8 | uint16(pkt[5])
	return qr == 0 && opcode == 0 && qdcount >= 1
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
