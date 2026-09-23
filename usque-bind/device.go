package usquebind

import (
	"os"
)

// filterDevice wraps the TUN fd and applies per-packet filters before
// packets reach the upstream tunnel pump: DNS interception (DoH/DoQ/system
// resolver or tunnel cache) and userspace route exclusion (Android < 13).
// It implements api.TunnelDevice for upstream MaintainTunnel.
type filterDevice struct {
	file     *os.File
	dns      *dnsInterceptor
	dnsCache *tunnelDnsCache
	direct   *directForwarder
}

// ReadPacket implements api.TunnelDevice.ReadPacket. It loops internally:
// DNS queries and excluded-prefix packets are consumed here (intercepted or
// relayed directly); only tunnel-bound packets are returned to the pump.
func (f *filterDevice) ReadPacket(buf []byte) (int, error) {
	for {
		n, err := f.file.Read(buf)
		if err != nil {
			return 0, err
		}
		pkt := buf[:n]
		txBytes.Add(int64(n))

		// Intercept DNS packets (IPv4 and IPv6)
		if srcIP, srcPort, dstIP, query, isIPv6, ok := detectDNSQuery(pkt); ok && isDNSQuery(query) {
			if f.dns != nil {
				bufPtr := dnsQueryPool.Get().(*[]byte)
				queryCopy := append((*bufPtr)[:0], query...)
				f.dns.forwardUp(dnsRequest{
					srcIP: srcIP, srcPort: srcPort, dstIP: dstIP,
					query: queryCopy, writeFunc: f.WritePacket,
					isIPv6: isIPv6, poolBuf: bufPtr,
				})
				continue
			}
			if f.dnsCache != nil && f.dnsCache.checkAndRespond(pkt, f.WritePacket) {
				continue
			}
		}

		// Userspace route exclusion: relay directly, do not tunnel.
		if f.direct != nil && f.direct.shouldForward(pkt) {
			f.direct.inject(pkt)
			continue
		}

		return n, nil
	}
}

// WritePacket implements api.TunnelDevice.WritePacket. Counts rx bytes and
// feeds the DNS response cache for tunnel-downlink packets.
func (f *filterDevice) WritePacket(pkt []byte) error {
	rxBytes.Add(int64(len(pkt)))
	if f.dnsCache != nil {
		f.dnsCache.cacheResponse(pkt)
	}
	_, err := f.file.Write(pkt)
	return err
}
