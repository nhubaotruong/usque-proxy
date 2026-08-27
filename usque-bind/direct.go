// Userspace route exclusion for Android API < 33 (Android 11/12).
//
// VpnService.Builder.excludeRoute does not exist below API 33 — verified
// against the API 30 framework stubs AND the runtime method table (dalvikvm
// reflection dump): neither public nor hidden methods exist. On those
// versions, excluded prefixes (local networks, Office 365 ranges, DNS
// servers) cannot be excluded at the kernel level, so packets for them still
// arrive on the TUN. This file implements the exclusion in userspace: TCP
// and UDP packets whose destination matches an excluded prefix are handed to
// a gVisor netstack instance which terminates the connections locally, and
// the data is relayed through sockets protected from the VPN
// (VpnService.protect), i.e. out the real underlying network — the same
// pattern the system-DNS interceptor already uses for port 53.
package usquebind

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"syscall"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	directQueueLen = 1024
	directBufSize  = 32 * 1024
	tcpRecvWindow  = 1 << 20
	tcpMaxInFlight = 1024
)

// directForwarder relays TCP/UDP traffic to excluded prefixes through
// protected sockets. It is nil when no prefixes are configured (API 33+ uses
// kernel excludeRoute instead, so no packets reach the TUN for them).
type directForwarder struct {
	ctx       context.Context
	cancel    context.CancelFunc
	stack     *stack.Stack
	nicID     tcpip.NICID
	endpoint  *channel.Endpoint
	prefixes  []*net.IPNet
	protector VpnProtector
	writePkt  func([]byte) error
	connsMu   sync.Mutex
	conns     map[net.Conn]struct{}
}

// newDirectForwarder builds the forwarder for the given CIDR prefixes.
// Returns nil if prefixes is empty.
func newDirectForwarder(prefixes []string, mtu uint32, protector VpnProtector, writePkt func([]byte) error) (*directForwarder, error) {
	nets := make([]*net.IPNet, 0, len(prefixes))
	for _, cidr := range prefixes {
		ipnet, err := parsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("exclude prefix %q: %w", cidr, err)
		}
		nets = append(nets, ipnet)
	}
	if len(nets) == 0 {
		return nil, nil
	}

	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	}
	stk := stack.New(opts)
	ep := channel.New(directQueueLen, mtu, "")
	nicID := stk.NextNICID()
	if err := stk.CreateNIC(nicID, ep); err != nil {
		return nil, fmt.Errorf("create NIC: %v", err)
	}
	// Default routes so replies to relayed flows (SYN-ACKs, data) can be
	// routed back out of the stack to the TUN.
	stk.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: nicID})
	stk.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: nicID})
	// Accept packets addressed to arbitrary excluded destinations (they are
	// not local addresses of the TUN).
	if err := stk.SetPromiscuousMode(nicID, true); err != nil {
		return nil, fmt.Errorf("promiscuous mode: %v", err)
	}
	// Spoofing makes the stack answer (and route) for arbitrary excluded
	// destinations, not just addresses assigned to the NIC.
	if err := stk.SetSpoofing(nicID, true); err != nil {
		return nil, fmt.Errorf("spoofing mode: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	df := &directForwarder{
		ctx:       ctx,
		cancel:    cancel,
		stack:     stk,
		nicID:     nicID,
		endpoint:  ep,
		prefixes:  nets,
		protector: protector,
		writePkt:  writePkt,
		conns:     make(map[net.Conn]struct{}),
	}

	tcpFwd := tcp.NewForwarder(stk, tcpRecvWindow, tcpMaxInFlight, df.handleTCP)
	stk.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	udpFwd := udp.NewForwarder(stk, df.handleUDP)
	stk.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	go df.pump()
	return df, nil
}

func parsePrefix(cidr string) (*net.IPNet, error) {
	if _, ipnet, err := net.ParseCIDR(cidr); err == nil {
		return ipnet, nil
	}
	ip := net.ParseIP(cidr)
	if ip == nil {
		return nil, errors.New("not a CIDR or IP")
	}
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}, nil
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
}

// shouldForward reports whether the raw IP packet targets an excluded prefix.
func (df *directForwarder) shouldForward(pkt []byte) bool {
	var dst net.IP
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return false
		}
		dst = net.IP(pkt[16:20])
	case 6:
		if len(pkt) < 40 {
			return false
		}
		dst = net.IP(pkt[24:40])
	default:
		return false
	}
	for _, p := range df.prefixes {
		if p.Contains(dst) {
			return true
		}
	}
	return false
}

// inject hands a raw IP packet to the gVisor stack (must only be called for
// packets that shouldForward matched).
func (df *directForwarder) inject(pkt []byte) {
	var proto tcpip.NetworkProtocolNumber
	switch pkt[0] >> 4 {
	case 4:
		proto = header.IPv4ProtocolNumber
	case 6:
		proto = header.IPv6ProtocolNumber
	default:
		return
	}
	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(pkt)})
	defer pb.DecRef()
	df.endpoint.InjectInbound(proto, pb)
}

// pump drains the stack's outbound queue into the TUN.
func (df *directForwarder) pump() {
	for {
		pkt := df.endpoint.ReadContext(df.ctx)
		if pkt == nil {
			return
		}
		v := pkt.ToView()
		if v != nil {
			_ = df.writePkt(v.AsSlice())
			v.Release()
		}
		pkt.DecRef()
	}
}

// close tears the forwarder down: cancels pumps, closes the NIC (which ends
// all stack endpoints) and all real sockets.
func (df *directForwarder) close() {
	df.cancel()
	_ = df.stack.RemoveNIC(df.nicID)
	df.endpoint.Close()
	df.connsMu.Lock()
	for c := range df.conns {
		_ = c.Close()
	}
	df.conns = nil
	df.connsMu.Unlock()
}

func (df *directForwarder) track(c net.Conn) {
	df.connsMu.Lock()
	if df.conns != nil {
		df.conns[c] = struct{}{}
	}
	df.connsMu.Unlock()
}

// wait blocks until the endpoint is ready for mask, or the forwarder shuts
// down. Drains stale notifications to avoid busy loops.
func (df *directForwarder) wait(wq *waiter.Queue, mask waiter.EventMask) error {
	entry, ch := waiter.NewChannelEntry(mask)
	wq.EventRegister(&entry)
	defer wq.EventUnregister(&entry)
	select {
	case <-ch:
	case <-df.ctx.Done():
		return df.ctx.Err()
	}
	// Drain coalesced notifications so the next wait doesn't spin.
	for {
		select {
		case <-ch:
		default:
			return nil
		}
	}
}

// handleTCP is invoked by the stack for each new inbound TCP connection to an
// excluded prefix. It dials the real destination through a protected socket
// and relays bytes in both directions.
func (df *directForwarder) handleTCP(r *tcp.ForwarderRequest) {
	go func() {
		id := r.ID()
		dst := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
		conn, err := dialProtected(df.ctx, "tcp", dst, df.protector)
		if err != nil {
			log.Printf("direct dial failed: %v", err)
			r.Complete(true) // reset the connection
			return
		}
		wq := new(waiter.Queue)
		ep, terr := r.CreateEndpoint(wq)
		if terr != nil {
			_ = conn.Close()
			r.Complete(true)
			return
		}
		df.track(conn)
		log.Printf("direct TCP relay: %s -> %s", id.RemoteAddress, dst)
		go df.stackToConn(ep, wq, conn)
		go df.connToStack(ep, wq, conn)
	}()
}

// handleUDP mirrors handleTCP for UDP flows. Returns true so the packet is
// consumed; the endpoint created here then owns the 4-tuple.
func (df *directForwarder) handleUDP(r *udp.ForwarderRequest) bool {
	go func() {
		id := r.ID()
		dst := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
		conn, err := dialProtected(df.ctx, "udp", dst, df.protector)
		if err != nil {
			return
		}
		wq := new(waiter.Queue)
		ep, terr := r.CreateEndpoint(wq)
		if terr != nil {
			_ = conn.Close()
			return
		}
		df.track(conn)
		log.Printf("direct UDP relay: %s -> %s", id.RemoteAddress, dst)
		go df.stackToConn(ep, wq, conn)
		go df.connToStack(ep, wq, conn)
	}()
	return true
}

// connToStack copies data from the real socket into the stack and owns the
// connection teardown: when the remote side closes, the endpoint is closed so
// the stack sends FIN (or RST) to the peer.
func (df *directForwarder) connToStack(ep tcpip.Endpoint, wq *waiter.Queue, conn net.Conn) {
	defer func() {
		ep.Close()
		_ = conn.Close()
	}()
	buf := make([]byte, directBufSize)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			if werr := df.writeToStack(ep, wq, buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (df *directForwarder) writeToStack(ep tcpip.Endpoint, wq *waiter.Queue, data []byte) error {
	for len(data) > 0 {
		n, werr := ep.Write(bytes.NewReader(data), tcpip.WriteOptions{})
		if werr != nil {
			if _, wouldBlock := werr.(*tcpip.ErrWouldBlock); wouldBlock {
				// Writability events may have fired before we registered,
				// so only block when the endpoint actually refuses data.
				if err := df.wait(wq, waiter.EventOut); err != nil {
					return err
				}
				continue
			}
			return fmt.Errorf("stack write: %s", werr)
		}
		if n == 0 {
			return errors.New("zero-byte stack write")
		}
		data = data[n:]
	}
	return nil
}

// stackToConn copies data from the stack into the real socket. When the peer
// closes its send side (FIN), it stops relaying but must NOT close the socket:
// the response may still be in flight, and connToStack performs the final
// teardown once the remote side is done.
func (df *directForwarder) stackToConn(ep tcpip.Endpoint, wq *waiter.Queue, conn net.Conn) {
	for {
		for {
			var out bytes.Buffer
			rr, rerr := ep.Read(&out, tcpip.ReadOptions{})
			if rerr != nil {
				if _, wouldBlock := rerr.(*tcpip.ErrWouldBlock); wouldBlock {
					break
				}
				if _, closed := rerr.(*tcpip.ErrClosedForReceive); closed {
					// Peer FIN: drain done, response may still arrive on
					// the socket. Let connToStack finish the teardown.
					return
				}
				// Aborted (RST) or not connected: tear everything down.
				ep.Close()
				_ = conn.Close()
				return
			}
			if rr.Count > 0 {
				if _, werr := conn.Write(out.Bytes()); werr != nil {
					ep.Close()
					_ = conn.Close()
					return
				}
			}
			if rr.Count == 0 {
				break
			}
		}
		// Block for more data or close/error notifications.
		if err := df.wait(wq, waiter.EventIn|waiter.EventHUp|waiter.EventErr); err != nil {
			_ = conn.Close()
			return
		}
	}
}

// dialProtected dials a real destination through a socket excluded from the
// VPN, so the relayed traffic goes out the underlying network.
func dialProtected(ctx context.Context, network, addr string, protector VpnProtector) (net.Conn, error) {
	d := net.Dialer{
		Control: func(_, _ string, rc syscall.RawConn) error {
			var protectErr error
			err := rc.Control(func(fd uintptr) {
				if !protector.ProtectFd(int(fd)) {
					protectErr = errors.New("VPN protect() failed on direct socket")
				}
			})
			if err != nil {
				return err
			}
			return protectErr
		},
	}
	return d.DialContext(ctx, network, addr)
}
