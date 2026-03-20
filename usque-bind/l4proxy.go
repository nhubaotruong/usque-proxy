// l4proxy.go — Hybrid L4/L3 transparent proxy.
//
// TCP traffic is terminated locally by gvisor netstack and relayed over
// HTTP/3 CONNECT streams on the same QUIC connection used for Connect-IP.
// This eliminates TCP-in-QUIC meltdown where inner TCP retransmits cascade
// into outer QUIC retransmits, achieving ~2x TCP throughput.
//
// UDP, ICMP, and other IP protocols continue through the existing Connect-IP
// datagram path (L3). If the server does not support HTTP/3 CONNECT (405/501),
// all traffic falls back to pure Connect-IP — no regressions.
package usquebind

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sync"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/quic-go/quic-go/http3"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	l4NICID       = 1
	l4ChannelSize = 512
	l4MTU         = 1280
)

// l4Proxy routes TCP through gvisor netstack → HTTP/3 CONNECT streams,
// while non-TCP traffic is handled via Connect-IP datagrams.
type l4Proxy struct {
	ctx     context.Context
	tunFile *os.File           // Android TUN fd
	hconn   *http3.ClientConn  // shared HTTP/3 connection
	ipConn  *connectip.Conn    // for fallback awareness

	s       *stack.Stack
	ep      *channel.Endpoint
	active  bool               // true if server supports CONNECT and stack is running
	stopWg  sync.WaitGroup
}

func newL4Proxy(ctx context.Context, tunFile *os.File, hconn *http3.ClientConn, ipConn *connectip.Conn) *l4Proxy {
	return &l4Proxy{
		ctx:     ctx,
		tunFile: tunFile,
		hconn:   hconn,
		ipConn:  ipConn,
	}
}

// start initializes the gvisor netstack and TCP forwarder.
// Returns true if L4 proxying is active, false if the server doesn't
// support CONNECT (falls back to pure Connect-IP).
func (l *l4Proxy) start() bool {
	// Probe: try opening a CONNECT stream to verify server support.
	if !l.probeConnect() {
		log.Println("L4 proxy: server does not support HTTP/3 CONNECT, falling back to Connect-IP")
		return false
	}

	l.ep = channel.New(l4ChannelSize, l4MTU, "")

	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	}
	l.s = stack.New(opts)

	if err := l.s.CreateNIC(l4NICID, l.ep); err != nil {
		log.Printf("L4 proxy: CreateNIC failed: %v", err)
		l.s.Close()
		return false
	}

	// Accept packets for any destination IP.
	l.s.SetPromiscuousMode(l4NICID, true)
	l.s.SetSpoofing(l4NICID, true)

	l.s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: l4NICID},
		{Destination: header.IPv6EmptySubnet, NIC: l4NICID},
	})

	// TCP forwarder intercepts all inbound SYN packets.
	tcpFwd := tcp.NewForwarder(l.s, 0, 256, l.handleTCP)
	l.s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	// Goroutine: read outbound packets from netstack → write to TUN.
	l.stopWg.Add(1)
	go l.netstackToTun()

	l.active = true
	log.Println("L4 proxy: active — TCP via HTTP/3 CONNECT streams")
	return true
}

// stop shuts down the gvisor stack and waits for goroutines.
func (l *l4Proxy) stop() {
	l.active = false
	if l.s != nil {
		l.s.Close()
	}
	if l.ep != nil {
		l.ep.Close()
	}
	l.stopWg.Wait()
}

// probeConnect sends a test CONNECT request to verify the server supports it.
func (l *l4Proxy) probeConnect() bool {
	rstr, err := l.hconn.OpenRequestStream(l.ctx)
	if err != nil {
		log.Printf("L4 probe: open stream failed: %v", err)
		return false
	}

	// Send CONNECT to a test target (RFC 9110 §9.3.6)
	err = rstr.SendRequestHeader(&http.Request{
		Method: http.MethodConnect,
		Host:   "0.0.0.0:1",
		URL:    &url.URL{Host: "0.0.0.0:1"},
	})
	if err != nil {
		rstr.Close()
		log.Printf("L4 probe: send header failed: %v", err)
		return false
	}

	resp, err := rstr.ReadResponse()
	rstr.Close()
	if err != nil {
		// Connection error reading response — might still be supported.
		// Some servers may reset the stream for an unreachable target,
		// which is different from 405/501 (method not supported).
		log.Printf("L4 probe: read response error: %v (assuming supported)", err)
		return true
	}

	// 405 Method Not Allowed or 501 Not Implemented = not supported.
	if resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusNotImplemented {
		return false
	}

	// Any other status (200, 502 connection refused, etc.) means CONNECT is supported.
	return true
}

// injectInbound sends a raw IP packet into the gvisor netstack.
func (l *l4Proxy) injectInbound(pkt []byte) {
	var proto tcpip.NetworkProtocolNumber
	switch header.IPVersion(pkt) {
	case 4:
		proto = header.IPv4ProtocolNumber
	case 6:
		proto = header.IPv6ProtocolNumber
	default:
		return
	}

	pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(pkt),
	})
	l.ep.InjectInbound(proto, pkb)
	pkb.DecRef()
}

// handleTCP is called by the TCP forwarder for each new connection.
// It opens an HTTP/3 CONNECT stream and relays bidirectionally.
func (l *l4Proxy) handleTCP(fr *tcp.ForwarderRequest) {
	id := fr.ID()
	target := fmt.Sprintf("%s:%d", id.LocalAddress, id.LocalPort)

	var wq waiter.Queue
	ep, tcpErr := fr.CreateEndpoint(&wq)
	if tcpErr != nil {
		log.Printf("L4 proxy: accept TCP to %s failed: %v", target, tcpErr)
		fr.Complete(true) // send RST
		return
	}
	fr.Complete(false)
	conn := gonet.NewTCPConn(&wq, ep)

	go func() {
		defer conn.Close()

		rstr, err := l.hconn.OpenRequestStream(l.ctx)
		if err != nil {
			log.Printf("L4 proxy: open stream to %s failed: %v", target, err)
			return
		}
		defer rstr.Close()

		err = rstr.SendRequestHeader(&http.Request{
			Method: http.MethodConnect,
			Host:   target,
			URL:    &url.URL{Host: target},
		})
		if err != nil {
			log.Printf("L4 proxy: send CONNECT to %s failed: %v", target, err)
			return
		}

		resp, err := rstr.ReadResponse()
		if err != nil {
			log.Printf("L4 proxy: CONNECT response from %s failed: %v", target, err)
			return
		}
		if resp.StatusCode != http.StatusOK {
			log.Printf("L4 proxy: CONNECT to %s rejected: %s", target, resp.Status)
			return
		}

		// Bidirectional relay.
		var relayWg sync.WaitGroup
		relayWg.Add(1)
		go func() {
			defer relayWg.Done()
			io.Copy(rstr, conn) // app → Cloudflare
		}()
		io.Copy(conn, rstr) // Cloudflare → app
		relayWg.Wait()
	}()
}

// netstackToTun reads outbound packets from the gvisor stack
// (SYN-ACK, TCP data, etc.) and writes them to the Android TUN fd.
func (l *l4Proxy) netstackToTun() {
	defer l.stopWg.Done()
	for {
		pkt := l.ep.ReadContext(l.ctx)
		if pkt == nil {
			return
		}
		view := pkt.ToView()
		l.tunFile.Write(view.AsSlice())
		view.Release()
		pkt.DecRef()
	}
}

// isTCPPacket returns true if pkt is an IPv4 or IPv6 TCP packet.
func isTCPPacket(pkt []byte) bool {
	if len(pkt) < 1 {
		return false
	}
	switch pkt[0] >> 4 {
	case 4: // IPv4
		if len(pkt) < 20 {
			return false
		}
		return pkt[9] == 6 // Protocol = TCP
	case 6: // IPv6
		if len(pkt) < 40 {
			return false
		}
		return pkt[6] == 6 // Next Header = TCP (no extension headers)
	}
	return false
}
