package tunnel

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const nicID = 1

type DialFunc func(network, address string) (net.Conn, error)

type NetStack struct {
	ep             *channel.Endpoint
	stack          *stack.Stack
	events         chan tun.Event
	incomingPacket chan *buffer.View
	closed         chan struct{}
	closeOnce      sync.Once
	mtu            int
}

func CreateNetStack(localAddrs []netip.Addr, mtu int) (tun.Device, *NetStack, error) {
	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
		HandleLocal:        false,
	}
	dev := &NetStack{
		ep:             channel.New(1024, uint32(mtu), ""),
		stack:          stack.New(opts),
		events:         make(chan tun.Event, 10),
		incomingPacket: make(chan *buffer.View),
		closed:         make(chan struct{}),
		mtu:            mtu,
	}
	sackEnabled := tcpip.TCPSACKEnabled(true)
	if err := dev.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabled); err != nil {
		return nil, nil, fmt.Errorf("enable TCP SACK: %v", err)
	}
	dev.ep.AddNotify(dev)
	if err := dev.stack.CreateNIC(nicID, dev.ep); err != nil {
		return nil, nil, fmt.Errorf("CreateNIC: %v", err)
	}
	for _, ip := range localAddrs {
		if !ip.Is4() {
			continue
		}
		protoAddr := tcpip.ProtocolAddress{
			Protocol:          ipv4.ProtocolNumber,
			AddressWithPrefix: tcpip.AddrFromSlice(ip.AsSlice()).WithPrefix(),
		}
		if err := dev.stack.AddProtocolAddress(nicID, protoAddr, stack.AddressProperties{}); err != nil {
			return nil, nil, fmt.Errorf("AddProtocolAddress(%v): %v", ip, err)
		}
	}
	dev.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: nicID})

	dev.events <- tun.EventUp
	return dev, dev, nil
}

func (n *NetStack) Stack() *stack.Stack {
	return n.stack
}

func (n *NetStack) Name() (string, error) { return "portlyn", nil }
func (n *NetStack) File() *os.File        { return nil }
func (n *NetStack) Events() <-chan tun.Event {
	return n.events
}
func (n *NetStack) MTU() (int, error) { return n.mtu, nil }
func (n *NetStack) BatchSize() int    { return 1 }

func (n *NetStack) Read(buf [][]byte, sizes []int, offset int) (int, error) {
	var view *buffer.View
	select {
	case view = <-n.incomingPacket:
	case <-n.closed:
		return 0, os.ErrClosed
	}
	count, err := view.Read(buf[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = count
	return 1, nil
}

func (n *NetStack) Write(buf [][]byte, offset int) (int, error) {
	for _, b := range buf {
		packet := b[offset:]
		if len(packet) == 0 {
			continue
		}
		if packet[0]>>4 != 4 {
			return 0, syscall.EAFNOSUPPORT
		}
		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
		n.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
	}
	return len(buf), nil
}

func (n *NetStack) WriteNotify() {
	pkt := n.ep.Read()
	if pkt.IsNil() {
		return
	}
	view := pkt.ToView()
	pkt.DecRef()
	select {
	case n.incomingPacket <- view:
	case <-n.closed:
	}
}

func (n *NetStack) Close() error {
	n.closeOnce.Do(func() {
		close(n.closed)
		n.stack.RemoveNIC(nicID)
		n.ep.Close()
		close(n.events)
	})
	return nil
}

func (n *NetStack) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, sport, err := net.SplitHostPort(address)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Err: err}
	}
	port, err := strconv.Atoi(sport)
	if err != nil || port < 0 || port > 65535 {
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("invalid port %q", sport)}
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Err: fmt.Errorf("netstack dial requires an ip host: %w", err)}
	}
	full := tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFromSlice(ip.AsSlice()), Port: uint16(port)}
	return gonet.DialContextTCP(ctx, n.stack, full, ipv4.ProtocolNumber)
}

func (n *NetStack) ListenTCP(port int) (net.Listener, error) {
	full := tcpip.FullAddress{NIC: nicID, Port: uint16(port)}
	return gonet.ListenTCP(n.stack, full, ipv4.ProtocolNumber)
}

func (n *NetStack) EnableForwarding() error {
	if err := n.stack.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true); err != nil {
		return fmt.Errorf("enable ipv4 forwarding: %v", err)
	}
	return nil
}

func (n *NetStack) EnableSubnetProxy(subnets []netip.Prefix, dial DialFunc) error {
	if len(subnets) == 0 {
		return nil
	}
	if err := n.stack.SetPromiscuousMode(nicID, true); err != nil {
		return fmt.Errorf("set promiscuous: %v", err)
	}
	if err := n.stack.SetSpoofing(nicID, true); err != nil {
		return fmt.Errorf("set spoofing: %v", err)
	}
	tcpFwd := tcp.NewForwarder(n.stack, 0, 2048, func(req *tcp.ForwarderRequest) {
		id := req.ID()
		target := net.JoinHostPort(addrToIP(id.LocalAddress), strconv.Itoa(int(id.LocalPort)))
		var wq waiter.Queue
		ep, tErr := req.CreateEndpoint(&wq)
		if tErr != nil {
			req.Complete(true)
			return
		}
		req.Complete(false)
		go proxyTCP(gonet.NewTCPConn(&wq, ep), target, dial)
	})
	n.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	udpFwd := udp.NewForwarder(n.stack, func(req *udp.ForwarderRequest) {
		id := req.ID()
		target := net.JoinHostPort(addrToIP(id.LocalAddress), strconv.Itoa(int(id.LocalPort)))
		var wq waiter.Queue
		ep, tErr := req.CreateEndpoint(&wq)
		if tErr != nil {
			return
		}
		go proxyUDP(gonet.NewUDPConn(&wq, ep), target, dial)
	})
	n.stack.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)
	return nil
}

func addrToIP(addr tcpip.Address) string {
	return net.IP(addr.AsSlice()).String()
}

func proxyTCP(tunnelConn net.Conn, target string, dial DialFunc) {
	defer tunnelConn.Close()
	remote, err := dial("tcp", target)
	if err != nil {
		return
	}
	defer remote.Close()
	const idle = 5 * time.Minute
	done := make(chan struct{}, 2)
	copyIdle := func(dst, src net.Conn) {
		buf := make([]byte, 32*1024)
		for {
			_ = src.SetReadDeadline(time.Now().Add(idle))
			count, readErr := src.Read(buf)
			if count > 0 {
				if _, writeErr := dst.Write(buf[:count]); writeErr != nil {
					break
				}
			}
			if readErr != nil {
				break
			}
		}
		done <- struct{}{}
	}
	go copyIdle(remote, tunnelConn)
	go copyIdle(tunnelConn, remote)
	<-done
}

func proxyUDP(tunnelConn net.Conn, target string, dial DialFunc) {
	defer tunnelConn.Close()
	remote, err := dial("udp", target)
	if err != nil {
		return
	}
	defer remote.Close()
	const idle = 2 * time.Minute
	done := make(chan struct{}, 2)
	pump := func(dst, src net.Conn) {
		buf := make([]byte, 65535)
		for {
			_ = src.SetReadDeadline(time.Now().Add(idle))
			count, readErr := src.Read(buf)
			if count > 0 {
				if _, writeErr := dst.Write(buf[:count]); writeErr != nil {
					break
				}
			}
			if readErr != nil {
				break
			}
		}
		done <- struct{}{}
	}
	go pump(remote, tunnelConn)
	go pump(tunnelConn, remote)
	<-done
}
