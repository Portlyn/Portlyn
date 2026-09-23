package tunnel

import (
	"net/netip"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestSubnetProxyPermits(t *testing.T) {
	proxy := &SubnetProxy{
		Subnets: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		AllowSource: func(addr netip.Addr) bool {
			return addr == netip.MustParseAddr("10.42.0.1")
		},
	}
	id := func(src, dst [4]byte) stack.TransportEndpointID {
		return stack.TransportEndpointID{RemoteAddress: tcpip.AddrFrom4(src), LocalAddress: tcpip.AddrFrom4(dst)}
	}
	if !proxy.permits(id([4]byte{10, 42, 0, 1}, [4]byte{192, 168, 1, 5})) {
		t.Fatal("expected hub flow into advertised subnet to be permitted")
	}
	if proxy.permits(id([4]byte{10, 42, 0, 1}, [4]byte{192, 168, 2, 5})) {
		t.Fatal("expected destination outside advertised subnets to be rejected")
	}
	if proxy.permits(id([4]byte{10, 42, 0, 1}, [4]byte{127, 0, 0, 1})) {
		t.Fatal("expected loopback destination to be rejected")
	}
	if proxy.permits(id([4]byte{10, 42, 1, 9}, [4]byte{192, 168, 1, 5})) {
		t.Fatal("expected unauthorized source to be rejected")
	}
}
