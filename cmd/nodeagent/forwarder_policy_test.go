package main

import (
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

type remoteConn struct {
	net.Conn
	remote net.Addr
}

func (c *remoteConn) RemoteAddr() net.Addr { return c.remote }

type queueListener struct {
	conns  chan net.Conn
	closed chan struct{}
}

func newQueueListener() *queueListener {
	return &queueListener{conns: make(chan net.Conn, 4), closed: make(chan struct{})}
}

func (l *queueListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *queueListener) Close() error   { close(l.closed); return nil }
func (l *queueListener) Addr() net.Addr { return &net.TCPAddr{} }

func TestForwarderOnlyRelaysConnectionsFromHub(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend listen: %v", err)
	}
	defer backend.Close()
	accepted := make(chan struct{}, 4)
	go func() {
		for {
			c, err := backend.Accept()
			if err != nil {
				return
			}
			accepted <- struct{}{}
			_ = c.Close()
		}
	}()

	peers := &peerPolicy{}
	if !peers.setHub("10.42.0.1") {
		t.Fatal("expected hub ip to parse")
	}
	f := newForwarder(&fakeClient{}, peers)
	ln := newQueueListener()
	defer ln.Close()
	go f.accept(&activeListener{listener: ln, localAddr: backend.Addr().String()})

	rogueLocal, rogueRemote := net.Pipe()
	defer rogueLocal.Close()
	ln.conns <- &remoteConn{Conn: rogueRemote, remote: &net.TCPAddr{IP: net.ParseIP("10.42.1.5"), Port: 40000}}
	_ = rogueLocal.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := rogueLocal.Read(make([]byte, 1)); err != io.EOF && err != io.ErrClosedPipe {
		t.Fatalf("expected relay from a non-hub peer to be closed, got %v", err)
	}
	select {
	case <-accepted:
		t.Fatal("non-hub peer reached the backend")
	case <-time.After(200 * time.Millisecond):
	}

	hubLocal, hubRemote := net.Pipe()
	defer hubLocal.Close()
	ln.conns <- &remoteConn{Conn: hubRemote, remote: &net.TCPAddr{IP: net.ParseIP("10.42.0.1"), Port: 40001}}
	select {
	case <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("expected relay from the hub to reach the backend")
	}
}

func TestForwarderRejectsRelayWhenHubUnknown(t *testing.T) {
	peers := &peerPolicy{}
	if peers.isHub(netip.MustParseAddr("10.42.0.1")) {
		t.Fatal("expected unknown hub to match nothing")
	}
}

func TestPeerPolicySubnetSources(t *testing.T) {
	peers := &peerPolicy{}
	peers.setHub("10.42.0.1")
	if peers.allowSubnetSource(netip.MustParseAddr("10.42.1.2")) {
		t.Fatal("expected client source to be rejected before the hub lists it")
	}
	if !peers.allowSubnetSource(netip.MustParseAddr("10.42.0.1")) {
		t.Fatal("expected hub source to be allowed")
	}
	peers.setSources([]string{"10.42.1.2", "bogus"})
	if !peers.allowSubnetSource(netip.MustParseAddr("10.42.1.2")) {
		t.Fatal("expected listed client source to be allowed")
	}
	if peers.allowSubnetSource(netip.MustParseAddr("10.42.1.3")) {
		t.Fatal("expected unlisted client source to be rejected")
	}
	if peers.allowSubnetSource(netip.MustParseAddr("10.42.0.2")) {
		t.Fatal("expected other node source to be rejected")
	}
}
