package main

import (
	"net"
	"sync"
	"testing"
)

type fakeListener struct {
	closed bool
}

func (f *fakeListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (f *fakeListener) Close() error              { f.closed = true; return nil }
func (f *fakeListener) Addr() net.Addr            { return &net.TCPAddr{} }

type fakeClient struct {
	mu      sync.Mutex
	opened  []int
	makeErr bool
}

func (c *fakeClient) ListenTCP(port int) (net.Listener, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.makeErr {
		return nil, net.ErrClosed
	}
	c.opened = append(c.opened, port)
	return &fakeListener{}, nil
}

func TestForwarderReconcileAddsAndRemoves(t *testing.T) {
	client := &fakeClient{}
	f := newForwarder(client, &peerPolicy{})

	f.reconcile([]targetSpec{
		{ListenPort: 3000, LocalAddr: "127.0.0.1:3000"},
		{ListenPort: 8080, LocalAddr: "127.0.0.1:8080"},
	})
	if got := len(f.listeners); got != 2 {
		t.Fatalf("expected 2 listeners, got %d", got)
	}

	ln3000 := f.listeners[3000].listener.(*fakeListener)

	f.reconcile([]targetSpec{
		{ListenPort: 3000, LocalAddr: "127.0.0.1:3000"},
	})
	if got := len(f.listeners); got != 1 {
		t.Fatalf("expected 1 listener after removal, got %d", got)
	}
	if _, ok := f.listeners[8080]; ok {
		t.Fatal("expected port 8080 listener to be removed")
	}
	if ln3000.closed {
		t.Fatal("unchanged listener on 3000 should not be closed")
	}
}

func TestForwarderReconcileReopensOnLocalAddrChange(t *testing.T) {
	client := &fakeClient{}
	f := newForwarder(client, &peerPolicy{})

	f.reconcile([]targetSpec{{ListenPort: 3000, LocalAddr: "127.0.0.1:3000"}})
	first := f.listeners[3000].listener.(*fakeListener)

	f.reconcile([]targetSpec{{ListenPort: 3000, LocalAddr: "127.0.0.1:4000"}})
	if !first.closed {
		t.Fatal("expected old listener to be closed when local addr changes")
	}
	if f.listeners[3000].localAddr != "127.0.0.1:4000" {
		t.Fatalf("expected updated local addr, got %s", f.listeners[3000].localAddr)
	}
}

func TestForwarderReconcileSkipsInvalid(t *testing.T) {
	client := &fakeClient{}
	f := newForwarder(client, &peerPolicy{})
	f.reconcile([]targetSpec{
		{ListenPort: 0, LocalAddr: "127.0.0.1:3000"},
		{ListenPort: 3000, LocalAddr: ""},
	})
	if got := len(f.listeners); got != 0 {
		t.Fatalf("expected no listeners for invalid targets, got %d", got)
	}
}
