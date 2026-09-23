package main

import (
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type tunnelClient interface {
	ListenTCP(port int) (net.Listener, error)
}

type targetSpec struct {
	ListenPort int    `json:"listen_port"`
	LocalAddr  string `json:"local_addr"`
}

type forwarder struct {
	mu        sync.Mutex
	client    tunnelClient
	peers     *peerPolicy
	listeners map[int]*activeListener
}

type peerPolicy struct {
	hub     atomic.Pointer[netip.Addr]
	sources atomic.Pointer[[]netip.Addr]
}

func (p *peerPolicy) setHub(value string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	p.hub.Store(&addr)
	return true
}

func (p *peerPolicy) setSources(values []string) {
	out := make([]netip.Addr, 0, len(values))
	for _, value := range values {
		if addr, err := netip.ParseAddr(strings.TrimSpace(value)); err == nil {
			out = append(out, addr.Unmap())
		}
	}
	p.sources.Store(&out)
}

func (p *peerPolicy) isHub(addr netip.Addr) bool {
	hub := p.hub.Load()
	return hub != nil && addr.IsValid() && *hub == addr.Unmap()
}

func (p *peerPolicy) allowSubnetSource(addr netip.Addr) bool {
	if p.isHub(addr) {
		return true
	}
	sources := p.sources.Load()
	if sources == nil {
		return false
	}
	addr = addr.Unmap()
	for _, allowed := range *sources {
		if allowed == addr {
			return true
		}
	}
	return false
}

func remoteAddrOf(conn net.Conn) netip.Addr {
	if conn == nil || conn.RemoteAddr() == nil {
		return netip.Addr{}
	}
	if tcp, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		return tcp.AddrPort().Addr().Unmap()
	}
	parsed, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil {
		return netip.Addr{}
	}
	return parsed.Addr().Unmap()
}

type activeListener struct {
	listener  net.Listener
	localAddr string
}

func newForwarder(client tunnelClient, peers *peerPolicy) *forwarder {
	return &forwarder{client: client, peers: peers, listeners: make(map[int]*activeListener)}
}

func (f *forwarder) reconcile(targets []targetSpec) {
	f.mu.Lock()
	defer f.mu.Unlock()

	desired := make(map[int]string, len(targets))
	for _, t := range targets {
		if t.ListenPort <= 0 || t.LocalAddr == "" {
			continue
		}
		desired[t.ListenPort] = t.LocalAddr
	}

	for port, active := range f.listeners {
		local, ok := desired[port]
		if !ok || local != active.localAddr {
			_ = active.listener.Close()
			delete(f.listeners, port)
		}
	}

	for port, local := range desired {
		if _, ok := f.listeners[port]; ok {
			continue
		}
		ln, err := f.client.ListenTCP(port)
		if err != nil {
			log.Printf("forwarder: listen on tunnel port %d failed: %v", port, err)
			continue
		}
		active := &activeListener{listener: ln, localAddr: local}
		f.listeners[port] = active
		go f.accept(active)
		log.Printf("forwarder: tunnel port %d -> %s", port, local)
	}
}

func (f *forwarder) accept(active *activeListener) {
	for {
		conn, err := active.listener.Accept()
		if err != nil {
			return
		}
		if remote := remoteAddrOf(conn); !f.peers.isHub(remote) {
			log.Printf("forwarder: rejected relay connection from %s", remote)
			_ = conn.Close()
			continue
		}
		go handleConn(conn, active.localAddr)
	}
}

func (f *forwarder) stop() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for port, active := range f.listeners {
		_ = active.listener.Close()
		delete(f.listeners, port)
	}
}

func handleConn(tunnelConn net.Conn, localAddr string) {
	defer tunnelConn.Close()
	local, err := net.DialTimeout("tcp", localAddr, 10*time.Second)
	if err != nil {
		log.Printf("forwarder: dial local %s failed: %v", localAddr, err)
		return
	}
	defer local.Close()

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
	go copyIdle(local, tunnelConn)
	go copyIdle(tunnelConn, local)
	<-done
}
