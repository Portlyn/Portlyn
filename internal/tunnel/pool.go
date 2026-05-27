package tunnel

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
)

var (
	ErrPoolExhausted = errors.New("tunnel ip pool exhausted")
	ErrIPNotInPool   = errors.New("ip not in tunnel pool")
)

type IPPool struct {
	mu        sync.Mutex
	prefix    netip.Prefix
	reserved  map[string]struct{}
	allocated map[string]struct{}
}

func NewIPPool(cidr string, reserved ...netip.Addr) (*IPPool, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("parse cidr: %w", err)
	}
	prefix = prefix.Masked()
	if !prefix.Addr().Is4() {
		return nil, fmt.Errorf("only ipv4 cidrs supported")
	}
	pool := &IPPool{
		prefix:    prefix,
		reserved:  make(map[string]struct{}),
		allocated: make(map[string]struct{}),
	}
	for _, addr := range reserved {
		pool.reserved[addr.String()] = struct{}{}
	}
	return pool, nil
}

func (p *IPPool) Prefix() netip.Prefix { return p.prefix }

func (p *IPPool) MarkAllocated(addr netip.Addr) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.prefix.Contains(addr) {
		return ErrIPNotInPool
	}
	p.allocated[addr.String()] = struct{}{}
	return nil
}

func (p *IPPool) Release(addr netip.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.allocated, addr.String())
}

func (p *IPPool) Allocate() (netip.Addr, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	base := p.prefix.Addr().As4()
	bits := p.prefix.Bits()
	hostBits := 32 - bits
	if hostBits <= 1 {
		return netip.Addr{}, ErrPoolExhausted
	}
	total := uint32(1) << uint(hostBits)
	baseInt := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])

	for offset := uint32(2); offset < total-1; offset++ {
		candidateInt := baseInt + offset
		candidate := netip.AddrFrom4([4]byte{
			byte(candidateInt >> 24),
			byte(candidateInt >> 16),
			byte(candidateInt >> 8),
			byte(candidateInt),
		})
		key := candidate.String()
		if _, taken := p.allocated[key]; taken {
			continue
		}
		if _, taken := p.reserved[key]; taken {
			continue
		}
		p.allocated[key] = struct{}{}
		return candidate, nil
	}
	return netip.Addr{}, ErrPoolExhausted
}

func (p *IPPool) AllocatedCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.allocated)
}
