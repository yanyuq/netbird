package uspfilter

import (
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/firewall/uspfilter/common"
)

// localIPSnapshot is an immutable snapshot of local IP addresses. The v4 bitmap
// gives O(1) lookup for IPv4, and the v6 map handles the small number of local
// IPv6 addresses. The entire snapshot is swapped atomically so reads are lock-free.
type localIPSnapshot struct {
	ipv4Bitmap [256]*ipv4LowBitmap
	ipv6Set    map[netip.Addr]struct{}
}

// ipv4LowBitmap is a bitmap for the lower 24 bits of an IPv4 address
type ipv4LowBitmap struct {
	bitmap [8192]uint32
}

type localIPManager struct {
	snapshot atomic.Pointer[localIPSnapshot]
}

func newLocalIPManager() *localIPManager {
	m := &localIPManager{}
	m.snapshot.Store(&localIPSnapshot{
		ipv6Set: make(map[netip.Addr]struct{}),
	})
	return m
}



func addToSnapshot(ip netip.Addr, bitmap *[256]*ipv4LowBitmap, ipv6Set map[netip.Addr]struct{}, addresses *[]netip.Addr) {
	if ip.Is4() {
		ipv4 := ip.AsSlice()

		high := uint16(ipv4[0])
		low := (uint16(ipv4[1]) << 8) | (uint16(ipv4[2]) << 4) | uint16(ipv4[3])

		if bitmap[high] == nil {
			bitmap[high] = &ipv4LowBitmap{}
		}

		index := low / 32
		bit := low % 32
		bitmap[high].bitmap[index] |= 1 << bit
	} else if ip.Is6() {
		ipv6Set[ip] = struct{}{}
	}

	*addresses = append(*addresses, ip)
}

func checkBitmapBit(bitmap *[256]*ipv4LowBitmap, ip []byte) bool {
	high := uint16(ip[0])
	low := (uint16(ip[1]) << 8) | (uint16(ip[2]) << 4) | uint16(ip[3])

	if bitmap[high] == nil {
		return false
	}

	index := low / 32
	bit := low % 32
	return (bitmap[high].bitmap[index] & (1 << bit)) != 0
}

func processInterface(iface net.Interface, bitmap *[256]*ipv4LowBitmap, ipv6Set map[netip.Addr]struct{}, addresses *[]netip.Addr) {
	addrs, err := iface.Addrs()
	if err != nil {
		log.Debugf("get addresses for interface %s failed: %v", iface.Name, err)
		return
	}

	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		default:
			continue
		}

		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			log.Warnf("invalid IP address %s in interface %s", ip.String(), iface.Name)
			continue
		}

		addToSnapshot(addr.Unmap(), bitmap, ipv6Set, addresses)
	}
}

// UpdateLocalIPs rebuilds the local IP snapshot and swaps it in atomically.
func (m *localIPManager) UpdateLocalIPs(iface common.IFaceMapper) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()

	var newBitmap [256]*ipv4LowBitmap
	newV6 := make(map[netip.Addr]struct{})
	var addresses []netip.Addr

	// 127.0.0.0/8
	newBitmap[127] = &ipv4LowBitmap{}
	for i := 0; i < 8192; i++ {
		// #nosec G602 -- bitmap is defined as [8192]uint32, loop range is correct
		newBitmap[127].bitmap[i] = 0xFFFFFFFF
	}

	// ::1
	newV6[netip.IPv6Loopback()] = struct{}{}

	if iface != nil {
		addToSnapshot(iface.Address().IP, &newBitmap, newV6, &addresses)
		if v6 := iface.Address().IPv6; v6.IsValid() {
			addToSnapshot(v6, &newBitmap, newV6, &addresses)
		}
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		log.Warnf("failed to get interfaces: %v", err)
	} else {
		for _, intf := range interfaces {
			processInterface(intf, &newBitmap, newV6, &addresses)
		}
	}

	m.snapshot.Store(&localIPSnapshot{
		ipv4Bitmap: newBitmap,
		ipv6Set:    newV6,
	})

	log.Debugf("Local IP addresses: %v", addresses)
	return nil
}

// IsLocalIP checks if the given IP is a local address. Lock-free on the read path.
func (m *localIPManager) IsLocalIP(ip netip.Addr) bool {
	s := m.snapshot.Load()

	if ip.Is4() {
		return checkBitmapBit(&s.ipv4Bitmap, ip.AsSlice())
	}

	_, found := s.ipv6Set[ip]
	return found
}
