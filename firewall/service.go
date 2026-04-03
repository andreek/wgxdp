// Package firewall manages XDP program to filter packets per peer
package firewall

//go:generate go tool bpf2go -tags linux program c/program.c

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Firewall holds an attached XDP program and its eBPF maps for per-peer
// traffic filtering on a WireGuard interface.
type Firewall struct {
	objs programObjects
	link link.Link
}

// PeerRuleKey is the eBPF map key for a firewall rule. Fields use host byte
// order (LittleEndian on LE systems) to match the XDP program's expectations.
type PeerRuleKey struct {
	SrcIP uint32
	DstIP uint32
	Port  uint16
	Proto uint8
	Pad   uint8
}

// New loads the XDP program, configures the subnet filter, and attaches it to
// the named network interface. The caller must ensure CAP_BPF and CAP_NET_ADMIN.
func New(ifaceName string, wgSubnet string) (*Firewall, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifaceName, err)
		return nil, err
	}

	spec, err := loadProgram()
	if err != nil {
		log.Fatal("Loading eBPF spec:", err)
	}

	// Only filter traffic from the WireGuard subnet
	_, subnet, _ := net.ParseCIDR(wgSubnet)
	if subnet != nil {
		netIP := binary.LittleEndian.Uint32(subnet.IP.To4())
		mask := binary.LittleEndian.Uint32(subnet.Mask)
		if err := spec.Variables["filter_net"].Set(netIP); err != nil {
			log.Fatal("Setting filter_net:", err)
		}
		if err := spec.Variables["filter_mask"].Set(mask); err != nil {
			log.Fatal("Setting filter_mask:", err)
		}
	}

	var objs programObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}

	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.Filter,
		Interface: iface.Index,
	})
	if err != nil {
		objs.Close()
		log.Fatal("Attaching XDP:", err)
		return nil, err
	}

	return &Firewall{
		link: link,
		objs: objs,
	}, nil
}

// AddPeerRule inserts a traffic rule into the eBPF peer_rules map.
func (fw Firewall) AddPeerRule(srcIP string, dstIP string, port int, proto uint8) error {
	key, err := getRuleKey(srcIP, dstIP, port, proto)
	if err != nil {
		return fmt.Errorf("could not parse rule key: %w", err)
	}
	if err := fw.objs.PeerRules.Put(key, uint32(1)); err != nil {
		return fmt.Errorf("could not add peer rule: %w", err)
	}
	return nil
}

// RemovePeerRule deletes a traffic rule from the eBPF peer_rules map.
func (fw Firewall) RemovePeerRule(srcIP string, dstIP string, port int, proto uint8) error {
	key, err := getRuleKey(srcIP, dstIP, port, proto)
	if err != nil {
		return fmt.Errorf("could not parse rule key: %w", err)
	}
	if err := fw.objs.PeerRules.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("could not delete rule key: %w", err)
	}
	return nil
}

func getRuleKey(srcIP string, dstIP string, port int, proto uint8) (*PeerRuleKey, error) {
	src := net.ParseIP(srcIP)
	if src == nil {
		return nil, fmt.Errorf("invalid source IP: %q", srcIP)
	}
	src4 := src.To4()
	if src4 == nil {
		return nil, fmt.Errorf("source IP is not IPv4: %q", srcIP)
	}

	dst := net.ParseIP(dstIP)
	if dst == nil {
		return nil, fmt.Errorf("invalid destination IP: %q", dstIP)
	}
	dst4 := dst.To4()
	if dst4 == nil {
		return nil, fmt.Errorf("destination IP is not IPv4: %q", dstIP)
	}

	key := PeerRuleKey{
		SrcIP: binary.LittleEndian.Uint32(src4),
		DstIP: binary.LittleEndian.Uint32(dst4),
		Port:  uint16(port),
		Proto: proto,
	}
	return &key, nil
}
