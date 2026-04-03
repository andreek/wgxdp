// Package wireguard manages WireGuard network interfaces and peers via
// wgctrl and netlink.
package wireguard

import (
	"context"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// DeviceAttrs holds the WireGuard device configuration: keys, listen port, and MTU.
type DeviceAttrs struct {
	listenPort int
	privateKey *wgtypes.Key
	publicKey  *wgtypes.Key
	psk        *wgtypes.Key
	keepalive  *time.Duration
	name       string
	MTU        int
}

// Device represents a WireGuard network interface.
type Device struct {
	link  *netlink.GenericLink
	attrs *DeviceAttrs
}

// NewDevice creates a WireGuard interface, loads or generates keys, and applies
// the configuration. The interface is removed when ctx is cancelled.
func NewDevice(ctx context.Context, wg *sync.WaitGroup, name string, listenPort int, keyFile string) (*Device, error) {
	logrus.WithField("pkg", "WireGuard").Infof("Set up device: %s (port %d)", name, listenPort)

	devAttrs := DeviceAttrs{
		listenPort: listenPort,
		name:       name,
		MTU:        1420,
	}

	err := devAttrs.setupKeys(keyFile, "")
	if err != nil {
		return nil, err
	}

	la := netlink.LinkAttrs{
		Name: devAttrs.name,
		MTU:  devAttrs.MTU,
	}
	link := &netlink.GenericLink{LinkAttrs: la, LinkType: "wireguard"}

	link, err = ensureLink(link)
	if err != nil {
		return nil, err
	}

	dev := Device{
		link:  link,
		attrs: &devAttrs,
	}

	cfg := wgtypes.Config{
		PrivateKey:   dev.attrs.privateKey,
		ListenPort:   &dev.attrs.listenPort,
		ReplacePeers: true,
	}

	err = dev.apply(cfg)
	if err != nil {
		return nil, err
	}

	// Remove the device on context cancellation
	wg.Add(1)
	go func() {
		<-ctx.Done()
		err := dev.remove()
		if err != nil {
			logrus.WithField("pkg", "WireGuard").Errorf("Error while removing device: %v", err)
		}
		logrus.WithField("pkg", "WireGuard").Infof("Removed device %s", dev.attrs.name)
		wg.Done()
	}()

	return &dev, nil
}

// PublicKey returns the device's WireGuard public key as a base64 string.
func (dev *Device) PublicKey() string {
	return dev.attrs.publicKey.String()
}

// SetAddress assigns an IP address to the WireGuard interface.
func (dev *Device) SetAddress(ipCIDR string) error {
	addr, err := netlink.ParseAddr(ipCIDR)
	if err != nil {
		return fmt.Errorf("could not parse address %s: %w", ipCIDR, err)
	}
	err = netlink.AddrAdd(dev.link, addr)
	if err != nil {
		return fmt.Errorf("could not add address to %s: %w", dev.attrs.name, err)
	}
	return nil
}

// UpAndAddRoute brings the interface up and adds a route for the given subnet.
func (dev *Device) UpAndAddRoute(dst *net.IPNet) error {
	return dev.upAndAddRoute(dst)
}

// AddPeer adds a WireGuard peer with the given public key and allowed IP (/32).
// The endpoint is not set — WireGuard learns it from the first handshake.
func (dev *Device) AddPeer(peerPublicKeyRaw string, allowedIP string) error {
	peerPublicKey, err := wgtypes.ParseKey(peerPublicKeyRaw)
	if err != nil {
		return fmt.Errorf("failed to parse publicKey: %w", err)
	}

	_, peerNet, err := net.ParseCIDR(allowedIP + "/32")
	if err != nil {
		return fmt.Errorf("failed to parse allowed IP: %w", err)
	}

	cfg := wgtypes.Config{
		ReplacePeers: false,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:         peerPublicKey,
				PresharedKey:      dev.attrs.psk,
				ReplaceAllowedIPs: true,
				AllowedIPs: []net.IPNet{
					*peerNet,
				},
			},
		},
	}

	err = dev.apply(cfg)
	if err != nil {
		return fmt.Errorf("failed to add peer: %w", err)
	}

	return nil
}

// RemovePeer removes a WireGuard peer by public key.
func (dev *Device) RemovePeer(peerPublicKeyRaw string) error {
	peerPublicKey, err := wgtypes.ParseKey(peerPublicKeyRaw)
	if err != nil {
		return fmt.Errorf("failed to parse publicKey: %w", err)
	}

	cfg := wgtypes.Config{
		ReplacePeers: false,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey: peerPublicKey,
				Remove:    true,
			},
		},
	}

	err = dev.apply(cfg)
	if err != nil {
		return fmt.Errorf("failed to remove peer: %w", err)
	}

	return nil
}

// PeerStatus holds the runtime status of a WireGuard peer.
type PeerStatus struct {
	PublicKey         string    `json:"public_key"`
	LastHandshakeTime time.Time `json:"last_handshake"`
	ReceiveBytes      int64     `json:"receive_bytes"`
	TransmitBytes     int64     `json:"transmit_bytes"`
	Active            bool      `json:"active"`
}

// GetPeerStatuses returns the handshake and traffic status of all peers.
func (dev *Device) GetPeerStatuses() (map[string]PeerStatus, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("failed to open wgctrl: %w", err)
	}
	defer client.Close()

	d, err := client.Device(dev.attrs.name)
	if err != nil {
		return nil, fmt.Errorf("failed to get device: %w", err)
	}

	result := make(map[string]PeerStatus, len(d.Peers))
	for _, p := range d.Peers {
		active := !p.LastHandshakeTime.IsZero() && time.Since(p.LastHandshakeTime) < 3*time.Minute
		result[p.PublicKey.String()] = PeerStatus{
			PublicKey:         p.PublicKey.String(),
			LastHandshakeTime: p.LastHandshakeTime,
			ReceiveBytes:      p.ReceiveBytes,
			TransmitBytes:     p.TransmitBytes,
			Active:            active,
		}
	}
	return result, nil
}

func ensureLink(wglan *netlink.GenericLink) (*netlink.GenericLink, error) {
	err := netlink.LinkAdd(wglan)
	if err == syscall.EEXIST {
		existing, err := netlink.LinkByName(wglan.Name)
		if err != nil {
			return nil, err
		}

		logrus.WithField("pkg", "WireGuard").Warningf("%q already exists; recreating device", wglan.Name)
		err = netlink.LinkDel(existing)
		if err != nil {
			return nil, err
		}

		err = netlink.LinkAdd(wglan)
		if err != nil {
			return nil, fmt.Errorf("could not create wireguard interface: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("could not create wireguard interface: %w", err)
	}

	_, err = netlink.LinkByIndex(wglan.Index)
	if err != nil {
		return nil, fmt.Errorf("can't locate created wireguard device with index %v: %w", wglan.Index, err)
	}

	return wglan, nil
}

func (dev *Device) remove() error {
	err := netlink.LinkDel(dev.link)
	if err != nil {
		return fmt.Errorf("could not remove wireguard device: %w", err)
	}
	return nil
}
