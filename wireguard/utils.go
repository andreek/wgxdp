package wireguard

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"github.com/vishvananda/netlink"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func (dev *Device) apply(cfg wgtypes.Config) error {
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to open wgctrl: %w", err)
	}
	defer client.Close()

	err = client.ConfigureDevice(dev.attrs.name, cfg)
	if err != nil {
		dev.remove()
		return fmt.Errorf("failed to configure device %w", err)
	}
	return nil
}

func (devAttrs *DeviceAttrs) setupKeys(keyFile string, psk string) error {
	if keyFile == "" {
		keyFile = "/var/lib/wgxdp/wgkey"
	}

	if _, err := os.Stat(keyFile); errors.Is(err, os.ErrNotExist) {
		privateKey, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return fmt.Errorf("could not generate private key: %w", err)
		}
		devAttrs.privateKey = &privateKey

		publicKey := privateKey.PublicKey()
		devAttrs.publicKey = &publicKey

		err = writePrivateKey(keyFile, privateKey.String())
		if err != nil {
			return fmt.Errorf("could not write key file: %w", err)
		}
	} else {
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return err
		}
		privateKey, err := wgtypes.ParseKey(string(data))
		if err != nil {
			return fmt.Errorf("could not parse private key from file: %w", err)
		}
		devAttrs.privateKey = &privateKey
		publicKey := privateKey.PublicKey()
		devAttrs.publicKey = &publicKey
	}

	if psk != "" {
		presharedKey, err := wgtypes.ParseKey(psk)
		if err != nil {
			return fmt.Errorf("could not parse psk: %w", err)
		}
		devAttrs.psk = &presharedKey
	}

	return nil
}

func (dev *Device) upAndAddRoute(dst *net.IPNet) error {
	err := netlink.LinkSetUp(dev.link)
	if err != nil {
		return fmt.Errorf("failed to set interface %s to UP state: %w", dev.attrs.name, err)
	}

	route := netlink.Route{
		LinkIndex: dev.link.Attrs().Index,
		Scope:     netlink.SCOPE_LINK,
		Dst:       dst,
	}
	err = netlink.RouteAdd(&route)
	if err != nil && !errors.Is(err, syscall.EEXIST) {
		return fmt.Errorf("failed to add route %s: %w", dev.attrs.name, err)
	}

	return nil
}

// GetIP returns the first IP address assigned to the named network interface.
func GetIP(interfaceName string) string {
	var ip net.IP
	if interfaceName != "" {
		existing, _ := net.InterfaceByName(interfaceName)
		addrs, _ := existing.Addrs()
		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			break
		}
	}
	return ip.String()
}

func writePrivateKey(path string, content string) error {
	dir, _ := filepath.Split(path)
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		return err
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}

	err = os.Chmod(path, 0400)
	if err != nil {
		return err
	}

	_, err = f.WriteString(content)
	if err != nil {
		return err
	}

	f.Close()

	return nil
}
