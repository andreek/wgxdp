package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/andreek/wgxdp/config"
	"github.com/andreek/wgxdp/firewall"
	"github.com/andreek/wgxdp/internal"
	"github.com/andreek/wgxdp/wireguard"
	"github.com/sirupsen/logrus"
)

func main() {
	logrus.SetFormatter(&logrus.TextFormatter{
		DisableColors: false,
		FullTimestamp: true,
	})
	logrus.SetLevel(logrus.DebugLevel)

	cfg, err := config.New()
	if err != nil {
		logrus.Fatalf("[Config] %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	logrus.Info("Installing signal handlers")
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		shutdownHandler(ctx, sigs, cancel)
		wg.Done()
	}()

	// Open database
	d, err := wgxdp.GetDatabase(cfg.DBPath)
	if err != nil {
		logrus.Fatalf("[SQLite] Could not get database: %v", err)
	}

	// Create WireGuard device
	dev, err := wireguard.NewDevice(ctx, &wg, cfg.WGInterfaceName, cfg.WGListenPort, cfg.WGKeyFile)
	if err != nil {
		logrus.Fatalf("[WireGuard] Could not create device: %v", err)
	}

	// Assign server IP to the WireGuard interface
	_, subnet, err := net.ParseCIDR(cfg.WGSubnet)
	if err != nil {
		logrus.Fatalf("[WireGuard] Invalid subnet %s: %v", cfg.WGSubnet, err)
	}

	maskSize, _ := subnet.Mask.Size()
	serverAddr := cfg.WGInterfaceIP + "/" + fmt.Sprintf("%d", maskSize)
	err = dev.SetAddress(serverAddr)
	if err != nil {
		logrus.Fatalf("[WireGuard] Could not set address: %v", err)
	}

	// Bring interface up and add route
	err = dev.UpAndAddRoute(subnet)
	if err != nil {
		logrus.Fatalf("[WireGuard] Could not bring up interface: %v", err)
	}

	logrus.Infof("[WireGuard] Interface %s up with IP %s", cfg.WGInterfaceName, serverAddr)
	logrus.Infof("[WireGuard] Public key: %s", dev.PublicKey())

	// Restore peers from database
	peers, err := d.GetAllPeers()
	if err != nil {
		logrus.Fatalf("[SQLite] Could not load peers: %v", err)
	}
	for _, p := range peers {
		err = dev.AddPeer(p.PublicKey, p.AssignedIP)
		if err != nil {
			logrus.Errorf("[WireGuard] Could not restore peer %s: %v", p.Name, err)
		} else {
			logrus.Infof("[WireGuard] Restored peer %s (%s)", p.Name, p.AssignedIP)
		}
	}

	fw, err := firewall.New(cfg.WGInterfaceName, cfg.WGSubnet)
	if err != nil {
		logrus.Fatalf("[XDP] Could not load program: %v", err)
	}

	// Restore firewall rules from database
	rules, err := d.GetAllRules()
	if err != nil {
		logrus.Fatalf("[SQLite] Could not load rules: %v", err)
	}
	for _, r := range rules {
		if err := fw.AddPeerRule(r.SrcIP, r.DstIP, r.Port, uint8(r.Proto)); err != nil {
			logrus.Errorf("[XDP] Could not restore rule %d (%s -> %s:%d): %v", r.ID, r.SrcIP, r.DstIP, r.Port, err)
		} else {
			logrus.Infof("[XDP] Restored rule: %s -> %s:%d (proto %d)", r.SrcIP, r.DstIP, r.Port, r.Proto)
		}
	}

	// Start HTTP server
	srv := &wgxdp.Server{
		DB:     d,
		Device: dev,
		Config: cfg,
		XDP:    fw,
	}
	wgxdp.StartServer(srv, logrus.WithField("pkg", "server"))

	logrus.Infof("wgxdp-server v0.2.0 listening on :8337")

	wg.Wait()
	logrus.Info("Exiting cleanly...")
}

func shutdownHandler(ctx context.Context, sigs chan os.Signal, cancel context.CancelFunc) {
	select {
	case <-ctx.Done():
		logrus.Infof("Stopping shutdownHandler...")
	case <-sigs:
		cancel()
		logrus.Infof("shutdownHandler sent cancel signal...")
	}
	signal.Stop(sigs)
}
