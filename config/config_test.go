package config

import (
	"os"
	"testing"
)

func TestNewConfigFileNotFound(t *testing.T) {
	t.Setenv("CONFIG_FILE", "/nonexistent/config.yaml")
	_, err := New()
	if err == nil {
		t.Fatal("New() should return error for missing config file")
	}
}

func TestNewConfigValid(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatalf("could not create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString("name: test-vpn\nserver_url: http://192.168.1.1:8337\nwg_endpoint: home.example.com:5820\nwg_subnet: 10.200.0.0/24\nwg_interface_ip: 10.200.0.1\nwg_interface_name: wg0\nwg_listen_port: 5820\n")
	if err != nil {
		t.Fatalf("could not write temp file: %v", err)
	}
	tmpFile.Close()

	t.Setenv("CONFIG_FILE", tmpFile.Name())
	cfg, err := New()
	if err != nil {
		t.Fatalf("New() should not return error: %v", err)
	}
	if cfg.Name != "test-vpn" {
		t.Errorf("expected Name = %q, got %q", "test-vpn", cfg.Name)
	}
	if cfg.ServerURL != "http://192.168.1.1:8337" {
		t.Errorf("expected ServerURL = %q, got %q", "http://192.168.1.1:8337", cfg.ServerURL)
	}
	if cfg.WGEndpoint != "home.example.com:5820" {
		t.Errorf("expected WGEndpoint = %q, got %q", "home.example.com:5820", cfg.WGEndpoint)
	}
	if cfg.WGSubnet != "10.200.0.0/24" {
		t.Errorf("expected WGSubnet = %q, got %q", "10.200.0.0/24", cfg.WGSubnet)
	}
	if cfg.WGInterfaceIP != "10.200.0.1" {
		t.Errorf("expected WGInterfaceIP = %q, got %q", "10.200.0.1", cfg.WGInterfaceIP)
	}
	if cfg.WGInterfaceName != "wg0" {
		t.Errorf("expected WGInterfaceName = %q, got %q", "wg0", cfg.WGInterfaceName)
	}
	if cfg.WGListenPort != 5820 {
		t.Errorf("expected WGListenPort = %d, got %d", 5820, cfg.WGListenPort)
	}
}

func TestNewConfigInvalidYAML(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatalf("could not create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString(":\tinvalid:\n\t- [yaml\n")
	if err != nil {
		t.Fatalf("could not write temp file: %v", err)
	}
	tmpFile.Close()

	t.Setenv("CONFIG_FILE", tmpFile.Name())
	_, err = New()
	if err == nil {
		t.Fatal("New() should return error for invalid YAML")
	}
}
