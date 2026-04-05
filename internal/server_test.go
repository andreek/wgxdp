package wgxdp

import (
	"testing"

	"github.com/andreek/wgxdp/config"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	db, err := GetDatabase("server_test.sql")
	if err != nil {
		t.Fatalf("GetDatabase() error: %v", err)
	}
	return &Server{
		DB:     db,
		Device: nil, // nil in tests — WireGuard calls are skipped
		Config: &config.Config{
			ServerURL:  "http://localhost:8337",
			WGSubnet:   "10.200.0.0/24",
			WGEndpoint: "home.example.com:5820",
		},
		indexHTML: []byte("<!DOCTYPE html><html><body>wgxdp</body></html>"),
	}
}
