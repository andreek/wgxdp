package wgxdp

import (
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"time"

	"github.com/andreek/wgxdp/config"
	"github.com/andreek/wgxdp/firewall"
	"github.com/andreek/wgxdp/wireguard"
	"github.com/sirupsen/logrus"
)

//go:generate cp -r ../web ./web
//go:embed web
var webFS embed.FS

// Server holds the dependencies for all HTTP handlers.
type Server struct {
	DB     *DB
	Device *wireguard.Device
	Config *config.Config
	XDP    *firewall.Firewall
}

// StartServer registers HTTP routes, starts background cleanup, and begins
// listening on port 8337. It returns immediately; the server runs in a goroutine.
func StartServer(s *Server, logger *logrus.Entry) error {
	mux := http.NewServeMux()

	// Protected routes (require forwarded user header)
	mux.HandleFunc("GET /peers", s.requireAuth(s.ListPeers))
	mux.HandleFunc("DELETE /peers/{name}", s.requireAuth(s.DeletePeer))
	mux.HandleFunc("GET /rules", s.requireAuth(s.ListRules))
	mux.HandleFunc("POST /rules", s.requireAuth(s.CreateRule))
	mux.HandleFunc("DELETE /rules/{id}", s.requireAuth(s.DeleteRule))
	mux.HandleFunc("GET /server-info", s.requireAuth(s.ServerInfo))
	mux.HandleFunc("/device/verify", s.requireAuth(s.DeviceVerifyHandler))

	// Public routes (client device flow — use their own access token auth)
	mux.HandleFunc("/join", s.JoinHandler)
	mux.HandleFunc("/device/code", s.DeviceCodeHandler)
	mux.HandleFunc("/device/token", s.DeviceTokenHandler)

	// PWA — served at root, registered last so API routes take precedence
	webSub, err := fs.Sub(webFS, "web")
	if err != nil {
		return fmt.Errorf("could not create sub filesystem: %w", err)
	}
	fileServer := http.FileServerFS(webSub)

	// SW and manifest must be public for PWA installability
	mux.Handle("GET /sw.js", fileServer)
	mux.Handle("GET /manifest.json", fileServer)
	mux.Handle("GET /icon-192.png", fileServer)
	mux.Handle("GET /icon-512.png", fileServer)

	// Everything else under / requires auth
	mux.Handle("/", s.requireAuthHandler(fileServer))

	// Periodically clean expired device codes
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		for range ticker.C {
			if err := s.DB.CleanExpiredDeviceCodes(); err != nil {
				logger.Errorf("Failed to clean expired device codes: %v", err)
			}
		}
	}()

	listenAddr := "127.0.0.1:8337"
	if s.Config != nil && s.Config.ListenAddr != "" {
		listenAddr = s.Config.ListenAddr
	}

	go func() {
		logger.Infof("Listening on %s", listenAddr)
		if err := http.ListenAndServe(listenAddr, mux); err != nil {
			logger.Errorf("Error: %v", err)
		}
	}()

	return nil
}
