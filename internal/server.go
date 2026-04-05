package wgxdp

import (
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
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
	DB        *DB
	Device    *wireguard.Device
	Config    *config.Config
	XDP       *firewall.Firewall
	indexHTML  []byte
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
	mux.HandleFunc("GET /device/verify", s.requireAuth(s.DeviceVerifyGet))
	mux.HandleFunc("POST /device/verify", s.requireAuth(s.deviceVerifyPost))

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
	s.indexHTML, _ = fs.ReadFile(webSub, "index.html")

	// SW and manifest must be public for PWA installability
	mux.Handle("GET /sw.js", fileServer)
	mux.Handle("GET /manifest.json", fileServer)
	mux.Handle("GET /icon-192.png", fileServer)
	mux.Handle("GET /icon-512.png", fileServer)

	// Everything else under / requires auth, with SPA fallback
	mux.Handle("/", s.requireAuthHandler(spaFallback(webSub, fileServer)))

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

// spaFallback wraps a file server to serve index.html for paths that don't
// exist in the embedded filesystem. This enables client-side routing.
func spaFallback(fsys fs.FS, fileServer http.Handler) http.Handler {
	indexHTML, _ := fs.ReadFile(fsys, "index.html")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			fileServer.ServeHTTP(w, r)
			return
		}
		if _, err := fs.Stat(fsys, p); err != nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(indexHTML)
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}
