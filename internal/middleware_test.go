package wgxdp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequireAuthBlocksWithoutHeader(t *testing.T) {
	s := testServer(t)
	protected := s.requireAuth(s.ListPeers)

	req := httptest.NewRequest(http.MethodGet, "/peers", nil)
	w := httptest.NewRecorder()
	protected(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected %d, got %d", http.StatusUnauthorized, w.Code)
	}
	if !strings.Contains(w.Body.String(), "X-Forwarded-User") {
		t.Errorf("expected error to mention header name, got: %s", w.Body.String())
	}
}

func TestRequireAuthPassesWithHeader(t *testing.T) {
	s := testServer(t)
	protected := s.requireAuth(s.ListPeers)

	req := httptest.NewRequest(http.MethodGet, "/peers", nil)
	req.Header.Set("X-Forwarded-User", "admin")
	w := httptest.NewRecorder()
	protected(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected %d, got %d", http.StatusOK, w.Code)
	}
}

func TestRequireAuthCustomHeader(t *testing.T) {
	s := testServer(t)
	s.Config.AuthHeader = "Remote-User"
	protected := s.requireAuth(s.ListPeers)

	// Default header should not work
	req := httptest.NewRequest(http.MethodGet, "/peers", nil)
	req.Header.Set("X-Forwarded-User", "admin")
	w := httptest.NewRecorder()
	protected(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected %d with wrong header, got %d", http.StatusUnauthorized, w.Code)
	}

	// Custom header should work
	req = httptest.NewRequest(http.MethodGet, "/peers", nil)
	req.Header.Set("Remote-User", "admin")
	w = httptest.NewRecorder()
	protected(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected %d with correct header, got %d", http.StatusOK, w.Code)
	}
}

func TestRequireAuthProtectedRoutes(t *testing.T) {
	s := testServer(t)

	paths := []struct {
		method string
		path   string
	}{
		{"GET", "/peers"},
		{"DELETE", "/peers/test"},
		{"GET", "/rules"},
		{"POST", "/rules"},
		{"DELETE", "/rules/1"},
		{"GET", "/device/verify"},
		{"GET", "/"},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /peers", s.requireAuth(s.ListPeers))
	mux.HandleFunc("DELETE /peers/{name}", s.requireAuth(s.DeletePeer))
	mux.HandleFunc("GET /rules", s.requireAuth(s.ListRules))
	mux.HandleFunc("POST /rules", s.requireAuth(s.CreateRule))
	mux.HandleFunc("DELETE /rules/{id}", s.requireAuth(s.DeleteRule))
	mux.HandleFunc("GET /device/verify", s.requireAuth(s.DeviceVerifyGet))
	mux.HandleFunc("POST /device/verify", s.requireAuth(s.deviceVerifyPost))
	mux.Handle("/", s.requireAuthHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	for _, tc := range paths {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without auth: expected %d, got %d", tc.method, tc.path, http.StatusUnauthorized, w.Code)
		}
	}
}

func TestPublicRoutesNoAuthRequired(t *testing.T) {
	s := testServer(t)

	req := httptest.NewRequest(http.MethodPost, "/device/code", nil)
	w := httptest.NewRecorder()
	s.DeviceCodeHandler(w, req)
	if w.Code == http.StatusUnauthorized {
		t.Error("/device/code should not require auth")
	}

	tokenBody := strings.NewReader(`{"device_code":"x"}`)
	req = httptest.NewRequest(http.MethodPost, "/device/token", tokenBody)
	w = httptest.NewRecorder()
	s.DeviceTokenHandler(w, req)
	if w.Code == http.StatusUnauthorized {
		t.Error("/device/token should not require auth")
	}
}
