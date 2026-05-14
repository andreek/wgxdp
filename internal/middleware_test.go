package wgxdp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type sessionLostBody struct {
	Error    string `json:"error"`
	Message  string `json:"message"`
	Redirect string `json:"redirect"`
}

func decodeSessionLost(t *testing.T, w *httptest.ResponseRecorder) sessionLostBody {
	t.Helper()
	var body sessionLostBody
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("expected JSON body, got %q: %v", w.Body.String(), err)
	}
	return body
}

func TestRequireAuthBlocksWithoutHeader(t *testing.T) {
	s := testServer(t)
	protected := s.requireAuth(s.ListPeers)

	req := httptest.NewRequest(http.MethodGet, "/peers", nil)
	w := httptest.NewRecorder()
	protected(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected %d, got %d", http.StatusUnauthorized, w.Code)
	}
	if got := w.Header().Get("WWW-Authenticate"); got != "Session" {
		t.Errorf("expected WWW-Authenticate: Session, got %q", got)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("expected JSON Content-Type, got %q", ct)
	}
	body := decodeSessionLost(t, w)
	if body.Error != "session_lost" {
		t.Errorf("expected error=session_lost, got %q", body.Error)
	}
	if !strings.Contains(body.Message, "X-Forwarded-User") {
		t.Errorf("expected message to mention header name, got: %s", body.Message)
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

func TestRequireAuthRedirectURLRendered(t *testing.T) {
	s := testServer(t)
	s.Config.AuthRedirectURL = "/oauth2/start?rd={path}"
	protected := s.requireAuth(s.ListPeers)

	req := httptest.NewRequest(http.MethodGet, "/peers?foo=bar", nil)
	w := httptest.NewRecorder()
	protected(w, req)

	body := decodeSessionLost(t, w)
	want := "/oauth2/start?rd=" + "%2Fpeers%3Ffoo%3Dbar"
	if body.Redirect != want {
		t.Errorf("expected redirect %q, got %q", want, body.Redirect)
	}
}

func TestRequireAuthNoRedirectWhenUnconfigured(t *testing.T) {
	s := testServer(t)
	s.Config.AuthRedirectURL = ""
	protected := s.requireAuth(s.ListPeers)

	req := httptest.NewRequest(http.MethodGet, "/peers", nil)
	w := httptest.NewRecorder()
	protected(w, req)

	body := decodeSessionLost(t, w)
	if body.Redirect != "" {
		t.Errorf("expected empty redirect, got %q", body.Redirect)
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
