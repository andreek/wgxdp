package wgxdp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestListPeers(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/peers", nil)
	w := httptest.NewRecorder()
	s.ListPeers(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestJoinHandlerMethodNotAllowed(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/join", nil)
	w := httptest.NewRecorder()
	s.JoinHandler(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

func TestJoinHandlerEmptyBody(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest(http.MethodPost, "/join", nil)
	w := httptest.NewRecorder()
	s.JoinHandler(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestJoinHandlerWrongContentType(t *testing.T) {
	s := testServer(t)
	body := strings.NewReader(`{"access_token":"abc"}`)
	req := httptest.NewRequest(http.MethodPost, "/join", body)
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	s.JoinHandler(w, req)
	if w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("expected status %d, got %d", http.StatusUnsupportedMediaType, w.Code)
	}
}

func TestJoinHandlerInvalidJSON(t *testing.T) {
	s := testServer(t)
	body := strings.NewReader(`{not json}`)
	req := httptest.NewRequest(http.MethodPost, "/join", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.JoinHandler(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

func TestJoinHandlerMissingAccessToken(t *testing.T) {
	s := testServer(t)
	body := strings.NewReader(`{"public_key":"somekey"}`)
	req := httptest.NewRequest(http.MethodPost, "/join", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.JoinHandler(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestJoinHandlerMissingPublicKey(t *testing.T) {
	s := testServer(t)
	body := strings.NewReader(`{"access_token":"sometoken"}`)
	req := httptest.NewRequest(http.MethodPost, "/join", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.JoinHandler(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestJoinHandlerInvalidAccessToken(t *testing.T) {
	s := testServer(t)
	body := strings.NewReader(`{"access_token":"invalid","public_key":"somekey"}`)
	req := httptest.NewRequest(http.MethodPost, "/join", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.JoinHandler(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestDeviceFlowAutoName(t *testing.T) {
	s := testServer(t)

	dc, _ := s.DB.CreateDeviceCode()
	accessToken, _ := s.DB.ApproveDeviceCode(dc.UserCode, "test-user")

	joinBody := `{"access_token":"` + accessToken + `","public_key":"test-pubkey"}`
	req := httptest.NewRequest(http.MethodPost, "/join", strings.NewReader(joinBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.JoinHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("JoinHandler: expected status %d, got %d, body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var jr JoinResponse
	json.NewDecoder(w.Body).Decode(&jr)
	if jr.PeerName == "" {
		t.Fatal("peer name should be auto-generated")
	}
}

func TestDeletePeer(t *testing.T) {
	s := testServer(t)

	s.DB.AddPeer("deleteme", "pubkey123", "10.200.0.50")

	req := httptest.NewRequest(http.MethodDelete, "/peers/deleteme", nil)
	req.SetPathValue("name", "deleteme")
	w := httptest.NewRecorder()
	s.DeletePeer(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected %d, got %d, body: %s", http.StatusNoContent, w.Code, w.Body.String())
	}

	peer, _ := s.DB.GetPeerByName("deleteme")
	if peer != nil {
		t.Fatal("peer should be deleted")
	}
}

func TestDeletePeerNotFound(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest(http.MethodDelete, "/peers/nonexistent", nil)
	req.SetPathValue("name", "nonexistent")
	w := httptest.NewRecorder()
	s.DeletePeer(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestDeletePeerCascadesRules(t *testing.T) {
	s := testServer(t)

	s.DB.AddPeer("cascade-test", "pubkey-cascade", "10.200.0.60")
	s.DB.AddRule("10.200.0.60", "10.200.0.1", 80, 6)
	s.DB.AddRule("10.200.0.60", "10.200.0.1", 443, 6)

	req := httptest.NewRequest(http.MethodDelete, "/peers/cascade-test", nil)
	req.SetPathValue("name", "cascade-test")
	w := httptest.NewRecorder()
	s.DeletePeer(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected %d, got %d", http.StatusNoContent, w.Code)
	}

	rules, _ := s.DB.GetAllRules()
	for _, r := range rules {
		if r.SrcIP == "10.200.0.60" {
			t.Fatalf("rules for deleted peer should be removed, found: %+v", r)
		}
	}
}
