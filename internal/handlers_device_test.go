package wgxdp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Full device flow: request code -> approve -> get token -> join
func TestDeviceFlowFull(t *testing.T) {
	s := testServer(t)

	// Step 1: Request device code
	req := httptest.NewRequest(http.MethodPost, "/device/code", nil)
	req.Host = "localhost:8337"
	w := httptest.NewRecorder()
	s.DeviceCodeHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("DeviceCodeHandler: expected status %d, got %d", http.StatusOK, w.Code)
	}

	var dcResp DeviceCodeResponse
	err := json.NewDecoder(w.Body).Decode(&dcResp)
	if err != nil {
		t.Fatalf("could not decode device code response: %v", err)
	}
	if dcResp.DeviceCode == "" || dcResp.UserCode == "" {
		t.Fatal("device_code and user_code should not be empty")
	}

	// Step 2: Poll before approval (should be pending)
	tokenBody := `{"device_code":"` + dcResp.DeviceCode + `","grant_type":"urn:ietf:params:oauth:grant-type:device_code"}`
	req = httptest.NewRequest(http.MethodPost, "/device/token", strings.NewReader(tokenBody))
	w = httptest.NewRecorder()
	s.DeviceTokenHandler(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("DeviceTokenHandler (pending): expected status %d, got %d", http.StatusTooManyRequests, w.Code)
	}

	// Step 3: Verify page GET
	req = httptest.NewRequest(http.MethodGet, "/device/verify?code="+dcResp.UserCode, nil)
	w = httptest.NewRecorder()
	s.DeviceVerifyHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("DeviceVerifyHandler GET: expected status %d, got %d", http.StatusOK, w.Code)
	}
	if !strings.Contains(w.Body.String(), dcResp.UserCode) {
		t.Fatal("verify page should contain the user code")
	}

	// Step 4: Approve
	formBody := "user_code=" + dcResp.UserCode + "&action=approve"
	req = httptest.NewRequest(http.MethodPost, "/device/verify", strings.NewReader(formBody))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	s.DeviceVerifyHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("DeviceVerifyHandler POST approve: expected status %d, got %d", http.StatusOK, w.Code)
	}
	if !strings.Contains(w.Body.String(), "Approved") {
		t.Fatal("approve response should contain 'Approved'")
	}

	// Step 5: Poll after approval (should get token)
	req = httptest.NewRequest(http.MethodPost, "/device/token", strings.NewReader(tokenBody))
	w = httptest.NewRecorder()
	s.DeviceTokenHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("DeviceTokenHandler (approved): expected status %d, got %d, body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var tokenResp DeviceTokenResponse
	err = json.NewDecoder(w.Body).Decode(&tokenResp)
	if err != nil {
		t.Fatalf("could not decode token response: %v", err)
	}
	if tokenResp.AccessToken == "" {
		t.Fatal("access_token should not be empty")
	}

	// Step 6: Join with access token and public key
	joinBody := `{"access_token":"` + tokenResp.AccessToken + `","public_key":"test-pubkey","name":"my-laptop"}`
	req = httptest.NewRequest(http.MethodPost, "/join", strings.NewReader(joinBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	s.JoinHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("JoinHandler: expected status %d, got %d, body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var jr JoinResponse
	err = json.NewDecoder(w.Body).Decode(&jr)
	if err != nil {
		t.Fatalf("could not decode join response: %v", err)
	}
	if jr.AssignedIP == "" {
		t.Fatal("assigned_ip should not be empty")
	}
	if jr.AssignedIP != "10.200.0.2" {
		t.Fatalf("expected first assigned IP to be 10.200.0.2, got %s", jr.AssignedIP)
	}
	if jr.PeerName != "my-laptop" {
		t.Fatalf("expected peer name my-laptop, got %s", jr.PeerName)
	}
	if jr.ServerEndpoint != "home.example.com:5820" {
		t.Fatalf("expected server endpoint home.example.com:5820, got %s", jr.ServerEndpoint)
	}
	if jr.Subnet != "10.200.0.0/24" {
		t.Fatalf("expected subnet 10.200.0.0/24, got %s", jr.Subnet)
	}

	// Step 7: Replay should fail
	req = httptest.NewRequest(http.MethodPost, "/join", strings.NewReader(joinBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	s.JoinHandler(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("JoinHandler (replay): expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestDeviceFlowDeny(t *testing.T) {
	s := testServer(t)

	req := httptest.NewRequest(http.MethodPost, "/device/code", nil)
	req.Host = "localhost:8337"
	w := httptest.NewRecorder()
	s.DeviceCodeHandler(w, req)

	var dcResp DeviceCodeResponse
	json.NewDecoder(w.Body).Decode(&dcResp)

	// Deny
	formBody := "user_code=" + dcResp.UserCode + "&action=deny"
	req = httptest.NewRequest(http.MethodPost, "/device/verify", strings.NewReader(formBody))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	s.DeviceVerifyHandler(w, req)
	if !strings.Contains(w.Body.String(), "Denied") {
		t.Fatal("deny response should contain 'Denied'")
	}

	// Poll should return access_denied
	tokenBody := `{"device_code":"` + dcResp.DeviceCode + `","grant_type":"urn:ietf:params:oauth:grant-type:device_code"}`
	req = httptest.NewRequest(http.MethodPost, "/device/token", strings.NewReader(tokenBody))
	w = httptest.NewRecorder()
	s.DeviceTokenHandler(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("DeviceTokenHandler (denied): expected status %d, got %d", http.StatusForbidden, w.Code)
	}
}

func TestDeviceCodeHandlerMethodNotAllowed(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/device/code", nil)
	w := httptest.NewRecorder()
	s.DeviceCodeHandler(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

func TestDeviceTokenHandlerExpired(t *testing.T) {
	s := testServer(t)
	tokenBody := `{"device_code":"nonexistent-code","grant_type":"urn:ietf:params:oauth:grant-type:device_code"}`
	req := httptest.NewRequest(http.MethodPost, "/device/token", strings.NewReader(tokenBody))
	w := httptest.NewRecorder()
	s.DeviceTokenHandler(w, req)
	if w.Code != http.StatusGone {
		t.Errorf("expected status %d, got %d", http.StatusGone, w.Code)
	}
}

func TestDeviceVerifyPostInvalidCode(t *testing.T) {
	s := testServer(t)
	formBody := "user_code=INVALID&action=approve"
	req := httptest.NewRequest(http.MethodPost, "/device/verify", strings.NewReader(formBody))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.DeviceVerifyHandler(w, req)
	if !strings.Contains(w.Body.String(), "Invalid or expired") {
		t.Fatalf("expected error message for invalid code, got: %s", w.Body.String())
	}
}

func TestDeviceVerifyPostEmptyCode(t *testing.T) {
	s := testServer(t)
	formBody := "user_code=&action=approve"
	req := httptest.NewRequest(http.MethodPost, "/device/verify", strings.NewReader(formBody))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.DeviceVerifyHandler(w, req)
	if !strings.Contains(w.Body.String(), "No user code") {
		t.Fatalf("expected error for empty code, got: %s", w.Body.String())
	}
}
