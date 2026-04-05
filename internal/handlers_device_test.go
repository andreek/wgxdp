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

	// Step 3: Verify page GET (JSON)
	req = httptest.NewRequest(http.MethodGet, "/device/verify?code="+dcResp.UserCode, nil)
	req.Header.Set("Accept", "application/json")
	w = httptest.NewRecorder()
	s.DeviceVerifyGet(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("DeviceVerifyHandler GET: expected status %d, got %d", http.StatusOK, w.Code)
	}
	var verifyInfo DeviceVerifyInfo
	if err := json.NewDecoder(w.Body).Decode(&verifyInfo); err != nil {
		t.Fatalf("could not decode verify info: %v", err)
	}
	if verifyInfo.UserCode != dcResp.UserCode {
		t.Fatalf("verify info user_code = %q, want %q", verifyInfo.UserCode, dcResp.UserCode)
	}
	if verifyInfo.Status != "pending" {
		t.Fatalf("verify info status = %q, want pending", verifyInfo.Status)
	}

	// Step 4: Approve (JSON)
	approveBody := `{"user_code":"` + dcResp.UserCode + `","action":"approve"}`
	req = httptest.NewRequest(http.MethodPost, "/device/verify", strings.NewReader(approveBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	s.deviceVerifyPost(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("DeviceVerifyHandler POST approve: expected status %d, got %d", http.StatusOK, w.Code)
	}
	var result DeviceVerifyResult
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("could not decode verify result: %v", err)
	}
	if result.Title != "Approved" {
		t.Fatalf("verify result title = %q, want Approved", result.Title)
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

	// Deny (JSON)
	denyBody := `{"user_code":"` + dcResp.UserCode + `","action":"deny"}`
	req = httptest.NewRequest(http.MethodPost, "/device/verify", strings.NewReader(denyBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	s.deviceVerifyPost(w, req)
	var result DeviceVerifyResult
	json.NewDecoder(w.Body).Decode(&result)
	if result.Title != "Denied" {
		t.Fatalf("verify result title = %q, want Denied", result.Title)
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
	body := `{"user_code":"INVALID","action":"approve"}`
	req := httptest.NewRequest(http.MethodPost, "/device/verify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.deviceVerifyPost(w, req)
	var result DeviceVerifyResult
	json.NewDecoder(w.Body).Decode(&result)
	if result.Message != "Invalid or expired code." {
		t.Fatalf("expected error message for invalid code, got: %s", result.Message)
	}
}

func TestDeviceVerifyPostEmptyCode(t *testing.T) {
	s := testServer(t)
	body := `{"user_code":"","action":"approve"}`
	req := httptest.NewRequest(http.MethodPost, "/device/verify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.deviceVerifyPost(w, req)
	var result DeviceVerifyResult
	json.NewDecoder(w.Body).Decode(&result)
	if result.Message != "No user code provided." {
		t.Fatalf("expected error for empty code, got: %s", result.Message)
	}
}

func TestDeviceVerifyGetServesSPA(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/device/verify?code=ABCD-EFGH", nil)
	req.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	s.DeviceVerifyGet(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if ct != "text/html; charset=utf-8" {
		t.Fatalf("expected text/html content type, got %s", ct)
	}
	if !strings.Contains(w.Body.String(), "wgxdp") {
		t.Fatal("expected SPA HTML in response body")
	}
}

func TestDeviceVerifyGetJSON(t *testing.T) {
	s := testServer(t)

	// Create a device code first
	req := httptest.NewRequest(http.MethodPost, "/device/code", nil)
	req.Host = "localhost:8337"
	w := httptest.NewRecorder()
	s.DeviceCodeHandler(w, req)
	var dcResp DeviceCodeResponse
	json.NewDecoder(w.Body).Decode(&dcResp)

	// GET with JSON accept
	req = httptest.NewRequest(http.MethodGet, "/device/verify?code="+dcResp.UserCode, nil)
	req.Header.Set("Accept", "application/json")
	w = httptest.NewRecorder()
	s.DeviceVerifyGet(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, w.Code)
	}
	var info DeviceVerifyInfo
	json.NewDecoder(w.Body).Decode(&info)
	if info.UserCode != dcResp.UserCode {
		t.Fatalf("user_code = %q, want %q", info.UserCode, dcResp.UserCode)
	}
	if info.Status != "pending" {
		t.Fatalf("status = %q, want pending", info.Status)
	}
}
