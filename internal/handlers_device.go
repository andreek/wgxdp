package wgxdp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DeviceCodeResponse is the JSON response from POST /device/code.
type DeviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

// DeviceTokenRequest is the JSON body for POST /device/token.
type DeviceTokenRequest struct {
	DeviceCode string `json:"device_code"`
	GrantType  string `json:"grant_type"`
}

// DeviceTokenResponse is the JSON response from POST /device/token.
type DeviceTokenResponse struct {
	AccessToken string `json:"access_token,omitempty"`
	TokenType   string `json:"token_type,omitempty"`
	Error       string `json:"error,omitempty"`
}

// DeviceVerifyInfo is the JSON response from GET /device/verify when
// the client sends Accept: application/json.
type DeviceVerifyInfo struct {
	UserCode  string `json:"user_code"`
	Status    string `json:"status"`
	ExpiresAt int64  `json:"expires_at"`
}

// DeviceVerifyRequest is the JSON body for POST /device/verify.
type DeviceVerifyRequest struct {
	UserCode string `json:"user_code"`
	Action   string `json:"action"`
}

// DeviceVerifyResult is the JSON response from POST /device/verify.
type DeviceVerifyResult struct {
	OK      bool   `json:"ok"`
	Title   string `json:"title"`
	Message string `json:"message"`
}

// DeviceCodeHandler handles POST /device/code. It creates a new device
// authorization code for the OAuth2 device flow.
func (s *Server) DeviceCodeHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	dc, err := s.DB.CreateDeviceCode()
	if err != nil {
		http.Error(w, fmt.Sprintf("could not create device code: %v", err), http.StatusInternalServerError)
		return
	}

	verificationURI := s.Config.ServerURL + "/device/verify"

	resp := DeviceCodeResponse{
		DeviceCode:      dc.DeviceCode,
		UserCode:        dc.UserCode,
		VerificationURI: verificationURI,
		ExpiresIn:       deviceCodeExpiry,
		Interval:        dc.Interval,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// DeviceTokenHandler handles POST /device/token. Clients poll this endpoint
// to check whether their device code has been approved, denied, or expired.
func (s *Server) DeviceTokenHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body []byte
	if req.Body != nil {
		if data, err := io.ReadAll(req.Body); err == nil {
			body = data
		}
	}
	if len(body) == 0 {
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}

	var dtr DeviceTokenRequest
	err := json.Unmarshal(body, &dtr)
	if err != nil {
		http.Error(w, fmt.Sprintf("could not parse json: %v", err), http.StatusBadRequest)
		return
	}

	dc, err := s.DB.GetDeviceCodeByDeviceCode(dtr.DeviceCode)
	if err != nil {
		http.Error(w, fmt.Sprintf("server error: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	if dc == nil || dc.ExpiresAt < time.Now().Unix() {
		w.WriteHeader(http.StatusGone)
		json.NewEncoder(w).Encode(DeviceTokenResponse{Error: "expired_token"})
		return
	}

	switch dc.Status {
	case "pending":
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(DeviceTokenResponse{Error: "authorization_pending"})
	case "denied":
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(DeviceTokenResponse{Error: "access_denied"})
	case "approved":
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(DeviceTokenResponse{
			AccessToken: dc.AccessToken,
			TokenType:   "Bearer",
		})
	default:
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(DeviceTokenResponse{Error: "server_error"})
	}
}

// DeviceVerifyGet handles GET /device/verify. If the request accepts JSON,
// it returns device code info. Otherwise it serves the PWA shell so the
// client-side router can handle the view.
func (s *Server) DeviceVerifyGet(w http.ResponseWriter, req *http.Request) {
	code := req.URL.Query().Get("code")

	// JSON response for PWA fetch calls
	if strings.Contains(req.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")

		if code == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(DeviceVerifyResult{Title: "Error", Message: "No code provided."})
			return
		}

		dc, err := s.DB.GetDeviceCodeByUserCode(code)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(DeviceVerifyResult{Title: "Error", Message: "Server error."})
			return
		}

		if dc == nil || dc.ExpiresAt < time.Now().Unix() {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(DeviceVerifyResult{Title: "Error", Message: "Invalid or expired code."})
			return
		}

		json.NewEncoder(w).Encode(DeviceVerifyInfo{
			UserCode:  dc.UserCode,
			Status:    dc.Status,
			ExpiresAt: dc.ExpiresAt,
		})
		return
	}

	// Browser navigation: serve the PWA shell for client-side routing
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(s.indexHTML)
}

func (s *Server) deviceVerifyPost(w http.ResponseWriter, req *http.Request) {
	var dvr DeviceVerifyRequest
	if err := json.NewDecoder(req.Body).Decode(&dvr); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(DeviceVerifyResult{Title: "Error", Message: "Invalid request body."})
		return
	}

	w.Header().Set("Content-Type", "application/json")

	if dvr.UserCode == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(DeviceVerifyResult{Title: "Error", Message: "No user code provided."})
		return
	}

	dc, err := s.DB.GetDeviceCodeByUserCode(dvr.UserCode)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(DeviceVerifyResult{Title: "Error", Message: "Server error."})
		return
	}

	if dc == nil || dc.ExpiresAt < time.Now().Unix() {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(DeviceVerifyResult{Title: "Error", Message: "Invalid or expired code."})
		return
	}

	if dc.Status != "pending" {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(DeviceVerifyResult{Title: "Error", Message: "This code has already been used."})
		return
	}

	actingUser := s.getAuthUser(req)

	switch dvr.Action {
	case "approve":
		_, err := s.DB.ApproveDeviceCode(dvr.UserCode, actingUser)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(DeviceVerifyResult{Title: "Error", Message: "Could not approve device."})
			return
		}
		msg := "The device has been authorized to join the network."
		if actingUser != "" {
			msg += fmt.Sprintf(" Approved by %s.", actingUser)
		}
		json.NewEncoder(w).Encode(DeviceVerifyResult{OK: true, Title: "Approved", Message: msg})
	case "deny":
		s.DB.DenyDeviceCode(dvr.UserCode, actingUser)
		msg := "The device request has been denied."
		if actingUser != "" {
			msg += fmt.Sprintf(" Denied by %s.", actingUser)
		}
		json.NewEncoder(w).Encode(DeviceVerifyResult{OK: true, Title: "Denied", Message: msg})
	default:
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(DeviceVerifyResult{Title: "Error", Message: "Invalid action."})
	}
}
