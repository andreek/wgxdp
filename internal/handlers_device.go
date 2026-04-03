package wgxdp

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
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

// DeviceVerifyHandler handles GET and POST /device/verify. It renders the
// browser-facing approval form and processes approve/deny actions.
func (s *Server) DeviceVerifyHandler(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		s.deviceVerifyGet(w, req)
	case http.MethodPost:
		s.deviceVerifyPost(w, req)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) deviceVerifyGet(w http.ResponseWriter, req *http.Request) {
	code := html.EscapeString(req.URL.Query().Get("code"))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, verifyFormHTML, code)
}

func (s *Server) deviceVerifyPost(w http.ResponseWriter, req *http.Request) {
	err := req.ParseForm()
	if err != nil {
		http.Error(w, "could not parse form", http.StatusBadRequest)
		return
	}

	userCode := req.FormValue("user_code")
	action := req.FormValue("action")

	if userCode == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, verifyResultHTML("Error", "No user code provided."))
		return
	}

	dc, err := s.DB.GetDeviceCodeByUserCode(userCode)
	if err != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, verifyResultHTML("Error", "Server error."))
		return
	}

	if dc == nil || dc.ExpiresAt < time.Now().Unix() {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, verifyResultHTML("Error", "Invalid or expired code."))
		return
	}

	if dc.Status != "pending" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, verifyResultHTML("Error", "This code has already been used."))
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	actingUser := s.getAuthUser(req)

	switch action {
	case "approve":
		_, err := s.DB.ApproveDeviceCode(userCode, actingUser)
		if err != nil {
			fmt.Fprint(w, verifyResultHTML("Error", "Could not approve device."))
			return
		}
		msg := "The device has been authorized to join the network."
		if actingUser != "" {
			msg += fmt.Sprintf(" Approved by %s.", actingUser)
		}
		fmt.Fprint(w, verifyResultHTML("Approved", msg))
	case "deny":
		s.DB.DenyDeviceCode(userCode, actingUser)
		msg := "The device request has been denied."
		if actingUser != "" {
			msg += fmt.Sprintf(" Denied by %s.", actingUser)
		}
		fmt.Fprint(w, verifyResultHTML("Denied", msg))
	default:
		fmt.Fprint(w, verifyResultHTML("Error", "Invalid action."))
	}
}
