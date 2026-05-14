package wgxdp

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

func (s *Server) getAuthHeader() string {
	if s.Config != nil && s.Config.AuthHeader != "" {
		return s.Config.AuthHeader
	}
	return "X-Forwarded-User"
}

func (s *Server) getAuthUser(req *http.Request) string {
	return req.Header.Get(s.getAuthHeader())
}

// renderAuthRedirect substitutes {path} in the configured redirect template
// with the URL-encoded original request URI. Returns "" if no template is set.
func (s *Server) renderAuthRedirect(req *http.Request) string {
	if s.Config == nil || s.Config.AuthRedirectURL == "" {
		return ""
	}
	rd := url.QueryEscape(req.URL.RequestURI())
	return strings.ReplaceAll(s.Config.AuthRedirectURL, "{path}", rd)
}

// writeSessionLost emits a structured 401 the PWA can recognize as a session
// loss (vs. an application-level auth error). The WWW-Authenticate header tags
// the failure mode; the JSON body carries the URL the PWA should navigate to.
func (s *Server) writeSessionLost(w http.ResponseWriter, req *http.Request) {
	body := struct {
		Error    string `json:"error"`
		Message  string `json:"message"`
		Redirect string `json:"redirect,omitempty"`
	}{
		Error:    "session_lost",
		Message:  "unauthorized: missing " + s.getAuthHeader() + " header",
		Redirect: s.renderAuthRedirect(req),
	}
	w.Header().Set("WWW-Authenticate", "Session")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(body)
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if s.getAuthUser(req) == "" {
			s.writeSessionLost(w, req)
			return
		}
		next(w, req)
	}
}

func (s *Server) requireAuthHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if s.getAuthUser(req) == "" {
			s.writeSessionLost(w, req)
			return
		}
		next.ServeHTTP(w, req)
	})
}
