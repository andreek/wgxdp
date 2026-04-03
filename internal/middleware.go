package wgxdp

import "net/http"

func (s *Server) getAuthHeader() string {
	if s.Config != nil && s.Config.AuthHeader != "" {
		return s.Config.AuthHeader
	}
	return "X-Forwarded-User"
}

func (s *Server) getAuthUser(req *http.Request) string {
	return req.Header.Get(s.getAuthHeader())
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if s.getAuthUser(req) == "" {
			http.Error(w, "unauthorized: missing "+s.getAuthHeader()+" header", http.StatusUnauthorized)
			return
		}
		next(w, req)
	}
}

func (s *Server) requireAuthHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if s.getAuthUser(req) == "" {
			http.Error(w, "unauthorized: missing "+s.getAuthHeader()+" header", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, req)
	})
}
