package wgxdp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/andreek/wgxdp/wireguard"
)

// JoinRequest is the JSON body for POST /join.
type JoinRequest struct {
	AccessToken string `json:"access_token"`
	PublicKey   string `json:"public_key"`
	Name        string `json:"name"`
}

// JoinResponse is the JSON response from POST /join.
type JoinResponse struct {
	AssignedIP      string `json:"assigned_ip"`
	Subnet          string `json:"subnet"`
	ServerPublicKey string `json:"server_public_key"`
	ServerEndpoint  string `json:"server_endpoint"`
	PeerName        string `json:"peer_name"`
}

// ServerInfo handles GET /server-info and returns the server's WireGuard IP.
func (s *Server) ServerInfo(w http.ResponseWriter, req *http.Request) {
	info := struct {
		WGIP string `json:"wg_ip"`
	}{}
	if s.Config != nil {
		info.WGIP = s.Config.WGInterfaceIP
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

// PeerResponse is a peer record enriched with WireGuard runtime status.
type PeerResponse struct {
	Name       string `json:"name"`
	PublicKey  string `json:"public_key"`
	AssignedIP string `json:"assigned_ip"`
	Active     bool   `json:"active"`
}

// ListPeers handles GET /peers and returns all registered peers as JSON,
// enriched with WireGuard handshake status.
func (s *Server) ListPeers(w http.ResponseWriter, req *http.Request) {
	peers, err := s.DB.GetAllPeers()
	if err != nil {
		http.Error(w, fmt.Sprintf("could not get peers: %v", err), http.StatusInternalServerError)
		return
	}

	// Get live WireGuard peer statuses
	var statuses map[string]wireguard.PeerStatus
	if s.Device != nil {
		statuses, _ = s.Device.GetPeerStatuses()
	}

	resp := make([]PeerResponse, len(peers))
	for i, p := range peers {
		resp[i] = PeerResponse{
			Name:       p.Name,
			PublicKey:  p.PublicKey,
			AssignedIP: p.AssignedIP,
		}
		if st, ok := statuses[p.PublicKey]; ok {
			resp[i].Active = st.Active
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// DeletePeer handles DELETE /peers/{name}. It removes the peer from WireGuard,
// deletes associated firewall rules from both eBPF and the database, and removes
// the peer record.
func (s *Server) DeletePeer(w http.ResponseWriter, req *http.Request) {
	name := req.PathValue("name")
	if name == "" {
		http.Error(w, "missing peer name", http.StatusBadRequest)
		return
	}

	peer, err := s.DB.GetPeerByName(name)
	if err != nil {
		http.Error(w, fmt.Sprintf("could not look up peer: %v", err), http.StatusInternalServerError)
		return
	}
	if peer == nil {
		http.Error(w, "peer not found", http.StatusNotFound)
		return
	}

	// Remove peer from WireGuard
	if s.Device != nil {
		err = s.Device.RemovePeer(peer.PublicKey)
		if err != nil {
			http.Error(w, fmt.Sprintf("could not remove wireguard peer: %v", err), http.StatusInternalServerError)
			return
		}
	}

	// Remove associated firewall rules from eBPF
	deletedRules, err := s.DB.RemoveRulesForPeer(peer.AssignedIP)
	if err != nil {
		http.Error(w, fmt.Sprintf("could not remove rules for peer: %v", err), http.StatusInternalServerError)
		return
	}
	if s.XDP != nil {
		for _, r := range deletedRules {
			s.XDP.RemovePeerRule(r.SrcIP, r.DstIP, r.Port, uint8(r.Proto))
		}
	}

	// Remove peer from database
	err = s.DB.RemovePeer(name)
	if err != nil {
		http.Error(w, fmt.Sprintf("could not remove peer: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// JoinHandler handles POST /join. It validates an access token, allocates an IP,
// stores the peer, adds it to WireGuard, and returns the connection details.
func (s *Server) JoinHandler(w http.ResponseWriter, req *http.Request) {
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

	contentType := req.Header.Get("Content-Type")
	if contentType != "application/json" {
		http.Error(w, "invalid Content-Type, expect `application/json`", http.StatusUnsupportedMediaType)
		return
	}

	var jr JoinRequest
	err := json.Unmarshal(body, &jr)
	if err != nil {
		http.Error(w, fmt.Sprintf("could not parse json: %v", err), http.StatusInternalServerError)
		return
	}

	if jr.AccessToken == "" {
		http.Error(w, "missing access_token", http.StatusUnauthorized)
		return
	}

	if jr.PublicKey == "" {
		http.Error(w, "missing public_key", http.StatusBadRequest)
		return
	}

	valid, err := s.DB.ConsumeAccessToken(jr.AccessToken)
	if err != nil {
		http.Error(w, fmt.Sprintf("could not verify token: %v", err), http.StatusInternalServerError)
		return
	}
	if !valid {
		http.Error(w, "invalid or expired access token", http.StatusUnauthorized)
		return
	}

	// Allocate an IP for the new peer
	assignedIP, err := s.DB.NextAvailableIP(s.Config.WGSubnet)
	if err != nil {
		http.Error(w, fmt.Sprintf("could not allocate IP: %v", err), http.StatusInternalServerError)
		return
	}

	// Generate a peer name if not provided
	peerName := jr.Name
	if peerName == "" {
		peerName = fmt.Sprintf("peer-%s", assignedIP)
	}

	// Store in database
	err = s.DB.AddPeer(peerName, jr.PublicKey, assignedIP)
	if err != nil {
		http.Error(w, fmt.Sprintf("could not add peer: %v", err), http.StatusInternalServerError)
		return
	}

	// Add peer to WireGuard interface
	if s.Device != nil {
		err = s.Device.AddPeer(jr.PublicKey, assignedIP)
		if err != nil {
			http.Error(w, fmt.Sprintf("could not configure wireguard peer: %v", err), http.StatusInternalServerError)
			return
		}
	}

	// Build response
	resp := JoinResponse{
		AssignedIP: assignedIP,
		Subnet:     s.Config.WGSubnet,
		PeerName:   peerName,
	}
	if s.Device != nil {
		resp.ServerPublicKey = s.Device.PublicKey()
	}
	if s.Config != nil {
		resp.ServerEndpoint = s.Config.WGEndpoint
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
