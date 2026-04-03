package wgxdp

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
)

// CreateRuleRequest is the JSON body for POST /rules.
type CreateRuleRequest struct {
	SrcIP string `json:"src_ip"`
	DstIP string `json:"dst_ip"`
	Port  int    `json:"port"`
	Proto int    `json:"proto"`
}

// ListRules handles GET /rules and returns all firewall rules as JSON.
func (s *Server) ListRules(w http.ResponseWriter, req *http.Request) {
	rules, err := s.DB.GetAllRules()
	if err != nil {
		http.Error(w, fmt.Sprintf("could not get rules: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rules)
}

// CreateRule handles POST /rules. It validates the request, persists the rule
// to SQLite, and inserts it into the eBPF peer_rules map.
func (s *Server) CreateRule(w http.ResponseWriter, req *http.Request) {
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

	var cr CreateRuleRequest
	if err := json.Unmarshal(body, &cr); err != nil {
		http.Error(w, fmt.Sprintf("invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	if cr.SrcIP == "" || cr.DstIP == "" || cr.Port == 0 {
		http.Error(w, "src_ip, dst_ip, and port are required", http.StatusBadRequest)
		return
	}
	if net.ParseIP(cr.SrcIP) == nil {
		http.Error(w, fmt.Sprintf("invalid source IP: %s", cr.SrcIP), http.StatusBadRequest)
		return
	}
	if net.ParseIP(cr.DstIP) == nil {
		http.Error(w, fmt.Sprintf("invalid destination IP: %s", cr.DstIP), http.StatusBadRequest)
		return
	}
	if cr.Proto == 0 {
		cr.Proto = 6 // default to TCP
	}

	id, err := s.DB.AddRule(cr.SrcIP, cr.DstIP, cr.Port, cr.Proto)
	if err != nil {
		http.Error(w, fmt.Sprintf("could not add rule: %v", err), http.StatusInternalServerError)
		return
	}

	if s.XDP != nil {
		if err := s.XDP.AddPeerRule(cr.SrcIP, cr.DstIP, cr.Port, uint8(cr.Proto)); err != nil {
			http.Error(w, fmt.Sprintf("could not add eBPF rule: %v", err), http.StatusInternalServerError)
			return
		}
	}

	rule := RuleRecord{ID: id, SrcIP: cr.SrcIP, DstIP: cr.DstIP, Port: cr.Port, Proto: cr.Proto}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(rule)
}

// DeleteRule handles DELETE /rules/{id}. It removes the rule from the eBPF map
// and deletes it from the database.
func (s *Server) DeleteRule(w http.ResponseWriter, req *http.Request) {
	idStr := req.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid rule id", http.StatusBadRequest)
		return
	}

	rule, err := s.DB.GetRuleByID(id)
	if err != nil {
		http.Error(w, fmt.Sprintf("could not look up rule: %v", err), http.StatusInternalServerError)
		return
	}
	if rule == nil {
		http.Error(w, "rule not found", http.StatusNotFound)
		return
	}

	if s.XDP != nil {
		// Best-effort eBPF removal — skip if the rule has invalid IPs
		// (it was never loaded into the map in that case)
		if net.ParseIP(rule.SrcIP) != nil && net.ParseIP(rule.DstIP) != nil {
			if err := s.XDP.RemovePeerRule(rule.SrcIP, rule.DstIP, rule.Port, uint8(rule.Proto)); err != nil {
				http.Error(w, fmt.Sprintf("could not remove eBPF rule: %v", err), http.StatusInternalServerError)
				return
			}
		}
	}

	if err := s.DB.RemoveRule(id); err != nil {
		http.Error(w, fmt.Sprintf("could not remove rule: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
