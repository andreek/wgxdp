package wgxdp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestListRules(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/rules", nil)
	w := httptest.NewRecorder()
	s.ListRules(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestCreateRule(t *testing.T) {
	s := testServer(t)
	body := strings.NewReader(`{"src_ip":"10.200.0.2","dst_ip":"10.200.0.1","port":8080,"proto":6}`)
	req := httptest.NewRequest(http.MethodPost, "/rules", body)
	w := httptest.NewRecorder()
	s.CreateRule(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d, body: %s", http.StatusCreated, w.Code, w.Body.String())
	}

	var rule RuleRecord
	json.NewDecoder(w.Body).Decode(&rule)
	if rule.ID == 0 {
		t.Fatal("rule ID should not be 0")
	}
	if rule.SrcIP != "10.200.0.2" {
		t.Fatalf("expected src_ip 10.200.0.2, got %s", rule.SrcIP)
	}
}

func TestCreateRuleDefaultProto(t *testing.T) {
	s := testServer(t)
	body := strings.NewReader(`{"src_ip":"10.200.0.3","dst_ip":"10.200.0.1","port":443}`)
	req := httptest.NewRequest(http.MethodPost, "/rules", body)
	w := httptest.NewRecorder()
	s.CreateRule(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d, body: %s", http.StatusCreated, w.Code, w.Body.String())
	}

	var rule RuleRecord
	json.NewDecoder(w.Body).Decode(&rule)
	if rule.Proto != 6 {
		t.Fatalf("expected default proto 6 (TCP), got %d", rule.Proto)
	}
}

func TestCreateRuleEmptyBody(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest(http.MethodPost, "/rules", nil)
	w := httptest.NewRecorder()
	s.CreateRule(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestCreateRuleMissingFields(t *testing.T) {
	s := testServer(t)
	body := strings.NewReader(`{"src_ip":"10.200.0.2"}`)
	req := httptest.NewRequest(http.MethodPost, "/rules", body)
	w := httptest.NewRecorder()
	s.CreateRule(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestDeleteRuleNotFound(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest(http.MethodDelete, "/rules/99999", nil)
	req.SetPathValue("id", "99999")
	w := httptest.NewRecorder()
	s.DeleteRule(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestDeleteRuleInvalidID(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest(http.MethodDelete, "/rules/abc", nil)
	req.SetPathValue("id", "abc")
	w := httptest.NewRecorder()
	s.DeleteRule(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestCreateAndDeleteRule(t *testing.T) {
	s := testServer(t)

	// Create
	body := strings.NewReader(`{"src_ip":"10.200.0.5","dst_ip":"10.200.0.1","port":9090,"proto":6}`)
	req := httptest.NewRequest(http.MethodPost, "/rules", body)
	w := httptest.NewRecorder()
	s.CreateRule(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: expected %d, got %d", http.StatusCreated, w.Code)
	}

	var rule RuleRecord
	json.NewDecoder(w.Body).Decode(&rule)

	// Delete
	idStr := strings.NewReader("")
	req = httptest.NewRequest(http.MethodDelete, "/rules/"+string(rune(rule.ID+'0')), idStr)
	req.SetPathValue("id", fmt.Sprintf("%d", rule.ID))
	w = httptest.NewRecorder()
	s.DeleteRule(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete: expected %d, got %d, body: %s", http.StatusNoContent, w.Code, w.Body.String())
	}

	// Verify gone
	req = httptest.NewRequest(http.MethodDelete, "/rules/"+string(rune(rule.ID+'0')), nil)
	req.SetPathValue("id", fmt.Sprintf("%d", rule.ID))
	w = httptest.NewRecorder()
	s.DeleteRule(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("delete again: expected %d, got %d", http.StatusNotFound, w.Code)
	}
}
