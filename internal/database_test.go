package wgxdp

import (
	"database/sql"
	"os"
	"testing"
)

func TestGetDatabase(t *testing.T) {
	db, err := GetDatabase("foo.sql")
	if err != nil {
		t.Fatalf("GetDatabase() should not return error %v", err)
	}
	if db == nil {
		t.Fatal("GetDatabase() should return not nil")
	}
}

func TestAddPeer(t *testing.T) {
	db, err := GetDatabase("fooPeer.sql")
	if err != nil {
		t.Fatalf("GetDatabase() should not return error %v", err)
	}

	err = db.AddPeer("test1", "<GENERATEPUBLICKEY!>", "10.200.0.2")
	if err != nil {
		t.Fatalf("AddPeer() should not return error %v", err)
	}

	length, err := getCount(db.db, "peers")
	if err != nil {
		t.Fatal(err)
	}
	if length != "1" {
		t.Fatalf("There should be one peer in database. Actually found %s peers.", length)
	}

	var name string
	var publicKey string
	var assignedIP string
	err = db.db.QueryRow("SELECT name, publicKey, assignedIP FROM peers WHERE id = 1").Scan(&name, &publicKey, &assignedIP)
	if err != nil {
		t.Fatal(err)
	}
	if name != "test1" {
		t.Fatalf(`name = %q, want "test1"`, name)
	}
	if assignedIP != "10.200.0.2" {
		t.Fatalf(`assignedIP = %q, want "10.200.0.2"`, assignedIP)
	}
}

func TestRemovePeer(t *testing.T) {
	db, err := GetDatabase("removePeer.sql")
	if err != nil {
		t.Fatalf("GetDatabase() should not return error %v", err)
	}

	err = db.AddPeer("test1", "<GENERATEPUBLICKEY!>", "10.200.0.2")
	if err != nil {
		t.Fatalf("AddPeer() should not return error %v", err)
	}
	err = db.AddPeer("test2", "<GENERATEPUBLICKEY!>", "10.200.0.3")
	if err != nil {
		t.Fatalf("AddPeer() should not return error %v", err)
	}

	err = db.RemovePeer("test1")
	if err != nil {
		t.Fatal(err)
	}

	length, err := getCount(db.db, "peers")
	if err != nil {
		t.Fatal(err)
	}
	if length != "1" {
		t.Fatalf("There should be still one peer in database. Actually found %s peers.", length)
	}
}

func TestGetAllPeers(t *testing.T) {
	db, err := GetDatabase("allpeers.sql")
	if err != nil {
		t.Fatalf("GetDatabase() error: %v", err)
	}

	db.AddPeer("peer1", "key1", "10.200.0.2")
	db.AddPeer("peer2", "key2", "10.200.0.3")

	peers, err := db.GetAllPeers()
	if err != nil {
		t.Fatalf("GetAllPeers() error: %v", err)
	}
	if len(peers) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(peers))
	}
	if peers[0].Name != "peer1" || peers[1].Name != "peer2" {
		t.Fatalf("unexpected peer names: %v", peers)
	}
}

func TestNextAvailableIP(t *testing.T) {
	db, err := GetDatabase("nextip.sql")
	if err != nil {
		t.Fatalf("GetDatabase() error: %v", err)
	}

	// First allocation should be .2
	ip, err := db.NextAvailableIP("10.200.0.0/24")
	if err != nil {
		t.Fatalf("NextAvailableIP() error: %v", err)
	}
	if ip != "10.200.0.2" {
		t.Fatalf("expected 10.200.0.2, got %s", ip)
	}

	// Add a peer at .2, next should be .3
	db.AddPeer("p1", "key1", "10.200.0.2")
	ip, err = db.NextAvailableIP("10.200.0.0/24")
	if err != nil {
		t.Fatalf("NextAvailableIP() error: %v", err)
	}
	if ip != "10.200.0.3" {
		t.Fatalf("expected 10.200.0.3, got %s", ip)
	}

	// Add .3, skip .4, add .5 — next should be .4 (fills gap)
	db.AddPeer("p2", "key2", "10.200.0.3")
	db.AddPeer("p3", "key3", "10.200.0.5")
	ip, err = db.NextAvailableIP("10.200.0.0/24")
	if err != nil {
		t.Fatalf("NextAvailableIP() error: %v", err)
	}
	if ip != "10.200.0.4" {
		t.Fatalf("expected 10.200.0.4, got %s", ip)
	}
}

func TestNextAvailableIPExhausted(t *testing.T) {
	db, err := GetDatabase("nextipfull.sql")
	if err != nil {
		t.Fatalf("GetDatabase() error: %v", err)
	}

	// /30 gives network .0, server .1, and only .2 and .3 usable (broadcast is .3 in /30... actually /30 has .0=net, .1=server, .2=one host, .3=broadcast)
	// So only .2 is available
	db.AddPeer("p1", "key1", "10.0.0.2")
	_, err = db.NextAvailableIP("10.0.0.0/30")
	if err == nil {
		t.Fatal("expected error for exhausted subnet")
	}
}

func TestNextAvailableIPInvalidSubnet(t *testing.T) {
	db, err := GetDatabase("nextipinvalid.sql")
	if err != nil {
		t.Fatalf("GetDatabase() error: %v", err)
	}

	_, err = db.NextAvailableIP("not-a-subnet")
	if err == nil {
		t.Fatal("expected error for invalid subnet")
	}
}

func TestCreateDeviceCode(t *testing.T) {
	db, err := GetDatabase("devicecode.sql")
	if err != nil {
		t.Fatalf("GetDatabase() error: %v", err)
	}

	dc, err := db.CreateDeviceCode()
	if err != nil {
		t.Fatalf("CreateDeviceCode() error: %v", err)
	}
	if dc.DeviceCode == "" {
		t.Fatal("DeviceCode should not be empty")
	}
	if len(dc.UserCode) != 9 { // XXXX-XXXX
		t.Fatalf("UserCode should be 9 chars (XXXX-XXXX), got %q", dc.UserCode)
	}
	if dc.UserCode[4] != '-' {
		t.Fatalf("UserCode should have hyphen at position 4, got %q", dc.UserCode)
	}
	if dc.Status != "pending" {
		t.Fatalf("Status should be pending, got %q", dc.Status)
	}
}

func TestGetDeviceCodeByUserCode(t *testing.T) {
	db, err := GetDatabase("devicecode.sql")
	if err != nil {
		t.Fatalf("GetDatabase() error: %v", err)
	}

	dc, err := db.CreateDeviceCode()
	if err != nil {
		t.Fatalf("CreateDeviceCode() error: %v", err)
	}

	found, err := db.GetDeviceCodeByUserCode(dc.UserCode)
	if err != nil {
		t.Fatalf("GetDeviceCodeByUserCode() error: %v", err)
	}
	if found == nil {
		t.Fatal("expected device code to be found")
	}
	if found.DeviceCode != dc.DeviceCode {
		t.Fatalf("DeviceCode mismatch: got %q, want %q", found.DeviceCode, dc.DeviceCode)
	}
}

func TestGetDeviceCodeByUserCodeNotFound(t *testing.T) {
	db, err := GetDatabase("devicecode.sql")
	if err != nil {
		t.Fatalf("GetDatabase() error: %v", err)
	}

	found, err := db.GetDeviceCodeByUserCode("XXXX-YYYY")
	if err != nil {
		t.Fatalf("GetDeviceCodeByUserCode() error: %v", err)
	}
	if found != nil {
		t.Fatal("expected nil for non-existent user code")
	}
}

func TestGetDeviceCodeByDeviceCode(t *testing.T) {
	db, err := GetDatabase("devicecode.sql")
	if err != nil {
		t.Fatalf("GetDatabase() error: %v", err)
	}

	dc, err := db.CreateDeviceCode()
	if err != nil {
		t.Fatalf("CreateDeviceCode() error: %v", err)
	}

	found, err := db.GetDeviceCodeByDeviceCode(dc.DeviceCode)
	if err != nil {
		t.Fatalf("GetDeviceCodeByDeviceCode() error: %v", err)
	}
	if found == nil {
		t.Fatal("expected device code to be found")
	}
	if found.UserCode != dc.UserCode {
		t.Fatalf("UserCode mismatch: got %q, want %q", found.UserCode, dc.UserCode)
	}
}

func TestApproveDeviceCode(t *testing.T) {
	db, err := GetDatabase("devicecode_approve.sql")
	if err != nil {
		t.Fatalf("GetDatabase() error: %v", err)
	}

	dc, err := db.CreateDeviceCode()
	if err != nil {
		t.Fatalf("CreateDeviceCode() error: %v", err)
	}

	accessToken, err := db.ApproveDeviceCode(dc.UserCode, "test-user")
	if err != nil {
		t.Fatalf("ApproveDeviceCode() error: %v", err)
	}
	if accessToken == "" {
		t.Fatal("access token should not be empty")
	}

	found, err := db.GetDeviceCodeByUserCode(dc.UserCode)
	if err != nil {
		t.Fatalf("GetDeviceCodeByUserCode() error: %v", err)
	}
	if found.Status != "approved" {
		t.Fatalf("status should be approved, got %q", found.Status)
	}
}

func TestDenyDeviceCode(t *testing.T) {
	db, err := GetDatabase("devicecode_deny.sql")
	if err != nil {
		t.Fatalf("GetDatabase() error: %v", err)
	}

	dc, err := db.CreateDeviceCode()
	if err != nil {
		t.Fatalf("CreateDeviceCode() error: %v", err)
	}

	err = db.DenyDeviceCode(dc.UserCode, "test-user")
	if err != nil {
		t.Fatalf("DenyDeviceCode() error: %v", err)
	}

	found, err := db.GetDeviceCodeByUserCode(dc.UserCode)
	if err != nil {
		t.Fatalf("GetDeviceCodeByUserCode() error: %v", err)
	}
	if found.Status != "denied" {
		t.Fatalf("status should be denied, got %q", found.Status)
	}
}

func TestConsumeAccessToken(t *testing.T) {
	db, err := GetDatabase("devicecode_consume.sql")
	if err != nil {
		t.Fatalf("GetDatabase() error: %v", err)
	}

	dc, err := db.CreateDeviceCode()
	if err != nil {
		t.Fatalf("CreateDeviceCode() error: %v", err)
	}

	accessToken, err := db.ApproveDeviceCode(dc.UserCode, "test-user")
	if err != nil {
		t.Fatalf("ApproveDeviceCode() error: %v", err)
	}

	// First consume should succeed
	valid, err := db.ConsumeAccessToken(accessToken)
	if err != nil {
		t.Fatalf("ConsumeAccessToken() error: %v", err)
	}
	if !valid {
		t.Fatal("expected token to be valid")
	}

	// Second consume should fail (token already used)
	valid, err = db.ConsumeAccessToken(accessToken)
	if err != nil {
		t.Fatalf("ConsumeAccessToken() error: %v", err)
	}
	if valid {
		t.Fatal("expected token to be invalid after consumption")
	}
}

func TestConsumeAccessTokenInvalid(t *testing.T) {
	db, err := GetDatabase("devicecode_consume.sql")
	if err != nil {
		t.Fatalf("GetDatabase() error: %v", err)
	}

	valid, err := db.ConsumeAccessToken("nonexistent-token")
	if err != nil {
		t.Fatalf("ConsumeAccessToken() error: %v", err)
	}
	if valid {
		t.Fatal("expected invalid token to return false")
	}
}

func TestAddRule(t *testing.T) {
	db, err := GetDatabase("rules.sql")
	if err != nil {
		t.Fatalf("GetDatabase() error: %v", err)
	}

	id, err := db.AddRule("10.200.0.2", "10.200.0.1", 8080, 6)
	if err != nil {
		t.Fatalf("AddRule() error: %v", err)
	}
	if id == 0 {
		t.Fatal("expected non-zero ID")
	}

	count, err := getCount(db.db, "firewall_rules")
	if err != nil {
		t.Fatal(err)
	}
	if count != "1" {
		t.Fatalf("expected 1 rule, got %s", count)
	}
}

func TestAddRuleDuplicate(t *testing.T) {
	db, err := GetDatabase("rules_dup.sql")
	if err != nil {
		t.Fatalf("GetDatabase() error: %v", err)
	}

	_, err = db.AddRule("10.200.0.2", "10.200.0.1", 8080, 6)
	if err != nil {
		t.Fatalf("first AddRule() error: %v", err)
	}

	_, err = db.AddRule("10.200.0.2", "10.200.0.1", 8080, 6)
	if err == nil {
		t.Fatal("expected error for duplicate rule")
	}
}

func TestGetAllRules(t *testing.T) {
	db, err := GetDatabase("rules_all.sql")
	if err != nil {
		t.Fatalf("GetDatabase() error: %v", err)
	}

	db.AddRule("10.200.0.2", "10.200.0.1", 80, 6)
	db.AddRule("10.200.0.3", "10.200.0.1", 443, 6)

	rules, err := db.GetAllRules()
	if err != nil {
		t.Fatalf("GetAllRules() error: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
}

func TestGetRuleByID(t *testing.T) {
	db, err := GetDatabase("rules_byid.sql")
	if err != nil {
		t.Fatalf("GetDatabase() error: %v", err)
	}

	id, _ := db.AddRule("10.200.0.2", "10.200.0.1", 8080, 6)

	rule, err := db.GetRuleByID(id)
	if err != nil {
		t.Fatalf("GetRuleByID() error: %v", err)
	}
	if rule == nil {
		t.Fatal("expected rule to be found")
	}
	if rule.SrcIP != "10.200.0.2" || rule.Port != 8080 {
		t.Fatalf("unexpected rule: %+v", rule)
	}
}

func TestGetRuleByIDNotFound(t *testing.T) {
	db, err := GetDatabase("rules_byid_nf.sql")
	if err != nil {
		t.Fatalf("GetDatabase() error: %v", err)
	}

	rule, err := db.GetRuleByID(99999)
	if err != nil {
		t.Fatalf("GetRuleByID() error: %v", err)
	}
	if rule != nil {
		t.Fatal("expected nil for non-existent rule")
	}
}

func TestRemoveRule(t *testing.T) {
	db, err := GetDatabase("rules_rm.sql")
	if err != nil {
		t.Fatalf("GetDatabase() error: %v", err)
	}

	id, _ := db.AddRule("10.200.0.2", "10.200.0.1", 8080, 6)

	err = db.RemoveRule(id)
	if err != nil {
		t.Fatalf("RemoveRule() error: %v", err)
	}

	rule, _ := db.GetRuleByID(id)
	if rule != nil {
		t.Fatal("rule should be deleted")
	}
}

func TestRemoveRulesForPeer(t *testing.T) {
	db, err := GetDatabase("rules_peer.sql")
	if err != nil {
		t.Fatalf("GetDatabase() error: %v", err)
	}

	db.AddRule("10.200.0.2", "10.200.0.1", 80, 6)
	db.AddRule("10.200.0.2", "10.200.0.1", 443, 6)
	db.AddRule("10.200.0.3", "10.200.0.1", 80, 6) // different peer

	deleted, err := db.RemoveRulesForPeer("10.200.0.2")
	if err != nil {
		t.Fatalf("RemoveRulesForPeer() error: %v", err)
	}
	if len(deleted) != 2 {
		t.Fatalf("expected 2 deleted rules, got %d", len(deleted))
	}

	// Other peer's rule should remain
	rules, _ := db.GetAllRules()
	if len(rules) != 1 {
		t.Fatalf("expected 1 remaining rule, got %d", len(rules))
	}
	if rules[0].SrcIP != "10.200.0.3" {
		t.Fatalf("wrong remaining rule: %+v", rules[0])
	}
}

func TestGetPeerByName(t *testing.T) {
	db, err := GetDatabase("peer_byname.sql")
	if err != nil {
		t.Fatalf("GetDatabase() error: %v", err)
	}

	db.AddPeer("test-peer", "pubkey123", "10.200.0.2")

	peer, err := db.GetPeerByName("test-peer")
	if err != nil {
		t.Fatalf("GetPeerByName() error: %v", err)
	}
	if peer == nil {
		t.Fatal("expected peer to be found")
	}
	if peer.AssignedIP != "10.200.0.2" {
		t.Fatalf("expected IP 10.200.0.2, got %s", peer.AssignedIP)
	}
}

func TestGetPeerByNameNotFound(t *testing.T) {
	db, err := GetDatabase("peer_byname_nf.sql")
	if err != nil {
		t.Fatalf("GetDatabase() error: %v", err)
	}

	peer, err := db.GetPeerByName("nonexistent")
	if err != nil {
		t.Fatalf("GetPeerByName() error: %v", err)
	}
	if peer != nil {
		t.Fatal("expected nil for non-existent peer")
	}
}

func getCount(db *sql.DB, tableName string) (string, error) {
	query, err := db.Prepare("SELECT COUNT(*) FROM " + tableName)
	if err != nil {
		return "", err
	}
	var length string
	err = query.QueryRow().Scan(&length)
	if err != nil {
		return "", err
	}
	return length, nil
}

func shutdown() {
	os.Remove("foo.sql")
	os.Remove("fooPeer.sql")
	os.Remove("removePeer.sql")
	os.Remove("allpeers.sql")
	os.Remove("nextip.sql")
	os.Remove("nextipfull.sql")
	os.Remove("nextipinvalid.sql")
	os.Remove("devicecode.sql")
	os.Remove("devicecode_approve.sql")
	os.Remove("devicecode_deny.sql")
	os.Remove("devicecode_consume.sql")
	os.Remove("server_test.sql")
	os.Remove("rules.sql")
	os.Remove("rules_dup.sql")
	os.Remove("rules_all.sql")
	os.Remove("rules_byid.sql")
	os.Remove("rules_byid_nf.sql")
	os.Remove("rules_rm.sql")
	os.Remove("rules_peer.sql")
	os.Remove("peer_byname.sql")
	os.Remove("peer_byname_nf.sql")
}

func TestMain(m *testing.M) {
	code := m.Run()
	shutdown()
	os.Exit(code)
}
