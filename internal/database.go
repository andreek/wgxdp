// Package wgxdp implements the wgxdp HTTP server, SQLite persistence,
// and embedded admin PWA for managing WireGuard peers and eBPF firewall rules.
package wgxdp

import (
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const (
	deviceCodeExpiry       = 600 // 10 minutes
	deviceCodePollInterval = 5   // seconds
	// Unambiguous characters (excludes 0/O, 1/I/L)
	userCodeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
)

// DB wraps a SQLite database connection and provides methods for managing
// peers, firewall rules, and device authorization codes.
type DB struct {
	db *sql.DB
}

// DeviceCode represents an OAuth2 device authorization code used during
// the peer onboarding flow.
type DeviceCode struct {
	DeviceCode  string
	UserCode    string
	ExpiresAt   int64
	Interval    int
	Status      string
	AccessToken string
}

// PeerRecord represents a WireGuard peer stored in the database.
type PeerRecord struct {
	Name       string `json:"name"`
	PublicKey  string `json:"public_key"`
	AssignedIP string `json:"assigned_ip"`
}

// RuleRecord represents an eBPF firewall rule stored in the database.
type RuleRecord struct {
	ID    int64  `json:"id"`
	SrcIP string `json:"src_ip"`
	DstIP string `json:"dst_ip"`
	Port  int    `json:"port"`
	Proto int    `json:"proto"`
}

func (d *DB) createTables() error {
	createPeersSQL := `CREATE TABLE IF NOT EXISTS peers (
		"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
		"name" TEXT NOT NULL UNIQUE,
		"publicKey" TEXT NOT NULL,
		"assignedIP" TEXT NOT NULL UNIQUE,
		"created_at" INTEGER NOT NULL
	);`
	createDeviceCodesSQL := `CREATE TABLE IF NOT EXISTS device_codes (
		"id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
		"device_code" TEXT NOT NULL UNIQUE,
		"user_code" TEXT NOT NULL UNIQUE,
		"expires_at" INTEGER NOT NULL,
		"interval" INTEGER NOT NULL DEFAULT 5,
		"status" TEXT NOT NULL DEFAULT 'pending',
		"access_token" TEXT,
		"approved_by" TEXT NOT NULL DEFAULT '',
		"created_at" INTEGER NOT NULL
	);`
	_, err := d.db.Exec(createPeersSQL)
	if err != nil {
		return fmt.Errorf("could not create peers table: %w", err)
	}

	_, err = d.db.Exec(createDeviceCodesSQL)
	if err != nil {
		return fmt.Errorf("could not create device_codes table: %w", err)
	}

	createFirewallRulesSQL := `CREATE TABLE IF NOT EXISTS firewall_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		src_ip TEXT NOT NULL,
		dst_ip TEXT NOT NULL,
		port INTEGER NOT NULL,
		proto INTEGER NOT NULL DEFAULT 6,
		created_at INTEGER NOT NULL,
		UNIQUE(src_ip, dst_ip, port, proto)
	);`
	_, err = d.db.Exec(createFirewallRulesSQL)
	if err != nil {
		return fmt.Errorf("could not create firewall_rules table: %w", err)
	}

	return nil
}

// GetDatabase opens a SQLite database at the given path and creates tables if needed.
// If path is empty, it defaults to /var/lib/wgxdp/wgxdp.db.
func GetDatabase(path string) (*DB, error) {
	if path == "" {
		path = "/var/lib/wgxdp/wgxdp.db"
	}
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("could not open database: %w", err)
	}

	d := &DB{
		db: db,
	}

	err = d.createTables()
	if err != nil {
		return nil, err
	}

	return d, nil
}

// AddPeer inserts a new peer into the database.
func (d *DB) AddPeer(name string, publicKey string, assignedIP string) error {
	_, err := d.db.Exec(
		`INSERT INTO peers(name, publicKey, assignedIP, created_at) VALUES (?, ?, ?, ?)`,
		name, publicKey, assignedIP, time.Now().Unix(),
	)
	return err
}

// RemovePeer deletes a peer by name.
func (d *DB) RemovePeer(name string) error {
	_, err := d.db.Exec(`DELETE FROM peers WHERE name = ?`, name)
	return err
}

// GetAllPeers returns all peers stored in the database.
func (d *DB) GetAllPeers() ([]PeerRecord, error) {
	rows, err := d.db.Query(`SELECT name, publicKey, assignedIP FROM peers`)
	if err != nil {
		return nil, fmt.Errorf("could not query peers: %w", err)
	}
	defer rows.Close()

	var peers []PeerRecord
	for rows.Next() {
		var p PeerRecord
		if err := rows.Scan(&p.Name, &p.PublicKey, &p.AssignedIP); err != nil {
			return nil, fmt.Errorf("could not scan peer: %w", err)
		}
		peers = append(peers, p)
	}
	return peers, rows.Err()
}

// NextAvailableIP allocates the next unused IPv4 address from the given subnet.
// It skips .0 (network) and .1 (server) and fills gaps in the allocation.
func (d *DB) NextAvailableIP(subnetCIDR string) (string, error) {
	_, subnet, err := net.ParseCIDR(subnetCIDR)
	if err != nil {
		return "", fmt.Errorf("could not parse subnet: %w", err)
	}

	// Collect all assigned IPs
	rows, err := d.db.Query(`SELECT assignedIP FROM peers`)
	if err != nil {
		return "", fmt.Errorf("could not query assigned IPs: %w", err)
	}
	defer rows.Close()

	used := make(map[string]bool)
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return "", err
		}
		used[ip] = true
	}
	if err := rows.Err(); err != nil {
		return "", err
	}

	// Start from .2 (skip .0 network and .1 server)
	ip := make(net.IP, len(subnet.IP))
	copy(ip, subnet.IP)
	ip = ip.To4()
	if ip == nil {
		return "", fmt.Errorf("only IPv4 subnets are supported")
	}

	ipInt := binary.BigEndian.Uint32(ip)
	// Start at network + 2 (skip .0 and .1)
	candidate := ipInt + 2

	// Calculate broadcast address
	maskInt := binary.BigEndian.Uint32(subnet.Mask)
	broadcast := ipInt | ^maskInt

	for candidate < broadcast {
		candidateIP := make(net.IP, 4)
		binary.BigEndian.PutUint32(candidateIP, candidate)
		candidateStr := candidateIP.String()

		if !used[candidateStr] {
			return candidateStr, nil
		}
		candidate++
	}

	return "", fmt.Errorf("no available IPs in subnet %s", subnetCIDR)
}

// CreateDeviceCode generates a new device authorization code with a 10-minute expiry.
// The user code is formatted as XXXX-XXXX using unambiguous characters.
func (d *DB) CreateDeviceCode() (*DeviceCode, error) {
	deviceCode, err := generateRandomHex(32)
	if err != nil {
		return nil, fmt.Errorf("could not generate device code: %w", err)
	}

	userCode, err := generateUserCode(8)
	if err != nil {
		return nil, fmt.Errorf("could not generate user code: %w", err)
	}
	// Format as XXXX-XXXX
	userCode = userCode[:4] + "-" + userCode[4:]

	now := time.Now().Unix()
	expiresAt := now + deviceCodeExpiry

	dc := &DeviceCode{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		ExpiresAt:  expiresAt,
		Interval:   deviceCodePollInterval,
		Status:     "pending",
	}

	_, err = d.db.Exec(
		`INSERT INTO device_codes(device_code, user_code, expires_at, interval, status, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		dc.DeviceCode, dc.UserCode, dc.ExpiresAt, dc.Interval, dc.Status, now,
	)
	if err != nil {
		return nil, fmt.Errorf("could not insert device code: %w", err)
	}

	return dc, nil
}

// GetDeviceCodeByUserCode retrieves a device code by its user-facing code.
// Returns nil if not found.
func (d *DB) GetDeviceCodeByUserCode(userCode string) (*DeviceCode, error) {
	dc := &DeviceCode{}
	err := d.db.QueryRow(
		`SELECT device_code, user_code, expires_at, interval, status, COALESCE(access_token, '') FROM device_codes WHERE user_code = ?`,
		userCode,
	).Scan(&dc.DeviceCode, &dc.UserCode, &dc.ExpiresAt, &dc.Interval, &dc.Status, &dc.AccessToken)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("could not query device code: %w", err)
	}
	return dc, nil
}

// GetDeviceCodeByDeviceCode retrieves a device code by its client-facing code.
// Returns nil if not found.
func (d *DB) GetDeviceCodeByDeviceCode(deviceCode string) (*DeviceCode, error) {
	dc := &DeviceCode{}
	err := d.db.QueryRow(
		`SELECT device_code, user_code, expires_at, interval, status, COALESCE(access_token, '') FROM device_codes WHERE device_code = ?`,
		deviceCode,
	).Scan(&dc.DeviceCode, &dc.UserCode, &dc.ExpiresAt, &dc.Interval, &dc.Status, &dc.AccessToken)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("could not query device code: %w", err)
	}
	return dc, nil
}

// ApproveDeviceCode marks a pending device code as approved, generates an access
// token, and returns it. Returns an error if the code is not found or not pending.
func (d *DB) ApproveDeviceCode(userCode string, approvedBy string) (string, error) {
	accessToken, err := generateRandomHex(32)
	if err != nil {
		return "", fmt.Errorf("could not generate access token: %w", err)
	}

	result, err := d.db.Exec(
		`UPDATE device_codes SET status = 'approved', access_token = ?, approved_by = ? WHERE user_code = ? AND status = 'pending'`,
		accessToken, approvedBy, userCode,
	)
	if err != nil {
		return "", fmt.Errorf("could not approve device code: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return "", fmt.Errorf("device code not found or not pending")
	}

	return accessToken, nil
}

// DenyDeviceCode marks a pending device code as denied.
func (d *DB) DenyDeviceCode(userCode string, deniedBy string) error {
	_, err := d.db.Exec(
		`UPDATE device_codes SET status = 'denied', approved_by = ? WHERE user_code = ? AND status = 'pending'`,
		deniedBy, userCode,
	)
	return err
}

// ConsumeAccessToken deletes an approved, non-expired access token and returns
// true if it existed. This ensures tokens are single-use.
func (d *DB) ConsumeAccessToken(accessToken string) (bool, error) {
	result, err := d.db.Exec(
		`DELETE FROM device_codes WHERE access_token = ? AND status = 'approved' AND expires_at > ?`,
		accessToken, time.Now().Unix(),
	)
	if err != nil {
		return false, fmt.Errorf("could not consume access token: %w", err)
	}
	rows, _ := result.RowsAffected()
	return rows > 0, nil
}

// AddRule inserts a firewall rule and returns its ID. The combination of
// src_ip, dst_ip, port, and proto must be unique.
func (d *DB) AddRule(srcIP, dstIP string, port, proto int) (int64, error) {
	result, err := d.db.Exec(
		`INSERT INTO firewall_rules(src_ip, dst_ip, port, proto, created_at) VALUES (?, ?, ?, ?, ?)`,
		srcIP, dstIP, port, proto, time.Now().Unix(),
	)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// RemoveRule deletes a firewall rule by ID.
func (d *DB) RemoveRule(id int64) error {
	_, err := d.db.Exec(`DELETE FROM firewall_rules WHERE id = ?`, id)
	return err
}

// GetRuleByID retrieves a firewall rule by ID. Returns nil if not found.
func (d *DB) GetRuleByID(id int64) (*RuleRecord, error) {
	r := &RuleRecord{}
	err := d.db.QueryRow(
		`SELECT id, src_ip, dst_ip, port, proto FROM firewall_rules WHERE id = ?`, id,
	).Scan(&r.ID, &r.SrcIP, &r.DstIP, &r.Port, &r.Proto)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

// GetAllRules returns all firewall rules stored in the database.
func (d *DB) GetAllRules() ([]RuleRecord, error) {
	rows, err := d.db.Query(`SELECT id, src_ip, dst_ip, port, proto FROM firewall_rules`)
	if err != nil {
		return nil, fmt.Errorf("could not query rules: %w", err)
	}
	defer rows.Close()

	var rules []RuleRecord
	for rows.Next() {
		var r RuleRecord
		if err := rows.Scan(&r.ID, &r.SrcIP, &r.DstIP, &r.Port, &r.Proto); err != nil {
			return nil, fmt.Errorf("could not scan rule: %w", err)
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// RemoveRulesForPeer deletes all firewall rules with the given source IP
// and returns the deleted rules for eBPF map cleanup.
func (d *DB) RemoveRulesForPeer(srcIP string) ([]RuleRecord, error) {
	rules, err := d.db.Query(`SELECT id, src_ip, dst_ip, port, proto FROM firewall_rules WHERE src_ip = ?`, srcIP)
	if err != nil {
		return nil, err
	}
	defer rules.Close()

	var deleted []RuleRecord
	for rules.Next() {
		var r RuleRecord
		if err := rules.Scan(&r.ID, &r.SrcIP, &r.DstIP, &r.Port, &r.Proto); err != nil {
			return nil, err
		}
		deleted = append(deleted, r)
	}
	if err := rules.Err(); err != nil {
		return nil, err
	}

	_, err = d.db.Exec(`DELETE FROM firewall_rules WHERE src_ip = ?`, srcIP)
	if err != nil {
		return nil, err
	}
	return deleted, nil
}

// GetPeerByName retrieves a peer by name. Returns nil if not found.
func (d *DB) GetPeerByName(name string) (*PeerRecord, error) {
	p := &PeerRecord{}
	err := d.db.QueryRow(
		`SELECT name, publicKey, assignedIP FROM peers WHERE name = ?`, name,
	).Scan(&p.Name, &p.PublicKey, &p.AssignedIP)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

// CleanExpiredDeviceCodes deletes all device codes past their expiry time.
func (d *DB) CleanExpiredDeviceCodes() error {
	_, err := d.db.Exec(`DELETE FROM device_codes WHERE expires_at < ?`, time.Now().Unix())
	return err
}

func generateRandomHex(n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func generateUserCode(length int) (string, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	for _, v := range b {
		sb.WriteByte(userCodeAlphabet[int(v)%len(userCodeAlphabet)])
	}
	return sb.String(), nil
}
