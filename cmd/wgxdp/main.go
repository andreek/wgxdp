package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type DeviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

type DeviceTokenRequest struct {
	DeviceCode string `json:"device_code"`
	GrantType  string `json:"grant_type"`
}

type DeviceTokenResponse struct {
	AccessToken string `json:"access_token,omitempty"`
	TokenType   string `json:"token_type,omitempty"`
	Error       string `json:"error,omitempty"`
}

type JoinRequest struct {
	AccessToken string `json:"access_token"`
	PublicKey   string `json:"public_key"`
	Name        string `json:"name,omitempty"`
}

type JoinResponse struct {
	AssignedIP      string `json:"assigned_ip"`
	Subnet          string `json:"subnet"`
	ServerPublicKey string `json:"server_public_key"`
	ServerEndpoint  string `json:"server_endpoint"`
	PeerName        string `json:"peer_name"`
}

func main() {
	joinCmd := flag.NewFlagSet("join", flag.ExitOnError)
	server := joinCmd.String("server", "", "wgxdp server URL (e.g. http://192.168.1.1:8337)")
	name := joinCmd.String("name", "", "Requested peer name (optional, server will auto-generate if empty)")

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: wgxdp <command>\n\nCommands:\n  join    Join a wgxdp network\n")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "join":
		joinCmd.Parse(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}

	if *server == "" {
		fmt.Fprintln(os.Stderr, "--server is required")
		joinCmd.Usage()
		os.Exit(1)
	}

	if err := runJoin(*server, *name); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runJoin(serverURL, name string) error {
	// Step 1: Generate WireGuard key pair
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return fmt.Errorf("could not generate WireGuard key pair: %w", err)
	}
	publicKey := privateKey.PublicKey()

	fmt.Println("Generated WireGuard key pair.")

	// Step 2: Request device code
	fmt.Println("Requesting authorization...")
	resp, err := http.Post(serverURL+"/device/code", "application/json", nil)
	if err != nil {
		return fmt.Errorf("could not request device code: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var dcResp DeviceCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&dcResp); err != nil {
		return fmt.Errorf("could not decode response: %w", err)
	}

	// Step 3: Display verification URL
	fmt.Printf("\nOpen the following URL in your browser and approve the request:\n\n")
	fmt.Printf("  URL:  %s?code=%s\n", dcResp.VerificationURI, dcResp.UserCode)
	fmt.Printf("  Code: %s\n\n", dcResp.UserCode)
	fmt.Println("Waiting for authorization...")

	// Step 4: Poll for token
	interval := time.Duration(dcResp.Interval) * time.Second
	deadline := time.Now().Add(time.Duration(dcResp.ExpiresIn) * time.Second)

	var accessToken string
	for time.Now().Before(deadline) {
		time.Sleep(interval)

		token, done, err := pollToken(serverURL, dcResp.DeviceCode)
		if err != nil {
			return err
		}
		if done {
			accessToken = token
			break
		}
	}

	if accessToken == "" {
		return fmt.Errorf("authorization timed out")
	}

	fmt.Println("Authorized! Joining network...")

	// Step 5: Join with access token and public key
	joinReq := JoinRequest{
		AccessToken: accessToken,
		PublicKey:   publicKey.String(),
		Name:        name,
	}

	joinBody, err := json.Marshal(joinReq)
	if err != nil {
		return fmt.Errorf("could not marshal join request: %w", err)
	}

	joinResp, err := http.Post(serverURL+"/join", "application/json", bytes.NewReader(joinBody))
	if err != nil {
		return fmt.Errorf("could not join network: %w", err)
	}
	defer joinResp.Body.Close()

	respBody, _ := io.ReadAll(joinResp.Body)

	if joinResp.StatusCode != http.StatusOK {
		return fmt.Errorf("join failed (%d): %s", joinResp.StatusCode, string(respBody))
	}

	var jr JoinResponse
	if err := json.Unmarshal(respBody, &jr); err != nil {
		return fmt.Errorf("could not decode join response: %w", err)
	}

	// Step 6: Print wg-quick config
	fmt.Printf("\nSuccessfully joined as %q with IP %s\n\n", jr.PeerName, jr.AssignedIP)
	fmt.Println("WireGuard configuration (save to /etc/wireguard/wgxdp.conf):")
	fmt.Println("---")
	fmt.Println("[Interface]")
	fmt.Printf("PrivateKey = %s\n", privateKey.String())
	fmt.Printf("Address = %s\n", jr.AssignedIP+"/"+maskFromCIDR(jr.Subnet))
	fmt.Println()
	fmt.Println("[Peer]")
	fmt.Printf("PublicKey = %s\n", jr.ServerPublicKey)
	fmt.Printf("Endpoint = %s\n", jr.ServerEndpoint)
	fmt.Printf("AllowedIPs = %s\n", jr.Subnet)
	fmt.Println("PersistentKeepalive = 25")
	fmt.Println("---")

	return nil
}

func maskFromCIDR(cidr string) string {
	parts := strings.SplitN(cidr, "/", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return "24"
}

func pollToken(serverURL, deviceCode string) (token string, done bool, err error) {
	reqBody, _ := json.Marshal(DeviceTokenRequest{
		DeviceCode: deviceCode,
		GrantType:  "urn:ietf:params:oauth:grant-type:device_code",
	})

	resp, err := http.Post(serverURL+"/device/token", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return "", false, fmt.Errorf("could not poll for token: %w", err)
	}
	defer resp.Body.Close()

	var tokenResp DeviceTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", false, fmt.Errorf("could not decode token response: %w", err)
	}

	switch tokenResp.Error {
	case "authorization_pending":
		return "", false, nil
	case "access_denied":
		return "", true, fmt.Errorf("authorization was denied")
	case "expired_token":
		return "", true, fmt.Errorf("device code expired")
	case "":
		return tokenResp.AccessToken, true, nil
	default:
		return "", false, fmt.Errorf("unexpected error: %s", tokenResp.Error)
	}
}
