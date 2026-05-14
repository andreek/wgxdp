# wgxdp

A WireGuard overlay network management tool. wgxdp provides a REST API for clients to join and manage WireGuard networks using an OAuth2 Device Authorization flow. The server allocates IPs, configures WireGuard peers, and manages per-peer firewall rules via eBPF/XDP - all administered through a built-in web UI.

## Features

- **OAuth2 Device Authorization** - clients request a code, users approve in a browser, then the client joins the network
- **Server-side IP allocation** - the server assigns IPs from a configured subnet
- **Automatic WireGuard configuration** - server creates the WireGuard interface and adds peers via wgctrl
- **eBPF/XDP firewall** - per-peer traffic filtering rules (TCP/UDP) enforced at the kernel level via XDP, persisted in SQLite and restored on restart
- **Web UI (PWA)** - manage peers and firewall rules from a browser at `/`, installable as a Progressive Web App (requires HTTPS for install prompt)
- **Auth middleware** - protected routes require a forwarded user header (e.g. `X-Forwarded-User` from a reverse proxy); client device flow endpoints remain public
- **SQLite persistence** - stores peers, device codes, and firewall rules locally with no external dependencies
- **Two binaries** - `wgxdp-server` (API server) and `wgxdp` (CLI client)

## Background

This is a learning project. It started in April 2022 as a Python/Redis experiment for blocking packets by port with XDP, and evolved into a full WireGuard overlay network manager in Go.

Built while working through:
- *Linux Observability with BPF: Advanced Programming for Performance Analysis and Networking* by David Calavera and Lorenzo Fontana
- *100 Go Mistakes and How to Avoid Them* by Teiva Harsanyi

## Usage

### CLI client

```shell
wgxdp join --server https://<your-server>
```

The client generates a WireGuard key pair, requests authorization, and after approval prints a `wg-quick` compatible configuration file.

Optional:
- `--name my-laptop` to request a specific peer name (otherwise auto-generated).
- `--qrcode` display qr code in the terminal.

### Web UI

Features:
- **Peers list** - card grid showing all peers with name, IP (green when active via WireGuard handshake), and public key. Click a peer to drill into its detail view
- **Peer detail** - peer info, outbound/inbound firewall rules with resolved peer names, quick-add buttons for common services (DNS, HTTP, HTTPS, SSH), and a collapsible custom rule form
- **Device approval** - approve or deny new device join requests directly in the PWA, with the device code pre-filled when following the CLI link
- **Live status** - peer online/offline indicator based on WireGuard last handshake time
- **Light/dark mode** - automatic via `prefers-color-scheme`, neutral color palette
- Toast notifications, confirm dialogs, responsive layout

## API

### Protected routes (require `X-Forwarded-User` header)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/peers` | List all peers |
| `DELETE` | `/peers/{name}` | Delete a peer and its firewall rules |
| `GET` | `/rules` | List all firewall rules |
| `POST` | `/rules` | Create a firewall rule |
| `DELETE` | `/rules/{id}` | Delete a firewall rule |
| `GET` | `/server-info` | Server WireGuard IP (for PWA) |
| `GET/POST` | `/device/verify` | Device approval (JSON for PWA, redirects browser to PWA) |

### Public routes (client device flow)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/join` | Join the network with an access token |
| `POST` | `/device/code` | Request a new device code |
| `POST` | `/device/token` | Poll for an access token |

The auth header name defaults to `X-Forwarded-User` and can be changed via `auth_header` in the config. This is designed to work behind a reverse proxy (e.g. Authelia, oauth2-proxy) that sets the header after authentication.

### `POST /join`

Request:
```json
{
  "access_token": "hex-encoded-token",
  "public_key": "base64-encoded-wireguard-public-key",
  "name": "my-laptop"
}
```

Response:
```json
{
  "assigned_ip": "10.200.0.2",
  "server_public_key": "base64-encoded-server-public-key",
  "server_endpoint": "home.example.com:5820",
  "peer_name": "my-laptop"
}
```

### `POST /rules`

Request:
```json
{
  "src_ip": "10.200.0.2",
  "dst_ip": "10.200.0.1",
  "port": 8080,
  "proto": 6
}
```

`proto` defaults to `6` (TCP) if omitted. Use `17` for UDP. Source and destination IPs are validated on submission.

Response (`201 Created`):
```json
{
  "id": 1,
  "src_ip": "10.200.0.2",
  "dst_ip": "10.200.0.1",
  "port": 8080,
  "proto": 6
}
```

### `DELETE /peers/{name}`

Deletes the peer from WireGuard, removes all associated firewall rules from both the eBPF map and the database, and removes the peer record. Returns `204 No Content`.

The server listens on port **8337**.

## Configuration

### Config file

```yaml
name: my-vpn
server_url: http://192.168.1.1:8337
wg_endpoint: 192.168.1.1:5820
wg_subnet: 10.200.0.0/24
wg_interface_ip: 10.200.0.1
wg_interface_name: wg0
wg_listen_port: 5820
auth_header: X-Forwarded-User
```

Set the config file path via the `CONFIG_FILE` environment variable (default: `/config/config.yaml`).

### Environment variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CONFIG_FILE` | Path to YAML config file | `/config/config.yaml` |

The WireGuard private key file path is configured via `wg_key_file` in the config YAML (default: `/var/lib/wgxdp/wgkey`). If no key file exists, wgxdp generates a new WireGuard key pair and persists the private key.

### Reverse proxy

wgxdp should be deployed behind a reverse proxy that provides TLS and authentication. The server listens on `127.0.0.1:8337` by default (loopback only) and trusts the `X-Forwarded-User` header for user identity - without a proxy in front, anyone who can reach the port can forge this header.

Recommended setup:
- **nginx** for TLS termination
- **oauth2-proxy** for authentication, setting the `X-Forwarded-User` header (or a custom header configured via `auth_header`)

TLS is also required for the PWA install prompt to appear in browsers.

## Deployment

### systemd

Create a dedicated user:

```shell
sudo useradd -r -s /usr/sbin/nologin -d /var/lib/wgxdp wgxdp
sudo mkdir -p /var/lib/wgxdp
sudo chown wgxdp:wgxdp /var/lib/wgxdp
```

Install the unit file at `/etc/systemd/system/wgxdp-server.service`:

```ini
[Unit]
Description=wgxdp WireGuard Management Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=wgxdp
Group=wgxdp
ExecStart=/usr/local/bin/wgxdp-server
Environment=CONFIG_FILE=/etc/wgxdp/config.yaml

# CAP_NET_ADMIN    - WireGuard interface management
# CAP_BPF          - load eBPF programs and create maps
# CAP_SYS_RESOURCE - raise MEMLOCK rlimit for eBPF maps
# CAP_PERFMON      - required for variable-offset pointer arithmetic in eBPF verifier
AmbientCapabilities=CAP_NET_ADMIN CAP_BPF CAP_PERFMON CAP_SYS_RESOURCE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_BPF CAP_PERFMON CAP_SYS_RESOURCE

# Hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/wgxdp
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes

Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start:

```shell
sudo systemctl daemon-reload
sudo systemctl enable --now wgxdp-server
```

## Project structure

```
cmd/
  wgxdp/                CLI client (device flow + wg-quick config output)
  wgxdp-server/         Server entry point (startup, signal handling, rule restoration)
config/                 YAML configuration loading
firewall/
  c/program.c           XDP kernel program (TCP/UDP per-peer filtering)
  service.go            eBPF program loading, peer rule map management
internal/
  database.go           SQLite: peers, device codes, firewall rules
  server.go             HTTP routing, auth middleware, embedded PWA
  handlers_peers.go     Peer CRUD + WireGuard status
  handlers_rules.go     Firewall rule CRUD + eBPF map sync
  handlers_device.go    OAuth2 device authorization flow
  middleware.go         Auth header validation
web/                    PWA
  components/           peers-list, peer-detail, device-approve, toast-notification
wireguard/              WireGuard device management via wgctrl/netlink
```

## Requirements

- **Linux** - uses netlink, WireGuard kernel interfaces, and eBPF/XDP
- **Kernel 5.8+** - for `CAP_BPF` support
- **Root or capabilities** - `CAP_NET_ADMIN`, `CAP_BPF`, `CAP_SYS_RESOURCE` for the server
- **Go 1.22+** - for building from source (method-based HTTP routing patterns)

---

"WireGuard" is a registered trademark of Jason A. Donenfeld.
