# NodeSentinel

NodeSentinel is a self-hosted monitoring dashboard for Linux hosts. It
provides system metrics, Docker and security information, persistent history,
and notifications via Telegram, Discord, Ntfy, Pushover, e-mail (SMTP), generic
webhooks and Gotify. Temperature alerts
and a daily report with a configurable time help you monitor your homelab.

**Perfect for:** Home labs, small server farms, personal infrastructure monitoring.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Installation](#installation)
  - [Dashboard Setup](#dashboard-setup)
  - [Agent Setup](#agent-setup)
  - [Systemd Services](#systemd-services)
  - [Updating the Dashboard UI](#updating-the-dashboard-ui)
- [Configuration](#configuration)
- [Deployment Options](#deployment-options)
- [Security](#security)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## Features

![NodeSentinel Übersicht](screenshots/dashboard-aktuell.png)

Der Screenshot verwendet synthetische Beispieldaten.

- CPU, RAM, root filesystem and temperature monitoring
- Persistent per-host metrics history: one sample per minute, retained for 30 days
- Docker container status, start times and restarts, plus CPU, RAM and network per container with history
- Reachability checks (HTTP, TCP, ping, DNS) with outage notifications
- UFW and Fail2Ban status where configured
- Telegram, Discord, Ntfy, Pushover, e-mail (SMTP), webhook and Gotify notifications
- Per-host temperature alerts and a daily report with a configurable time
- Password-protected dashboard and optional agent authentication
- Customizable overview: move and resize panels; layout is saved in the browser
- German, English and French interface; light and dark themes
- Native Linux or Docker deployment on AMD64 and ARM64

---

## Architecture

```
┌───────────────────────────────────────────────────┐
│              Dashboard Host (Pi 1)                │
│  ┌─────────────────────────────────────────────┐  │
│  │          Go API + HTML/JavaScript UI        │  │
│  │       Aggregates metrics from agents        │  │
│  └─────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────┘
                         ↓
         ┌───────────────┬───────────────┐
         ↓               ↓               ↓
    ┌─────────┐     ┌─────────┐     ┌─────────┐
    │ Agent   │     │ Agent   │     │ Agent   │
    │ (Pi 2)  │     │ (NAS)   │     │ (Other) │
    └─────────┘     └─────────┘     └─────────┘
```

**How it works:**
1. Dashboard runs a Go HTTP server and serves the web UI
2. One or more lightweight Go agents run on monitored devices
3. Agents expose `/api/metrics` endpoint
4. Dashboard polls agents and aggregates the data
5. Web UI auto-refreshes every 15 seconds

---

## Requirements

Choose one deployment method:

- **Native Go:** Linux hosts and Go 1.24+ on the dashboard and each agent host.
- **Docker Compose:** Docker Engine and the Docker Compose plugin. Go does not
  need to be installed on the host; the Dockerfiles build the Go executable
  inside a multi-stage image.

Python is not required for either deployment. UFW, Fail2Ban and Docker on
monitored hosts are optional agent integrations.

---

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/TheArchitect998/NodeSentinel.git
cd NodeSentinel
```

### 2. Build the Go executable

```bash
mkdir -p bin
go build -o bin/nodesentinel ./cmd/nodesentinel
```

For Docker deployment, skip the native build and use [Docker Compose](#docker-compose).

### 3. Configure dashboard

```bash
cp .env.example .env
# Edit .env and add your agent URLs
nano .env
```

Example `.env`:
```env
NODESENTINEL_DASHBOARD_HOST=0.0.0.0
NODESENTINEL_DASHBOARD_PORT=8888
AGENT_URLS='["http://pi-1.local:9100/api/metrics","http://pi-2.local:9100/api/metrics"]'
AGENT_KEY=your-long-random-agent-key
NODESENTINEL_STATE_DIR=/opt/nodesentinel/state
```

`AGENT_KEY` must match `NODESENTINEL_AGENT_KEY` on each agent. Protect `.env` from other users. `AGENT_URLS` accepts the existing `/api/metrics` URLs or agent base URLs; names remain `agent-1`, `agent-2`, and so on.

### 4. Set the first password locally

The state directory must be writable only by the dashboard service user. Replace `user` with your actual service user:

```bash
sudo install -d -o user -g user -m 0700 /opt/nodesentinel/state
sudo chown user:user .env
sudo chmod 600 .env
set -a
source .env
set +a
./bin/nodesentinel dashboard setup
```

Set a password of at least 12 characters. For a service installation, run the setup command as the same user as the dashboard, with the same `NODESENTINEL_STATE_DIR`. The password can later be changed under Settings.

### 5. Start dashboard

```bash
set -a
source .env
set +a
./bin/nodesentinel dashboard
```

Open `http://localhost:8888` locally and sign in. Use trusted HTTPS for network access; HTTP exposes credentials and session cookies.

---

## Docker Compose

Published dashboard and agent images support Linux AMD64 and ARM64. Releases
are available from Docker Hub as `thearchitect998/nodesentinel` and
`thearchitect998/nodesentinel-agent`. Use a version tag such as `1.2.3` for
reproducible deployments; `latest` follows the newest published release.

The two files `compose.yaml` and `compose.agent.yaml` are ready to use on a
Raspberry Pi, in Dockhand, Portainer or any other Docker Compose environment.
They pull the published images and do not require a Git checkout or a local Go
build.

```bash
docker compose pull
docker compose up -d

docker compose -f compose.agent.yaml pull
docker compose -f compose.agent.yaml up -d
```

Override `NODESENTINEL_DASHBOARD_IMAGE` or `NODESENTINEL_AGENT_IMAGE` to pin a
specific release tag.

### Dashboard

```bash
cp nodesentinel.config.example.json nodesentinel.config.json
```

Edit `nodesentinel.config.json`: set the agent addresses and a strong
`agent_key` shared with the agents. Protect this file; it may contain secrets.
The container runs as UID/GID 10001 and must be able to read it. Agent
`127.0.0.1` addresses refer to the dashboard container itself.

By default, Compose mounts `./nodesentinel.config.json` relative to the
Compose project. Set `NODESENTINEL_CONFIG_PATH` to an absolute path on the Docker
host to use a protected configuration file elsewhere, for example when
deploying a Git stack through Dockhand and Hawser. The file must already
exist, and UID/GID 10001 must be able to traverse its parent directories and
read it. Do not commit the configuration file or its secrets.

```bash
docker compose run --rm dashboard /usr/local/bin/nodesentinel dashboard setup
docker compose up -d
```

The dashboard listens on `127.0.0.1:8888` by default. Set
`NODESENTINEL_BIND_ADDRESS` and optionally `NODESENTINEL_PORT` for a protected LAN.
The default timezone is UTC; set `NODESENTINEL_TIMEZONE`, for example to
`Europe/Berlin`, and recreate the container to change it.

Settings and history are stored in the `dashboard-state` volume. Protect and
back up this volume. `docker compose down -v` deletes it.

For agents using HTTPS with self-signed certificates, uncomment the certificate
mount in `compose.yaml` and set `NODESENTINEL_AGENT_CERTS_DIR` to an existing
host directory containing only public agent or CA certificates, never private
keys. The dashboard's UID/GID 10001 must be able to traverse and read that
directory. Configure each agent's `ca_cert` as
`/etc/nodesentinel/certs/<filename>`.

When replacing an existing stack, retain its Compose project name so that it
continues to use the existing `dashboard-state` volume.

### Agent

On each monitored Linux host, create a protected `.env` file containing the
same key as the dashboard:

```env
NODESENTINEL_AGENT_KEY=replace-with-a-strong-random-key
NODESENTINEL_AGENT_BIND_ADDRESS=127.0.0.1
```

```bash
chmod 600 .env
docker compose -f compose.agent.yaml pull
docker compose -f compose.agent.yaml up -d
```

Set `NODESENTINEL_AGENT_BIND_ADDRESS` to a suitable LAN IP for remote dashboard
access and restrict port 9100 with the host firewall. Without TLS, agent
communication is unencrypted; enable HTTPS (see
[Encrypted agent communication](#encrypted-agent-communication)) or use an
encrypted tunnel.

The agent refuses to start without `NODESENTINEL_AGENT_KEY` of at least 16
characters (the example value `change-me` is rejected). Generate one with
`openssl rand -base64 32`.

The agent reads host metrics and Docker status. Journal event collection and
UFW and Fail2Ban status checks are disabled by default. Unavailable sources are
shown as unavailable. Docker Desktop reports the Docker Linux VM, not the
Windows or macOS host.

**Security:** Docker socket access effectively grants host-root privileges,
even when the socket mount is read-only. The read-only host-root mount may
expose sensitive files. Only run trusted images and restrict agent access.

#### Optional security sources

Journal event collection and UFW and Fail2Ban status checks are disabled by
default. The existing read-only host-root mount may nevertheless expose
sensitive files, including system logs, to the container.

For SSH and Fail2Ban events, set `NODESENTINEL_JOURNAL_DIR` to the host journal
directory as seen through the existing `/host/root` mount, for example
`/host/root/var/log/journal/<machine-id>` or
`/host/root/run/log/journal/<machine-id>`. Choose the directory on each host
that actually contains its `.journal` files and verify that the container can
read them. Collection fails if the directory or journal files are unavailable.
Journal access exposes sensitive logs.

HTTPS, journal, UFW, Fail2Ban and S.M.A.R.T. are optional examples in
`compose.agent.yaml`. Uncomment only the environment variables, capabilities,
mounts or devices needed on that host. HTTPS additionally requires an
`NODESENTINEL_AGENT_TLS_DIR` containing `agent.crt` and `agent.key`.

For UFW status, enable host networking, the `NET_ADMIN` capability,
`NODESENTINEL_ENABLE_UFW=1` and the read-only `/etc/ufw` mount. Comment out the
`ports` section when using host networking. The agent then listens on
`NODESENTINEL_AGENT_BIND_ADDRESS` and `NODESENTINEL_AGENT_PORT` directly on the
host; the defaults are `127.0.0.1` and `9100`. Select a suitable host address
and restrict access with the host firewall. `NET_ADMIN` allows changes to the
host firewall; host networking and compatible UFW/iptables versions are
required.

To enable Fail2Ban status, uncomment
`NODESENTINEL_ENABLE_FAIL2BAN=1` on hosts running Fail2Ban. The agent connects to
`/run/fail2ban/fail2ban.sock` through the existing host-root mount. Socket
access allows administrative commands even with a read-only mount. The client
in the image must be compatible with the host's Fail2Ban server. On hosts
without Fail2Ban, leave the setting disabled.

Recreate the container after changes and verify status and real events. Missing
permissions or sources remain unavailable; the daily report marks missing
event coverage as incomplete.

#### Hardware metrics

Swap, disk I/O, per-interface network rates, NVIDIA GPU (`nvidia-smi`), ZFS pools
(`zpool`) and battery are reported automatically when available; the dashboard
shows "Unavailable" with the reason (tooltip) otherwise. Rates are computed from
counter deltas between requests; loopback, `veth*`, `docker*` and `br-*`
interfaces are ignored. In the container agent, network counters describe the
container's namespace unless host networking is enabled in `compose.agent.yaml`,
and GPU/ZFS tools are not part of the image. Intel/AMD GPUs are not supported.

S.M.A.R.T. is opt-in (`NODESENTINEL_ENABLE_SMART=1`) because it needs raw disk access.
Results are cached for 10 minutes and standby disks are not woken (`-n standby`).
A failed health check, reallocated/pending/uncorrectable sectors, or an NVMe
critical warning or media errors are shown as a warning. Not every USB adapter
passes SMART commands through.

- Native: install `smartmontools`, enable the commented `NODESENTINEL_SMART` lines in
  `systemd/nodesentinel.sudoers` and set `NODESENTINEL_ENABLE_SMART=1` in
  `/etc/nodesentinel-agent.env`.
- Docker Compose: uncomment the S.M.A.R.T. environment variable, `SYS_RAWIO`
  capability and matching `devices` entry in `compose.agent.yaml`.

The GitHub Actions workflow `publish-docker-images.yml` publishes both images
to Docker Hub when a semantic version tag such as `v2.4.0` is pushed. The
repository secrets `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` must be
configured. Each release is published as a multi-architecture manifest for
`linux/amd64` and `linux/arm64`, with `latest`, `<version>` and
`<major>.<minor>` tags.

## Installation

### Dashboard Setup

#### Step 1: Prepare the host

```bash
# Create application directory
sudo mkdir -p /opt/nodesentinel
cd /opt/nodesentinel

# Clone repository
git clone https://github.com/TheArchitect998/NodeSentinel.git .

# Build the dashboard and agent binary
mkdir -p bin
go build -o bin/nodesentinel ./cmd/nodesentinel
```

#### Step 2: Configure environment

```bash
# Copy example configuration
cp .env.example .env

# Edit with your agent URLs
nano .env
```

Set your agent URLs (hostnames or IPs):
```env
NODESENTINEL_DASHBOARD_HOST=0.0.0.0
NODESENTINEL_DASHBOARD_PORT=8888
AGENT_URLS='["http://192.168.1.100:9100/api/metrics","http://192.168.1.101:9100/api/metrics"]'
AGENT_KEY=your-long-random-agent-key
NODESENTINEL_STATE_DIR=/opt/nodesentinel/state
```

Create the state directory and set the initial password as described in [Quick Start](#4-set-the-first-password-locally). Configure the same key on every agent.

#### Step 3: Test locally

```bash
set -a
source .env
set +a
./bin/nodesentinel dashboard
```

Visit `http://localhost:8888` to verify the dashboard loads.

---

### Agent Setup

Run these steps on **each monitored device** (Pi 2, NAS, etc.).

#### Step 1: Prepare the host

```bash
# Create application directory (same path as dashboard)
sudo mkdir -p /opt/nodesentinel
cd /opt/nodesentinel

# Clone repository
git clone https://github.com/TheArchitect998/NodeSentinel.git .

# Build the agent binary
mkdir -p bin
go build -o bin/nodesentinel ./cmd/nodesentinel
```

#### Step 2: Configure agent

```bash
# Copy example configuration
cp nodesentinel-agent.env.example nodesentinel-agent.env

# Edit with a secure key
nano nodesentinel-agent.env
```

Set a strong key:
```env
NODESENTINEL_AGENT_KEY=your-secure-random-key-here
```

#### Step 3: Configure optional security access

To read UFW and Fail2Ban status, review the provided sudoers template and
adjust its username and command paths for your host before installing it:

```bash
sudo install -m 0440 systemd/nodesentinel.sudoers /etc/sudoers.d/nodesentinel
sudo visudo -cf /etc/sudoers.d/nodesentinel
```

The template permits specific status commands rather than unrestricted access
to UFW and Fail2Ban. Journal access for SSH and Fail2Ban event notifications
must be configured separately. Grant it only after considering that system
logs can contain sensitive information.

#### Step 4: Test locally

```bash
set -a
source nodesentinel-agent.env
set +a
./bin/nodesentinel agent
```

Test the agent:
```bash
curl -H "X-Agent-Key: $NODESENTINEL_AGENT_KEY" http://localhost:9100/api/metrics
```

---

### Systemd Services

#### Dashboard Service

Copy the example service file:

```bash
sudo cp systemd/nodesentinel.service.example /etc/systemd/system/nodesentinel.service
```

Edit as needed:
```bash
sudo nano /etc/systemd/system/nodesentinel.service
```

Key settings to verify:
- `User=` (your username)
- `WorkingDirectory=` (path to cloned repo)
- `EnvironmentFile=` (absolute path to the protected `.env`)

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable nodesentinel.service
sudo systemctl start nodesentinel.service
sudo systemctl status nodesentinel.service
```

#### Agent Service

Copy the example service file on **each agent host**:

```bash
sudo cp systemd/nodesentinel-agent.service.example /etc/systemd/system/nodesentinel-agent.service
```

Edit as needed:
```bash
sudo nano /etc/systemd/system/nodesentinel-agent.service
```

Key settings to verify:
- `User=` (your username)
- `WorkingDirectory=` (path to cloned repo)
- `EnvironmentFile=` (path to nodesentinel-agent.env)

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable nodesentinel-agent.service
sudo systemctl start nodesentinel-agent.service
sudo systemctl status nodesentinel-agent.service
```

Check agent logs:
```bash
sudo journalctl -u nodesentinel-agent.service -f
```

### Migrating earlier releases to NodeSentinel

The project was renamed to NodeSentinel. Existing installations keep working:

- `NODESENTINEL_*` environment variables are preferred; the older
  `HOMELAB_*` names remain accepted as fallbacks.
- Docker: the default Compose project name is now `nodesentinel`. To keep the
  state volume, history and password without moving data, set
  `COMPOSE_PROJECT_NAME` to the previous project name before redeploying.
  The container-internal state path is now `/opt/nodesentinel/state`. Agent
  certificates can be mounted at `/etc/nodesentinel/certs`. The Go dashboard
  reads JSON configuration; copy the required settings from an older
  `nodesentinel.config.py` into `nodesentinel.config.json`, using
  `nodesentinel.config.example.json` as a template. Python is not needed to run
  the Go version. Set `NODESENTINEL_CONFIG_PATH` (or the older
  `HOMELAB_CONFIG_PATH`) if the JSON file is elsewhere.
- Published images are now called `thearchitect998/nodesentinel` and
  `thearchitect998/nodesentinel-agent`.
- Users must log in once again because the session cookie was renamed.
- Native installs: systemd units, sudoers file and env file examples were
  renamed (`nodesentinel.service`, `nodesentinel-agent.service`, `nodesentinel.sudoers`,
  `nodesentinel-agent.env`). Existing units under the old names keep working.
- In Dockhand, save and redeploy each stack after updating (edit, then save
  and deploy), so the new Compose files are used.

### Updating an existing installation

Back up the dashboard state directory first, including its settings and both
SQLite databases. The Go dashboard and agents keep the existing HTTP API,
`settings.json`, `metrics.sqlite3` and `monitoring.sqlite3`, so dashboard
settings and history do not need to be recreated. The Go dashboard uses JSON
configuration; copy any required settings from a legacy Python configuration
file into the JSON example. Alternatively, the environment-based `AGENT_URLS`
configuration is still supported. No Python runtime or Python packages are
needed for the Go version.

Build and install the single Go executable on each corresponding host:

```bash
mkdir -p bin
go build -o bin/nodesentinel ./cmd/nodesentinel
```

Restart the dashboard and agent services after replacing the executable and
systemd unit commands. Docker users can rebuild and recreate the corresponding
Compose services instead. Verify login, agent connectivity, notification
settings and existing history afterwards.

### Updating the Dashboard UI

For a UI-only update, use a frontend version compatible with the installed
backend. Back up the deployed `frontend/index.html`, then copy the new
`frontend/index.html` from the checked-out release into the dashboard's
frontend directory. The dashboard reads this file on each page request, so a
service restart is not required for a UI-only update.

---

## Configuration

### Adding/Removing Agents

Edit `.env` on the **dashboard** host:

```env
# Add more agents by appending URLs to the JSON list
AGENT_URLS='["http://pi-1.local:9100/api/metrics","http://pi-2.local:9100/api/metrics","http://nas.local:9100/api/metrics"]'
```

Then restart the dashboard:
```bash
sudo systemctl restart nodesentinel.service
```

### Notifications, temperature alerts and daily report

Under **Notifications**, select Telegram, Discord, Ntfy, Pushover, E-Mail (SMTP),
Webhook or Gotify and
configure the provider. Multiple providers can be enabled at the same time.
Use the test button to verify delivery. Stored credentials are not displayed;
leaving a secret field empty retains the saved value.

- **E-Mail (SMTP)**: server, port, encryption (STARTTLS, SSL/TLS or none), optional
  login, sender and one or more recipients (comma separated). Certificates are
  verified.
- **Webhook**: the dashboard sends `POST` with JSON
  `{"source": "nodesentinel", "message": "...", "text": "..."}` to your URL
  (`text` is included for Slack/Mattermost-style receivers). An optional token is
  sent as `Authorization: Bearer <token>`.
- **Gotify**: server URL and an application token.

Enable temperature alerts and/or the daily report under **Temperature and
daily report**. At least one provider must be enabled. Temperature thresholds
are configured per host. Alerts repeat every five minutes while the threshold
is exceeded; a recovery message follows when the temperature returns to normal.

Optionally enable **hardware alerts** in the same form. They require
S.M.A.R.T. (`NODESENTINEL_ENABLE_SMART=1`) and/or ZFS data from the agent and are off
by default. Hosts are checked every five minutes. A notification is sent when
the list of problems changes (failed health check, reallocated/pending/
uncorrectable sectors, NVMe warnings, ZFS pool not `ONLINE`), and again when all
problems are resolved. Unchanged problems are not repeated.

### Container metrics and reachability checks

The agent reports CPU, RAM and network rates per container (`docker stats`,
sampled at most every 30 seconds) next to the container list. The network rates
are derived from the totals reported by Docker, so they are approximate for
very low traffic. The dashboard stores these values once a minute for 30 days;
the **History** page shows per-container charts. The metrics need the same
Docker access as the container list.

Open **Reachability** to add checks that run every minute **from the dashboard**:

| Type | Target | Success |
| --- | --- | --- |
| HTTP | URL | status below 400 (redirects are followed, certificates verified) |
| TCP | host and port | connection established |
| Ping | host or IP | ICMP reply (the Docker image includes `ping`; for a native install, `ping` must be installed) |
| DNS | host name | name resolves |

After two failed runs in a row a check counts as down and a notification is
sent to all enabled providers (per check, switchable); another message follows
when the check recovers. Check state is shown live; outages are not stored as
history.

Choose the report time in the dashboard. The default is 12:00 in the
dashboard process's timezone. The report is sent once per host and provider
after the selected time and covers the previous 24 hours. If delivery fails,
it is retried when possible on the same day. Incomplete event or temperature
coverage is marked in the report.

SSH and Fail2Ban events require readable host journal entries; Docker events
require access to the Docker socket. Grant these permissions deliberately:
journal access exposes potentially sensitive logs, and Docker socket access
effectively grants host-root privileges. Container agents need the relevant
optional host access enabled separately.

Settings, provider credentials and monitoring databases are stored in the
dashboard state directory. Protect and back up this directory. Resource history
is sampled every minute and retained for 30 days; report events and temperature
samples are retained for approximately 25 hours. Run one dashboard worker only.

### Changing Ports

**Dashboard port:** Set `NODESENTINEL_DASHBOARD_PORT` in the environment or `bind_port` in the JSON dashboard config.

**Agent port:**
Set `NODESENTINEL_AGENT_PORT` in the agent environment file and update the
dashboard agent URL. For host-network Compose overlays, set the same variable:
```ini
NODESENTINEL_AGENT_PORT=9100
```

Then update all agent URLs in the dashboard `.env`.

---

## Deployment Options

### Option 1: Dashboard + Agent on Same Device (Single Device Setup)

Simplest setup if you only want to monitor one machine.

```env
AGENT_URLS='["http://localhost:9100/api/metrics"]'
```

Run both dashboard and agent services on the same Pi.

---

### Option 2: Central Dashboard with Multiple Agents (Recommended)

One dashboard aggregating metrics from multiple devices.

**Dashboard Host (Pi 1):**
```env
AGENT_URLS='["http://pi-2.local:9100/api/metrics","http://nas.local:9100/api/metrics"]'
```

**Agent Hosts:**
- Pi 2: runs agent only
- NAS: runs agent only
- Any other device: add more URLs

---

### Option 3: Scalable Multi-Device Setup

Add new devices anytime by appending to the agent URL list.

```env
# Currently monitoring:
AGENT_URLS='["http://pi-1.local:9100/api/metrics","http://pi-2.local:9100/api/metrics"]'

# Add a third device:
AGENT_URLS='["http://pi-1.local:9100/api/metrics","http://pi-2.local:9100/api/metrics","http://my-nas.local:9100/api/metrics"]'

# Add a fourth device:
AGENT_URLS='["http://pi-1.local:9100/api/metrics","http://pi-2.local:9100/api/metrics","http://my-nas.local:9100/api/metrics","http://server.local:9100/api/metrics"]'
```

No code changes needed—just restart the dashboard.

---

## Security

⚠️ **Important Notes:**

- ✅ **Never commit `.env` files** to version control
- ✅ **Use strong agent keys** (NODESENTINEL_AGENT_KEY)
- ✅ **Keep agents on trusted network** (not exposed to internet)
- ✅ **Use TLS/reverse proxy** if exposing dashboard externally
- ✅ **Restrict sudoers** to only UFW and Fail2Ban commands
- ✅ **Firewall rules** to limit dashboard/agent access
- ✅ **Keep the state directory private**: it contains the password hash, Telegram token and monitoring data
- ✅ **Use HTTPS for network access**, not only internet access; plain HTTP exposes login credentials and cookies

### Encrypted agent communication

Every agent request is authenticated with the `X-Agent-Key` header (compared in
constant time; the agent rejects missing, short or example keys). Without TLS
the key and metrics travel in clear text, so enable HTTPS on agents outside
`127.0.0.1`.

1. Create a certificate on the agent host (replace the name/IP with the address
   the dashboard uses):

   ```bash
   openssl req -x509 -newkey rsa:4096 -nodes -days 825 \
     -keyout agent.key -out agent.crt -subj "/CN=homelab1.lan" \
     -addext "subjectAltName=DNS:homelab1.lan,IP:192.168.1.20"
   chmod 600 agent.key
   ```

2. Start the agent with TLS. Native: set `NODESENTINEL_AGENT_TLS_CERTFILE` and
   `NODESENTINEL_AGENT_TLS_KEYFILE` in `/etc/nodesentinel-agent.env`. Docker
   Compose: uncomment the TLS environment variables and certificate mount in
   `compose.agent.yaml`, then set `NODESENTINEL_AGENT_TLS_DIR` to the directory
   containing `agent.crt` and `agent.key`.
3. Copy `agent.crt` (not the key) to the dashboard host and use an `https://`
   URL. With a config file, pin the certificate per agent:

   ```json
   {
     "agents": {
       "HomeLab1": {
         "url": "https://homelab1.lan:9100",
         "ca_cert": "/opt/nodesentinel/certs/homelab1.crt"
       }
     }
   }
   ```

   With `AGENT_URLS`, set `AGENT_CA_CERT` to the certificate path. Certificates
   are always verified; there is no option to disable verification.

### Per-agent keys

Prefer a different key per agent so a leaked key only affects one host. In the
config file, add `"key"` to the agent entry; agents without it use `AGENT_KEY`.
To register a new agent, generate its key, set it as `NODESENTINEL_AGENT_KEY` on the
agent and as `"key"` in the dashboard config entry.

```json
{
  "agents": {
    "HomeLab1": {
      "url": "https://homelab1.lan:9100",
      "key": "unique-key-for-homelab1"
    }
  },
  "agent_key": "shared-fallback-key"
}
```

### Agent permissions

| Capability | Needed for | Default |
| --- | --- | --- |
| Read-only `/proc` and `/` mounts | CPU, RAM, storage | On |
| Docker socket (root-equivalent) | Container status and events | On; remove the mount if not needed (Docker data is then shown as unavailable) |
| `NODESENTINEL_JOURNAL_DIR` | SSH and Fail2Ban events | Off |
| `NET_ADMIN`, host network and `/etc/ufw` in `compose.agent.yaml` | UFW status | Off |
| `NODESENTINEL_ENABLE_FAIL2BAN=1` | Fail2Ban status | Off |

All capabilities are dropped except those listed, the root filesystem is
read-only and `no-new-privileges` is set. Enable only the sources you need.

### HTTPS for the dashboard behind a reverse proxy

Run the dashboard on `127.0.0.1` and let the proxy terminate TLS. Set
`NODESENTINEL_TRUSTED_PROXIES` to the proxy's source IP or CIDR so the dashboard
trusts its `X-Forwarded-Proto` header and marks session cookies `Secure`.
Forwarded headers from other sources are ignored.

Caddy (automatic certificates):

```caddyfile
homelab.example.com {
    reverse_proxy 127.0.0.1:8888
}
```

nginx:

```nginx
server {
    listen 443 ssl;
    server_name homelab.example.com;
    ssl_certificate     /etc/ssl/homelab.crt;
    ssl_certificate_key /etc/ssl/homelab.key;
    location / {
        proxy_pass http://127.0.0.1:8888;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Traefik: route to `http://127.0.0.1:8888` with a TLS router and the
`X-Forwarded-Proto` header (set by default).

**Example: Firewall rules to restrict agent access**

On each agent host:
```bash
# Allow dashboard to query agent (replace with dashboard IP)
sudo ufw allow from 192.168.1.50 to any port 9100

# Deny all other access to agent port
sudo ufw deny 9100
```

---

## Troubleshooting

### Dashboard shows all agents as "offline"

**Check:**
1. Agents are running:
   ```bash
   sudo systemctl status nodesentinel-agent.service
   ```

2. Agent port is accessible:
   ```bash
   curl -H "X-Agent-Key: YOUR_AGENT_KEY" http://agent-hostname:9100/api/metrics
   ```

3. Hostnames resolve:
   ```bash
   ping pi-1.local
   ping pi-2.local
   ```

4. Dashboard has correct URLs in `.env`

---

### HTTPS via Nginx Proxy Manager

If the browser says the server cannot be found, first check DNS with `nslookup YOUR-SUBDOMAIN` on the client. The name must resolve to the proxy host's reachable IP, not the dashboard port. For LAN-only use, configure the local DNS server to resolve the name to the proxy's LAN IP. Check DNS caches and that the client uses that DNS server.

In Nginx Proxy Manager, forward using scheme `http`, the dashboard host's reachable IP and port `8888`, and select a trusted certificate for the subdomain. Verify port 443 is reachable and test `curl http://DASHBOARD-IP:8888/` from the proxy host. Within a container, `127.0.0.1` normally refers to the container, not the dashboard host.

For TLS terminated on another host, configure `NODESENTINEL_TRUSTED_PROXIES`
with the actual trusted proxy source IP/CIDR so HTTPS cookies are marked
`Secure`. Do not trust all forwarded-header sources. Restrict direct dashboard
access with a firewall and restart the service after changing its configuration.

---

### UFW or Fail2Ban shows as inactive

**Check on the agent host:**
```bash
sudo -n ufw status
sudo -n fail2ban-client status
```

If these commands fail with permission errors, check sudoers configuration (see [Agent Setup → Step 3](#step-3-configure-sudo-optional-but-recommended)).

---

### Docker containers don't show

**Check on the agent host:**
```bash
docker ps -a
```

If Docker is not installed, the agent simply skips container monitoring (no error).

---

### Agent won't start with "no new privileges" error

Remove `NoNewPrivileges=true` from the systemd service file:

```bash
sudo nano /etc/systemd/system/nodesentinel-agent.service
# Delete or comment out: NoNewPrivileges=true
sudo systemctl daemon-reload
sudo systemctl restart nodesentinel-agent.service
```

---

### Dashboard won't connect to agent

**Check dashboard logs:**
```bash
sudo journalctl -u nodesentinel.service -n 50 -f
```

**Check agent logs:**
```bash
sudo journalctl -u nodesentinel-agent.service -n 50 -f
```

---

### Port already in use

**Find which process uses port 8888:**
```bash
sudo lsof -i :8888
# or
sudo netstat -tuln | grep 8888
```

Then either:
- Kill the process: `sudo kill -9 <PID>`
- Change port in `.env` and systemd service

---

## Contributing

Contributions are welcome! To contribute:

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/my-feature`)
3. **Make your changes**
4. **Commit with clear messages** (`git commit -m "Add feature X"`)
5. **Push to your fork** (`git push origin feature/my-feature`)
6. **Open a Pull Request**

**Guidelines:**
- Keep changes focused and minimal
- Test on at least one device before submitting
- Do not commit local secrets, `.env` files, or host-specific data
- Document changes in the PR description

---

## License

This project is licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for details.

You may use, modify, and distribute this software in accordance with the terms of the Apache License 2.0, including commercial use, provided that the license notice and copyright information are retained.

---

## Project Structure

```
NodeSentinel/
├── LICENSE                              # Apache License 2.0
├── README.md                            # This file
├── .gitignore                           # Git ignore rules
├── .env.example                         # Dashboard config template
├── nodesentinel-agent.env.example       # Agent config template
├── go.mod / go.sum                      # Go module and dependency lock
├── cmd/
│   └── nodesentinel/
│       ├── main.go                      # Dashboard/agent entry point
│       ├── agent.go                     # Linux metrics and event API
│       ├── dashboard.go                 # Dashboard HTTP API and storage
│       ├── notify.go                    # Notification providers
│       ├── monitor.go                   # History and monitoring workers
│       └── nodesentinel_test.go         # Go service tests
│
├── frontend/
│   └── index.html                       # Web UI (HTML + inline CSS/JS)
├── nodesentinel.config.example.json     # Dashboard configuration example
│
└── systemd/
    ├── nodesentinel.service.example         # Dashboard systemd service template
    └── nodesentinel-agent.service.example   # Agent systemd service template
```

---

## Support

If you encounter issues:

1. **Check the [Troubleshooting](#troubleshooting) section**
2. **Review the logs:**
   - Dashboard: `sudo journalctl -u nodesentinel.service -f`
   - Agent: `sudo journalctl -u nodesentinel-agent.service -f`
3. **Open an issue** on GitHub with:
   - What you tried
   - What you expected
   - What went wrong
   - Relevant log output

---

**Enjoy monitoring your home lab! 🎉**
