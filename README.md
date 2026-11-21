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
- [Choosing an installation method](#choosing-an-installation-method)
- [Quick Start](#quick-start)
- [Docker Compose](#docker-compose)
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
                         ↑
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
3. New agents open an outbound authenticated WebSocket and push metrics to the dashboard
4. The dashboard reads the latest received sample and requests event time ranges over the same connection
5. Web UI auto-refreshes every 15 seconds

Existing HTTP-pull agents remain supported. An agent without `NODESENTINEL_HUB_URL`
uses the legacy HTTP listener; the supplied new-agent configuration uses push.
Use `wss://` for remote connections. Plain `ws://` is allowed only to loopback.
Measurements are not buffered while disconnected; the dashboard marks stale
or disconnected agents offline and resumes history with new samples on reconnect.

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

## Choosing an installation method

| Method | Best for | What you need | Start here |
| --- | --- | --- | --- |
| Docker Compose | Users who prefer prebuilt images and container-based deployment | Docker Engine and the Compose plugin | [Docker Compose](#docker-compose) |
| Dockhand or Portainer stack | Users who manage Docker deployments through a web interface | Docker and a Dockhand or Portainer installation | [Stack guide](#deploy-as-a-dockhand-or-portainer-stack) |
| Native Linux | Users who prefer a host executable and systemd services | Linux and Go 1.24+ to build the executable | [Quick Start](#quick-start), then [native installation](#installation) |

The Quick Start and the later Installation section describe the native setup.
Systemd and sudoers instructions there do not apply to a Compose deployment.

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
cp nodesentinel.config.example.json nodesentinel.config.json
# Edit .env and configure push agents with unique keys in the JSON file
nano .env
nano nodesentinel.config.json
```

Example `.env`:
```env
NODESENTINEL_DASHBOARD_HOST=0.0.0.0
NODESENTINEL_DASHBOARD_PORT=8888
NODESENTINEL_DASHBOARD_CONFIG=./nodesentinel.config.json
NODESENTINEL_STATE_DIR=/opt/nodesentinel/state
```

Set each push agent's `mode` to `push` and its own random `key` of at least
16 characters. The agent's name and `NODESENTINEL_AGENT_KEY` must match the
JSON entry. Remove example agents you do not use. Protect both configuration
files from other users. For existing pull agents, `AGENT_URLS` remains supported
when no dashboard JSON configuration is selected.

### 4. Set the first password locally

The state directory must be writable only by the dashboard service user. Replace `user` with your actual service user:

```bash
sudo install -d -o user -g user -m 0700 /opt/nodesentinel/state
sudo chown user:user .env
sudo chmod 600 .env
sudo chown user:user nodesentinel.config.json
sudo chmod 600 nodesentinel.config.json
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

### Install Docker

On Linux, install Docker Engine and the Docker Compose plugin by following the
[official Docker Engine installation guide](https://docs.docker.com/engine/install/)
for your distribution and the
[Compose plugin instructions](https://docs.docker.com/compose/install/linux/).
Then verify both commands are available:

```bash
docker --version
docker compose version
```

Get the Compose files and example configuration. This downloads the deployment
files only; Compose pulls the prebuilt image, so no Go installation or local
image build is needed:

```bash
git clone https://github.com/TheArchitect998/NodeSentinel.git
cd NodeSentinel
```

Run the commands below from this directory. For Dockhand or Portainer, the
Compose file can be entered or selected in the stack UI; the dashboard
configuration must still exist at a readable path on the Docker host (see the
stack guide below).

The two files `compose.yaml` and `compose.agent.yaml` are ready to use on a
Raspberry Pi, in Dockhand, Portainer or any other Docker Compose environment.
They pull the published images and do not require a Git checkout or a local Go
build.

### Deploy as a Dockhand or Portainer stack

1. **Prepare the dashboard configuration on the Docker host.** Create the file
   before deploying the stack because Compose requires the bind-mounted file to
   exist:

   ```bash
   sudo install -d -o 10001 -g 10001 -m 0750 /opt/nodesentinel
   sudo cp nodesentinel.config.example.json /opt/nodesentinel/nodesentinel.config.json
   sudo chown 10001:10001 /opt/nodesentinel/nodesentinel.config.json
   sudo chmod 600 /opt/nodesentinel/nodesentinel.config.json
   sudoedit /opt/nodesentinel/nodesentinel.config.json
   ```

   Replace the example agent entries with named push agents and unique strong
   keys. The dashboard container runs as UID/GID 10001 and needs to read this file.

2. **Create the dashboard stack.** In Portainer, open **Stacks > Add stack**;
   in Dockhand, create a new stack. Select the Git repository or paste/upload
   `compose.yaml`. Add this stack environment variable, pointing to the
   configuration file created above:

   ```text
   NODESENTINEL_CONFIG_PATH=/opt/nodesentinel/nodesentinel.config.json
   ```

   Deploy the stack. Compose pulls the published dashboard image automatically.
   Keep the same stack/project name when updating so the `dashboard-state`
   volume remains attached.

3. **Set the dashboard password.** Open a terminal/console for the running
   dashboard container and run:

   ```text
   /usr/local/bin/nodesentinel dashboard setup
   ```

   Follow the prompts, then open the dashboard at `http://<docker-host>:8888`.
   The default bind address is localhost; set `NODESENTINEL_BIND_ADDRESS` to
   the Docker host's LAN address in the stack environment to access it remotely.

4. **Deploy agents.** On each monitored Linux host, create another stack from
   `compose.agent.yaml`. Set `NODESENTINEL_AGENT_NAME` and
   `NODESENTINEL_AGENT_KEY` to the matching dashboard push entry, and set
   `NODESENTINEL_HUB_URL` to the dashboard's reachable `wss://` URL. Configure
   HTTPS on the dashboard or a WebSocket-capable reverse proxy first.

Override `NODESENTINEL_DASHBOARD_IMAGE` or `NODESENTINEL_AGENT_IMAGE` to pin a
specific release tag.

### Dashboard

```bash
cp nodesentinel.config.example.json nodesentinel.config.json
```

Edit `nodesentinel.config.json`: replace the example agent entries with named
push agents and a different strong `key` for each one.
Protect this file; it may contain secrets. The container runs as UID/GID 10001
and must be able to read it. Agent `127.0.0.1` addresses refer to the dashboard
container itself.

By default, Compose mounts `./nodesentinel.config.json` relative to the
Compose project. Set `NODESENTINEL_CONFIG_PATH` to an absolute path on the Docker
host to use a protected configuration file elsewhere, for example when
deploying a Git stack through Dockhand and Hawser. The file must already
exist, and UID/GID 10001 must be able to traverse its parent directories and
read it. Do not commit the configuration file or its secrets.

```bash
docker compose pull
docker compose run --rm dashboard /usr/local/bin/nodesentinel dashboard setup
docker compose up -d
docker compose ps
```

The setup command prompts you to create the dashboard password. After startup,
open `http://localhost:8888` (or the configured bind address and port) and sign
in.

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

On each monitored Linux host, place `compose.agent.yaml` in a deployment
directory (clone the repository there or copy the file from the dashboard
deployment). Create a `.env` file containing the matching push name and key:

```env
NODESENTINEL_AGENT_KEY=replace-with-a-strong-random-key
NODESENTINEL_AGENT_NAME=HomeLab1
NODESENTINEL_HUB_URL=wss://dashboard.example
```

```bash
chmod 600 .env
docker compose -f compose.agent.yaml pull
docker compose -f compose.agent.yaml up -d
docker compose -f compose.agent.yaml ps
```

The dashboard URL must resolve from the agent container. Configure a reverse
proxy for WebSocket upgrades and HTTPS, or enable dashboard TLS directly.
For a private CA, uncomment the CA mount and `NODESENTINEL_HUB_CA_CERT` in
`compose.agent.yaml`. The agent verifies the dashboard certificate. Push mode
does not expose an inbound agent port.

The agent refuses to start without `NODESENTINEL_AGENT_KEY` of at least 16
characters (the example value `change-me` is rejected). Generate one with
`openssl rand -base64 32`.

The default container mounts only host `/proc` read-only. Docker, host root
filesystem usage, journal, UFW, Fail2Ban and S.M.A.R.T. are disabled by default.
Unavailable sources are shown as unavailable. Container network counters describe
the container network namespace unless host networking is enabled. Even read-only
`/proc` access can expose process metadata; run only trusted agent images.

**Security:** Opting into Docker socket access effectively grants host-root
privileges, even when the socket mount is read-only. Opting into a read-only
host-root mount can expose sensitive files. Only run trusted images.

#### Optional security sources

For Docker, set `NODESENTINEL_ENABLE_DOCKER=1` and enable the Docker socket
mount. For root filesystem usage, set `NODESENTINEL_ENABLE_HOST_ROOT=1` and
enable the host-root mount. Each grants the access described above.

For SSH and Fail2Ban events, set `NODESENTINEL_ENABLE_JOURNAL=1`, mount only the
directory containing the host's `.journal` files at `/host/journal`, and set
`NODESENTINEL_JOURNAL_DIR=/host/journal`. Verify the container can read it.
Journal access exposes sensitive logs; missing files cause an explicit error.

For UFW status, enable host networking, the `NET_ADMIN` capability,
`NODESENTINEL_ENABLE_UFW=1`, the `/run` tmpfs and read-only `/etc/ufw` mount.
`NET_ADMIN` allows changes to the host firewall; host networking and compatible
UFW/iptables versions are required. Push mode still opens no agent listener.

To enable Fail2Ban status, uncomment `NODESENTINEL_ENABLE_FAIL2BAN=1` and the
separate Fail2Ban directory mount. The agent connects to
`/host/fail2ban/fail2ban.sock`. Socket
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
  `/etc/nodesentinel-agent.env`. The hardened systemd example prevents sudo
  privilege elevation; enabling it requires a deliberate service override or a
  separately restricted privileged helper.
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
cp nodesentinel.config.example.json nodesentinel.config.json

# Edit the named push-agent entries and their unique keys
nano .env
nano nodesentinel.config.json
```

Create the state directory and set the initial password as described in
[Quick Start](#4-set-the-first-password-locally). Configure a unique matching
name and key on each agent.

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

# Edit the dashboard URL, agent name and secure key
nano nodesentinel-agent.env
```

Set the name and key from the dashboard JSON configuration:
```env
NODESENTINEL_AGENT_KEY=your-secure-random-key-here
NODESENTINEL_AGENT_NAME=HomeLab1
NODESENTINEL_HUB_URL=wss://dashboard.example
```

#### Step 3: Configure optional security access

Docker, journal, UFW, Fail2Ban and SMART are opt-in. For Docker, explicitly set
`NODESENTINEL_ENABLE_DOCKER=1` and grant Docker access only if its root-equivalent
privileges are acceptable. For SSH and Fail2Ban events, set
`NODESENTINEL_ENABLE_JOURNAL=1` and grant the service user journal read access.

To read UFW and Fail2Ban status, set the corresponding `NODESENTINEL_ENABLE_UFW=1`
or `NODESENTINEL_ENABLE_FAIL2BAN=1` and review the provided sudoers template.
Adjust its username and command paths for your host before installing it:

```bash
sudo install -m 0440 systemd/nodesentinel.sudoers /etc/sudoers.d/nodesentinel
sudo visudo -cf /etc/sudoers.d/nodesentinel
```

The template permits specific status commands rather than unrestricted access
to UFW and Fail2Ban. The hardened systemd example has `NoNewPrivileges=yes`,
which blocks sudo elevation; choose a deliberately restricted privileged helper
or service override if these sources are needed. Journal access can expose
sensitive system logs.

#### Step 4: Test locally

```bash
set -a
source nodesentinel-agent.env
set +a
./bin/nodesentinel agent
```

The agent logs connection errors and retries. Verify that the matching host
appears online in the dashboard. Push mode does not start an HTTP listener.

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

Create a dedicated unprivileged user and install the protected agent
configuration on **each agent host**. Make sure `/opt/nodesentinel` and the
agent binary are readable and executable by that user:

```bash
sudo useradd --system --user-group --no-create-home --shell /usr/sbin/nologin nodesentinel
sudo install -o nodesentinel -g nodesentinel -m 0600 nodesentinel-agent.env /etc/nodesentinel-agent.env
```

Skip user creation if the account already exists. Copy the example service:

```bash
sudo cp systemd/nodesentinel-agent.service.example /etc/systemd/system/nodesentinel-agent.service
```

Edit as needed:
```bash
sudo nano /etc/systemd/system/nodesentinel-agent.service
```

Key settings to verify:
- `User=nodesentinel` (a dedicated, non-root service account)
- `WorkingDirectory=` (path to cloned repo)
- `EnvironmentFile=` (`/etc/nodesentinel-agent.env`, readable only by the service account)

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

Existing HTTP-pull configurations continue to work when `NODESENTINEL_HUB_URL`
is unset. Docker, journal, UFW and Fail2Ban now require explicit enable flags;
container root filesystem usage also requires the opt-in mount and flag. To
migrate to push, configure a named `mode: "push"` agent and unique key in the
dashboard JSON, then set the matching name, key and `wss://` hub URL on that
agent. The supplied new Compose example uses push and no inbound agent port.
To keep pull when adopting that example, remove the required `HUB_URL` and
`AGENT_NAME` environment entries and explicitly add a restricted port mapping;
retain the legacy dashboard URL and agent TLS settings. Configure the opt-in
flags and mounts needed by the previous installation.

### Updating the Dashboard UI

For a UI-only update, use a frontend version compatible with the installed
backend. Back up the deployed `frontend/index.html`, then copy the new
`frontend/index.html` from the checked-out release into the dashboard's
frontend directory. The dashboard reads this file on each page request, so a
service restart is not required for a UI-only update.

---

## Configuration

### Adding/Removing Agents

Edit `nodesentinel.config.json` on the **dashboard** host:

```json
{
  "agents": {
    "host1": {"mode": "push", "key": "replace-with-a-unique-random-key"},
    "old-host": {"url": "https://old-host:9100", "key": "existing-pull-agent-key"}
  }
}
```

Restart the dashboard and configure the push agent with the same name and key.
Legacy `AGENT_URLS` remains available when no JSON configuration is selected.
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
require access to the Docker socket and the corresponding enable flags. Grant
these permissions deliberately:
journal access exposes potentially sensitive logs, and Docker socket access
effectively grants host-root privileges. Container agents need the relevant
optional host access enabled separately.

Event notification cursors persist across dashboard restarts. On reconnection,
the dashboard requests the missed time range from the agent's local source.
Recovery is limited by that source's retention (Docker's event history is
bounded); unavailable or expired source data cannot be reconstructed. If
notification delivery partially fails, retries can result in duplicates.

Settings, provider credentials and monitoring databases are stored in the
dashboard state directory. Protect and back up this directory. Resource history
is sampled every minute and retained for 30 days; report events and temperature
samples are retained for approximately 25 hours. Run one dashboard worker only.

### Changing Ports

**Dashboard port:** Set `NODESENTINEL_DASHBOARD_PORT` in the environment or `bind_port` in the JSON dashboard config.

**Agent port (legacy HTTP-pull mode only):**
Set `NODESENTINEL_AGENT_PORT` in the agent environment file and update the
dashboard agent URL. For host-network Compose overlays, set the same variable:
```ini
NODESENTINEL_AGENT_PORT=9100
```

Then update the corresponding legacy agent URL in the dashboard configuration.

---

## Deployment Options

Run the dashboard and agent on one device or deploy a central dashboard with
agents on multiple devices. Register each agent by name and unique key as shown
in [Adding/Removing Agents](#addingremoving-agents), then restart the dashboard.
Each agent needs outbound access to the dashboard's WebSocket URL. A native
agent on the dashboard host may use `ws://127.0.0.1:8888`; separate containers
do not share loopback unless explicitly configured to share a network namespace.

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

Push agents authenticate with their configured name and unique `X-Agent-Key`.
The agent verifies the dashboard's certificate and uses `wss://` for remote
connections. Plain `ws://` is accepted only for loopback. A TLS-terminating
proxy must support WebSocket upgrades; restrict access between the proxy and
dashboard because that hop also carries the key and data.

For private CAs, configure the agent's `NODESENTINEL_HUB_CA_CERT` with a
readable public CA certificate. Compose users can enable the public CA mount
in `compose.agent.yaml`; never mount the dashboard's private key on an agent.

For **legacy HTTP-pull mode**, every request uses the `X-Agent-Key` header.
Without TLS the key and metrics travel in clear text, so enable HTTPS on
agents outside `127.0.0.1`:

1. Create a certificate on the agent host (replace the name/IP with the address
   the dashboard uses):

   ```bash
   openssl req -x509 -newkey rsa:4096 -nodes -days 825 \
     -keyout agent.key -out agent.crt -subj "/CN=homelab1.lan" \
     -addext "subjectAltName=DNS:homelab1.lan,IP:192.168.1.20"
   chmod 600 agent.key
   ```

2. Leave `NODESENTINEL_HUB_URL` unset and start the agent with
   `NODESENTINEL_AGENT_TLS_CERTFILE` and `NODESENTINEL_AGENT_TLS_KEYFILE`
   pointing to the agent certificate and private key. Legacy container
   deployments also need a listener, port mapping and a protected TLS mount.
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

Use a different key per agent so a leaked key only affects one host. Push
agents require their own key in the JSON config; legacy pull agents without a
per-agent key use `AGENT_KEY`. Set the push agent name and key in both the
agent environment and dashboard config.

```json
{
  "agents": {
    "HomeLab1": {
      "mode": "push",
      "key": "unique-key-for-homelab1"
    }
  }
}
```

### Agent permissions

| Capability | Needed for | Default |
| --- | --- | --- |
| Read-only `/proc` mount | Host CPU, RAM and other kernel metrics | On |
| Read-only `/` mount and `NODESENTINEL_ENABLE_HOST_ROOT=1` | Container agent host filesystem usage | Off |
| Docker socket and `NODESENTINEL_ENABLE_DOCKER=1` | Container status and events | Off; socket access is root-equivalent |
| Journal mount and `NODESENTINEL_ENABLE_JOURNAL=1` | SSH and Fail2Ban events | Off |
| `NET_ADMIN`, host network and `/etc/ufw` in `compose.agent.yaml` | UFW status | Off |
| `NODESENTINEL_ENABLE_FAIL2BAN=1` | Fail2Ban status | Off |

The container drops all capabilities by default, uses a read-only container
filesystem and sets `no-new-privileges`. Native service hardening is provided
in the systemd example. Enable only the sources you need.

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
    location /api/agent/connect {
        proxy_pass http://127.0.0.1:8888;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
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

**Example: Firewall rules for legacy pull-agent access**

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

2. Push agent logs show a successful connection. Verify the dashboard `wss://`
   URL, certificate trust, WebSocket proxy support and outbound access.
3. Agent name and key match its `mode: "push"` entry in the dashboard JSON.
4. For legacy pull agents only, check the configured URL and agent port.

---

### HTTPS via Nginx Proxy Manager

If the browser says the server cannot be found, first check DNS with `nslookup YOUR-SUBDOMAIN` on the client. The name must resolve to the proxy host's reachable IP, not the dashboard port. For LAN-only use, configure the local DNS server to resolve the name to the proxy's LAN IP. Check DNS caches and that the client uses that DNS server.

In Nginx Proxy Manager, forward using scheme `http`, the dashboard host's reachable IP and port `8888`, enable WebSocket support, and select a trusted certificate for the subdomain. Verify port 443 is reachable and test `curl http://DASHBOARD-IP:8888/` from the proxy host. Within a container, `127.0.0.1` normally refers to the container, not the dashboard host.

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

Ensure the relevant enable flag and permissions are configured. The hardened
systemd service prevents sudo elevation; see [optional security access](#step-3-configure-optional-security-access).

---

### Docker containers don't show

**Check on the agent host:**
```bash
docker ps -a
```

Enable `NODESENTINEL_ENABLE_DOCKER=1` and grant Docker access only if its
root-equivalent privileges are acceptable. Missing access is shown as unavailable.

---

### Privileged optional sources unavailable under systemd

The hardened service blocks sudo privilege elevation. Prefer a narrowly
restricted helper, or deliberately change the service restrictions after
assessing the increased risk. Do not remove protections just to hide errors.

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
