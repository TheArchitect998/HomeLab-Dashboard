# HomeLab Dashboard

A lightweight, self-hosted monitoring dashboard for your home lab. Monitor multiple devices (Raspberry Pi, mini PCs, NAS, etc.) from a single web interface. Track CPU, RAM, disk usage, temperature, firewall status, and running containers in real-time.

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
- [Configuration](#configuration)
- [Deployment Options](#deployment-options)
- [Security](#security)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## Features

✅ **Real-time Monitoring**
- CPU, RAM, disk usage, and temperature
- Multi-device support with auto-refresh (15s)

✅ **Security Monitoring**
- UFW firewall status and active rules
- Fail2Ban status and jail overview
- Failed login attempt tracking

✅ **Container Management**
- Docker container status
- Container restart history
- Last start timestamp

✅ **Zero Database**
- Lightweight agents with no persistence required
- Simple JSON-based communication

✅ **Easy Deployment**
- Example systemd service files included
- Single `.env` configuration file
- No external dependencies

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│           Dashboard Host (Pi 1)                      │
│  ┌─────────────────────────────────────────────┐   │
│  │  Web UI (FastAPI + HTML)                    │   │
│  │  Aggregates metrics from agents             │   │
│  └─────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
                        ↓
        ┌───────────────┬───────────────┐
        ↓               ↓               ↓
   ┌─────────┐     ┌─────────┐     ┌─────────┐
   │ Agent   │     │ Agent   │     │ Agent   │
   │ (Pi 2)  │     │ (NAS)   │     │ (Other) │
   └─────────┘     └─────────┘     └─────────┘
```

**How it works:**
1. Dashboard runs a FastAPI server exposing a web UI
2. One or more lightweight agents run on monitored devices
3. Agents expose `/api/metrics` endpoint
4. Dashboard polls agents and aggregates the data
5. Web UI auto-refreshes every 15 seconds

---

## Requirements

**Dashboard Host:**
- Python 3.11+
- pip / venv
- Linux (systemd-enabled, recommended)
- ~50 MB disk space

**Agent Hosts:**
- Python 3.11+
- pip / venv
- Linux (systemd-enabled, recommended)
- ~30 MB disk space
- Optional: UFW, Fail2Ban, Docker (for full feature set)

---

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/TheArchitect998/HomeLab-Dashboard.git
cd HomeLab-Dashboard
```

### 2. Create virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install fastapi uvicorn httpx psutil
```

### 3. Configure dashboard

```bash
cp .env.example .env
# Edit .env and add your agent URLs
nano .env
```

Example `.env`:
```env
DASHBOARD_HOST=0.0.0.0
DASHBOARD_PORT=8888
AGENT_URLS='["http://pi-1.local:9100/api/metrics","http://pi-2.local:9100/api/metrics"]'
```

### 4. Start dashboard

```bash
source venv/bin/activate
uvicorn dashboard_api:app --host 0.0.0.0 --port 8888
```

Open browser: `http://localhost:8888`

---

## Installation

### Dashboard Setup

#### Step 1: Prepare the host

```bash
# Create application directory
sudo mkdir -p /opt/homelab-dashboard
cd /opt/homelab-dashboard

# Clone repository
git clone https://github.com/TheArchitect998/HomeLab-Dashboard.git .

# Create virtual environment
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install fastapi uvicorn httpx psutil
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
DASHBOARD_HOST=0.0.0.0
DASHBOARD_PORT=8888
AGENT_URLS='["http://192.168.1.100:9100/api/metrics","http://192.168.1.101:9100/api/metrics"]'
```

#### Step 3: Test locally

```bash
source venv/bin/activate
uvicorn dashboard_api:app --host 0.0.0.0 --port 8888
```

Visit `http://localhost:8888` to verify the dashboard loads.

---

### Agent Setup

Run these steps on **each monitored device** (Pi 2, NAS, etc.).

#### Step 1: Prepare the host

```bash
# Create application directory (same path as dashboard)
sudo mkdir -p /opt/homelab-dashboard
cd /opt/homelab-dashboard

# Clone repository
git clone https://github.com/TheArchitect998/HomeLab-Dashboard.git .

# Create virtual environment
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install fastapi uvicorn psutil
```

#### Step 2: Configure agent

```bash
# Copy example configuration
cp homelab-agent.env.example homelab-agent.env

# Edit with a secure key
nano homelab-agent.env
```

Set a strong key:
```env
HOMELAB_AGENT_KEY=your-secure-random-key-here
```

#### Step 3: Configure sudo (optional but recommended)

To allow the agent to read UFW and Fail2Ban status without password prompts:

```bash
# Add to sudoers
sudo visudo

# Add these lines at the end:
_agent ALL=(ALL) NOPASSWD: /usr/sbin/ufw
_agent ALL=(ALL) NOPASSWD: /usr/bin/fail2ban-client
```

(Replace `_agent` with your actual username if different)

#### Step 4: Test locally

```bash
source venv/bin/activate
uvicorn backend.agent:app --host 0.0.0.0 --port 9100
```

Test the agent:
```bash
curl http://localhost:9100/api/metrics
```

---

### Systemd Services

#### Dashboard Service

Copy the example service file:

```bash
sudo cp systemd/homelab-dashboard.service.example /etc/systemd/system/homelab-dashboard.service
```

Edit as needed:
```bash
sudo nano /etc/systemd/system/homelab-dashboard.service
```

Key settings to verify:
- `User=` (your username)
- `WorkingDirectory=` (path to cloned repo)
- `EnvironmentFile=` (path to .env)

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable homelab-dashboard.service
sudo systemctl start homelab-dashboard.service
sudo systemctl status homelab-dashboard.service
```

#### Agent Service

Copy the example service file on **each agent host**:

```bash
sudo cp systemd/homelab-agent.service.example /etc/systemd/system/homelab-agent.service
```

Edit as needed:
```bash
sudo nano /etc/systemd/system/homelab-agent.service
```

Key settings to verify:
- `User=` (your username)
- `WorkingDirectory=` (path to cloned repo)
- `EnvironmentFile=` (path to homelab-agent.env)

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable homelab-agent.service
sudo systemctl start homelab-agent.service
sudo systemctl status homelab-agent.service
```

Check agent logs:
```bash
sudo journalctl -u homelab-agent.service -f
```

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
sudo systemctl restart homelab-dashboard.service
```

### Changing Ports

**Dashboard port:**
```env
DASHBOARD_PORT=8888  # Default: 8888
```

**Agent port:**
Update the agent startup command in the systemd service file:
```ini
ExecStart=/opt/homelab-dashboard/venv/bin/uvicorn backend.agent:app --host 0.0.0.0 --port 9100
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
- ✅ **Use strong agent keys** (HOMELAB_AGENT_KEY)
- ✅ **Keep agents on trusted network** (not exposed to internet)
- ✅ **Use TLS/reverse proxy** if exposing dashboard externally
- ✅ **Restrict sudoers** to only UFW and Fail2Ban commands
- ✅ **Firewall rules** to limit dashboard/agent access

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
   sudo systemctl status homelab-agent.service
   ```

2. Agent port is accessible:
   ```bash
   curl http://agent-hostname:9100/api/metrics
   ```

3. Hostnames resolve:
   ```bash
   ping pi-1.local
   ping pi-2.local
   ```

4. Dashboard has correct URLs in `.env`

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
sudo nano /etc/systemd/system/homelab-agent.service
# Delete or comment out: NoNewPrivileges=true
sudo systemctl daemon-reload
sudo systemctl restart homelab-agent.service
```

---

### Dashboard won't connect to agent

**Check dashboard logs:**
```bash
sudo journalctl -u homelab-dashboard.service -n 50 -f
```

**Check agent logs:**
```bash
sudo journalctl -u homelab-agent.service -n 50 -f
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

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

You are free to use, modify, and distribute this software for personal or commercial purposes, provided you include the license notice.

---

## Project Structure

```
HomeLab-Dashboard/
├── LICENSE                              # MIT License
├── README.md                            # This file
├── .gitignore                           # Git ignore rules
├── .env.example                         # Dashboard config template
├── homelab-agent.env.example            # Agent config template
│
├── dashboard_api.py                     # Dashboard web server
├── frontend/
│   └── index.html                       # Web UI (HTML + inline CSS/JS)
├── backend/
│   └── agent.py                         # Lightweight metrics agent
│
└── systemd/
    ├── homelab-dashboard.service.example  # Dashboard systemd service template
    └── homelab-agent.service.example      # Agent systemd service template
```

---

## Support

If you encounter issues:

1. **Check the [Troubleshooting](#troubleshooting) section**
2. **Review the logs:**
   - Dashboard: `sudo journalctl -u homelab-dashboard.service -f`
   - Agent: `sudo journalctl -u homelab-agent.service -f`
3. **Open an issue** on GitHub with:
   - What you tried
   - What you expected
   - What went wrong
   - Relevant log output

---

**Enjoy monitoring your home lab! 🎉**
