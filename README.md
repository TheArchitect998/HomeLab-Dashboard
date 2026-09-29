# HomeLab Dashboard

A lightweight HomeLab monitoring dashboard for self-hosted devices. It collects system metrics from multiple lightweight agents and displays them in a single web dashboard.

This project is designed to run on a central dashboard host and connect to one or more agent services running on other machines such as Raspberry Pi devices or mini PCs.

## Features

- CPU, RAM, disk, and temperature monitoring
- UFW firewall status and rules
- Fail2Ban status and active jail list
- Docker container overview and restart counts
- Multi-device support via agent endpoints
- Simple web dashboard without a database
- Easy deployment with systemd services

## Architecture

- Dashboard host: central web UI and aggregator
- Agent hosts: lightweight Python service exposing metrics
- Communication: HTTPS or HTTP inside your home network

Typical setup:

- Pi 1 runs the dashboard and optional agent
- Pi 2 runs a second agent
- Additional hosts can be added by adding more agents to the dashboard config

## Project layout

```text
.
├── LICENSE
├── README.md
├── .gitignore
├── .env.example
├── dashboard_api.py
├── frontend/
│   └── index.html
├── backend/
│   └── agent.py
├── systemd/
│   ├── homelab-dashboard.service.example
│   └── homelab-agent.service.example
├── homelab-agent.env.example
└── .env
```

## Requirements

- Python 3.11+
- pip
- systemd-enabled Linux host (recommended)
- UFW and/or Fail2Ban on agent hosts (optional)
- Docker (optional for container monitoring)

## Quick start

### 1. Clone the repository

```bash
git clone https://github.com/TheArchitect998/HomeLab-Dashboard.git
cd HomeLab-Dashboard
```

### 2. Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install fastapi uvicorn httpx psutil
```

### 3. Configure the dashboard

Copy the example environment file:

```bash
cp .env.example .env
```

Edit `.env` and set the values:

```env
DASHBOARD_HOST=0.0.0.0
DASHBOARD_PORT=8888
AGENT_URLS='["http://pi-1.local:9100/api/metrics","http://pi-2.local:9100/api/metrics"]'
```

Notes:

- Replace the placeholder hostnames with your own device names or IPs.
- To add more devices later, append additional agent URLs to the JSON list.
- Keep the list valid JSON.

### 4. Start the dashboard

```bash
source venv/bin/activate
uvicorn dashboard_api:app --host 0.0.0.0 --port 8888
```

Open the app in your browser:

```text
http://localhost:8888
```

---

## Agent setup

Each monitored machine should run a small Python agent exposing metrics.

### 1. Copy the example environment

```bash
cp homelab-agent.env.example homelab-agent.env
```

Edit it:

```env
HOMELAB_AGENT_KEY=change-me
```

### 2. Run the agent

```bash
cd /opt/homelab-dashboard
source venv/bin/activate
uvicorn backend.agent:app --host 0.0.0.0 --port 9100
```

### 3. Use a systemd service

Example files are included in `systemd/`:

- `homelab-agent.service.example`
- `homelab-dashboard.service.example`

Install them with `systemctl` on your Linux hosts. Replace placeholder paths and hostnames as needed.

---

## Recommended deployment layout

### Option 1: Dashboard on one device, agents on others

This is the recommended default setup.

- Device A: dashboard server
- Device B: agent host (Pi 1)
- Device C: agent host (Pi 2)
- Additional machines: same pattern, add more URLs to `AGENT_URLS`

### Option 2: Dashboard and one agent on the same device

This works as well if you only want a single monitored machine.

### Option 3: More devices later

To add new monitored devices, append more entries in the JSON list in `.env`:

```env
AGENT_URLS='["http://pi-1.local:9100/api/metrics","http://pi-2.local:9100/api/metrics","http://nas.local:9100/api/metrics"]'
```

---

## Security notes

- Do not commit `.env` files.
- Use a strong shared agent key.
- Keep the dashboard and agents on a trusted local network.
- Restrict access to the dashboard behind your firewall if needed.
- If you expose the dashboard externally, use a reverse proxy and TLS.

---

## Included services

The project includes example service definitions for:

- dashboard service
- agent service

These are intended as a starting point and should be adjusted to your OS, user, and installation paths.

---

## Troubleshooting

### Dashboard shows offline hosts

Check:

- the agent is running
- the port is correct
- the hostname resolves locally
- the agent key matches

### UFW or Fail2Ban status missing

On the monitored host:

```bash
sudo -n ufw status
sudo -n fail2ban-client status
```

If those commands work manually, the agent should also be able to read them.

### Agent key mismatch

Make sure the same key is set in both places:

- agent environment
- dashboard configuration if required by your deployment

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

## Contributing

Contributions are welcome. Please open an issue or create a pull request with a clear description of the change.

Keep changes focused and avoid committing local secrets, environment files, or host-specific data.
