# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| main    | ✅ Supported       |
| older   | ❌ Not supported   |

## Reporting a Vulnerability

Please report security vulnerabilities **privately** — do not open a public GitHub issue.

Use GitHub's private vulnerability reporting:

1. Go to the **Security** tab of this repository
2. Click **Report a vulnerability**

Alternatively, contact the maintainer directly via the email listed on their GitHub profile.

Please include:

- A description of the issue and its potential impact
- Steps to reproduce (or a proof of concept)
- The affected file, endpoint, or configuration

You can expect a response within a few days. Coordinated disclosure is appreciated — please give us time to fix the issue.

## Scope

NodeSentinel is designed to run **inside a trusted home network (LAN)**. It is not intended to be exposed directly to the public internet.

Security issues caused by exposing the dashboard or agents to the internet without additional protection (reverse proxy, TLS, firewall rules) are considered misconfiguration rather than a vulnerability — though reports are still welcome.

## Known Security Considerations

- **Agent authentication**: agents accept an `X-Agent-Key` header. Set a strong `NODESENTINEL_AGENT_KEY` on every agent and use the same key in the dashboard configuration. Previous environment-variable prefixes remain supported for migration. A native agent without a key accepts unauthenticated requests; the container agent refuses to start without one.
- **Network access**: dashboard-to-agent connections use unencrypted HTTP. Restrict agent ports to the dashboard host and use a trusted network or an encrypted tunnel. Use HTTPS for dashboard access across the network to protect passwords and session cookies.
- **Native agent privileges**: UFW and Fail2Ban status checks use `sudo`. Restrict sudoers to the required status commands, adapting the supplied template to the service user and host command paths. Docker group or socket access grants extensive host privileges. Journal access can expose sensitive system logs.
- **Container agent privileges**: the Docker socket effectively grants host-root access, even when mounted read-only. The read-only host-root mount may expose sensitive files. Only use trusted images and restrict access to the agent.
- **Optional container security sources**: journal event collection and UFW and Fail2Ban status checks are disabled by default, although the host-root mount may still expose journal files. Enabling collection exposes sensitive logs; additional administrative capabilities are required for status checks. A Fail2Ban socket permits administrative commands, and UFW access using `NET_ADMIN` with host networking can change the host firewall. Review the Docker Compose instructions and grant only the access needed.
- **Secrets and state**: protect agent keys, configuration files, notification credentials and the dashboard state directory or volume, including backups. The state contains password hashes, provider credentials and monitoring data. Do not commit credentials or expose configuration files.
