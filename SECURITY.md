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

HomeLab Dashboard is designed to run **inside a trusted home network (LAN)**. It is not intended to be exposed directly to the public internet.

Security issues caused by exposing the dashboard or agents to the internet without additional protection (reverse proxy, TLS, firewall rules) are considered misconfiguration rather than a vulnerability — though reports are still welcome.

## Known Security Considerations

- **Agent authentication**: agents accept an `X-Agent-Key` header. Set `HOMELAB_AGENT_KEY` on every agent; without it, the metrics endpoint is unauthenticated.
- **Plain HTTP**: communication between dashboard and agents is unencrypted HTTP. Keep all endpoints on a trusted LAN segment.
- **Privileged commands**: the agent invokes `sudo` for firewall and Fail2Ban status. Ensure your sudoers configuration only allows the specific commands used here (`NOPASSWD` for `ufw status` and `fail2ban-client`), not broad root access.
