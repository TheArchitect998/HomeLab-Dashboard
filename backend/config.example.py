# Dashboard läuft auf Pi2. IPs/Hostnamen anpassen.
# Optional pro Agent: "key" (eigener Schlüssel statt AGENT_KEY) und "ca_cert"
# (Pfad zum CA-/Agent-Zertifikat für HTTPS mit selbst signiertem Zertifikat).
AGENTS = {
    "HomeLab1": {"url": "https://homelab1.lan:9100", "key": "Eigener Schlüssel dieses Agenten", "ca_cert": "/opt/homelab-dashboard/certs/homelab1.crt"},
    "HomeLab2": {"url": "http://127.0.0.1:9100"},
}
AGENT_KEY = "Zufälliger Secure Key (mind. 16 Zeichen), der in den Agenten eingetragen werden muss. Wird für Agenten ohne eigenen \"key\" verwendet."
POLL_SECONDS = 15
BIND_HOST = "0.0.0.0"
BIND_PORT = 8888
