# Dashboard läuft auf Pi2. IPs/Hostnamen anpassen.
AGENTS = {
    "HomeLab1": {"url": "http://192.168.1.XXX:9100"},
    "HomeLab2": {"url": "http://127.0.0.1:9100"},
}
AGENT_KEY = "Zufälliger Secure Key, der in den Agenten eingetragen werden muss. Muss auf allen Agenten gleich sein."
POLL_SECONDS = 15
BIND_HOST = "0.0.0.0"
BIND_PORT = 8888
