"""Fase II-C y prueba obligatoria 6: el secreto viene de una fuente externa."""
import json
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from app import config

ROOT = Path(__file__).resolve().parent.parent


def test_secreto_desde_variable_de_entorno(app, env):
    assert app.config["SECRET_KEY"] == env["FLASK_SECRET_KEY"]


def test_falla_cerrado_si_falta(monkeypatch, env):
    monkeypatch.delenv("FLASK_SECRET_KEY")
    from app import create_app
    with pytest.raises(config.SecretNotFound) as e:
        create_app()
    assert "FLASK_SECRET_KEY" in str(e.value) and env["DATA_KEY_v1"] not in str(e.value)


def test_secreto_desde_archivo_run_secrets(monkeypatch, tmp_path):
    (tmp_path / "SMTP_PASSWORD").write_text("ficticio-desde-archivo\n")
    monkeypatch.setenv("SECRETS_DIR", str(tmp_path))
    monkeypatch.delenv("SMTP_PASSWORD", raising=False)
    assert config.get_secret("SMTP_PASSWORD") == "ficticio-desde-archivo"


def test_secreto_desde_vault(monkeypatch):
    """Servidor que imita la API KV v2 de HashiCorp Vault y exige el token."""
    class Fake(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.headers.get("X-Vault-Token") != "token-app-ficticio" or self.path != "/v1/secret/data/portal":
                self.send_response(403); self.end_headers(); return
            body = json.dumps({"data": {"data": {"SMTP_PASSWORD": "ficticio-desde-vault"}}}).encode()
            self.send_response(200); self.end_headers(); self.wfile.write(body)
        def log_message(self, *a): pass
    srv = HTTPServer(("127.0.0.1", 0), Fake)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setenv("VAULT_ADDR", f"http://127.0.0.1:{srv.server_port}")
    monkeypatch.setenv("VAULT_TOKEN", "token-app-ficticio")
    monkeypatch.setenv("SMTP_PASSWORD", "valor-de-entorno")
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    assert config.get_secret("SMTP_PASSWORD") == "ficticio-desde-vault"   # Vault tiene prioridad
    monkeypatch.setenv("VAULT_TOKEN", "token-revocado")
    with pytest.raises(Exception):
        config.get_secret("SMTP_PASSWORD")                                 # token revocado -> sin acceso
    srv.shutdown()


@pytest.mark.skipif(subprocess.run(["which", "gitleaks"], capture_output=True).returncode, reason="gitleaks no instalado")
def test_codigo_fuente_sin_secretos():
    r = subprocess.run(["gitleaks", "dir", str(ROOT / "app"), "--no-banner", "--no-color", "--redact"],
                       capture_output=True, text=True)
    print(r.stdout, r.stderr)
    assert r.returncode == 0, "Gitleaks encontró secretos en app/"
