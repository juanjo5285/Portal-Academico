import base64
import os
import secrets
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


@pytest.fixture()
def env(tmp_path, monkeypatch):
    """Secretos de prueba generados al azar en cada ejecución (ninguno en el código)."""
    vals = {
        "FLASK_SECRET_KEY": secrets.token_urlsafe(32),
        "DATA_KEY_ACTIVE": "v1",
        "DATA_KEY_v1": base64.b64encode(os.urandom(32)).decode(),
        "ADMIN_INITIAL_PASSWORD": secrets.token_urlsafe(16),
        "DB_PATH": str(tmp_path / "portal.db"),
        "REPORT_DIR": str(tmp_path / "reportes"),
        "LOG_PATH": str(tmp_path / "seguridad.log"),
        "COOKIE_SECURE": "0",
        "SECRETS_DIR": str(tmp_path / "no-existe"),
    }
    for k in ("VAULT_ADDR", "VAULT_TOKEN", "DATA_KEY_OLD"):
        monkeypatch.delenv(k, raising=False)
    for k, v in vals.items():
        monkeypatch.setenv(k, v)
    return vals


@pytest.fixture()
def app(env):
    from app import create_app
    from app.db import get_db
    from app.security.passwords import hash_password
    a = create_app({"TESTING": True, "LAB_VULN": True, "SQL_TRACE": []})
    with a.app_context():
        db = get_db()
        for email, rol, carnet in (("cat@ejemplo.edu.gt", "catedratico", None),
                                   ("est@ejemplo.edu.gt", "estudiante", "1290-23-10001")):
            db.execute("INSERT INTO usuarios (email,password_hash,rol,carnet) VALUES (?,?,?,?)",
                       (email, hash_password("Clave-Ficticia-2026!"), rol, carnet))
        db.commit()
    return a


def csrf(client):
    client.get("/login")
    with client.session_transaction() as s:
        return s["csrf"]


def post(client, url, data):
    return client.post(url, data={**data, "csrf": csrf(client)})


def login(client, email, pwd="Clave-Ficticia-2026!"):
    return post(client, "/login", {"email": email, "password": pwd})


@pytest.fixture()
def cat(app):
    c = app.test_client()
    assert login(c, "cat@ejemplo.edu.gt").status_code == 302
    return c


@pytest.fixture()
def est(app):
    c = app.test_client()
    assert login(c, "est@ejemplo.edu.gt").status_code == 302
    return c


def read_log(env):
    p = Path(env["LOG_PATH"])
    return p.read_text(encoding="utf-8") if p.exists() else ""


def inyeccion(marca):
    """Carga que crea el archivo `marca` si el shell interpreta el texto (Windows o Linux/Mac)."""
    if os.name == "nt":
        return f'x & type nul > "{marca}" & echo'
    return f'x; touch "{marca}"; echo'
