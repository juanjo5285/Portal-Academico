"""Fase II-A y pruebas obligatorias 3 y 4: KDF con sal; contraseña incorrecta rechazada."""
import hashlib
import time

from app.db import get_db
from app.security.passwords import hash_password, legacy_sha256, verify_password
from conftest import login, post

PWD = "Clave-Ficticia-2026!"


def test_hash_argon2id_con_sal(app):
    with app.app_context():
        h = get_db().execute("SELECT password_hash FROM usuarios WHERE email='est@ejemplo.edu.gt'").fetchone()[0]
    print("\n[hash almacenado]", h)
    assert h.startswith("$argon2id$v=19$m=65536,t=3,p=1$")
    salt = h.split("$")[4]
    assert len(salt) >= 22                                   # 16 bytes de sal en base64
    assert PWD not in h and legacy_sha256(PWD) not in h


def test_misma_clave_hash_distinto():
    a, b = hash_password(PWD), hash_password(PWD)
    assert a != b                                            # sal aleatoria por usuario
    assert verify_password(PWD, a) and verify_password(PWD, b)


def test_sha256_sin_sal_es_determinista_y_rapido():
    assert legacy_sha256(PWD) == legacy_sha256(PWD)          # mismo hash -> tablas arcoíris
    t = time.perf_counter()
    for _ in range(100_000):
        hashlib.sha256(b"Clave-Ficticia-2026!").digest()
    sha = (time.perf_counter() - t) / 100_000
    t = time.perf_counter(); hash_password(PWD); argon = time.perf_counter() - t
    print(f"\n[SHA-256] {sha*1e6:.2f} µs/intento  [Argon2id] {argon*1e3:.0f} ms/intento  -> {argon/sha:,.0f}x más costoso")
    assert argon / sha > 10_000


def test_login_correcto(app):
    assert login(app.test_client(), "est@ejemplo.edu.gt").status_code == 302


def test_login_incorrecto_rechazado(app):
    c = app.test_client()
    r = login(c, "est@ejemplo.edu.gt", "Clave-Equivocada-2026!")
    assert r.status_code == 401 and b"Correo o contrase" in r.data
    assert c.get("/").status_code == 302                     # sigue sin sesión
    r2 = login(c, "noexiste@ejemplo.edu.gt", "loquesea")
    assert r2.status_code == 401 and r2.data == r.data       # mismo mensaje: no enumera usuarios


def test_registro_guarda_hash(app):
    c = app.test_client()
    post(c, "/registro", {"email": "nuevo@ejemplo.edu.gt", "carnet": "1290-23-10003", "password": "Otra-Clave-Larga-99"})
    with app.app_context():
        h = get_db().execute("SELECT password_hash FROM usuarios WHERE email='nuevo@ejemplo.edu.gt'").fetchone()[0]
    assert h.startswith("$argon2id$") and verify_password("Otra-Clave-Larga-99", h)


def test_bloqueo_tras_5_intentos_fallidos(app, env):
    """Fuerza bruta: tras 5 fallos la cuenta se bloquea, incluso con la clave correcta."""
    import json
    c = app.test_client()
    for _ in range(5):
        assert login(c, "est@ejemplo.edu.gt", "Clave-Equivocada-2026!").status_code == 401
    r = login(c, "est@ejemplo.edu.gt", PWD)                 # contraseña CORRECTA
    assert r.status_code == 401 and c.get("/").status_code == 302
    eventos = [json.loads(l) for l in open(env["LOG_PATH"], encoding="utf-8") if l.strip()]
    assert any(e["event"] == "cuenta_bloqueada" for e in eventos)
    fallidos = [e for e in eventos if e["event"] == "login_fallido"]
    assert fallidos[-1]["motivo"] == "cuenta_bloqueada"      # el 6.º intento se rechazó por bloqueo
    # El mensaje es idéntico al de una contraseña incorrecta (no revela el bloqueo).
    import re
    r2 = login(app.test_client(), "noexiste@ejemplo.edu.gt", "x")
    flash = lambda resp: re.search(rb'class="flash">(.*?)<', resp.data).group(1)
    assert r2.status_code == 401 and flash(r) == flash(r2)


def test_bloqueo_expira(app):
    """Pasado el tiempo de bloqueo, la clave correcta vuelve a funcionar."""
    from app.db import get_db
    c = app.test_client()
    for _ in range(5):
        login(c, "est@ejemplo.edu.gt", "Clave-Equivocada-2026!")
    with app.app_context():
        get_db().execute("UPDATE usuarios SET bloqueado_hasta = 0 WHERE email='est@ejemplo.edu.gt'")
        get_db().commit()
    assert login(c, "est@ejemplo.edu.gt", PWD).status_code == 302


def test_exito_reinicia_contador(app):
    from app.db import get_db
    c = app.test_client()
    for _ in range(4):
        login(c, "est@ejemplo.edu.gt", "Clave-Equivocada-2026!")
    assert login(c, "est@ejemplo.edu.gt", PWD).status_code == 302
    with app.app_context():
        n = get_db().execute("SELECT intentos_fallidos FROM usuarios WHERE email='est@ejemplo.edu.gt'").fetchone()[0]
    assert n == 0
