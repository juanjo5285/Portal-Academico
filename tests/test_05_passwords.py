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
