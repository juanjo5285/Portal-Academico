"""Fase II-B: cifrado en reposo (AES-256-GCM) y manejo de claves."""
import base64
import os
import sqlite3

import pytest
from cryptography.exceptions import InvalidTag

from app.security.crypto import FieldCipher


def test_bd_no_contiene_dpi_en_claro(app, env):
    raw = open(env["DB_PATH"], "rb").read()
    assert b"1234 56789 0101" not in raw and b"5555-0101" not in raw
    fila = sqlite3.connect(env["DB_PATH"]).execute(
        "SELECT dpi_cifrado FROM estudiantes WHERE carnet='1290-23-10001'").fetchone()[0]
    print("\n[dpi en BD]", fila)
    assert fila.startswith("enc:v1:")


def test_expediente_muestra_dpi_enmascarado(est):
    r = est.get("/expedientes/1290-23-10001")
    assert "•••••••••0101".encode() in r.data and b"1234567890101" not in r.data


def test_estudiante_no_ve_expediente_ajeno(est):
    assert est.get("/expedientes/1290-23-10002").status_code == 403


def _cipher(kid="v1", key=None, old=None):
    keys = {kid: key or os.urandom(32), **(old or {})}
    return FieldCipher({"active": kid, "keys": keys})


def test_integridad_gcm_detecta_alteracion():
    c = _cipher()
    tok = c.encrypt("1234 56789 0101", "estudiantes.dpi:1290-23-10001")
    pre, kid, b64 = tok.split(":")
    blob = bytearray(base64.b64decode(b64)); blob[-1] ^= 1
    with pytest.raises(InvalidTag):
        c.decrypt(f"{pre}:{kid}:{base64.b64encode(bytes(blob)).decode()}", "estudiantes.dpi:1290-23-10001")


def test_aad_impide_mover_cifrado_a_otro_registro():
    c = _cipher()
    tok = c.encrypt("1234 56789 0101", "estudiantes.dpi:1290-23-10001")
    with pytest.raises(InvalidTag):
        c.decrypt(tok, "estudiantes.dpi:1290-23-10002")


def test_nonce_unico():
    c = _cipher()
    assert c.encrypt("x", "a") != c.encrypt("x", "a")


def test_rotacion_de_clave():
    k1 = os.urandom(32)
    viejo = _cipher("v1", k1)
    tok = viejo.encrypt("dato", "t.c:1")
    nuevo = _cipher("v2", old={"v1": k1})
    assert nuevo.needs_rotation(tok) and nuevo.decrypt(tok, "t.c:1") == "dato"
    tok2 = nuevo.encrypt(nuevo.decrypt(tok, "t.c:1"), "t.c:1")
    assert tok2.startswith("enc:v2:") and not nuevo.needs_rotation(tok2)
