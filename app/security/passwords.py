"""Almacenamiento seguro de contraseñas con Argon2id (RFC 9106).

Se usa la implementación de la biblioteca `cryptography` (OpenSSL), que genera
la cadena en formato PHC:  $argon2id$v=19$m=...,t=...,p=...$<sal>$<hash>
La sal (16 bytes aleatorios por usuario) y los parámetros viajan dentro de la
cadena, así que se guarda un solo campo en la base de datos.
"""
import hashlib
import os

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

# Parámetros recomendados por OWASP Password Storage Cheat Sheet (2025):
# Argon2id, m=19 MiB, t=2, p=1  (mínimo). Aquí: 64 MiB, t=3, p=1.
MEMORY_KIB = int(os.environ.get("ARGON2_MEMORY_KIB", 64 * 1024))
ITERATIONS = int(os.environ.get("ARGON2_ITERATIONS", 3))
LANES = 1
SALT_BYTES = 16
HASH_BYTES = 32

# Hash ficticio para igualar el tiempo de respuesta cuando el usuario no existe
# (evita enumerar correos midiendo tiempos).
_DUMMY = None


def _kdf(salt: bytes) -> Argon2id:
    return Argon2id(salt=salt, length=HASH_BYTES, iterations=ITERATIONS,
                    lanes=LANES, memory_cost=MEMORY_KIB)


def hash_password(password: str) -> str:
    salt = os.urandom(SALT_BYTES)
    return _kdf(salt).derive_phc_encoded(password.encode("utf-8"))


def verify_password(password: str, stored: str | None) -> bool:
    global _DUMMY
    if not stored:
        _DUMMY = _DUMMY or hash_password("contraseña-ficticia")
        stored, ok_if = _DUMMY, False
    else:
        ok_if = True
    try:
        Argon2id.verify_phc_encoded(password.encode("utf-8"), stored)
        return ok_if
    except (InvalidKey, ValueError):
        return False


def needs_rehash(stored: str) -> bool:
    """True si el hash se creó con parámetros más débiles que los actuales."""
    return f"m={MEMORY_KIB},t={ITERATIONS},p={LANES}" not in stored


# ---------------------------------------------------------------------------
# SOLO PARA LA DEMOSTRACIÓN COMPARATIVA (Fase II-A). No se usa en el login.
# ---------------------------------------------------------------------------
def legacy_sha256(password: str) -> str:
    """Mecanismo INSEGURO original: SHA-256 sin sal, una sola iteración."""
    return hashlib.sha256(password.encode()).hexdigest()
