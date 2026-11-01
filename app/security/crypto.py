"""Cifrado de campos sensibles en reposo con AES-256-GCM (AEAD).

Formato almacenado:  enc:<id_clave>:<base64(nonce(12) || ciphertext || tag(16))>

- AES-GCM da confidencialidad e integridad: cualquier alteración del dato
  cifrado provoca InvalidTag al descifrar.
- AAD (datos asociados) = "tabla.columna:id_registro". Así un atacante con
  acceso a la BD no puede copiar el DPI cifrado de un estudiante al registro
  de otro: el descifrado falla porque el AAD no coincide.
- El id de clave permite rotar: se cifra con la clave activa y se descifra
  con la que indique el prefijo.
"""
import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PREFIX = "enc"


class FieldCipher:
    def __init__(self, keyring: dict):
        self.active = keyring["active"]
        self.keys = keyring["keys"]

    def encrypt(self, plaintext: str, aad: str) -> str:
        nonce = os.urandom(12)  # único por operación; nunca se reutiliza
        ct = AESGCM(self.keys[self.active]).encrypt(nonce, plaintext.encode(), aad.encode())
        return f"{PREFIX}:{self.active}:{base64.b64encode(nonce + ct).decode()}"

    def decrypt(self, token: str, aad: str) -> str:
        prefix, kid, b64 = token.split(":", 2)
        if prefix != PREFIX:
            raise ValueError("Formato de dato cifrado desconocido")
        blob = base64.b64decode(b64)
        return AESGCM(self.keys[kid]).decrypt(blob[:12], blob[12:], aad.encode()).decode()

    def needs_rotation(self, token: str) -> bool:
        return token.split(":", 2)[1] != self.active


def mask(value: str, visible: int = 4) -> str:
    """Muestra solo los últimos dígitos (minimización de datos en pantalla)."""
    return "•" * max(0, len(value) - visible) + value[-visible:]
