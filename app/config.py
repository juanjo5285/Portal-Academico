"""Carga de secretos desde fuentes externas (nunca desde el código fuente).

Orden de resolución de cada secreto:
  1. HashiCorp Vault (KV v2), si VAULT_ADDR y VAULT_TOKEN están definidos.
  2. Variable de entorno con el mismo nombre (p. ej. inyectada por systemd,
     Docker, Azure App Settings o un archivo .env local que NO se versiona).
  3. Archivo en /run/secrets/<NOMBRE> (Docker/Kubernetes secrets).

Si un secreto obligatorio no aparece en ninguna fuente, la aplicación NO
arranca (fail closed): nunca se usa un valor por defecto "de desarrollo".
"""
import base64
import os
from pathlib import Path

import requests


class SecretNotFound(RuntimeError):
    pass


def _from_vault(name: str):
    addr = os.environ.get("VAULT_ADDR")
    token = os.environ.get("VAULT_TOKEN")
    if not (addr and token):
        return None
    path = os.environ.get("VAULT_SECRET_PATH", "secret/data/portal")
    resp = requests.get(
        f"{addr.rstrip('/')}/v1/{path}",
        headers={"X-Vault-Token": token},
        timeout=3,
        verify=os.environ.get("VAULT_CACERT", True),
    )
    resp.raise_for_status()
    return resp.json()["data"]["data"].get(name)


def _from_file(name: str):
    p = Path(os.environ.get("SECRETS_DIR", "/run/secrets")) / name
    if p.is_file():
        return p.read_text().strip()
    return None


def get_secret(name: str, required: bool = True):
    for source in (_from_vault, lambda n: os.environ.get(n), _from_file):
        value = source(name)
        if value:
            return value
    if required:
        # El mensaje nombra el secreto que falta, nunca un valor.
        raise SecretNotFound(f"Secreto requerido no configurado: {name}")
    return None


def load_data_keys() -> dict:
    """Devuelve {id_de_clave: bytes} para todas las DATA_KEY_<id> disponibles.

    La clave activa (para cifrar) es DATA_KEY_ACTIVE; las demás se conservan
    solo para descifrar datos antiguos durante una rotación.
    """
    active = get_secret("DATA_KEY_ACTIVE")
    keys = {}
    for kid in {active, *filter(None, (os.environ.get("DATA_KEY_OLD") or "").split(","))}:
        raw = base64.b64decode(get_secret(f"DATA_KEY_{kid}"))
        if len(raw) != 32:
            raise ValueError(f"DATA_KEY_{kid} debe tener 32 bytes (AES-256)")
        keys[kid] = raw
    return {"active": active, "keys": keys}
