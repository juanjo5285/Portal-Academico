"""Lector mínimo de archivos .env (equivalente a python-dotenv, sin dependencia).
No sobrescribe variables ya definidas en el entorno real."""
import os
from pathlib import Path


def load_env(path=".env"):
    p = Path(path)
    if not p.is_file():
        return
    if os.name == "posix" and p.stat().st_mode & 0o077:
        print(f"[ADVERTENCIA] {path} es legible por otros usuarios; ejecute: chmod 600 {path}")
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
