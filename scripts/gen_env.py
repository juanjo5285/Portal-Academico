"""Genera un .env local con secretos ALEATORIOS (nunca valores fijos en el código).
El archivo queda con permisos 600 y está en .gitignore."""
import base64, os, secrets, sys
from pathlib import Path

p = Path(".env")
if p.exists() and "--force" not in sys.argv:
    sys.exit(".env ya existe (use --force para regenerarlo)")
content = f"""# Generado por scripts/gen_env.py — NO versionar
FLASK_SECRET_KEY={secrets.token_urlsafe(48)}
DATA_KEY_ACTIVE=v1
DATA_KEY_v1={base64.b64encode(os.urandom(32)).decode()}
ADMIN_INITIAL_PASSWORD={secrets.token_urlsafe(18)}
LAB_VULN=1
"""
fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as fh:
    fh.write(content)
print("Creado .env (permisos 600). La contraseña inicial del admin está dentro del archivo.")
