"""Rotación de la clave de cifrado de datos (DATA_KEY).

Procedimiento:
 1. Generar nueva clave:  python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"
 2. Guardarla en la bóveda/entorno como DATA_KEY_v2, poner DATA_KEY_ACTIVE=v2 y DATA_KEY_OLD=v1.
 3. Ejecutar este script: re-cifra todo con v2.
 4. Verificar (0 registros con v1) y retirar DATA_KEY_v1 de la bóveda.
"""
import sqlite3, sys
sys.path.insert(0, ".")
from dotenv_lite import load_env
load_env(".env")
from app.config import load_data_keys
from app.security.crypto import FieldCipher
import os

c = FieldCipher(load_data_keys())
db = sqlite3.connect(os.environ.get("DB_PATH", "lab/portal.db"))
n = 0
for carnet, dpi, tel in db.execute("SELECT carnet, dpi_cifrado, telefono_cifrado FROM estudiantes").fetchall():
    for col, val in (("dpi", dpi), ("telefono", tel)):
        if c.needs_rotation(val):
            aad = f"estudiantes.{col}:{carnet}"
            db.execute(f"UPDATE estudiantes SET {col}_cifrado=? WHERE carnet=?",  # col viene de lista fija
                       (c.encrypt(c.decrypt(val, aad), aad), carnet))
            n += 1
db.commit()
print(f"Campos re-cifrados con la clave {c.active}: {n}")
