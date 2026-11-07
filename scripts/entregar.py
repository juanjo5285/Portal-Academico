"""Arma el zip de entrega SOLO con los archivos versionados en Git.

Así nunca se incluyen .env, llaves privadas (certs/), la base de datos, logs,
el entorno virtual (.venv) ni binarios como gitleaks.exe: todo eso está en
.gitignore y git archive lo respeta. Antes de terminar, verifica el contenido.

Uso:  python scripts/entregar.py            -> crea portal-seguro_entrega.zip
"""
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SALIDA = ROOT / "portal-seguro_entrega.zip"
PROHIBIDOS = (".env", ".key", ".db", ".log", ".venv/", "certs/", "lab/", "gitleaks.exe")

pendientes = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True).stdout
if pendientes.strip():
    print("Hay cambios sin confirmar. Ejecuta primero:  git add -A  y  git commit -m \"...\"")
    print(pendientes)
    sys.exit(1)

subprocess.run(["git", "archive", "--format=zip", "--prefix=portal-seguro/", "-o", str(SALIDA), "HEAD"],
               cwd=ROOT, check=True)

with zipfile.ZipFile(SALIDA) as z:
    nombres = z.namelist()
malos = [n for n in nombres if any(n.endswith(p) or f"/{p}" in n for p in PROHIBIDOS)
         and not n.endswith(".env.example")]
if malos:
    SALIDA.unlink()
    sys.exit(f"Entrega cancelada: contiene archivos sensibles {malos}")

print(f"Creado {SALIDA.name}: {len(nombres)} archivos, {SALIDA.stat().st_size / 1024:.0f} KB")
print("Verificado: sin .env, llaves privadas, base de datos, logs, .venv ni binarios.")
