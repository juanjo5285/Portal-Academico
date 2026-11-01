"""Generación y compresión de reportes sin inyección de comandos.

Controles:
1. La entrada del usuario (carnet, tipo) se valida por lista blanca.
2. El nombre de archivo lo construye el servidor; nunca se usa texto libre.
3. Se llama al binario con una LISTA de argumentos y shell=False: no hay
   intérprete que procese ; | & $() ` > <.
4. Ruta absoluta del ejecutable, entorno mínimo, timeout y "--" (fin de
   opciones) para que un nombre que empiece por "-" no se lea como opción.
5. Privilegios mínimos: si REPORT_RUN_AS está definido, el proceso hijo corre
   con ese usuario sin privilegios (p. ej. "reportes"), sin acceso a la BD ni a
   los secretos. En producción, además: contenedor con USER no-root,
   sistema de archivos de solo lectura y un volumen exclusivo para /reportes.
"""
import csv
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

TAR = shutil.which("tar") or "/usr/bin/tar"   # Windows 10+ incluye tar.exe (bsdtar)

# Entorno mínimo: el hijo NO hereda variables con secretos (FLASK_SECRET_KEY, DATA_KEY...).
if os.name == "nt":
    MIN_ENV = {"SYSTEMROOT": os.environ.get("SYSTEMROOT", r"C:\Windows"), "PATH": os.path.dirname(TAR)}
else:
    MIN_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}


def build_report(rows, carnet: str, tipo: str, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="rep_") as tmp:
        csv_name = f"{tipo}_{carnet}.csv"          # carnet y tipo ya validados
        with open(Path(tmp) / csv_name, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["curso", "nota"])
            for r in rows:
                # Neutraliza inyección de fórmulas en Excel (=, +, -, @)
                curso = r["curso"]
                if curso[:1] in ("=", "+", "-", "@"):
                    curso = "'" + curso
                w.writerow([curso, r["nota"]])
        out = out_dir / f"{tipo}_{carnet}.tar.gz"
        kwargs = {}
        run_as = os.environ.get("REPORT_RUN_AS")
        if run_as and os.geteuid() == 0:
            kwargs.update(user=run_as, group=run_as)
            os.chmod(tmp, 0o755)
        subprocess.run(
            [TAR, "-czf", str(out), "-C", tmp, "--", csv_name],
            shell=False, check=True, timeout=10,
            env=MIN_ENV,
            stdin=subprocess.DEVNULL, capture_output=True, **kwargs)
    return out
