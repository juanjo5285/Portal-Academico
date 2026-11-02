"""Fase II-D y prueba obligatoria 5: Gitleaks detecta la credencial ficticia en el historial."""
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def find_bash():
    """bash de Git (o de Linux/Mac). En Windows se evita System32\\bash.exe (WSL)."""
    candidates = [shutil.which("bash")]
    if os.name == "nt":
        candidates += [r"C:\Program Files\Git\bin\bash.exe", r"C:\Program Files\Git\usr\bin\bash.exe"]
        git = shutil.which("git")
        if git:
            candidates.append(str(Path(git).resolve().parent.parent / "bin" / "bash.exe"))
    for c in candidates:
        if c and Path(c).is_file() and "system32" not in c.lower():
            return c
    return None


def posix(p):
    return str(p).replace("\\", "/")   # C:\\Users\\... -> C:/Users/... (Git Bash lo entiende)


BASH = find_bash()


@pytest.mark.skipif((shutil.which("gitleaks") is None and not (ROOT / "gitleaks.exe").exists()) or BASH is None,
                    reason="requiere gitleaks y bash (en Windows: ejecutar desde Git Bash)")
def test_gitleaks_detecta_fuga_en_historial(tmp_path):
    out = tmp_path / "evid"
    r = subprocess.run([BASH, "scripts/gitleaks_demo.sh", posix(tmp_path / "repo"), posix(out)],
                       cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace")
    print(r.stdout[-2000:], r.stderr[-2000:])
    assert r.returncode == 1                                       # gitleaks: 1 = fugas encontradas
    assert "no leaks found" in (out / "gitleaks_01_dir_actual.txt").read_text(encoding="utf-8")   # HEAD parece limpio
    hallazgos = json.loads((out / "gitleaks_02_historial.json").read_text(encoding="utf-8"))
    reglas = {h["RuleID"] for h in hallazgos}
    assert {"aws-access-token", "github-pat"} <= reglas
    assert all(h["Secret"] == "REDACTED" for h in hallazgos)       # la evidencia no repite el secreto
    assert "no leaks found" in (out / "gitleaks_04_tras_limpieza.txt").read_text(encoding="utf-8")
