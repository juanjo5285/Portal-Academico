"""Fase II-D y prueba obligatoria 5: Gitleaks detecta la credencial ficticia en el historial."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.skipif(shutil.which("gitleaks") is None, reason="gitleaks no instalado")
def test_gitleaks_detecta_fuga_en_historial(tmp_path):
    out = tmp_path / "evid"
    r = subprocess.run(["bash", "scripts/gitleaks_demo.sh", str(tmp_path / "repo"), str(out)],
                       cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 1                                       # gitleaks: 1 = fugas encontradas
    assert "no leaks found" in (out / "gitleaks_01_dir_actual.txt").read_text()   # HEAD parece limpio
    hallazgos = json.loads((out / "gitleaks_02_historial.json").read_text())
    reglas = {h["RuleID"] for h in hallazgos}
    assert {"aws-access-token", "github-pat"} <= reglas
    assert all(h["Secret"] == "REDACTED" for h in hallazgos)       # la evidencia no repite el secreto
    assert "no leaks found" in (out / "gitleaks_04_tras_limpieza.txt").read_text()
