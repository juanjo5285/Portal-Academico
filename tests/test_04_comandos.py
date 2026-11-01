"""Fase I-D: inyección de comandos en la generación de reportes."""
import tarfile
from pathlib import Path

from conftest import post


def test_vulnerable_ejecuta_comando_inyectado(cat, tmp_path):
    marca = tmp_path / "PWNED"
    r = cat.get("/lab/vuln/reporte", query_string={"nombre": f"x; touch {marca}; echo"})
    assert marca.exists(), "el ; permitió ejecutar un segundo comando"
    print("\n[cmd vulnerable]", r.json["cmd"])


def test_corregido_rechaza_y_no_ejecuta(cat, tmp_path):
    marca = tmp_path / "PWNED2"
    for p in [f"1290-23-10001; touch {marca}", f"$(touch {marca})", f"`touch {marca}`",
              "1290-23-10001 | id", "--checkpoint-action=exec=id", "../../etc/passwd"]:
        r = post(cat, "/reportes", {"carnet": p, "tipo": "notas"})
        assert r.status_code == 400, p
    r = post(cat, "/reportes", {"carnet": "1290-23-10001", "tipo": f"notas;touch {marca}"})
    assert r.status_code == 400
    assert not marca.exists()


def test_corregido_genera_reporte(cat, env):
    r = post(cat, "/reportes", {"carnet": "1290-23-10001", "tipo": "notas"})
    assert r.status_code == 200
    out = Path(env["REPORT_DIR"]) / "notas_1290-23-10001.tar.gz"
    with tarfile.open(out) as t:
        assert t.getnames() == ["notas_1290-23-10001.csv"]


def test_build_report_usa_lista_sin_shell(monkeypatch, tmp_path):
    import subprocess
    from app import reports
    seen = {}
    real = subprocess.run

    def spy(args, **kw):
        seen.update(args=args, **kw)
        return real(args, **kw)
    monkeypatch.setattr(reports.subprocess, "run", spy)
    reports.build_report([{"curso": "=HYPERLINK(\"http://x\")", "nota": 90}], "1290-23-10001", "notas", tmp_path)
    assert isinstance(seen["args"], list) and seen["shell"] is False and seen["timeout"] == 10
    assert "--" in seen["args"] and seen["env"] == {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
