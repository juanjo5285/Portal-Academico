"""Demostración en vivo contra el portal corriendo en https://localhost:8443.

Uso (con el servidor arrancado y LAB_VULN=1):
    python scripts/evidencias_en_vivo.py > docs/evidencias/en_vivo.txt
"""
import json
import os
import re
import sqlite3
import sys
from pathlib import Path

import requests

sys.path.insert(0, ".")
from dotenv_lite import load_env  # noqa: E402

load_env(".env")
BASE = os.environ.get("PORTAL_URL", "https://localhost:8443")
CA = "certs/ca.crt"
os.environ.setdefault("NO_PROXY", "localhost,127.0.0.1")


def sesion(email, pwd):
    s = requests.Session()
    s.verify = CA
    s.trust_env = False   # usa SOLO la CA del laboratorio
    html = s.get(f"{BASE}/login").text
    tok = re.search(r'name="csrf" value="([^"]+)"', html).group(1)
    r = s.post(f"{BASE}/login", data={"email": email, "password": pwd, "csrf": tok}, allow_redirects=False)
    s.csrf = re.search(r'name="csrf" value="([^"]+)"', s.get(f"{BASE}/").text or "")
    s.csrf = s.csrf.group(1) if s.csrf else tok
    return s, r


def titulo(t):
    print("\n" + "=" * 78 + f"\n{t}\n" + "=" * 78)


admin, _ = sesion("admin@ejemplo.edu.gt", os.environ["ADMIN_INITIAL_PASSWORD"])

titulo("PRUEBA 1 · SQL Injection en la búsqueda")
for p in ["' OR '1'='1", "x' UNION SELECT clave, valor, 1 FROM config_interna --"]:
    v = admin.get(f"{BASE}/lab/vuln/buscar", params={"q": p}).json()
    print(f"\n[VULNERABLE] q={p!r}\n  SQL armado: {v['sql']}\n  filas devueltas: {v.get('resultados')}")
    html = admin.get(f"{BASE}/buscar", params={"q": p}).text
    print(f"[CORREGIDO ] q={p!r} -> {re.search(r'(\d+) resultado', html).group(0)}; "
          f"¿filtró config_interna? {'DATO-QUE-NO' in html}")
html = admin.get(f"{BASE}/buscar", params={"q": "O'Brien"}).text
print(f"[CORREGIDO ] búsqueda legítima q=\"O'Brien\" -> {re.search(r'(\d+) resultado', html).group(0)}")

titulo("PRUEBA 2 · Comentario con contenido HTML/JS")
payload = "<script>alert('XSS')</script><img src=x onerror=alert(1)>"
admin.post(f"{BASE}/comentarios", data={"texto": payload, "csrf": admin.csrf})
html = admin.get(f"{BASE}/comentarios").text
frag = re.search(r"<p>(&lt;script.*?)</p>", html).group(1)
print("[CORREGIDO ] HTML entregado al navegador:", frag)
print("             CSP:", admin.get(f"{BASE}/comentarios").headers["Content-Security-Policy"])
requests.post(f"{BASE}/lab/vuln/comentarios", data={"texto": payload}, verify=CA)
v = requests.get(f"{BASE}/lab/vuln/comentarios", verify=CA).text
print("[VULNERABLE] HTML entregado al navegador:", re.search(r"<div class='c'>(.*?)</div>", v).group(1))

titulo("PRUEBA 3 · Contraseña almacenada con KDF y sal")
db = sqlite3.connect("lab/portal.db")
for email, h in db.execute("SELECT email, password_hash FROM usuarios"):
    print(f"  {email:28} {h[:60]}…")

titulo("PRUEBA 4 · Contraseña incorrecta")
_, r = sesion("admin@ejemplo.edu.gt", "Contraseña-Incorrecta-123")
print(f"  HTTP {r.status_code} · mensaje: {re.search(r'class=.flash.>(.*?)<', r.text).group(1)}")

titulo("PRUEBA 6 · Secreto obtenido desde fuente externa")
print("  grep de secretos en app/:",
      [l for l in Path("app/__init__.py").read_text().splitlines() if "get_secret(" in l][:3])
print("  Origen: variables de entorno cargadas desde .env (permisos",
      oct(os.stat('.env').st_mode & 0o777), ") — el archivo está en .gitignore")

titulo("PRUEBA 7 · HTTPS")
r = admin.get(f"{BASE}/login")
print(f"  {r.url} -> {r.status_code}; HSTS: {r.headers.get('Strict-Transport-Security')}")

titulo("PRUEBA 8 · Inicio de sesión fallido en el log (sin contraseña)")
lineas = Path("lab/seguridad.log").read_text(encoding="utf-8").splitlines()
fallido = [l for l in lineas if '"login_fallido"' in l][-1]
print("  " + fallido)
print("  ¿Aparece la contraseña probada? ", "Contraseña-Incorrecta-123" in "\n".join(lineas))

titulo("PRUEBA 9 · Error interno")
r = admin.get(f"{BASE}/lab/forzar-error")
print(f"  HTTP {r.status_code} · lo que ve el usuario:", re.sub(r"\s+", " ", re.search(r"<main>(.*)</main>", r.text, re.S).group(1)).strip())
for fuga in ["postgres://", "Bearer", "Traceback", os.environ["FLASK_SECRET_KEY"]]:
    print(f"    ¿respuesta contiene {fuga[:12]!r}…? {fuga in r.text}")
err = [l for l in Path("lab/seguridad.log").read_text(encoding="utf-8").splitlines() if '"error_interno"' in l][-1]
print("  Log interno (redactado):", err[:420], "…")

titulo("EXTRA · Inyección de comandos en reportes")
marca = Path("lab/PWNED")
marca.unlink(missing_ok=True)
v = requests.get(f"{BASE}/lab/vuln/reporte", params={"nombre": f"x; touch {marca}; echo"}, verify=CA).json()
print(f"[VULNERABLE] cmd: {v['cmd']}\n             ¿se creó {marca}? {marca.exists()}")
marca.unlink(missing_ok=True)
r = admin.post(f"{BASE}/reportes", data={"carnet": f"1290-23-10001; touch {marca}", "tipo": "notas", "csrf": admin.csrf})
print(f"[CORREGIDO ] HTTP {r.status_code}; ¿se creó {marca}? {marca.exists()}")
r = admin.post(f"{BASE}/reportes", data={"carnet": "1290-23-10001", "tipo": "notas", "csrf": admin.csrf})
print(f"[CORREGIDO ] reporte legítimo: HTTP {r.status_code}, {r.headers.get('Content-Disposition')}")

titulo("EXTRA · DPI cifrado en la base de datos")
for c, d in db.execute("SELECT carnet, dpi_cifrado FROM estudiantes LIMIT 2"):
    print(f"  {c}  {d}")

titulo("EXTRA · Registro inseguro (endpoint vulnerable) vs. seguro")
requests.post(f"{BASE}/lab/vuln/registro", data={"email": "ana.perez@ejemplo.edu.gt", "password": "ClaveFicticia#2026"},
              headers={"Authorization": "Bearer tok_ficticio_abc123"}, verify=CA)
print("[INSEGURO]", Path("lab/inseguro.log").read_text(encoding="utf-8").strip().splitlines()[-1])
print("[SEGURO  ]", [l for l in Path("lab/seguridad.log").read_text(encoding="utf-8").splitlines()
                     if '"consulta_expediente"' in l or '"acceso_admin"' in l or '"login_ok"' in l][-1])
