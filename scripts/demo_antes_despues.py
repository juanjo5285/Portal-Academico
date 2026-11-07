"""Evidencia en texto: cada ataque contra la versión vulnerable y contra la corregida.

No necesita el servidor encendido: crea un portal temporal con secretos aleatorios
en una carpeta temporal, ejecuta cada caso y lo imprime.

Uso:
    python scripts/demo_antes_despues.py
    python scripts/demo_antes_despues.py > docs/evidencias/demo_antes_despues.txt
"""
import base64
import hashlib
import json
import os
import re
import secrets
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
TMP = Path(tempfile.mkdtemp(prefix="demo_portal_"))

# Secretos de demostración, aleatorios y solo en memoria de este proceso.
os.environ.update({
    "FLASK_SECRET_KEY": secrets.token_urlsafe(32),
    "DATA_KEY_ACTIVE": "v1",
    "DATA_KEY_v1": base64.b64encode(os.urandom(32)).decode(),
    "ADMIN_INITIAL_PASSWORD": secrets.token_urlsafe(16),
    "DB_PATH": str(TMP / "portal.db"),
    "REPORT_DIR": str(TMP / "reportes"),
    "LOG_PATH": str(TMP / "seguridad.log"),
    "COOKIE_SECURE": "0",
    "SECRETS_DIR": str(TMP / "sin-secretos"),
})
for k in ("VAULT_ADDR", "VAULT_TOKEN"):
    os.environ.pop(k, None)

from app import create_app                       # noqa: E402
from app.db import get_db                        # noqa: E402
from app import validators as V                  # noqa: E402
from app.security.passwords import hash_password, verify_password  # noqa: E402

TRACE = []
app = create_app({"TESTING": True, "LAB_VULN": True, "SQL_TRACE": TRACE})
with app.app_context():
    get_db().execute("INSERT INTO usuarios (email,password_hash,rol,carnet) VALUES (?,?,?,?)",
                     ("est@ejemplo.edu.gt", hash_password("Clave-Ficticia-2026!"), "estudiante", "1290-23-10001"))
    get_db().commit()


def titulo(t):
    print("\n" + "=" * 78 + f"\n {t}\n" + "=" * 78)


def sesion(email, pwd):
    c = app.test_client()
    c.get("/login")
    with c.session_transaction() as s:
        tok = s["csrf"]
    r = c.post("/login", data={"email": email, "password": pwd, "csrf": tok})
    with c.session_transaction() as s:
        c.csrf = s.get("csrf", tok)
    return c, r


def esqueleto(sql):
    return re.sub(r"'(?:[^']|'')*'", "?", sql)


admin, _ = sesion("admin@ejemplo.edu.gt", os.environ["ADMIN_INITIAL_PASSWORD"])
print(f"Portal temporal (carpeta temporal)  ·  {time.strftime('%Y-%m-%d %H:%M')}")

# ---------------------------------------------------------------- A
titulo("A. VALIDACIÓN DE ENTRADAS")
casos = [(V.email, "ana.perez@ejemplo.edu.gt"), (V.email, "x@y.com\r\nBcc: z@z.com"),
         (V.carnet, "1290-23-10001"), (V.carnet, "1290-23-10001;id"),
         (V.nombre, "O'Brien"), (V.nombre, "Ana<script>"),
         (V.calificacion, "87.456"), (V.calificacion, "NaN")]
for fn, valor in casos:
    try:
        print(f"  {fn.__name__:13} {valor!r:32} -> ACEPTADO como {fn(valor)!r}")
    except V.ValidationError as e:
        print(f"  {fn.__name__:13} {valor!r:32} -> RECHAZADO ({e.msg})")
print("\n  Validar no basta: O'Brien es válido y aun así rompe un SQL concatenado:")
print("   ", f"SELECT * FROM estudiantes WHERE apellidos = '{V.nombre(chr(79) + chr(39) + 'Brien')}'")

# ---------------------------------------------------------------- B
titulo("B. SQL INJECTION — ANTES (concatenación)")
for p in ["' OR '1'='1", "x' UNION SELECT clave, valor, 1 FROM config_interna --", "O'Brien"]:
    r = admin.get("/lab/vuln/buscar", query_string={"q": p}).get_json()
    print(f"\n  payload : {p!r}\n  SQL     : {r['sql']}")
    print(f"  filas   : {r.get('resultados', r.get('error'))}")
titulo("B. SQL INJECTION — DESPUÉS (consulta parametrizada)")
estructuras = set()
for p in ["' OR '1'='1", "x' UNION SELECT clave, valor, 1 FROM config_interna --", "O'Brien", "Ana"]:
    TRACE.clear()
    html = admin.get("/buscar", query_string={"q": p}).get_data(as_text=True)
    sql = [s for s in TRACE if "FROM estudiantes" in s and "LIKE" in s][0]
    estructuras.add(esqueleto(sql))
    print(f"\n  payload : {p!r}\n  resultado: {re.search(r'\d+ resultado\(s\)', html).group(0)}")
print(f"\n  Estructuras SQL distintas para las 4 entradas: {len(estructuras)}")
print(f"  -> {estructuras.pop()}")

# ---------------------------------------------------------------- C
titulo("C. XSS — ANTES (|safe) vs. DESPUÉS (autoescape + CSP)")
payload = "<script>alert('XSS')</script>"
admin.post("/lab/vuln/comentarios", data={"texto": payload})
v = admin.get("/lab/vuln/comentarios")
print("  ANTES  :", re.search(r"<div class='c'>(.*?)</div>", v.get_data(as_text=True)).group(1))
admin.post("/comentarios", data={"texto": payload, "csrf": admin.csrf})
s = admin.get("/comentarios")
print("  DESPUÉS:", re.search(r"<p>(&lt;script.*?)</p>", s.get_data(as_text=True)).group(1))
print("  CSP    :", s.headers["Content-Security-Policy"])

# ---------------------------------------------------------------- D
titulo("D. INYECCIÓN DE COMANDOS — ANTES (shell=True) vs. DESPUÉS (lista, shell=False)")
marca = TMP / "PWNED"
carga = (f'x & type nul > "{marca}" & echo' if os.name == "nt" else f'x; touch "{marca}"; echo')
r = admin.get("/lab/vuln/reporte", query_string={"nombre": carga}).get_json()
print(f"  ANTES  : cmd = {r['cmd']}\n           ¿se creó el archivo marcador? {marca.exists()}")
marca.unlink(missing_ok=True)
for p in [f"1290-23-10001; touch {marca}", "$(id)", "../../etc/passwd", "--checkpoint-action=exec=id"]:
    code = admin.post("/reportes", data={"carnet": p, "tipo": "notas", "csrf": admin.csrf}).status_code
    print(f"  DESPUÉS: carnet {p!r:42} -> HTTP {code}")
print(f"           ¿se creó el archivo marcador? {marca.exists()}")
r = admin.post("/reportes", data={"carnet": "1290-23-10001", "tipo": "notas", "csrf": admin.csrf})
print(f"  Reporte legítimo -> HTTP {r.status_code} · {r.headers.get('Content-Disposition')}")

# ---------------------------------------------------------------- E
titulo("E. CONTRASEÑAS — SHA-256 sin sal vs. Argon2id")
pwd = "Clave-Ficticia-2026!"
print("  SHA-256 #1 :", hashlib.sha256(pwd.encode()).hexdigest())
print("  SHA-256 #2 :", hashlib.sha256(pwd.encode()).hexdigest(), "(idéntico: sin sal)")
a1, a2 = hash_password(pwd), hash_password(pwd)
print("  Argon2id #1:", a1)
print("  Argon2id #2:", a2, "(distinto: sal aleatoria)")
print("  Verificación correcta / incorrecta:", verify_password(pwd, a1), "/", verify_password("otra", a1))
t = time.perf_counter(); n = 0
while time.perf_counter() - t < 1:
    hashlib.sha256(pwd.encode()).digest(); n += 1
t = time.perf_counter(); hash_password(pwd); argon = time.perf_counter() - t
print(f"  Benchmark: SHA-256 {n:,} intentos/s · Argon2id {1/argon:.1f} intentos/s "
      f"-> atacar SHA-256 es ~{n*argon:,.0f} veces más rápido")
c = app.test_client()
for i in range(6):
    _, r = sesion("est@ejemplo.edu.gt", "Clave-Equivocada!" if i < 5 else pwd)
print(f"  Bloqueo: tras 5 fallos, el 6.º intento CON la clave correcta -> HTTP {r.status_code} (rechazado)")

# ---------------------------------------------------------------- F
titulo("F. CIFRADO EN REPOSO (AES-256-GCM)")
with app.app_context():
    fila = get_db().execute("SELECT carnet, dpi_cifrado FROM estudiantes LIMIT 1").fetchone()
print(f"  Valor en la BD  : {fila['dpi_cifrado']}")
print(f"  ¿DPI en claro en el archivo de la BD? {b'1234 56789 0101' in Path(os.environ['DB_PATH']).read_bytes()}")
cipher = app.extensions["cipher"]
pre, kid, b64 = fila["dpi_cifrado"].split(":")
blob = bytearray(base64.b64decode(b64)); blob[-1] ^= 1
try:
    cipher.decrypt(f"{pre}:{kid}:{base64.b64encode(bytes(blob)).decode()}", f"estudiantes.dpi:{fila['carnet']}")
except Exception as e:
    print(f"  Un byte alterado -> {type(e).__name__} (integridad GCM)")
try:
    cipher.decrypt(fila["dpi_cifrado"], "estudiantes.dpi:1290-23-99999")
except Exception as e:
    print(f"  Copiado a otro registro -> {type(e).__name__} (AAD)")

# ---------------------------------------------------------------- G
titulo("G. SECRETOS — la aplicación exige una fuente externa")
guardado = os.environ.pop("FLASK_SECRET_KEY")
try:
    create_app()
except Exception as e:
    print(f"  Sin FLASK_SECRET_KEY -> {type(e).__name__}: {e}")
os.environ["FLASK_SECRET_KEY"] = guardado
print(f"  Con FLASK_SECRET_KEY en el entorno -> la aplicación arranca (clave de {len(guardado)} caracteres, no se imprime)")

# ---------------------------------------------------------------- H
titulo("H. REGISTRO — inseguro vs. seguro (mismo intento fallido)")
app.test_client().post("/lab/vuln/registro", data={"email": "ana@ejemplo.edu.gt", "password": "ClaveFicticia#2026"},
                       headers={"Authorization": "Bearer tok_ficticio_abc123"})
for h in __import__("logging").getLogger("inseguro").handlers:
    h.flush()
print("  INSEGURO:", (TMP / "inseguro.log").read_text(encoding="utf-8").strip().splitlines()[-1])
eventos = [json.loads(l) for l in Path(os.environ["LOG_PATH"]).read_text(encoding="utf-8").splitlines() if l.strip()]
for tipo in ("login_fallido", "cuenta_bloqueada", "consulta_expediente", "http_request"):
    ev = [e for e in eventos if e["event"] == tipo]
    if ev:
        print(f"  SEGURO  : {json.dumps(ev[-1], ensure_ascii=False)}")

# ---------------------------------------------------------------- I
titulo("I. ERROR INTERNO — respuesta al usuario vs. log interno")
r = admin.get("/lab/forzar-error")
cuerpo = re.sub(r"\s+", " ", re.search(r"<h1>.*?</code>", r.get_data(as_text=True), re.S).group(0))
print(f"  Usuario (HTTP {r.status_code}): {re.sub(r'<[^>]+>', '', cuerpo)}")
ev = [e for e in eventos + [json.loads(l) for l in Path(os.environ['LOG_PATH']).read_text(encoding='utf-8').splitlines()[-3:]]
      if e["event"] == "error_interno"][-1]
print(f"  Log     : incidente {ev['incidente']} · {ev['exc'].split(chr(92) + 'n')[-1]}")
print("\nFin de la demostración.")
