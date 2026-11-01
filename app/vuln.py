"""Rutas VULNERABLES de forma controlada (solo laboratorio).

Se registran únicamente si LAB_VULN=1. Existen para documentar el "antes"
de cada corrección y para que las pruebas automáticas comparen vulnerable vs.
corregido. NUNCA habilitar fuera del laboratorio.
"""
import hashlib
import logging
import os
import subprocess

from flask import Blueprint, current_app, render_template_string, request

from .db import get_db

bp = Blueprint("vuln", __name__, url_prefix="/lab/vuln")

# La credencial que antes estaba escrita aquí se retiró (ver app/config.py y
# scripts/gitleaks_demo.sh para la simulación de la fuga en Git).


@bp.route("/buscar")
def buscar():
    q = request.args.get("q", "")
    # [VULNERABLE] concatenación: la entrada pasa a formar parte del código SQL.
    sql = ("SELECT carnet, nombres, apellidos FROM estudiantes "
           f"WHERE nombres LIKE '%{q}%' OR apellidos LIKE '%{q}%'")
    try:
        rows = get_db().execute(sql).fetchall()
    except Exception as e:
        # [VULNERABLE] además filtra el error de la BD al usuario.
        return {"sql": sql, "error": str(e)}, 500
    return {"sql": sql, "resultados": [list(r) for r in rows]}


@bp.route("/comentarios", methods=["GET", "POST"])
def comentarios():
    db = get_db()
    if request.method == "POST":
        db.execute("INSERT INTO comentarios (autor, texto) VALUES ('anon', ?)", (request.form["texto"],))
        db.commit()
    filas = db.execute("SELECT texto FROM comentarios ORDER BY id DESC").fetchall()
    # [VULNERABLE] XSS almacenado: |safe desactiva la codificación de salida.
    # [VULNERABLE] XSS reflejado: el parámetro ?q se inserta sin codificar.
    return render_template_string(
        "<h1>Comentarios (vulnerable)</h1><p>Buscaste: " + request.args.get("q", "") + "</p>"
        "{% for c in filas %}<div class='c'>{{ c['texto']|safe }}</div>{% endfor %}"
        # [VULNERABLE] XSS basado en DOM: innerHTML con datos del fragmento (#) de la URL
        "<div id='saludo'></div><script>"
        "document.getElementById('saludo').innerHTML = decodeURIComponent(location.hash.slice(1));"
        "</script>", filas=filas)


@bp.route("/reporte")
def reporte():
    nombre = request.args.get("nombre", "reporte")
    out = current_app.config["REPORT_DIR"]
    os.makedirs(out, exist_ok=True)
    # [VULNERABLE] inyección de comandos: la cadena la interpreta el shell
    # (/bin/sh en Linux/Mac, cmd.exe en Windows), que procesa ; & | $() etc.
    cmd = f"echo curso,nota > {nombre}.csv && tar -czf {nombre}.tar.gz {nombre}.csv"
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=out)
    return {"cmd": cmd, "rc": r.returncode}


@bp.route("/registro", methods=["POST"])
def registro_inseguro():
    pwd = request.form["password"]
    # [VULNERABLE] SHA-256 sin sal + registro de la contraseña en claro
    logging.getLogger("inseguro").info(
        f"login user={request.form['email']} password={pwd} token={request.headers.get('Authorization')}")
    return {"hash_sha256": hashlib.sha256(pwd.encode()).hexdigest()}
