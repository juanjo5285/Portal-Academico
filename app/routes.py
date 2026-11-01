"""Rutas SEGURAS del portal."""
import hmac
import secrets
from functools import wraps
from pathlib import Path

from flask import (Blueprint, abort, current_app, flash, g, redirect,
                   render_template, request, send_file, session, url_for)

from . import validators as V
from .db import get_db
from .logging_setup import audit, mask_email
from .security.crypto import mask
from .security.passwords import hash_password, needs_rehash, verify_password

bp = Blueprint("portal", __name__)


# ---------------------------------------------------------------- utilidades
def client_ip():
    return request.remote_addr or "-"


def login_required(*roles):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            uid = session.get("uid")
            if not uid:
                return redirect(url_for("portal.login"))
            g.user = get_db().execute("SELECT * FROM usuarios WHERE id = ?", (uid,)).fetchone()
            if g.user is None:
                session.clear()
                return redirect(url_for("portal.login"))
            if roles and g.user["rol"] not in roles:
                audit("acceso_denegado", "Rol insuficiente", 30, user_id=uid,
                      ruta=request.path, ip=client_ip())
                abort(403)
            return fn(*a, **kw)
        return wrapper
    return deco


@bp.before_app_request
def csrf_protect():
    session.setdefault("csrf", secrets.token_urlsafe(32))
    if request.method == "POST" and request.blueprint != "vuln":
        sent = request.form.get("csrf", "")
        if not hmac.compare_digest(sent, session["csrf"]):
            abort(400)


def _ok_or_400(fn, *args):
    try:
        return fn(*args)
    except V.ValidationError as e:
        flash(f"Dato inválido en {e.field}: {e.msg}")
        return None


# ------------------------------------------------------------- autenticación
@bp.route("/registro", methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        try:
            email = V.email(request.form.get("email"))
            carnet = V.carnet(request.form.get("carnet"))
            pwd = V.password_nueva(request.form.get("password"))
        except V.ValidationError as e:
            flash(f"Dato inválido en {e.field}: {e.msg}")
            return render_template("registro.html"), 400
        db = get_db()
        try:
            db.execute("INSERT INTO usuarios (email, password_hash, rol, carnet) VALUES (?,?,?,?)",
                       (email, hash_password(pwd), "estudiante", carnet))
            db.commit()
        except Exception:
            # Mensaje genérico: no revela si el correo ya existe.
            pass
        audit("registro", "Solicitud de registro", user=mask_email(email), ip=client_ip())
        flash("Si los datos son válidos, la cuenta quedó creada.")
        return redirect(url_for("portal.login"))
    return render_template("registro.html")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        raw_email = request.form.get("email", "")
        pwd = request.form.get("password", "")
        try:
            email = V.email(raw_email)
        except V.ValidationError:
            email = None
        row = get_db().execute("SELECT * FROM usuarios WHERE email = ?", (email,)).fetchone() if email else None
        ok = verify_password(pwd, row["password_hash"] if row else None)
        if not ok:
            audit("login_fallido", "Inicio de sesión fallido", 30,
                  user=mask_email(raw_email), ip=client_ip(),
                  motivo="credenciales_invalidas")   # mismo motivo exista o no el usuario
            flash("Correo o contraseña incorrectos.")
            return render_template("login.html"), 401
        if needs_rehash(row["password_hash"]):
            get_db().execute("UPDATE usuarios SET password_hash=? WHERE id=?", (hash_password(pwd), row["id"]))
            get_db().commit()
        session.clear()                       # evita fijación de sesión
        session["uid"] = row["id"]
        session["csrf"] = secrets.token_urlsafe(32)
        audit("login_ok", "Inicio de sesión exitoso", user_id=row["id"], rol=row["rol"], ip=client_ip())
        return redirect(url_for("portal.inicio"))
    return render_template("login.html")


@bp.route("/logout", methods=["POST"])
def logout():
    audit("logout", "Cierre de sesión", user_id=session.get("uid"), ip=client_ip())
    session.clear()
    return redirect(url_for("portal.login"))


@bp.route("/")
@login_required()
def inicio():
    return render_template("inicio.html")


# ------------------------------------------------------- búsqueda (anti-SQLi)
@bp.route("/buscar")
@login_required("catedratico", "admin")
def buscar():
    q = request.args.get("q", "")
    resultados = []
    if q:
        q = _ok_or_400(V.busqueda, q)
        if q is None:
            return render_template("buscar.html", resultados=[], q=""), 400
        # Escapa comodines de LIKE para que "%" o "_" se busquen literalmente.
        like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        resultados = get_db().execute(
            "SELECT carnet, nombres, apellidos FROM estudiantes "
            "WHERE nombres LIKE ? ESCAPE '\\' OR apellidos LIKE ? ESCAPE '\\' "
            "ORDER BY apellidos LIMIT 50",
            (like, like)).fetchall()
        audit("busqueda", "Búsqueda de estudiantes", user_id=g.user["id"],
              resultados=len(resultados), ip=client_ip())
    return render_template("buscar.html", resultados=resultados, q=q)


# ---------------------------------------------------------- expedientes
@bp.route("/expedientes/<carnet>")
@login_required()
def expediente(carnet):
    carnet = _ok_or_400(V.carnet, carnet) or abort(400)
    # Control de acceso a nivel de objeto (evita IDOR): un estudiante solo ve el suyo.
    if g.user["rol"] == "estudiante" and g.user["carnet"] != carnet:
        audit("acceso_denegado", "Intento de ver expediente ajeno", 30,
              user_id=g.user["id"], carnet_solicitado=carnet, ip=client_ip())
        abort(403)
    db = get_db()
    est = db.execute("SELECT * FROM estudiantes WHERE carnet = ?", (carnet,)).fetchone() or abort(404)
    notas = db.execute("SELECT curso, nota FROM calificaciones WHERE carnet = ?", (carnet,)).fetchall()
    cipher = current_app.extensions["cipher"]
    dpi = cipher.decrypt(est["dpi_cifrado"], f"estudiantes.dpi:{carnet}")
    audit("consulta_expediente", "Consulta de expediente", user_id=g.user["id"],
          rol=g.user["rol"], carnet=carnet, ip=client_ip())
    return render_template("expediente.html", est=est, notas=notas, dpi_mask=mask(dpi.replace(" ", "")))


@bp.route("/expedientes/<carnet>/nota", methods=["POST"])
@login_required("catedratico", "admin")
def modificar_nota(carnet):
    try:
        carnet = V.carnet(carnet)
        nota = V.calificacion(request.form.get("nota"))
        curso = V._norm(request.form.get("curso"), "curso", 80)
    except V.ValidationError as e:
        flash(f"Dato inválido en {e.field}: {e.msg}")
        return redirect(url_for("portal.expediente", carnet=carnet)), 302
    db = get_db()
    anterior = db.execute("SELECT nota FROM calificaciones WHERE carnet=? AND curso=?", (carnet, curso)).fetchone()
    db.execute("UPDATE calificaciones SET nota=? WHERE carnet=? AND curso=?", (nota, carnet, curso))
    db.commit()
    audit("modificacion_nota", "Calificación modificada", user_id=g.user["id"], carnet=carnet,
          curso=curso, nota_anterior=anterior["nota"] if anterior else None, nota_nueva=nota, ip=client_ip())
    return redirect(url_for("portal.expediente", carnet=carnet))


# ---------------------------------------------------------- comentarios (anti-XSS)
@bp.route("/comentarios", methods=["GET", "POST"])
@login_required()
def comentarios():
    db = get_db()
    if request.method == "POST":
        texto = _ok_or_400(V.comentario, request.form.get("texto"))
        if texto is not None:
            # Se guarda el texto original; la defensa es codificar al MOSTRAR.
            db.execute("INSERT INTO comentarios (autor, texto) VALUES (?,?)", (g.user["email"], texto))
            db.commit()
        return redirect(url_for("portal.comentarios"))
    filas = db.execute("SELECT autor, texto, fecha FROM comentarios ORDER BY id DESC LIMIT 100").fetchall()
    return render_template("comentarios.html", comentarios=filas)


# ---------------------------------------------------------- reportes (anti-command-injection)
@bp.route("/reportes", methods=["POST"])
@login_required()
def reporte():
    from .reports import build_report
    try:
        carnet = V.carnet(request.form.get("carnet"))
        tipo = V.tipo_reporte(request.form.get("tipo", "notas"))
    except V.ValidationError as e:
        audit("entrada_rechazada", "Parámetro de reporte inválido", 30,
              user_id=g.user["id"], campo=e.field, ip=client_ip())
        abort(400)
    if g.user["rol"] == "estudiante" and g.user["carnet"] != carnet:
        abort(403)
    rows = get_db().execute("SELECT curso, nota FROM calificaciones WHERE carnet=?", (carnet,)).fetchall()
    out = build_report(rows, carnet, tipo, Path(current_app.config["REPORT_DIR"]))
    audit("reporte_generado", "Reporte generado", user_id=g.user["id"], carnet=carnet, tipo=tipo)
    return send_file(out, as_attachment=True)


# ---------------------------------------------------------- administración
@bp.route("/admin")
@login_required("admin")
def admin():
    audit("acceso_admin", "Acceso al panel administrativo", user_id=g.user["id"], ip=client_ip())
    usuarios = get_db().execute("SELECT id, email, rol FROM usuarios").fetchall()
    return render_template("admin.html", usuarios=usuarios)
