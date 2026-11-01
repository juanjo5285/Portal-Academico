import logging
import os
from datetime import timedelta
from pathlib import Path

from flask import Flask, render_template, request
from werkzeug.exceptions import HTTPException

from .config import get_secret, load_data_keys
from .db import close_db, init_db
from .logging_setup import new_incident_id, setup_logging
from .security.crypto import FieldCipher
from .security.passwords import hash_password

BASE = Path(__file__).resolve().parent.parent


def create_app(overrides: dict | None = None):
    app = Flask(__name__)
    app.config.update(
        # Secretos: SIEMPRE desde fuente externa (Vault / entorno / /run/secrets)
        SECRET_KEY=get_secret("FLASK_SECRET_KEY"),
        DB_PATH=os.environ.get("DB_PATH", str(BASE / "lab" / "portal.db")),
        REPORT_DIR=os.environ.get("REPORT_DIR", str(BASE / "lab" / "reportes")),
        LOG_PATH=os.environ.get("LOG_PATH", str(BASE / "lab" / "seguridad.log")),
        # Cookies de sesión endurecidas
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1") == "1",
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        MAX_CONTENT_LENGTH=64 * 1024,
        PROPAGATE_EXCEPTIONS=False,
        DEBUG=False,
    )
    app.config.update(overrides or {})
    Path(app.config["LOG_PATH"]).parent.mkdir(parents=True, exist_ok=True)
    setup_logging(app.config["LOG_PATH"])

    app.extensions["cipher"] = FieldCipher(load_data_keys())

    from .routes import bp
    app.register_blueprint(bp)
    if os.environ.get("LAB_VULN") == "1" or app.config.get("LAB_VULN"):
        from .vuln import bp as vuln_bp
        app.register_blueprint(vuln_bp)
        insecure = logging.getLogger("inseguro")
        insecure.handlers.clear()
        h = logging.FileHandler(Path(app.config["LOG_PATH"]).with_name("inseguro.log"), encoding="utf-8")
        h.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
        insecure.addHandler(h)
        insecure.setLevel(logging.INFO)
        insecure.propagate = False

    if app.config.get("TESTING") or os.environ.get("LAB_VULN") == "1":
        @app.route("/lab/forzar-error")
        def forzar_error():
            # Simula un fallo interno cuyo mensaje contiene datos sensibles.
            raise RuntimeError(f"Fallo de conexión postgres://portal:{app.config['SECRET_KEY']}@db:5432/portal "
                               f"token=Bearer eyJhbGciOi.eyJzdWIiOi.c2lnbmF0dXJh")

    app.teardown_appcontext(close_db)

    @app.after_request
    def security_headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; object-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Cache-Control"] = "no-store"
        if request.is_secure:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if request.blueprint == "vuln":
            resp.headers.pop("Content-Security-Policy")  # para que la demo sea visible
        return resp

    @app.errorhandler(Exception)
    def handle_error(e):
        if isinstance(e, HTTPException):
            return render_template("error.html", code=e.code, incidente=None), e.code
        incidente = new_incident_id()
        # Detalle completo SOLO al log interno (y pasa por el filtro de redacción).
        logging.getLogger("portal").error("Error interno", exc_info=e,
                                          extra={"event": "error_interno",
                                                 "ctx": {"incidente": incidente, "ruta": request.path}})
        # Al usuario: mensaje genérico + id para soporte.
        return render_template("error.html", code=500, incidente=incidente), 500

    with app.app_context():
        init_db(app.extensions["cipher"], hash_password, get_secret("ADMIN_INITIAL_PASSWORD"))
    return app
