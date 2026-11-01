"""Fase II-E y pruebas obligatorias 8 y 9: registro seguro y errores sin datos sensibles."""
import json
import logging

from conftest import login, post, read_log

PWD_MALA = "MiClaveSecreta-Equivocada-77"


def eventos(env):
    return [json.loads(l) for l in read_log(env).splitlines() if l.strip()]


def test_login_fallido_registra_sin_contrasena(app, env):
    login(app.test_client(), "est@ejemplo.edu.gt", PWD_MALA)
    log = read_log(env)
    ev = [e for e in eventos(env) if e["event"] == "login_fallido"][-1]
    print("\n[evento]", json.dumps(ev, ensure_ascii=False))
    assert PWD_MALA not in log and "est@ejemplo.edu.gt" not in log
    assert ev["user"] == "e***@ejemplo.edu.gt" and ev["ip"] and ev["level"] == "WARNING"


def test_eventos_de_auditoria(app, env, cat):
    c = app.test_client(); login(c, "admin@ejemplo.edu.gt", env["ADMIN_INITIAL_PASSWORD"])
    c.get("/admin")
    cat.get("/expedientes/1290-23-10001")
    post(cat, "/expedientes/1290-23-10001/nota", {"curso": "Criptografía", "nota": "95"})
    tipos = {e["event"] for e in eventos(env)}
    assert {"login_ok", "acceso_admin", "consulta_expediente", "modificacion_nota"} <= tipos
    assert env["ADMIN_INITIAL_PASSWORD"] not in read_log(env)


def test_filtro_redacta_aunque_el_desarrollador_se_equivoque(app, env):
    from app.logging_setup import audit
    audit("prueba", "conexion password=SuperSecreta1 user=x\nFALSO login_ok admin",
          token="eyJhbGciOi.eyJzdWIiOi.firma", authorization="Bearer abc.def",
          dsn="postgres://u:p@db/x", dpi="1234 56789 0101", nota="AKIAABCDEFGHIJKLMNOP")
    ev = eventos(env)[-1]
    s = json.dumps(ev)
    for secreto in ["SuperSecreta1", "eyJhbGciOi", "abc.def", "u:p@db", "1234 56789", "AKIAABCDEFGHIJKLMNOP"]:
        assert secreto not in s, secreto
    assert "\n" not in ev["msg"]                         # sin inyección de líneas en el log
    print("\n[evento redactado]", s)


def test_registro_inseguro_vs_seguro(app, env, tmp_path):
    """Ejemplo comparativo: el endpoint vulnerable deja la contraseña en claro."""
    c = app.test_client()
    c.post("/lab/vuln/registro", data={"email": "est@ejemplo.edu.gt", "password": PWD_MALA},
           headers={"Authorization": "Bearer token-ficticio-123"})
    for h in logging.getLogger("inseguro").handlers: h.flush()
    inseguro = (tmp_path / "inseguro.log").read_text()
    print("\n[log INSEGURO]", inseguro.strip())
    assert PWD_MALA in inseguro and "token-ficticio-123" in inseguro
    assert PWD_MALA not in read_log(env)


def test_error_interno_no_expone_detalles(app, env):
    r = app.test_client().get("/lab/forzar-error")
    body = r.data.decode()
    assert r.status_code == 500
    for fuga in [env["FLASK_SECRET_KEY"], "postgres://", "Bearer", "Traceback", "RuntimeError", "eyJ"]:
        assert fuga not in body, fuga
    inc = body.split("<code>")[1].split("</code>")[0]
    ev = [e for e in eventos(env) if e["event"] == "error_interno"][-1]
    assert ev["incidente"] == inc and "Traceback" in ev["exc"]        # el detalle queda SOLO en el log
    assert env["FLASK_SECRET_KEY"] not in read_log(env)               # ...y también redactado
    print(f"\n[usuario ve] código de incidente {inc}\n[log interno] {json.dumps(ev)[:400]}")
