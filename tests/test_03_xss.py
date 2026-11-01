"""Fase I-C y prueba obligatoria 2: comentario con HTML no se ejecuta."""
from conftest import post

PAYLOAD = '<script>alert(document.cookie)</script><img src=x onerror=alert(1)>'


def test_vulnerable_almacenado_y_reflejado(cat):
    cat.post("/lab/vuln/comentarios", data={"texto": PAYLOAD, "csrf": ""})
    r = cat.get("/lab/vuln/comentarios", query_string={"q": "<b onmouseover=alert(2)>x</b>"})
    assert b"<script>alert(document.cookie)</script>" in r.data           # almacenado
    assert b"<b onmouseover=alert(2)>" in r.data                          # reflejado
    assert b".innerHTML = decodeURIComponent(location.hash" in r.data     # sumidero DOM


def test_corregido_codifica_salida(cat):
    post(cat, "/comentarios", {"texto": PAYLOAD})
    r = cat.get("/comentarios")
    assert b"<script>alert" not in r.data and b"<img src=x" not in r.data
    assert b"&lt;script&gt;alert(document.cookie)&lt;/script&gt;" in r.data
    assert b"&lt;img src=x onerror=alert(1)&gt;" in r.data
    csp = r.headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp      # defensa en profundidad


def test_dom_seguro_usa_textcontent(cat):
    js = cat.get("/static/comentarios.js").data
    assert b"textContent" in js and b"innerHTML" not in js


def test_cookie_sesion_httponly(app):
    c = app.test_client()
    from conftest import login
    r = login(c, "cat@ejemplo.edu.gt")
    cookie = r.headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie
