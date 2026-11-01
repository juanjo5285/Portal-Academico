"""Fase I-B y prueba obligatoria 1: caracteres especiales no alteran la estructura SQL."""
import re

def esqueleto(sql):
    """Sustituye cada literal de cadena por ? para comparar SOLO la estructura."""
    return re.sub(r"'(?:[^']|'')*'", "?", sql)

PAYLOADS = ["' OR '1'='1", "%' OR 1=1 --", "x' UNION SELECT clave, valor, 1 FROM config_interna --", "O'Brien"]


def test_vulnerable_altera_sql(cat):
    r = cat.get("/lab/vuln/buscar", query_string={"q": "' OR '1'='1"})
    assert len(r.json["resultados"]) == 4                 # devuelve TODOS los estudiantes
    r = cat.get("/lab/vuln/buscar", query_string={"q": PAYLOADS[2]})
    assert ["nota_interna", "DATO-QUE-NO-DEBE-FILTRARSE", 1] in r.json["resultados"]   # exfiltración
    r = cat.get("/lab/vuln/buscar", query_string={"q": "O'Brien"})
    assert r.status_code == 500 and "syntax error" in r.json["error"]                # error de BD expuesto
    normal = esqueleto(cat.get("/lab/vuln/buscar", query_string={"q": "Ana"}).json["sql"])
    atacada = esqueleto(cat.get("/lab/vuln/buscar", query_string={"q": PAYLOADS[2]}).json["sql"])
    print(f"\n[vulnerable normal ] {normal}\n[vulnerable atacada] {atacada}")
    assert normal != atacada and "UNION SELECT" in atacada                          # la entrada CAMBIÓ la estructura


def test_corregido_no_altera_sql(app, cat):
    trace = app.config["SQL_TRACE"]
    estructuras = set()
    for p in PAYLOADS + ["Ana"]:
        trace.clear()
        r = cat.get("/buscar", query_string={"q": p})
        assert r.status_code == 200
        assert b"DATO-QUE-NO-DEBE-FILTRARSE" not in r.data
        selects = [s for s in trace if "FROM estudiantes" in s and "LIKE" in s]
        # La ENTRADA viaja como dato enlazado: el texto SQL preparado nunca cambia.
        assert len(selects) == 1
        estructuras.add(esqueleto(selects[0]))
        # El trace de SQLite muestra el valor enlazado como UN literal (comillas duplicadas).
        print(f"\n[payload] {p!r}\n[sql con valor enlazado] {selects[0]}")
    assert len(estructuras) == 1, "la estructura SQL cambió según la entrada"
    print(f"\n[estructura única para todas las entradas] {estructuras.pop()}")
    r = cat.get("/buscar", query_string={"q": "' OR '1'='1"})
    assert b"0 resultado(s)" in r.data
    r = cat.get("/buscar", query_string={"q": "O'Brien"})
    assert b"1 resultado(s)" in r.data and b"Carlos" in r.data     # la búsqueda legítima funciona


def test_comodines_like_literales(cat):
    assert b"0 resultado(s)" in cat.get("/buscar", query_string={"q": "%%"}).data
