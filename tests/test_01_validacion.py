"""Fase I-A: validación de entradas por lista blanca."""
import pytest

from app import validators as V


@pytest.mark.parametrize("ok", ["ana.perez@ejemplo.edu.gt", "  ANA@Ejemplo.EDU.gt "])
def test_email_valido(ok):
    assert V.email(ok) == ok.strip().lower()


@pytest.mark.parametrize("bad", ["sin-arroba", "a@b", "a@b.c", "x@y.com\r\nBcc: z@z.com", "<script>@x.com", "a" * 300])
def test_email_invalido(bad):
    with pytest.raises(V.ValidationError):
        V.email(bad)


def test_carnet():
    assert V.carnet("1290-23-10001") == "1290-23-10001"
    for bad in ["1290-23-10001' OR '1'='1", "../../etc/passwd", "1290231", "1290-23-10001;id"]:
        with pytest.raises(V.ValidationError):
            V.carnet(bad)


def test_nombres_unicode_y_apostrofo():
    assert V.nombre("María José") == "María José"
    assert V.nombre("O'Brien") == "O'Brien"         # válido... y aun así rompe SQL concatenado
    for bad in ["Ana<script>", "Juan123", "a" * 61, "Ana\x00"]:
        with pytest.raises(V.ValidationError):
            V.nombre(bad)


@pytest.mark.parametrize("v,exp", [("0", 0), ("100", 100), ("87.456", 87.46)])
def test_nota_valida(v, exp):
    assert V.calificacion(v) == exp


@pytest.mark.parametrize("bad", ["-1", "101", "NaN", "inf", "abc", "1e9"])
def test_nota_invalida(bad):
    with pytest.raises(V.ValidationError):
        V.calificacion(bad)


def test_validar_no_es_suficiente():
    """Un dato VÁLIDO puede seguir siendo peligroso en otro contexto."""
    apellido = V.nombre("O'Brien")
    sql = f"SELECT * FROM estudiantes WHERE apellidos = '{apellido}'"
    assert sql.count("'") % 2 == 1          # comillas desbalanceadas -> SQL roto/inyectable
    comentario = V.comentario("Mi nota es <100 & >90")
    assert "<" in comentario                 # válido como texto, peligroso como HTML sin codificar
