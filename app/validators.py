"""Validación de entradas por lista blanca (allow-list).

Cada función: normaliza (Unicode NFC, recorte de espacios), comprueba tipo,
longitud y formato, y devuelve el valor canónico o lanza ValidationError.

IMPORTANTE: validar NO equivale a "volver seguro" un dato para cualquier
contexto. Un apellido válido como O'Brien contiene una comilla que rompe una
consulta SQL concatenada; un comentario válido puede contener "<". Por eso la
validación se combina SIEMPRE con el control propio de cada contexto:
consultas parametrizadas (SQL), codificación de salida (HTML) y listas de
argumentos sin shell (SO).
"""
import re
import unicodedata

from email.utils import parseaddr


class ValidationError(ValueError):
    def __init__(self, field, msg):
        super().__init__(f"{field}: {msg}")
        self.field = field
        self.msg = msg


def _norm(value, field, max_len):
    if not isinstance(value, str):
        raise ValidationError(field, "valor requerido")
    value = unicodedata.normalize("NFC", value).strip()
    if not value:
        raise ValidationError(field, "valor requerido")
    if len(value) > max_len:
        raise ValidationError(field, f"máximo {max_len} caracteres")
    if any(unicodedata.category(c) == "Cc" for c in value):
        raise ValidationError(field, "contiene caracteres de control")
    return value


EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}$")


def email(value):
    v = _norm(value, "correo", 254).lower()
    if parseaddr(v)[1] != v or not EMAIL_RE.fullmatch(v):
        raise ValidationError("correo", "formato inválido")
    return v


# Carnet universitario: formato ficticio NNNN-AA-NNNNN (p. ej. 1290-23-12345)
CARNET_RE = re.compile(r"^\d{4}-\d{2}-\d{3,6}$")


def carnet(value):
    v = _norm(value, "carnet", 16)
    if not CARNET_RE.fullmatch(v):
        raise ValidationError("carnet", "formato esperado NNNN-AA-NNNNN")
    return v


# Letras Unicode (incluye tildes y ñ), espacios, apóstrofo y guion.
NAME_RE = re.compile(r"^[^\W\d_]+(?:[ '\-][^\W\d_]+)*$")


def nombre(value, field="nombre"):
    v = re.sub(r"\s+", " ", _norm(value, field, 60))
    if not NAME_RE.fullmatch(v):
        raise ValidationError(field, "solo letras, espacios, apóstrofo o guion")
    return v


def calificacion(value):
    try:
        n = float(str(value).strip())
    except (TypeError, ValueError):
        raise ValidationError("nota", "debe ser numérica")
    if not (0 <= n <= 100) or n != n:
        raise ValidationError("nota", "rango permitido 0-100")
    return round(n, 2)


# Búsqueda: texto libre corto. Se permite casi todo (incluida la comilla, para
# buscar "O'Brien"); la seguridad frente a SQLi la da la parametrización.
def busqueda(value):
    v = re.sub(r"\s+", " ", _norm(value, "q", 100))
    if len(v) < 2:
        raise ValidationError("q", "mínimo 2 caracteres")
    return v


def comentario(value):
    return _norm(value, "comentario", 1000)


def password_nueva(value):
    if not isinstance(value, str) or not (12 <= len(value) <= 128):
        raise ValidationError("contraseña", "entre 12 y 128 caracteres")
    return value


REPORT_TYPES = {"notas", "asistencia"}


def tipo_reporte(value):
    v = _norm(value, "tipo", 20)
    if v not in REPORT_TYPES:
        raise ValidationError("tipo", "tipo de reporte no permitido")
    return v
