"""Registro seguro (Secure Logging).

- Formato JSON estructurado (un evento por línea) -> fácil de enviar a un SIEM.
- Filtro de redacción: elimina contraseñas, tokens, claves, cookies,
  cabeceras Authorization, cadenas de conexión y DPI aunque un desarrollador
  los pase por error.
- Neutraliza CR/LF para impedir inyección de líneas falsas en el log.
- Correos se seudonimizan (j***@dominio) y el usuario se identifica por id.
"""
import json
import logging
import re
import sys
from datetime import datetime
import uuid

SENSITIVE_KEYS = re.compile(
    r"pass(word)?|contrase|pwd|secret|token|api[_-]?key|authorization|cookie|"
    r"session|private|data_key|dpi|connection|dsn|credential", re.I)

PATTERNS = [
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]+"), "Bearer [REDACTADO]"),
    (re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), "[JWT-REDACTADO]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[AWS-KEY-REDACTADA]"),
    (re.compile(r"(?i)(postgres(ql)?|mysql|mongodb(\+srv)?)://[^\s\"']+"), "[DSN-REDACTADO]"),
    (re.compile(r"(?i)(password|pwd|passwd|contraseña)\s*[=:]\s*\S+"), r"\1=[REDACTADO]"),
    (re.compile(r"\b\d{4}\s?\d{5}\s?\d{4}\b"), "[DPI-REDACTADO]"),  # CUI Guatemala (13 dígitos)
]


def mask_email(e: str) -> str:
    if not e or "@" not in e:
        return "[correo-inválido]"
    user, dom = e.rsplit("@", 1)
    return f"{user[:1]}***@{dom}"


def _scrub(value):
    if isinstance(value, dict):
        return {k: ("[REDACTADO]" if SENSITIVE_KEYS.search(k) else _scrub(v)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_scrub(v) for v in value]
    if isinstance(value, str):
        value = value.replace("\r", "\\r").replace("\n", "\\n")
        for rx, rep in PATTERNS:
            value = rx.sub(rep, value)
        return value[:4000]   # límite para evitar inundar el log
    return value


class JsonFormatter(logging.Formatter):
    def format(self, record):
        event = {
            "ts": datetime.fromtimestamp(record.created).astimezone().isoformat(timespec="seconds"),
            "level": record.levelname,
            "event": getattr(record, "event", "app"),
            "msg": record.getMessage(),
        }
        event.update(getattr(record, "ctx", {}) or {})
        if record.exc_info:
            # La traza va SOLO al log interno (nunca al usuario) y también se limpia.
            event["exc"] = self.formatException(record.exc_info)
        return json.dumps(_scrub(event), ensure_ascii=False)


def setup_logging(path=None, level=logging.INFO):
    logger = logging.getLogger("portal")
    logger.handlers.clear()
    logger.setLevel(level)
    logger.propagate = True  # permite que pytest capture con caplog
    handler = logging.FileHandler(path, encoding="utf-8") if path else logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    return logger


def audit(event, msg, level=logging.INFO, **ctx):
    """Punto único para eventos de seguridad: login_ok, login_fallido, ..."""
    logging.getLogger("portal").log(level, msg, extra={"event": event, "ctx": ctx})


def new_incident_id():
    return uuid.uuid4().hex[:12]
