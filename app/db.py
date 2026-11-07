import sqlite3

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,          -- cadena PHC Argon2id (incluye la sal)
    rol TEXT NOT NULL CHECK (rol IN ('estudiante','catedratico','admin')),
    carnet TEXT,
    intentos_fallidos INTEGER NOT NULL DEFAULT 0,   -- control de fuerza bruta
    bloqueado_hasta REAL                            -- epoch; NULL = no bloqueado
);
CREATE TABLE IF NOT EXISTS estudiantes (
    carnet TEXT PRIMARY KEY,
    nombres TEXT NOT NULL,
    apellidos TEXT NOT NULL,
    email TEXT NOT NULL,
    dpi_cifrado TEXT NOT NULL,            -- AES-256-GCM
    telefono_cifrado TEXT NOT NULL        -- AES-256-GCM
);
CREATE TABLE IF NOT EXISTS calificaciones (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    carnet TEXT NOT NULL REFERENCES estudiantes(carnet),
    curso TEXT NOT NULL,
    nota REAL NOT NULL CHECK (nota BETWEEN 0 AND 100)
);
CREATE TABLE IF NOT EXISTS comentarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    autor TEXT NOT NULL,
    texto TEXT NOT NULL,                  -- se guarda tal cual; se codifica al mostrar
    fecha TEXT DEFAULT CURRENT_TIMESTAMP
);
-- Tabla de demostración para la prueba de SQLi (dato que no debería salir)
CREATE TABLE IF NOT EXISTS config_interna (clave TEXT, valor TEXT);
"""

# Datos 100 % ficticios.
ESTUDIANTES = [
    ("1290-23-10001", "Ana Lucía", "Pérez Gómez", "ana.perez@ejemplo.edu.gt", "1234 56789 0101", "5555-0101"),
    ("1290-23-10002", "Carlos", "O'Brien Ruiz", "carlos.obrien@ejemplo.edu.gt", "2345 67890 0101", "5555-0102"),
    ("1290-23-10003", "María José", "López", "maria.lopez@ejemplo.edu.gt", "3456 78901 0101", "5555-0103"),
    ("1290-22-20004", "José", "Hernández", "jose.hernandez@ejemplo.edu.gt", "4567 89012 0101", "5555-0104"),
]


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DB_PATH"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        trace = current_app.config.get("SQL_TRACE")
        if trace is not None:
            g.db.set_trace_callback(trace.append)  # para evidencias de las pruebas
    return g.db


def close_db(_=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(cipher, hash_password, admin_password):
    db = get_db()
    db.executescript(SCHEMA)
    # Migración para bases creadas con la versión anterior (sin columnas de bloqueo).
    cols = {r[1] for r in db.execute("PRAGMA table_info(usuarios)")}
    if "intentos_fallidos" not in cols:
        db.execute("ALTER TABLE usuarios ADD COLUMN intentos_fallidos INTEGER NOT NULL DEFAULT 0")
    if "bloqueado_hasta" not in cols:
        db.execute("ALTER TABLE usuarios ADD COLUMN bloqueado_hasta REAL")
    db.commit()
    if db.execute("SELECT COUNT(*) FROM estudiantes").fetchone()[0]:
        return
    for carnet, nom, ape, mail, dpi, tel in ESTUDIANTES:
        db.execute(
            "INSERT INTO estudiantes VALUES (?,?,?,?,?,?)",
            (carnet, nom, ape, mail,
             cipher.encrypt(dpi, f"estudiantes.dpi:{carnet}"),
             cipher.encrypt(tel, f"estudiantes.telefono:{carnet}")))
        for curso, nota in (("Seguridad en Aplicaciones", 88), ("Criptografía", 91.5)):
            db.execute("INSERT INTO calificaciones (carnet, curso, nota) VALUES (?,?,?)", (carnet, curso, nota))
    db.execute("INSERT INTO usuarios (email, password_hash, rol) VALUES (?,?,?)",
               ("admin@ejemplo.edu.gt", hash_password(admin_password), "admin"))
    db.execute("INSERT INTO config_interna VALUES ('nota_interna', 'DATO-QUE-NO-DEBE-FILTRARSE')")
    db.commit()
