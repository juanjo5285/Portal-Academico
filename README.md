# Portal Académico Seguro — Tarea Integradora Semanas 4 y 5 (MASI)

Aplicación de laboratorio en **Python 3.11+ / Flask / SQLite** que contiene, lado a lado,
la versión **vulnerable** (controlada, bajo `/lab/vuln/*`) y la versión **corregida** de cada
control pedido en la tarea, con pruebas automáticas que demuestran que la corrección funciona.

> Todos los datos, credenciales y claves son **ficticios** y se generan al azar en cada instalación.
> Las rutas vulnerables solo se registran con `LAB_VULN=1`. No exponer este laboratorio a Internet.

## Puesta en marcha (5 minutos)

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python scripts/gen_env.py          # crea .env con secretos aleatorios (permisos 600, ignorado por Git)
python scripts/gen_cert.py         # CA de laboratorio + certificado para localhost
python run.py                      # https://localhost:8443  (TLS 1.2+, preferente 1.3)
```

Usuario inicial: `admin@ejemplo.edu.gt`; su contraseña está en `.env` (`ADMIN_INITIAL_PASSWORD`).
Para que el navegador confíe en el certificado, importe `certs/ca.crt` o acepte la advertencia (solo laboratorio).

## Pruebas y evidencias

```bash
python -m pytest -v                              # 62 pruebas (incluye las 9 obligatorias)
python scripts/demo_antes_despues.py             # evidencia en texto: cada ataque antes y después
bash scripts/gitleaks_demo.sh                    # fuga simulada en Git + detección + limpieza
python scripts/evidencias_en_vivo.py             # demostración contra el servidor corriendo
node scripts/capturas.js                         # capturas con Playwright (opcional)
```

Las salidas ya generadas están en `docs/evidencias/`.

| # | Prueba obligatoria | Dónde se verifica |
|---|---|---|
| 1 | Caracteres especiales en búsqueda no alteran el SQL | `tests/test_02_sqli.py`, `en_vivo.txt`, `cap_03/04/05` |
| 2 | Comentario con HTML no se ejecuta | `tests/test_03_xss.py`, `cap_01/02`, `xss_alertas_navegador.txt` |
| 3 | Contraseña almacenada con KDF + sal | `tests/test_05_passwords.py::test_hash_argon2id_con_sal` |
| 4 | Contraseña incorrecta rechazada | `tests/test_05_passwords.py::test_login_incorrecto_rechazado`, `test_bloqueo_tras_5_intentos_fallidos` |
| 5 | Gitleaks detecta credencial ficticia | `tests/test_08_gitleaks.py`, `gitleaks_0*.txt` |
| 6 | Secreto obtenido de fuente externa | `tests/test_07_secretos.py` (entorno, archivo, Vault simulado) |
| 7 | HTTPS con TLS correcto | `tests/test_09_tls.py`, `tls_01_curl.txt`, `tls_02_openssl.txt` |
| 8 | Login fallido registrado sin contraseña | `tests/test_10_logging.py::test_login_fallido_registra_sin_contrasena` |
| 9 | Error interno sin datos sensibles | `tests/test_10_logging.py::test_error_interno_no_expone_detalles`, `cap_07` |

## Estructura

```
app/
  __init__.py        fábrica Flask, cabeceras de seguridad, manejador de errores
  config.py          secretos: Vault KV v2 → variable de entorno → /run/secrets (fail closed)
  validators.py      validación por lista blanca (correo, carnet, nombres, notas, búsqueda)
  routes.py          rutas CORREGIDAS (login, búsqueda, expedientes, comentarios, reportes, admin)
  vuln.py            rutas VULNERABLES de referencia (solo LAB_VULN=1)
  reports.py         reportes con subprocess en lista, sin shell, timeout, entorno mínimo
  logging_setup.py   logs JSON + filtro de redacción + anti inyección de líneas
  security/passwords.py   Argon2id (formato PHC, sal de 16 bytes)
  security/crypto.py      AES-256-GCM con AAD e id de clave (rotación)
scripts/             gen_env, gen_cert, gitleaks_demo, rotate_data_key, evidencias_en_vivo, capturas
vault/               docker-compose de Vault (modo dev) + carga de secretos y política de solo lectura
tests/               pytest
docs/evidencias/     salidas de herramientas y capturas
```

## Prevención continua de fugas

- `.pre-commit-config.yaml`: Gitleaks revisa cada commit antes de crearlo (`pip install pre-commit && pre-commit install`).
- `.github/workflows/security.yml`: en cada push, Gitleaks escanea todo el historial y se ejecutan las pruebas, `pip-audit` y `bandit`.

## Entrega

```bash
python scripts/entregar.py      # zip solo con lo versionado: sin .env, llaves, BD, logs, .venv ni binarios
```

## Despliegue con privilegios mínimos (referencia)

`docker-compose.yml`: usuario sin privilegios, sistema de archivos de solo lectura, `cap_drop: ALL`,
`no-new-privileges` y secretos montados como archivos en `/run/secrets`.

## Uso opcional de HashiCorp Vault

```bash
export VAULT_DEV_ROOT_TOKEN=$(openssl rand -hex 16)
docker compose -f vault/docker-compose.yml up -d
APP_TOKEN=$(bash vault/cargar_secretos.sh | tail -1)
VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=$APP_TOKEN python run.py
```

La aplicación recibe un token con política de **solo lectura** sobre `secret/portal` y TTL de 24 h.

## Rotación de la clave de datos

```bash
python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"   # nueva clave
# .env / Vault:  DATA_KEY_v2=<nueva>  DATA_KEY_ACTIVE=v2  DATA_KEY_OLD=v1
python scripts/rotate_data_key.py       # re-cifra todos los campos con v2
# Verificar y retirar DATA_KEY_v1
```
