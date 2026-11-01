"""Arranca el portal con HTTPS (TLS 1.2+; se prefiere TLS 1.3).

Uso:  python scripts/gen_env.py && python scripts/gen_cert.py && python run.py
"""
import os
import ssl

from dotenv_lite import load_env
load_env(".env")               # carga .env local (no versionado) si existe

from app import create_app     # noqa: E402

app = create_app()

if __name__ == "__main__":
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")   # solo AEAD con secreto perfecto hacia adelante
    ctx.load_cert_chain(os.environ.get("TLS_CERT", "certs/server.crt"),
                        os.environ.get("TLS_KEY", "certs/server.key"))
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 8443)), ssl_context=ctx)
