"""Fase II-B y prueba obligatoria 7: la consulta por HTTPS usa TLS correctamente."""
import socket
import ssl
import subprocess
import threading
from pathlib import Path

import pytest

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")
from werkzeug.serving import make_server

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture()
def https_server(app, tmp_path):
    subprocess.run(["bash", str(ROOT / "scripts/gen_cert.sh")], cwd=tmp_path, check=True, capture_output=True)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")
    ctx.load_cert_chain(tmp_path / "certs/server.crt", tmp_path / "certs/server.key")
    srv = make_server("127.0.0.1", 0, app, ssl_context=ctx)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_port, tmp_path / "certs/ca.crt"
    srv.shutdown()


def _get(port, ctx, path="/login"):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        with ctx.wrap_socket(raw, server_hostname="localhost") as s:
            info = (s.version(), s.cipher(), s.getpeercert())
            s.sendall(f"GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".encode())
            data = b""
            while chunk := s.recv(4096):
                data += chunk
            return (*info, data)


def test_https_tls13_certificado_valido(https_server):
    port, ca = https_server
    ctx = ssl.create_default_context(cafile=str(ca))        # verifica cadena y nombre de host
    ver, cipher, cert, data = _get(port, ctx)
    print(f"\n[TLS] versión={ver} suite={cipher[0]} CN={dict(x[0] for x in cert['subject'])['commonName']}")
    assert ver == "TLSv1.3" and b" 200 OK" in data.split(b"\r\n")[0]
    assert b"Strict-Transport-Security: max-age=31536000" in data


def test_rechaza_tls_antiguo(https_server):
    port, ca = https_server
    ctx = ssl.create_default_context(cafile=str(ca))
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_1
    with pytest.raises(ssl.SSLError):
        _get(port, ctx)


def test_cliente_rechaza_certificado_no_confiable(https_server):
    port, _ = https_server
    with pytest.raises(ssl.SSLCertVerificationError):
        _get(port, ssl.create_default_context())            # sin la CA del laboratorio -> no confía
