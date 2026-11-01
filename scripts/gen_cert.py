"""Crea una CA de laboratorio y un certificado de servidor para localhost.

Funciona igual en Windows, macOS y Linux (solo usa la biblioteca cryptography).
Uso:  python scripts/gen_cert.py
En producción: certificado de una CA pública (Let's Encrypt) o la PKI institucional.
"""
import datetime as dt
import ipaddress
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

out = Path("certs")
out.mkdir(exist_ok=True)
now = dt.datetime.now(dt.timezone.utc)
valid = dict(not_valid_before=now - dt.timedelta(minutes=5), not_valid_after=now + dt.timedelta(days=30))


def save_key(key, path):
    data = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)  # solo el dueño puede leerla
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def ku(**on):
    base = dict(digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False)
    base.update(on)
    return x509.KeyUsage(**base)


# --- CA del laboratorio
ca_key = ec.generate_private_key(ec.SECP256R1())
ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "MASI Lab CA")])
ca_cert = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
           .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
           .not_valid_before(valid["not_valid_before"]).not_valid_after(valid["not_valid_after"])
           .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
           .add_extension(ku(key_cert_sign=True, crl_sign=True), critical=True)
           .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
           .sign(ca_key, hashes.SHA256()))

# --- Certificado del servidor (localhost)
srv_key = ec.generate_private_key(ec.SECP256R1())
srv_cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
            .issuer_name(ca_name).public_key(srv_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(valid["not_valid_before"]).not_valid_after(valid["not_valid_after"])
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(ku(digital_signature=True), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(srv_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))

save_key(ca_key, out / "ca.key")
save_key(srv_key, out / "server.key")
(out / "ca.crt").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
(out / "server.crt").write_bytes(srv_cert.public_bytes(serialization.Encoding.PEM))
print("Certificados creados en la carpeta certs/ (server.key con permisos restringidos)")
