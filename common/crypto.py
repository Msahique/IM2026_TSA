"""Real cryptography helpers shared by all servers.

Primitives used across the building block:
  * RSA 2048 key pairs
  * X.509 certificates (self-signed root CA + CA-issued leaf certs)
  * PKCS#10 certificate signing requests (CSR)
  * Detached RSA-SHA256 signatures (used for message signing, global
    config signing and RFC-3161-style timestamp tokens)
  * Certificate chain / validity verification

All signatures in this project are real RSA-SHA256 signatures produced by
CA-issued X.509 certificates. The timestamp token is a JSON profile of an
RFC-3161 token (same fields: messageImprint, genTime, serialNumber, TSA
identity + signature) rather than ASN.1 DER, to keep one consistent,
auditable signature mechanism across every component.
"""
from __future__ import annotations

import base64
import datetime as _dt
import ipaddress
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------

def generate_rsa_key(bits: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def key_to_pem(key: rsa.RSAPrivateKey) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def load_key(pem: str) -> rsa.RSAPrivateKey:
    return serialization.load_pem_private_key(pem.encode(), password=None)


def cert_to_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def load_cert(pem: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem.encode())


# ---------------------------------------------------------------------------
# Subject / Name helpers
# ---------------------------------------------------------------------------

def build_name(common_name: str, org: Optional[str] = None,
               org_unit: Optional[str] = None, country: str = "EE") -> x509.Name:
    attrs = [x509.NameAttribute(NameOID.COUNTRY_NAME, country),
             x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    if org:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    if org_unit:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, org_unit))
    return x509.Name(attrs)


# ---------------------------------------------------------------------------
# CSR
# ---------------------------------------------------------------------------

def create_csr(key: rsa.RSAPrivateKey, common_name: str, org: Optional[str] = None,
               org_unit: Optional[str] = None) -> str:
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(build_name(common_name, org, org_unit))
           .sign(key, hashes.SHA256()))
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def load_csr(pem: str) -> x509.CertificateSigningRequest:
    return x509.load_pem_x509_csr(pem.encode())


# ---------------------------------------------------------------------------
# CA operations
# ---------------------------------------------------------------------------

def create_self_signed_ca(key: rsa.RSAPrivateKey, common_name: str,
                          org: str = "GovStack IM", days: int = 3650) -> x509.Certificate:
    name = build_name(common_name, org=org)
    now = _dt.datetime.utcnow()
    return (x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _dt.timedelta(minutes=1))
            .not_valid_after(now + _dt.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False), critical=True)
            .sign(key, hashes.SHA256()))


# Certificate "profiles" understood by the CA
PROFILE_AUTH = "auth"      # security-server TLS / authentication cert
PROFILE_SIGN = "sign"      # member message-signing cert
PROFILE_TSA = "tsa"        # time-stamping authority cert
PROFILE_OCSP = "ocsp"      # OCSP responder
PROFILE_GENERIC = "generic"


def sign_csr(csr: x509.CertificateSigningRequest, ca_cert: x509.Certificate,
             ca_key: rsa.RSAPrivateKey, serial: int, profile: str = PROFILE_GENERIC,
             days: int = 825) -> x509.Certificate:
    now = _dt.datetime.utcnow()
    builder = (x509.CertificateBuilder()
               .subject_name(csr.subject)
               .issuer_name(ca_cert.subject)
               .public_key(csr.public_key())
               .serial_number(serial)
               .not_valid_before(now - _dt.timedelta(minutes=1))
               .not_valid_after(now + _dt.timedelta(days=days))
               .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True))

    if profile == PROFILE_AUTH:
        builder = builder.add_extension(x509.ExtendedKeyUsage(
            [ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        builder = builder.add_extension(x509.KeyUsage(
            digital_signature=True, key_encipherment=True, content_commitment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        # SAN so the gateway's mutual-TLS server cert validates for local hosts
        builder = builder.add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        ]), critical=False)
    elif profile == PROFILE_SIGN:
        builder = builder.add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=True, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
    elif profile == PROFILE_TSA:
        builder = builder.add_extension(x509.ExtendedKeyUsage(
            [ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
        builder = builder.add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=True, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
    elif profile == PROFILE_OCSP:
        builder = builder.add_extension(x509.ExtendedKeyUsage(
            [ExtendedKeyUsageOID.OCSP_SIGNING]), critical=False)

    return builder.sign(ca_key, hashes.SHA256())


# ---------------------------------------------------------------------------
# Detached RSA-SHA256 signatures  (message signing / globalconf / timestamps)
# ---------------------------------------------------------------------------

def sign_bytes(data: bytes, key: rsa.RSAPrivateKey) -> str:
    sig = key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    return base64.b64encode(sig).decode()


def verify_bytes(data: bytes, signature_b64: str, cert: x509.Certificate) -> bool:
    try:
        cert.public_key().verify(
            base64.b64decode(signature_b64), data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False


def sha256_b64(data: bytes) -> str:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return base64.b64encode(digest.finalize()).decode()


# ---------------------------------------------------------------------------
# Verification of a cert against a trust anchor
# ---------------------------------------------------------------------------

def cert_is_currently_valid(cert: x509.Certificate) -> bool:
    now = _dt.datetime.utcnow()
    return cert.not_valid_before <= now <= cert.not_valid_after


def verify_cert_chain(cert: x509.Certificate, ca_cert: x509.Certificate) -> bool:
    """Verify `cert` was directly issued by `ca_cert` and both are time-valid."""
    try:
        cert.verify_directly_issued_by(ca_cert)
    except Exception:
        return False
    return cert_is_currently_valid(cert) and cert_is_currently_valid(ca_cert)


def cert_serial(cert: x509.Certificate) -> str:
    return format(cert.serial_number, "x")


def cert_common_name(cert: x509.Certificate) -> str:
    try:
        return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception:
        return ""
