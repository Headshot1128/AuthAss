"""Generate a localhost-only development certificate without installing a system CA."""
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def main():
    directory = Path('data/tls')
    directory.mkdir(parents=True, exist_ok=True)
    cert_path, key_path = directory / 'localhost-cert.pem', directory / 'localhost-key.pem'
    if cert_path.exists() or key_path.exists():
        if not cert_path.exists() or not key_path.exists():
            raise SystemExit('Incomplete existing certificate pair; refusing to overwrite it.')
        print('Using existing development certificate pair.')
        return
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    current = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(current - timedelta(minutes=5))
        .not_valid_after(current + timedelta(days=7))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName('localhost'), x509.IPAddress(ip_address('127.0.0.1'))]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256()))
    with key_path.open('xb') as output:
        output.write(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    print('Created seven-day development certificate in data/tls (not installed in system trust).')


if __name__ == '__main__':
    main()
