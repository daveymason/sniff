import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def fetch_ssl_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert(True)
                cert = x509.load_der_x509_certificate(cert, default_backend())
                issuer = cert.issuer.rfc4514_string()
                subject = cert.subject.rfc4514_string()
                expiration_date = cert.not_valid_after_utc
                return issuer, subject, expiration_date
    except Exception as e:
        return None, None, None
