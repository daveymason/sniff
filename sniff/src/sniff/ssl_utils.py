import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def fetch_ssl_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # Fetch certificate in DER format and parse it with cryptography
                cert_der = ssock.getpeercert(True)
                cert = x509.load_der_x509_certificate(cert_der, default_backend())

                issuer = cert.issuer.rfc4514_string()
                subject = cert.subject.rfc4514_string()
                expiration_date = cert.not_valid_after_utc

                # Get the TLS version used during the handshake
                ssl_protocol_version = ssock.version()

                return issuer, subject, expiration_date, ssl_protocol_version
    except Exception as e:
        print(f"Error fetching SSL info: {e}")
        return None, None, None, None
