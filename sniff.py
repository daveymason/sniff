import requests
from bs4 import BeautifulSoup
import argparse
import socket
import whois
import ssl
from datetime import datetime
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

def fetch_website_info(url):
    # Add https:// if the URL doesn't start with http:// or https://
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    try:
        # Get the IP address of the website
        domain = url.split("//")[-1].split("/")[0]
        ip_address = socket.gethostbyname(domain)

        # Fetch the website content and measure response time
        response = requests.get(url)
        response_time = response.elapsed.total_seconds()
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        title = soup.title.string if soup.title else 'No title found'
        description_tag = soup.find('meta', attrs={'name': 'description'})
        description = description_tag['content'] if description_tag else 'No description found'
        
        headers = [header.text.strip() for header in soup.find_all(['h1', 'h2', 'h3'])]

        # Fetch WHOIS information
        whois_info = whois.whois(domain)
        registrar = whois_info.registrar
        creation_date = whois_info.creation_date
        expiration_date = whois_info.expiration_date

        # Fetch SSL certificate information
        ssl_issuer, ssl_subject, ssl_expiration_date = fetch_ssl_info(domain)
        
        # Fetch HTTP headers
        http_headers = response.headers

        print(f"\nWebsite URL: {url}")
        print(f"IP Address: {ip_address}")
        print(f"Response Time: {response_time} seconds")
        print(f"Title: {title}")
        print(f"Description: {description}\n")
        print("Headers:")
        for header in headers:
            print(f"  - {header}")
        print(f"\nRegistrar: {registrar}")
        print(f"Creation Date: {creation_date}")
        print(f"Expiration Date: {expiration_date}\n")
        print(f"SSL Issuer: {ssl_issuer}")
        print(f"SSL Subject: {ssl_subject}")
        print(f"SSL Expiration Date: {ssl_expiration_date}\n")
        print("HTTP Headers:")
        for key, value in http_headers.items():
            print(f"  {key}: {value}")
        print("\nTechnologies Used (basic analysis):")
        if 'X-Powered-By' in http_headers:
            print(f"  - {http_headers['X-Powered-By']}")
        if 'Server' in http_headers:
            print(f"  - {http_headers['Server']}")
    
    except requests.RequestException as e:
        print(f"Error fetching the website: {e}")
    except socket.gaierror:
        print(f"Error resolving the domain: {domain}")
    except whois.parser.PywhoisError:
        print(f"Error fetching WHOIS information for: {domain}")
    except Exception as e:
        print(f"An error occurred: {e}")

def main():
    parser = argparse.ArgumentParser(description="Fetch detailed information about a website.")
    parser.add_argument("url", help="The URL of the website to fetch information from")
    args = parser.parse_args()
    
    fetch_website_info(args.url)

if __name__ == "__main__":
    main()
