import requests
from bs4 import BeautifulSoup
import click
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

def analyze_content(soup):
    text = ' '.join(soup.stripped_strings)
    word_count = len(text.split())
    return word_count

def detect_security_headers(headers):
    security_headers = [
        'Content-Security-Policy', 'X-Content-Type-Options',
        'X-Frame-Options', 'Strict-Transport-Security'
    ]
    detected_headers = {header: headers.get(header, 'Not found') for header in security_headers}
    return detected_headers

def fetch_website_info(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    try:
        domain = url.split("//")[-1].split("/")[0]
        ip_address = socket.gethostbyname(domain)

        response = requests.get(url, timeout=10)
        response_time = response.elapsed.total_seconds()
        response.raise_for_status()

        soup = BeautifulSoup(response.text, 'html.parser')
        
        title = soup.title.string if soup.title else 'No title found'
        description_tag = soup.find('meta', attrs={'name': 'description'})
        description = description_tag['content'] if description_tag else 'No description found'
        
        headers = [header.text.strip() for header in soup.find_all(['h1', 'h2', 'h3', 'h4'])]
        word_count = analyze_content(soup)

        whois_info = whois.whois(domain)
        registrar = whois_info.registrar
        creation_date = whois_info.creation_date
        expiration_date = whois_info.expiration_date

        ssl_issuer, ssl_subject, ssl_expiration_date = fetch_ssl_info(domain)
        
        http_headers = response.headers
        security_headers = detect_security_headers(http_headers)

        result = {
            "Website URL": url,
            "IP Address": ip_address,
            "Response Time": f"{response_time} seconds",
            "Title": title,
            "Description": description,
            "Headers": headers,
            "Word Count": word_count,
            "Registrar": registrar,
            "Creation Date": creation_date.isoformat() if isinstance(creation_date, datetime) else str(creation_date),
            "Expiration Date": expiration_date.isoformat() if isinstance(expiration_date, datetime) else str(expiration_date),
            "SSL Issuer": ssl_issuer,
            "SSL Subject": ssl_subject,
            "SSL Expiration Date": ssl_expiration_date.isoformat() if isinstance(ssl_expiration_date, datetime) else str(ssl_expiration_date),
            "Security Headers": security_headers,
            "HTTP Headers": dict(http_headers),
        }


        return result
    
    except requests.RequestException as e:
        print(f"Error fetching the website: {e}")
    except socket.gaierror:
        print(f"Error resolving the domain: {domain}")
    except whois.parser.PywhoisError:
        print(f"Error fetching WHOIS information for: {domain}")
    except Exception as e:
        print(f"An error occurred: {e}")

@click.command()
@click.argument('url')
@click.option('--output', type=click.Choice(['json', 'csv', 'html']), help='Output format')
def main(url, output):
    result = fetch_website_info(url)

    if result:
        if output == 'json':
            import json
            with open('result.json', 'w') as f:
                json.dump(result, f, indent=4)
        elif output == 'csv':
            import csv
            with open('result.csv', 'w') as f:
                writer = csv.writer(f)
                for key, value in result.items():
                    writer.writerow([key, value])
        elif output == 'html':
            with open('result.html', 'w') as f:
                f.write('<html><body><h1>Website Scan Results</h1><table border="1">')
                for key, value in result.items():
                    f.write(f'<tr><th>{key}</th><td>{value}</td></tr>')
                f.write('</table></body></html>')
        else:
            print("\nWebsite Information:")
            print(f"Website URL: {result['Website URL']}")
            print(f"IP Address: {result['IP Address']}")
            print(f"Response Time: {result['Response Time']}")
            print(f"Title: {result['Title']}")
            print(f"Description: {result['Description']}\n")
            
            print("Headers:")
            for header in result['Headers']:
                print(f"  - {header}")
            print(f"\nWord Count: {result['Word Count']}\n")
            
            print("WHOIS Information:")
            print(f"Registrar: {result['Registrar']}")
            print(f"Creation Date: {result['Creation Date']}")
            print(f"Expiration Date: {result['Expiration Date']}\n")
            
            print("SSL Information:")
            print(f"SSL Issuer: {result['SSL Issuer']}")
            print(f"SSL Subject: {result['SSL Subject']}")
            print(f"SSL Expiration Date: {result['SSL Expiration Date']}\n")
            
            print("Security Headers:")
            for header, value in result['Security Headers'].items():
                print(f"  {header}: {value}")
            print("\nHTTP Headers:")
            for key, value in result['HTTP Headers'].items():
                print(f"  {key}: {value}")

if __name__ == "__main__":
    main()
