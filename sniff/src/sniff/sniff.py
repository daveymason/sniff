import requests
from bs4 import BeautifulSoup
import click
import socket
import whois
import ssl
import subprocess
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

def detect_security_headers(headers):
    security_headers = [
        'Content-Security-Policy', 'X-Content-Type-Options',
        'X-Frame-Options', 'Strict-Transport-Security'
    ]
    detected_headers = {header: headers.get(header, 'Not found') for header in security_headers}
    return detected_headers

def perform_nslookup(domain):
    try:
        # Perform nslookup using subprocess
        result = subprocess.run(["nslookup", domain], capture_output=True, text=True)
        
        # Check if nslookup produced any output
        if result.stdout:
            return result.stdout
        else:
            return "No output from nslookup."
        
    except Exception as e:
        return f"nslookup failed: {str(e)}"


def perform_dig(domain, record_type="A"):
    try:
        result = subprocess.run(["dig", domain, record_type], capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return f"dig failed: {str(e)}"

def enumerate_subdomains(domain):
    common_subdomains = [
        'www', 'mail', 'ftp', 'blog', 'dev', 'test', 'admin', 'login', 
        'backup', 'api', 'vpn', 'git', 'staging', 'aws', 'azure', 'gcp',
        'smtp', 'imap', 'pop', 'webmail', 'shop', 'crm', 'static', 'assets', 
        'beta', 'cdn', 'monitor', 'support', 'jira', 'confluence', 'portal', 
        'gateway', 'chat', 'secure', 'video', 'stream', 'news', 'media', 
        'jobs', 'payments', 'auth', 'login2', 'dashboard', 'sso', 'graph', 'test', 
        'alpha', 'beta', 'stage', 'prod', 'devops', 'qa', 'uat', 'dr', 'backup',
        'sandbox', 'demo', 'training', 'docs', 'wiki', 'help', 'download',
        'blog', 'news', 'status', 'events', 'calendar', 'photos', 'store',
        'market', 'shop', 'cart', 'checkout', 'payment', 'billing', 'invoice', 'order',
        'account', 'profile', 'settings', 'preferences', 'privacy', 'tos', 'terms', 'policy',
        'contact', 'support', 'help', 'faq', 'feedback', 'bug', 'report', 'abuse', 'legal',
        'kubernetes', 'k8', 'docker', 'jenkins', 'ansible', 'puppet', 'chef', 'salt', 'terraform',
        'google',
    ]
    subdomains = []
    for sub in common_subdomains:
        try:
            subdomain = f"{sub}.{domain}"
            socket.gethostbyname(subdomain)
            subdomains.append(subdomain)
        except socket.gaierror:
            continue
    return subdomains

def scan_ports(domain):
    common_ports = [21, 22, 25, 80, 443, 8080]
    open_ports = []
    banners = {}

    for port in common_ports:
        try:
            with socket.create_connection((domain, port), timeout=1) as sock:
                open_ports.append(port)
                # Try to grab the banner
                sock.send(b"HEAD / HTTP/1.1\r\nHost: %s\r\n\r\n" % domain.encode())
                banner = sock.recv(1024).decode().strip()
                banners[port] = banner
        except (socket.timeout, ConnectionRefusedError, socket.error) as e:
            continue

    return open_ports, banners


def check_directory_listing(url):
    directories = ['/admin/', '/login/', '/backup/', '/test/']
    open_directories = []
    for directory in directories:
        try:
            dir_url = url + directory
            response = requests.get(dir_url)
            if response.status_code == 200 and 'Index of' in response.text:
                open_directories.append(dir_url)
        except requests.RequestException:
            continue
    return open_directories

def detect_technology_stack(headers):
    tech_stack = []
    if 'X-Powered-By' in headers:
        tech_stack.append(headers['X-Powered-By'])
    if 'Server' in headers:
        tech_stack.append(headers['Server'])
    return tech_stack

def extract_external_links(soup, domain):
    external_links = []
    for link in soup.find_all('a', href=True):
        href = link['href']
        if href.startswith('http') and domain not in href:
            external_links.append(href)
    return external_links

def check_iso_27001_compliance(security_headers, ssl_info):
    compliance_issues = []

    if security_headers['Content-Security-Policy'] == 'Not found':
        compliance_issues.append("Missing Content-Security-Policy header")
    if security_headers['X-Content-Type-Options'] == 'Not found':
        compliance_issues.append("Missing X-Content-Type-Options header")
    if security_headers['X-Frame-Options'] == 'Not found':
        compliance_issues.append("Missing X-Frame-Options header")
    if security_headers['Strict-Transport-Security'] == 'Not found':
        compliance_issues.append("Missing Strict-Transport-Security header")
    
    expiration_date = ssl_info[2]
    if isinstance(expiration_date, str):
        try:
            expiration_date = datetime.fromisoformat(expiration_date)
        except ValueError:
            compliance_issues.append("Invalid SSL expiration date format")
    
    if expiration_date and expiration_date.tzinfo is not None:
        expiration_date = expiration_date.replace(tzinfo=None)

    now = datetime.now()
    if now.tzinfo is not None:
        now = now.replace(tzinfo=None)

    if expiration_date and expiration_date < now:
        compliance_issues.append("SSL certificate is expired")
    
    compliance_status = "Compliant" if not compliance_issues else "Non-Compliant"
    
    return compliance_status, compliance_issues

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
                
        whois_info = whois.whois(domain)
        registrar = whois_info.registrar
        creation_date = whois_info.creation_date
        expiration_date = whois_info.expiration_date

        ssl_issuer, ssl_subject, ssl_expiration_date = fetch_ssl_info(domain)
        
        http_headers = response.headers
        security_headers = detect_security_headers(http_headers)

        subdomains = enumerate_subdomains(domain)  # Original subdomain enumeration function
        open_ports, banners = scan_ports(domain)
        open_directories = check_directory_listing(url)
        tech_stack = detect_technology_stack(http_headers)
        external_links = extract_external_links(soup, domain)

        # Perform additional DNS lookup using nslookup and dig
        nslookup_result = perform_nslookup(domain)
        dig_result = perform_dig(domain)

        # Update the result dictionary with all collected information
        result = {
            "Website URL": url,
            "IP Address": ip_address,
            "Response Time": f"{response_time} seconds",
            "Title": title,
            "Description": description,
            "Registrar": registrar,
            "Creation Date": creation_date.isoformat() if isinstance(creation_date, datetime) else str(creation_date),
            "Expiration Date": expiration_date.isoformat() if isinstance(expiration_date, datetime) else str(expiration_date),
            "SSL Issuer": ssl_issuer,
            "SSL Subject": ssl_subject,
            "SSL Expiration Date": ssl_expiration_date.isoformat() if isinstance(ssl_expiration_date, datetime) else str(ssl_expiration_date),
            "Security Headers": security_headers,
            "HTTP Headers": dict(http_headers),
            "Subdomains": subdomains,
            "Open Ports": open_ports,
            "Service Banners": banners,
            "Open Directories": open_directories,
            "Technology Stack": tech_stack,
            "External Links": external_links,
            "nslookup Result": nslookup_result if nslookup_result else "No nslookup result found.",
            "dig Result": dig_result if dig_result else "No dig result found."
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


def format_output(result):
    bold = "\033[1m"
    reset = "\033[0m"
    green = "\033[92m"
    blue = "\033[94m"
    yellow = "\033[93m"
    cyan = "\033[96m"

    print(f"{bold}{green}SSL Information:{reset}")
    print(f"  {bold}SSL Issuer:{reset} {result['SSL Issuer']}")
    print(f"  {bold}SSL Subject:{reset} {result['SSL Subject']}")
    print(f"  {bold}SSL Expiration Date:{reset} {result['SSL Expiration Date']}")

    print(f"\n{bold}{blue}Security Headers:{reset}")
    for header, value in result['Security Headers'].items():
        print(f"  {header}: {value}")

    print(f"\n{bold}{yellow}HTTP Headers:{reset}")
    for key, value in result['HTTP Headers'].items():
        print(f"  {key}: {value}")

    print(f"\n{bold}{cyan}Additional Information:{reset}")
    print(f"  {bold}Subdomains:{reset} {', '.join(result['Subdomains']) if result['Subdomains'] else 'None found'}")
    print(f"  {bold}Open Ports:{reset} {', '.join(map(str, result['Open Ports'])) if result['Open Ports'] else 'None found'}")
    print(f"  {bold}Open Directories:{reset} {', '.join(result['Open Directories']) if result['Open Directories'] else 'None found'}")
    print(f"  {bold}Technology Stack:{reset} {', '.join(result['Technology Stack']) if result['Technology Stack'] else 'None detected'}")
    print(f"  {bold}External Links:{reset} {', '.join(result['External Links']) if result['External Links'] else 'None found'}")

    print(f"\n{bold}{green}DNS Information:{reset}")
    print(f"  {bold}nslookup Result:{reset}")
    for line in result['nslookup Result'].splitlines():
        print(f"{line}")
    print(f"  {bold}dig Result:{reset}\n{result['dig Result']}")

@click.command()
@click.argument('url')
@click.option('--output', type=click.Choice(['json', 'csv', 'html']), help='Output format')
@click.option('--assess-risks', is_flag=True, help='Perform a general security risk assessment')
def main(url, output, assess_risks):
    result = fetch_website_info(url)
    
    if result:
        if assess_risks:
            compliance_status, compliance_issues = check_iso_27001_compliance(
                result['Security Headers'], 
                (result['SSL Issuer'], result['SSL Subject'], result['SSL Expiration Date'])
            )
            result["Risk Assessment Status"] = compliance_status
            result["Risk Assessment Issues"] = compliance_issues

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
            # Print the formatted result in the CLI
            format_output(result)

        # Print the risk assessment results at the end
        if assess_risks:
            bold = "\033[1m"
            reset = "\033[0m"
            cyan = "\033[96m"
            print(f"\n{bold}{cyan}Risk Assessment Status:{reset} {result['Risk Assessment Status']}")
            if result["Risk Assessment Issues"]:
                print("Identified Issues:")
                for issue in result["Risk Assessment Issues"]:
                    print(f"  - {issue}")
            else:
                print("No major issues found.")


if __name__ == "__main__":
    main()