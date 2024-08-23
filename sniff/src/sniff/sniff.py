import requests
from bs4 import BeautifulSoup
import click
import socket
import whois
from datetime import datetime
from ssl_utils import fetch_ssl_info
from network_utils import perform_nslookup, perform_dig, enumerate_subdomains
from web_utils import detect_security_headers, check_directory_listing, detect_technology_stack, extract_external_links
from compliance_utils import check_iso_27001_compliance
from output_utils import format_output
from port_scanner import scan_ports

def fetch_website_info(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    try:
        domain = url.split("//")[-1].split("/")[0]
        ip_address = requests.get(f'https://api.ipify.org/?format=json').json().get('ip', 'Unknown') # Alternative IP fetch

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

        subdomains = enumerate_subdomains(domain)
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
    except Exception as e:
        print(f"An error occurred: {e}")

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