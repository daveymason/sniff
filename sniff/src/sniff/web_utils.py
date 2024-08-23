import requests
from bs4 import BeautifulSoup

def detect_security_headers(headers):
    security_headers = [
        'Content-Security-Policy', 'X-Content-Type-Options',
        'X-Frame-Options', 'Strict-Transport-Security'
    ]
    detected_headers = {header: headers.get(header, 'Not found') for header in security_headers}
    return detected_headers

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
