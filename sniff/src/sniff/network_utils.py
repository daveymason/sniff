import subprocess
import logging
import socket
from sublist3r import main as sublist3r

logging.basicConfig(filename='network_utils.log', level=logging.ERROR)

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
        logging.error(f"nslookup failed for {domain}: {str(e)}")
        return f"nslookup failed: {str(e)}"

def perform_dig(domain, record_types=["A", "CNAME", "MX", "TXT"]):
    results = {}
    for record_type in record_types:
        try:
            result = subprocess.run(["dig", domain, record_type], capture_output=True, text=True)
            output_lines = result.stdout.splitlines()
            relevant_lines = []
            recording = False

            for line in output_lines:
                if line.startswith(";; ANSWER SECTION:"):
                    recording = True
                elif line.startswith(";;") and recording:
                    break
                if recording and not line.startswith(";;"):
                    relevant_lines.append(line.strip())

            results[record_type] = "\n".join(relevant_lines) if relevant_lines else f"No {record_type} record found."

        except Exception as e:
            logging.error(f"dig failed for {record_type} record on {domain}: {str(e)}")
            results[record_type] = f"dig failed for {record_type}: {str(e)}"
    return results

def enumerate_subdomains(domain):
    common_subdomains = [
        'www', 'mail', 'ftp', 'blog', 'dev', 'test', 'admin', 'login', 
        'backup', 'api', 'vpn', 'git', 'staging', 'aws', 'azure', 'gcp',
        'sandbox', 'demo', 'training', 'docs', 'wiki', 'help', 'download',
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
    
    # TODO: Use sublist3r to find additional subdomains
    return subdomains

def perform_nmap_scan(domain, ports='21,22,25,80,443,8080'):
    try:
        result = subprocess.run(['nmap', '-p', ports, '-sV', domain], capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        logging.error(f"nmap scan failed for {domain}: {str(e)}")
        return f"nmap scan failed: {str(e)}"
