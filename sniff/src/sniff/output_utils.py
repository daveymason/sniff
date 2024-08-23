def format_output(result):
    bold = "\033[1m"
    reset = "\033[0m"
    green = "\033[92m"
    blue = "\033[94m"
    yellow = "\033[93m"
    cyan = "\033[96m"

    print(f"\n{bold}Website URL:{reset} {result['Website URL']}")
    print(f"{bold}IP Address:{reset} {result['IP Address']}")
    print(f"{bold}Response Time:{reset} {result['Response Time']}")
    print(f"{bold}Title:{reset} {result['Title']}")
    print(f"{bold}Description:{reset} {result['Description']}")

    print(f"\n{bold}{green}SSL Information:{reset}")
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
