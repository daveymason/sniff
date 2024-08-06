
# Sniff - Website Info Fetcher

This script fetches detailed information about a given website, including its IP address, response time, title, description, headers, WHOIS information, SSL certificate details, and basic technology analysis.

## Features

- Fetches website title and meta description
- Retrieves HTTP headers
- Resolves IP address of the website
- Measures response time
- Retrieves WHOIS information (registrar, creation date, expiration date)
- Fetches SSL certificate details (issuer, subject, expiration date)
- Performs basic technology analysis using HTTP headers

## Requirements

- Python 3.x
- `requests` library
- `beautifulsoup4` library
- `python-whois` library
- `cryptography` library

## Installation

Install the required Python libraries using pip:

```sh
pip install requests beautifulsoup4 python-whois cryptography
```

## Usage

Run the script with the website URL as an argument:

```sh
python website_info.py example.com
```

### Example Output

```sh
python website_info.py daveymason.com

Website URL: https://daveymason.com
IP Address: 50.18.215.94
Response Time: 0.650695 seconds
Title: Davey Mason - From Neurons to Pixels
Description: Davey Mason is an Irish UX Engineer that specializes in designing and building high-quality, pixel perfect web apps that run on all devices, browsers, and screen sizes. This website is a collection of his experience, education, and projects built in Javascript, Php, CSS, React, Node & Wordpress.
Headers:
  - D.
  - Projects
  - Experience
  - UX Software Engineer  |  Reel Metrics
  - Web Developer & Designer  |  Fat Head Solutions
  - Web Developer & Designer  |  DEITG I.T. Generalists
  - Education
Registrar: Hostinger Operations, UAB
Creation Date: 2020-01-09 05:30:00
Expiration Date: 2025-01-09 05:30:00
SSL Issuer: CN=E5,O=Let's Encrypt,C=US
SSL Subject: CN=*.daveymason.com
SSL Expiration Date: 2024-10-04 23:33:36
HTTP Headers:
  Accept-Ranges: bytes
  Age: 0
  Cache-Control: public,max-age=0,must-revalidate
  Cache-Status: "Netlify Edge"; fwd=miss
  Content-Encoding: gzip
  Content-Type: text/html; charset=UTF-8
  Date: Tue, 06 Aug 2024 19:24:12 GMT
  Etag: "1537c540a2a84b47e49e59ca22ad6dd9-ssl-df"
  Server: Netlify
  Strict-Transport-Security: max-age=31536000
  Vary: Accept-Encoding
  X-Nf-Request-Id: 01J4MJCAA6YNRM6RFTQE0SNAAE
Technologies Used (basic analysis):
  - Netlify
```

## Notes

- Ensure you have a stable internet connection while running the script.
- The script currently performs basic technology analysis using HTTP headers. For more detailed analysis, consider using specialized tools or libraries.

## License

This project is licensed under the MIT License.
