
# Sniff - The Website Sniffer

![Sniff Logo](SniffLogo.png)

This script fetches detailed information about a given website, including its IP address, response time, title, description, headers, WHOIS information, SSL certificate details, and basic technology analysis.

## Features

- Fetches website title and meta description
- Resolves IP address of the website
- Measures response time
- Retrieves WHOIS information (registrar, creation date, expiration date)
- Fetches SSL certificate details (issuer, subject, expiration date)
- Retrieves HTTP headers & performs basic technology analysis

## Requirements

- Python 3.x
- `beautifulsoup4`
- `certifi`
- `cffi`
- `charset-normalizer`
- `click`
- `cryptography`
- `idna`
- `pycparser`
- `python-dateutil`
- `python-whois`
- `requests`
- `six`
- `soupsieve`
- `urllib3`

## Installation

Install the required Python libraries using pip:

```sh
pip install beautifulsoup4 certifi cffi charset-normalizer click cryptography idna pycparser python-dateutil python-whois requests six soupsieve urllib3
```

## Usage

Run the script with the website URL as an argument:

```sh
python sniff.py example.com
```

## Options

The script supports the following options:

- `--output`: Specify the output format (json, csv, html)

```sh
python sniff.py example.com --output json
```
- `--help`: Show the help message and exit

```sh
python sniff.py --help
```



## Notes

- Ensure you have a stable internet connection while running the script.
- The script currently performs basic technology analysis using HTTP headers. For more detailed analysis, consider using specialized tools or libraries.

## License

This project is licensed under the MIT License.
