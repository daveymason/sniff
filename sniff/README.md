
# Sniff - The Website Sniffer

Sniff is a command-line tool for sniffing website information including SSL details, WHOIS information, security headers, and more.

## Installation

Install the package using pip:

```sh
pip install sniff_admanvoids
```

## Usage

Run the script with the website URL as an argument:

```sh
sniff example.com
```

## Options

The script supports the following options:

- `--output`: Specify the output format (json, csv, html)

```sh
sniff example.com --output json
```


## Notes

- Ensure you have a stable internet connection while running the script.
- The script currently performs basic technology analysis using HTTP headers. For more detailed analysis, consider using specialized tools or libraries.

## License

This project is licensed under the MIT License.
