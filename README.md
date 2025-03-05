# cidr2domains

A Go-based tool for extracting domain names associated with IP addresses in a given CIDR range using Shodan.

## Features

- Scan IP ranges (CIDR notation)
- Support for multiple input methods:
  - Single CIDR via command-line flag
  - List of CIDRs from a file
  - CIDRs piped from stdin
- Concurrent scanning for improved performance
- Optional filtering of results using regex
- Verbose logging mode

## Prerequisites

- Go 1.16+ 
- Internet connection
- Access to Shodan.io (no API key required for this tool)

## Installation

### Option 1: Go Install

```bash
go install github.com/gilsgil/cidr2domains@latest
```

### Option 2: Manual Installation

```bash
git clone https://github.com/gilsgil/cidr2domains.git
cd cidr2domains
go build
```

## Usage

### Basic Usage

Scan a single CIDR:
```bash
cidr2domains -t 192.168.0.0/24
```

Scan from a list file:
```bash
cidr2domains -l cidrs.txt
```

Pipe CIDRs from stdin:
```bash
echo "10.0.0.0/24" | cidr2domains
```

### Advanced Options

- `-c`: Set concurrent workers (default: 100)
- `-f`: Filter out domains matching a regex
- `-m`: Show only domains matching a regex
- `-v`: Enable verbose logging

### Examples

Scan with 50 concurrent workers:
```bash
cidr2domains -t 192.168.1.0/24 -c 50
```

Filter out unwanted domains:
```bash
cidr2domains -t 10.0.0.0/16 -f "internal|localhost"
```

Match only specific domains:
```bash
cidr2domains -t 172.16.0.0/12 -m "company\.com"
```

## Dependencies

- `github.com/PuerkitoBio/goquery`

## Limitations

- Relies on Shodan's web interface
- Rate limits may apply
- Requires internet connectivity

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

[Please add your license information here]

## Disclaimer

This tool is for educational and authorized testing purposes only. Ensure you have proper authorization before scanning networks.
