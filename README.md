# DNS Inspector

A simple command-line DNS inspection tool written in Python.

DNS Inspector queries a domain's DNS records and presents the results in a human-readable format. It also interprets SPF and DMARC policies instead of only displaying the raw DNS records.

## Features

### Address and Routing
- A record lookup
- AAAA record lookup
- CNAME lookup

### Email
- MX records and preference values
- SPF policy detection
- DMARC policy detection and explanation

### Zone and Authority
- NS records
- SOA information
  - Primary nameserver
  - Responsible mailbox
  - Serial number
  - Refresh interval
  - Retry interval
  - Expire interval
  - Minimum TTL

## Requirements

- Python 3
- dnspython

## Installation

Clone the repository:

```bash
git clone https://github.com/DenzelVW-xyz/DNS-Inspector.git
cd DNS-Inspector