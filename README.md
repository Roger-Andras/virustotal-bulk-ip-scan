# VirusTotal Bulk IP Scan

This Python script performs **bulk IP address analysis** using the [VirusTotal API v3](https://developers.virustotal.com/reference/ip-object).

It reads a list of IP addresses from a CSV file, queries VirusTotal for each address, and writes the results to a new CSV file for further review.

> ⚠️ Note: You must provide your own [VirusTotal API key](https://www.virustotal.com/gui/my-apikey) in the script.

---

## 🔧 Features

- Supports up to 500 IPs per scan (due to VT rate limits)
- Retrieves country, owner, and last analysis results
- Outputs detailed results to CSV
- Handles VT rate-limiting with sleep logic
- Basic error handling included

---

## 🐍 Requirements

- Python 3.7+
- `requests` library

Install via pip:

```bash
pip install requests
