# VirusTotal Bulk IP Scan

> ⚡ Quickly scan IPs using VirusTotal v3 API and export results to CSV

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


---


## Acknowledgments

- The **VirusTotal bulk IP scanner script** included here was originally written by **Ch. Jnana Ramakrishna (_ph1nx_)** and is used under the [MIT License]. See the script header for full attribution and license details. Sourced from [ph1nx/VirusTotal-Bulk-IP-Scanner] on GitHub. :contentReference[oaicite:1]{index=1}

