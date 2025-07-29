import csv
import json
import requests
import time

# //////////////////////////////////////////////
#
# Python script for VirusTotal API v3 list of IP address analysis
# by ph1nx
#
# Performs bulk IP address analysis
#
# Reports for each IP entry are saved to a CSV file
#
# //////////////////////////////////////////////

# Replace with your VirusTotal API key
apikey = 'ADD_VT_API_KEY_HERE'

# Function to check if an IP address is malicious
def check_ip(ip_address):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}' 
    headers = {'x-apikey': apikey}
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        raise requests.exceptions.RequestException(f"API request failed with status code {response.status_code}")
    response_json = response.json()
    if 'data' not in response_json:
        raise ValueError("Invalid response structure")
    attributes = response_json['data']['attributes']
    
    # JSON response parameters
    as_owner = attributes.get('as_owner')
    country = attributes.get('country')
    stat_analysis = attributes.get('last_analysis_stats')
    
    malicious = stat_analysis.get('malicious')
    suspicious = stat_analysis.get('suspicious')
    undetected = stat_analysis.get('undetected')
    harmless = stat_analysis.get('harmless')
    
    total = int(malicious) + int(suspicious) + int(undetected) + int(harmless)

    return {
        'IP Address': ip_address,
        'Country': country,
        'Owner': as_owner,
        'Malicious': malicious,
        'Suspicious': suspicious,
        'Undetected': undetected,
        'Total': total
    }

# File paths (relative)
input_file = "samples/VT-IP-LIST-UPLOAD.csv"
output_file = "samples/VT-IP-LIST-RESULTs.csv"

try:
    with open(input_file, 'r', encoding='utf-8-sig') as infile:
        reader = csv.DictReader(infile)
        ip_list = list(reader)

    if len(ip_list) > 500:
        print("IP count exceeds VirusTotal rate limit. Scanning first 500 IPs.")
        ip_list = ip_list[:500]

    with open(output_file, 'w', newline='', encoding='utf-8') as outfile:
        fieldnames = ['IP Address', 'Country', 'Owner', 'Malicious', 'Suspicious', 'Undetected', 'Total']
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()

        for col in ip_list:
            try:
                column_name = 'IP Address'
                ip_address = col[column_name]
                print(f"Scanning IP: {ip_address}")
                data = check_ip(ip_address)
                writer.writerow(data)
                time.sleep(15)  # Respect VirusTotal public rate limit

            except KeyError:
                print(f"The CSV does not contain '{column_name}' header.")
                break
            except requests.exceptions.RequestException as e:
                print(f"API error for IP {ip_address}: {e}")
                break
            except Exception as e:
                print(f"Unexpected error while processing IP {ip_address}: {e}")
                break

    print("IP scan completed!")

except FileNotFoundError:
    print(f"Input file '{input_file}' not found.")
except Exception as e:
    print(f"Unexpected error: {e}")
