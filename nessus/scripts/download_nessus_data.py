import os
import requests
from datetime import datetime
from requests.exceptions import RequestException
import sqlite3
import sys
import time
import json
import csv

# Append the path to the 'misc' directory to sys.path
sys.path.append("/var/csirt/source/scanner")
from misc import secrets

def convert_csv_to_json(csv_data):
    json_data = []
    csv_reader = csv.DictReader(csv_data.splitlines())
    for row in csv_reader:
        json_data.append(row)
    return json_data

def NMAPScanner(domain):
    # Performs an NMAP scan on the requested IP address or domain name.
    print("Performing NMAP scan on: {}".format(domain))
    try:
        # Run Nmap as an external comman
        nmap_args = ["nmap", "-T4", "-F", domain]
        nmap_output = subprocess.run(nmap_args, capture_output=True, text=True)

        # Extract the scan output from the completed process
        nmap_data = nmap_output.stdout
    except:
        nmap_data = None
    print(nmap_data)
    return nmap_data

def download_exported_scan():
    scan_ids = [111,20]

    nmap_scans = {}
    nmap_scanned_hosts = []          
    try:
        for scan_id in scan_ids:
            url = "https://nessus.okcsirt.no"
            access_key = os.environ["NESSUS_API_ACCESS_KEY"]
            secret_key = os.environ["NESSUS_API_SECRET_KEY"]

            headers = {
                "X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}",
                "Content-Type": "application/x-www-form-urlencoded"
            }

            export_format_value = "csv"

            export_url = f"{url}/scans/{scan_id}/export"
            payload = {"format": export_format_value}

            response = requests.post(export_url, headers=headers, data=payload, verify=False)
            response.raise_for_status()

            response_data = response.json()
            download_export_id = response_data["file"]
            time.sleep(30)
            download_url = f"{url}/scans/{scan_id}/export/{download_export_id}/download"
            download_response = requests.get(download_url, headers=headers, verify=False)
            download_response.raise_for_status()

            # Convert the downloaded content to a string
            exported_scan_data = download_response.content.decode("utf-8")

            json_data = convert_csv_to_json(exported_scan_data)
        
            for entry in json_data:
                if "Host" in entry:
                    domain = entry["Host"]
                    if domain in nmap_scanned_hosts:
                        entry["NMAP_DATA"] = nmap_scans[domain]
                    else:
                        nmap_data = NMAPScanner(domain)
                        nmap_scans[domain] = nmap_data
                        nmap_scanned_hosts.append(domain)

            # Connect to the SQLite database
            db_path = "/var/csirt/source/scanner/db.sqlite3"
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            # Get the current date and time
            current_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Insert exported scan data into the 'nessus_nessusdata' table
            insert_query = "INSERT INTO nessus_nessusdata (data, date, scan_id) VALUES (?, ?, ?);"
            cursor.execute(insert_query, (str(json_data), current_date, scan_id))
            conn.commit()

            conn.close()

            print("Exported scan data saved to the database.")
    except RequestException as e:
        print(f"Error: {e}")

    time.sleep(30)

if __name__ == "__main__":
    download_exported_scan()