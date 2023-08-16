import os
import requests
from requests.exceptions import RequestException
import sys
import time

# Append the path to the 'misc' directory to sys.path
sys.path.append("/var/csirt/source/scanner")

# Now you can import the entire 'secrets' module
from misc import secrets

def download_exported_scan():
    try:
        scan_id = 20  # Update this with the actual scan ID
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

        filename = f"data/exported_scan_{scan_id}.csv"
        with open(filename, "wb") as file:
            file.write(download_response.content)

        print(f"Exported scan saved as: {filename}")
    except RequestException as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    download_exported_scan()