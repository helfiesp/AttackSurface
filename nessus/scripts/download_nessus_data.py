import os
import requests
from requests.exceptions import RequestException
import sys

# Append the path to the 'misc' directory to sys.path
sys.path.append("/var/csirt/source/scanner/misc")

# Now you can import the entire 'secrets' module
import secrets

def download_exported_scan():
    try:
        scan_id = 20  # Update this with the actual scan ID
        url = "https://nessus.okcsirt.no"
        access_key = os.environ["NESSUS_API_ACCESS_KEY"]
        secret_key = os.environ["NESSUS_API_SECRET_KEY"]

        headers = {
            "X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}",
            "Content-Type": "application/json"
        }

        # Choose the export format "CSV"
        export_format_value = "csv"

        # Fetch the exported scan file
        download_url = f"{url}/scans/{scan_id}/export/{export_format_value}/download"
        response = requests.get(download_url, headers=headers, verify=False)
        response.raise_for_status()

        # Save the content of the file to a local file
        filename = f"exported_scan_{scan_id}.csv"
        with open(filename, "wb") as file:
            file.write(response.content)

        print(f"Exported scan saved as: {filename}")
    except RequestException as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    download_exported_scan()
