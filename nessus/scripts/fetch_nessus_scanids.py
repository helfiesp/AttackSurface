import os
import requests
import sys
sys.path.append("/var/csirt/source/scanner")
from misc import secrets

def get_nessus_scan_ids():
    # API endpoint to fetch the list of scans
    endpoint = "/scans"
    
    # Connection details
    url = "https://nessus.okcsirt.no" + endpoint
    access_key = os.environ["NESSUS_API_ACCESS_KEY"]
    secret_key = os.environ["NESSUS_API_SECRET_KEY"]

    headers = {
        "X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    response = requests.get(url, headers=headers, verify=False)
    
    if response.status_code == 200:
        scans = response.json()["scans"]
        scan_ids = [scan["id"] for scan in scans]
        return scan_ids
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return None

if __name__ == "__main__":
    scan_ids = get_nessus_scan_ids()
    if scan_ids:
        for id in scan_ids:
            print(f"Scan ID: {id}")
    else:
        print("Failed to fetch scan IDs")

