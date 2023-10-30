import os
import requests
import sys
sys.path.append("/var/csirt/source/scanner")
from misc import secrets

def get_nessus_scan_ids_and_names():
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
        scan_data = [{"id": scan["id"], "name": scan["name"]} for scan in scans]
        return scan_data
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return None

if __name__ == "__main__":
    scan_data = get_nessus_scan_ids_and_names()
    if scan_data:
        for scan in scan_data:
            print(f"Scan ID: {scan['id']} | Scan Name: {scan['name']}")
    else:
        print("Failed to fetch scan details")