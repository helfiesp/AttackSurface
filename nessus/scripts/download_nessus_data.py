import os
import requests
from requests.exceptions import RequestException
import sqlite3
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

        # Convert the downloaded content to a string
        exported_scan_data = download_response.content.decode("utf-8")

        # Connect to the SQLite database
        db_path = "/var/csirt/source/scanner/db.sqlite3"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Get the current date and time
        current_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Insert exported scan data into the 'nessus_nessusdata' table
        insert_query = "INSERT INTO nessus_nessusdata (data, date, scan_id) VALUES (?, ?, ?);"
        cursor.execute(insert_query, (exported_scan_data, current_date, scan_id))
        conn.commit()

        conn.close()

        print("Exported scan data saved to the database.")
    except RequestException as e:
        print(f"Error: {e}")




if __name__ == "__main__":
    download_exported_scan()