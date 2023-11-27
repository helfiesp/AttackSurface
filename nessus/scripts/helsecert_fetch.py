import os
import requests
import sqlite3
from datetime import datetime
import sys

sys.path.append("/var/csirt/source/scanner")
import secrets

print(secrets)

# Environment variables for API credentials
API_USERNAME = os.environ["HELSECERT_API_USERNAME"]
API_PASSWORD = os.environ["HELSECERT_API_PASSWORD"]

# Database path
DB_PATH = "/var/csirt/source/scanner/db.sqlite3"

# API endpoints to fetch data from
CHANNEL_LINKS = [
    {'url': 'https://data.helsecert.no/blocklist/v2?f=list_context&t=domain&category=phishing',
     'comment': 'Phishing domains with context'},
    {'url': 'https://data.helsecert.no/blocklist/v2?f=list_context&t=domain,ipv4&category=phishing',
     'comment': 'Phishing domains and ipv4 with context'},
    {'url': 'https://data.helsecert.no/blocklist/v2?f=list_context&t=domain,ipv4',
     'comment': 'Malicious ipv4 and domains with context'},
]

def fetch_data(url):
    """Fetch data from the API."""
    response = requests.get(url, auth=(API_USERNAME, API_PASSWORD))
    if response.status_code == 200:
        return response.text
    else:
        print(f"Failed to fetch data from {url}")
        return None

def insert_data_into_db(db_path, data, query_url, comment):
    """Insert data into the SQLite database."""
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO HelseCERTBlockList (query_url, data, comment, date_added)
                VALUES (?, ?, ?, ?)
            """, (query_url, data, comment, datetime.now()))
            conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    except Exception as e:
        print(f"Exception in _query: {e}")

def main():
    for channel in CHANNEL_LINKS:
        url = channel['url']
        comment = channel['comment']
        data = fetch_data(url)
        if data:
            insert_data_into_db(DB_PATH, data, url, comment)

if __name__ == "__main__":
    main()
