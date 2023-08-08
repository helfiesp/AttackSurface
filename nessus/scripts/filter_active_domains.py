import sqlite3
import requests

def CheckDomain():
    connection = sqlite3.connect('db.sqlite3')  # Connect to the SQLite database
    cursor = connection.cursor()

    cursor.execute("SELECT domain FROM nessus_okdomains")
    all_domains = cursor.fetchall()
    domains_to_delete = []

    for entry in all_domains:
        domain = entry[0]
        https_url = "https://{}".format(domain)
        http_url = "http://{}".format(domain)

        try:
            # Try HTTPS first
            response = requests.get(https_url, allow_redirects=True)
            if response.url != https_url:
                cursor.execute("SELECT * FROM nessus_okdomains WHERE domain = ?", (domain,))
                existing_entry = cursor.fetchone()
                if existing_entry:
                    http_code = response.status_code
                    http_redirect = "oslo.kommune.no" if "https://www.oslo.kommune.no" in response.url else response.url
                    cursor.execute("UPDATE nessus_okdomains SET http_code = ?, http_redirect = ? WHERE domain = ?", (http_code, http_redirect, domain))
                    connection.commit()

        except requests.RequestException:
            try:
                # If HTTPS fails, try HTTP
                response = requests.get(http_url, allow_redirects=True)
                if response.url != http_url:
                    cursor.execute("SELECT * FROM nessus_okdomains WHERE domain = ?", (domain,))
                    existing_entry = cursor.fetchone()
                    if existing_entry:
                        http_code = response.status_code
                        http_redirect = "oslo.kommune.no" if "https://www.oslo.kommune.no" in response.url else response.url
                        cursor.execute("UPDATE nessus_okdomains SET http_code = ?, http_redirect = ? WHERE domain = ?", (http_code, http_redirect, domain))
                        connection.commit()

            except requests.RequestException:
                print("[ERROR]: Could not get HTTP/HTTPS response for: {}".format(domain))
                domains_to_delete.append(domain)

    # Delete domains with no HTTP/HTTPS response
    for domain_to_delete in domains_to_delete:
        cursor.execute("DELETE FROM nessus_okdomains WHERE domain = ?", (domain_to_delete,))
        connection.commit()
        print("[INFO]: Deleted entry for domain: {}".format(domain_to_delete))

    connection.close()

CheckDomain()
