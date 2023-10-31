import os
import requests
from datetime import datetime
from requests.exceptions import RequestException
import sqlite3
import sys
import time

# Append the path to the 'misc' directory to sys.path
sys.path.append("/var/csirt/source/scanner")
from misc import secrets


def NMAPDomainScan():
    if request.method == 'POST':
        domains = request.POST.get('domains').split(",")
        for domain_name in domains:
            try:
                # Run Nmap as an external command
                nmap_args = ["nmap", "-T4", "-F", domain_name]
                nmap_output = subprocess.run(nmap_args, capture_output=True, text=True)

                # Extract the scan output from the completed process
                nmap_data = nmap_output.stdout

                # Create or update the record in the OKDomains table
                ok_domain, created = OKDomains.objects.get_or_create(domain=domain_name)
                ok_domain.nmap = nmap_data
                ok_domain.save()

            except subprocess.CalledProcessError as e:
                # Handle any errors that occurred while running Nmap
                error_message = f"Error running Nmap for domain '{domain_name}': {e}"
                print(error_message)

    return AttackSurfaceDomains(request)