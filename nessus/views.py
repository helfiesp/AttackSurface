from django.shortcuts import render
from .models import OKDomains
from .forms import OKDomainsForm
from nessus import views
import requests
import os 
from django.shortcuts import render, get_object_or_404
import json
import time
import subprocess
from django.contrib.auth.models import User
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
import socket
import sqlite3
from datetime import datetime


def index(request):
    context = {}
    return render(request, 'index.html', context)   


def UpdateDomainComments(request, pk):
    okdomain = get_object_or_404(OKDomains, pk=pk)
    if request.method == 'POST':
        new_comments = request.POST.get('comments')
        okdomain.comments = new_comments
        okdomain.save()
    okdomains = OKDomains.objects.all()
    return render(request, 'domains.html', {'okdomains': okdomains})

# Example usage:
def AttackSurfaceDomains(request):
    okdomains = OKDomains.objects.all()
    for domain_entry in okdomains:
        if domain_entry.urlscan:
            # Load the urlscan data into JSON.
            domain_entry.urlscan = json.loads(domain_entry.urlscan)

            # Modify the time variable to only display the day of the scan.
            domain_entry.urlscan["task"]["time"] = domain_entry.urlscan["task"]["time"].split("T")[0]

        if domain_entry.nmap:
            domain_entry.nmap = FilterNMAP(domain_entry.nmap)
        if domain_entry.ip_data:
            domain_entry.ip_data = json.loads(domain_entry.ip_data)
    return render(request, 'domains.html', {'okdomains': okdomains})


def DomainIPCheck(request):
    all_domains = OKDomains.objects.values_list('domain')
    for entry in all_domains:
        # Use subprocess.Popen to run the ping command and capture its output
        ping_process = subprocess.Popen(['ping', entry[0]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = ping_process.communicate()

        # Parse the output to extract the IP address
        for line in stdout.splitlines():
            if 'Pinging' in line:
                ip_start = line.find('[') + 1
                ip_end = line.find(']')
                ip = line[ip_start:ip_end]
                # Update database entry
                existing_entry = OKDomains.objects.get(domain=entry[0])
                existing_entry.ip = ip
                existing_entry.save()
    return AttackSurfaceDomains(request)


def IPGeoLookup(request):
    if request.method == 'POST':
        # Fetches all IP addresses from the database.
        all_ip_addresses = list(OKDomains.objects.values_list('ip', flat=True))
        for ip_address in all_ip_addresses:
            api_endpoint = "https://api.iplocation.net/?ip={}".format(ip_address)
            # Fetch data from the API
            response = requests.get(api_endpoint)
            if response.status_code == 200:
                api_data = response.json()
                api_data_json = json.dumps(api_data)
                print(api_data)

                # Update database entries
                existing_entries = OKDomains.objects.filter(ip=dict(api_data)["ip"])

                for existing_entry in existing_entries:
                    existing_entry.ip_data = api_data_json
                    existing_entry.save()
                existing_entries = OKDomains.objects.filter(ip=dict(api_data)["ip"])
            else:
                print("Error")

    return AttackSurfaceDomains(request)


def URLScan(request, url):
    data = []
    base_query = 'https://urlscan.io/api/v1/search/?q=domain:{}'.format(url)
    header = {"Authorization": os.environ["URLSCAN_API_SECRET"]}
    result = requests.get(base_query, headers=header).json()
    try:
        result_total = result["total"]
        result_took = result["took"]
        for entry in result["results"]:
            data.append(entry)
        return json.dumps(data)  # Return the JSON data instead of saving it directly
    except:
        print("[{}] Error: Could not parse URLScan result: {}".format(datetime.now().strftime("%d/%m/%Y %H:%M:%S"), result))

def UpdateURLScanData(domain, data, existing_entry):
    # Parse the JSON data into a list of dictionaries (assuming the data is a list)
    data_list = json.loads(data)
    if data_list:  # Check if the list is not empty
        data_dict = data_list[0]  # Access the dictionary inside the list
        existing_entry.urlscan = json.dumps(data_dict)  # Save the dictionary as a JSON string
        existing_entry.url = data_dict["task"].get("domain")
        existing_entry.tlsissuer = data_dict["page"].get("tlsIssuer")
        existing_entry.screenshot = data_dict.get("screenshot")
        existing_entry.server = data_dict["page"].get("server")
        existing_entry.save()

def DomainURLScan(request):
    all_domains = OKDomains.objects.values_list('domain')
    counter = 0
    for entry in all_domains:
        domain = entry[0].replace('http://', '').replace('https://', '').replace('/', '').replace('www.', '')
        existing_entry = OKDomains.objects.filter(domain=domain).first()
        if existing_entry and not existing_entry.urlscan:
          # Check if the urlscan field is empty
            data = URLScan(request, domain)
            if data:
                UpdateURLScanData(domain, data, existing_entry)
                print("Updating: {} | {}".format(domain, data))  # Update the data only if the urlscan field is empty
                counter += 1
                if counter >= 24:
                    print("[URLScan] Limit reached, waiting 15 minutes before continuing. Last domain was: {}".format(domain))
                    time.sleep(900)
            else:
                print("[URLScan] Could not get data for: {}".format(domain))
        else:
            print("Existing entry and data for: {}".format(domain))
        
    return AttackSurfaceDomains(request)


def NMAPDomainScan(request):
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


def FilterNMAP(nmap_results):
    import re
    open_ports = []
    pattern = r"(\d+)/tcp\s+open"

    matches = re.findall(pattern, nmap_results)
    for port in matches:
        open_ports.append(int(port))

    return open_ports

def NessusScan(request):
    from requests.exceptions import RequestException
    from django.http import HttpResponse
    try:
        access_key = os.environ["NESSUS_API_ACCESS_KEY"]
        secret_key = os.environ["NESSUS_API_SECRET_KEY"]
        scan_id = 20  # Update this with the actual scan ID
        url = "https://nessus.okcsirt.no"

        headers = {
            "X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}",
            "Content-Type": "application/json"
        }

        # Choose the export format "CSV"
        export_format_value = "csv"

        # Fetch the exported scan file
        download_url = f"{url}/scans/{scan_id}"
        response = requests.get(download_url, headers=headers, verify=False)
        response.raise_for_status()

        # Return the content of the file as an attachment
        content = response.content
        return HttpResponse(content, content_type="text/csv")
    except RequestException as e:
        content = f"Error: {e}"
        return HttpResponse(content)


def CheckDomain(request):
    all_domains = OKDomains.objects.values_list('domain')
    domains_to_delete = []

    for entry in all_domains:
        domain = entry[0]
        https_url = "https://{}".format(domain)
        http_url = "http://{}".format(domain)
        
        try:
            # Try HTTPS first
            response = requests.get(https_url, allow_redirects=True)
            if response.url != https_url:
                existing_entry = OKDomains.objects.get(domain=domain)
                existing_entry.http_code = response.status_code
                if "https://www.oslo.kommune.no" in response.url:
                    existing_entry.http_redirect = "oslo.kommune.no"
                else:
                    existing_entry.http_redirect = response.url
                existing_entry.save()

        except requests.RequestException:
            try:
                # If HTTPS fails, try HTTP
                response = requests.get(http_url, allow_redirects=True)
                if response.url != http_url:
                    existing_entry = OKDomains.objects.get(domain=domain)
                    existing_entry.http_code = response.status_code
                    if "https://www.oslo.kommune.no" in response.url:
                        existing_entry.http_redirect = "oslo.kommune.no"
                    else:
                        existing_entry.http_redirect = response.url
                    existing_entry.save()

            except requests.RequestException:
                print("[ERROR]: Could not get HTTP/HTTPS response for: {}".format(domain))
                domains_to_delete.append(domain)

    # Delete domains with no HTTP/HTTPS response
    for domain_to_delete in domains_to_delete:
        try:
            entry_to_delete = OKDomains.objects.get(domain=domain_to_delete)
            entry_to_delete.delete()
            print("[INFO]: Deleted entry for domain: {}".format(domain_to_delete))
        except OKDomains.DoesNotExist:
            pass

    return AttackSurfaceDomains(request)


def InsertOKDomain(request):
    blacklist = ['powerapps']
    if request.method == 'POST':
        form = OKDomainsForm(request.POST)
        if form.is_valid():
            # Extract form data and create a new OKDomains object
            domain = form.cleaned_data['domain']

            # Check if domain is in blacklist 
            for entry in blacklist:
                if entry in str(domain):
                    context = {'uploadmessage': 'Error: Domain is blacklisted'}
                    return render(request, 'domains_upload.html', context)

            okdomains, created = OKDomains.objects.get_or_create(domain=domain)

            if created:
                # New domain, set all fields from form data
                okdomains.registrar = form.cleaned_data['registrar']
                okdomains.server = form.cleaned_data['server']
                okdomains.system = form.cleaned_data['system']
                okdomains.system_owner = form.cleaned_data['system_owner']
                okdomains.comments = form.cleaned_data['comments']
                okdomains.changes_since_last = "Initial upload"
            else:
                # Existing domain, update fields only if not empty
                if form.cleaned_data['registrar']:
                    okdomains.registrar = form.cleaned_data['registrar']
                if form.cleaned_data['server']:
                    okdomains.server = form.cleaned_data['server']
                if form.cleaned_data['system']:
                    okdomains.system = form.cleaned_data['system']
                if form.cleaned_data['system_owner']:
                    okdomains.system_owner = form.cleaned_data['system_owner']
                if form.cleaned_data['comments']:
                    okdomains.comments = form.cleaned_data['comments']
                okdomains.changes_since_last = "Updated from upload"

            okdomains.save()
            context = {'uploadmessage': 'Upload completed'}
            return render(request, 'domains_upload.html', context)

        elif request.method == 'POST' and request.FILES:
            uploaded_file = request.FILES['file']  # Assuming you have a file input field named 'file' in your form

            # Decode the uploaded file and split it into lines
            file_content = uploaded_file.read().decode('utf-8')
            domain_names = file_content.strip().split('\n')

            for domain_name in domain_names:
                domain_name = domain_name.strip().replace("www.", "")

                # Check if the domain already exists in the database
                if not OKDomains.objects.filter(domain=domain_name).exists():
                    # Create a new OKDomains object if the domain is not present
                    ok_domain = OKDomains(domain=domain_name)
                    ok_domain.save()

    else:
        form = OKDomainsForm()
        context = {'form': form}
        return render(request, 'domains_upload.html', context)


# API

def APIGetDomain(request, domain):
    print("REQUEST METHOD: {}".format(request.method))
    if request.method == 'GET':
        try:
            data_from_domain = OKDomains.objects.filter(domain=str(domain)).values()
            if not data_from_domain.exists():
                return JsonResponse({'error': 'No data available for the provided domain'}, status=404)

            return JsonResponse(list(data_from_domain), safe=False)
        except OKDomains.DoesNotExist:
            return JsonResponse({'error': 'Invalid domain'}, status=400)

    return JsonResponse({'error': 'Invalid request'}, status=400) 
