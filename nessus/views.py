from django.shortcuts import render
from .models import OKDomains
from .forms import OKDomainsForm
import requests
import os 

# Create your views here.
def index(request):
	context = {}
	return render(request, 'index.html', context)

def AttackSurfaceDomains(request):
	okdomains = OKDomains.objects.all()
	return render(request,'domains.html', {'okdomains': okdomains})

def URLScan(request, url):
	data = []
	base_query = 'https://urlscan.io/api/v1/search/?q=domain:{}'.format(url)
	header = {"Authorization": os.environ["URLSCAN_API_SECRET"]}
	result = requests.get(base_query, headers=header).json()
	result_total = result["total"]
	result_took = result["took"]
	for entry in result["results"]:
		data.append(entry)
	UpdateURLScanData(str(data))
	return render(request, "domains.html")



def UpdateURLScanData(data):
	# Updates the known_exploited field in the QualysDB
	existing_entry = OKDomains.objects.filter(domain=domain)
	if existing_entry.urlscan != data:  # Only update if the value has changed
		existing_entry.urlscan = data
		existing_entry.save()

def DomainURLScan(request):
	if request.method == 'POST':
		domains = request.POST.get('domains')
		domains = domains.split(",")
		try:
			for entry in domains:
				domain = entry.replace('http://','').replace('https://','').replace('/', '').replace('www.','')
				results = URLScan(request, domain)
		except Exception as E:
			print(E)

	return render(request, "domains.html")


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
			# Read CSV file and update database
			try:
				file = request.FILES['file']
				decoded_file = file.read().decode('ISO-8859-1').splitlines()
				reader = csv.DictReader(decoded_file)

				domains = []
				for row in reader:
					domain = row.get('domain')
					domains.append(domain)

				# Get all existing domains from database
				existing_domains = OKDomains.objects.filter(domain__in=domains)

				# Update the existing domains
				for existing_domain in existing_domains:
					# Update fields only if not empty
					if row.get('registrar'):
						existing_domain.registrar = row.get('registrar')
					if row.get('server'):
						existing_domain.server = row.get('server')
					if row.get('system'):
						existing_domain.system = row.get('system')
					if row.get('system_owner'):
						existing_domain.system_owner = row.get('system_owner')
					if row.get('comments'):
						existing_domain.comments = row.get('comments')
					existing_domain.changes_since_last = "Updated from upload"
					existing_domain.save()

				existing_db_domains = []
				for entry in existing_domains.values():
					existing_db_domains.append(entry["domain"])
				reader = csv.DictReader(decoded_file)
				for row in reader:
					domain = row.get('domain')
					if domain not in existing_db_domains:
						for entry in blacklist:
							if entry not in str(domain):
								new_domain = OKDomains(
									domain=domain,
									registrar=row.get('registrar'),
									server=row.get('server'),
									system=row.get('system'),
									system_owner=row.get('system_owner'),
									comments=row.get('comments'),
									changes_since_last="Added from upload"
								)
								new_domain.save()

				context = {'uploadmessage': 'Upload completed'}
				return render(request, 'domains_upload.html', context)

			except Exception as e:
				context = {'uploadmessage': 'Error during file upload: {}'.format(e)}
				return render(request, 'domains_upload.html', context)
	else:
		form = OKDomainsForm()
		context = {'form': form}
		return render(request, 'domains_upload.html', context)