from django.db import models
import json

# Create your models here.
class OKDomains(models.Model):
	domain = models.TextField(default=None)
	ip = models.TextField(default=None, null=True)
	http_code = models.TextField(default=None, null=True)
	http_redirect = models.TextField(default=None, null=True)
	registrar = models.TextField(default=None, null=True)
	server = models.TextField(default=None, null=True)
	urlscan = models.TextField(default=None, null=True)
	system = models.TextField(default=None, null=True)
	system_owner = models.TextField(default=None, null=True)
	comments = models.TextField(default=None, null=True)
	vulnerabilities = models.TextField(default=None, null=True)
	nmap = models.TextField(default=None, null=True)
	ip_data = models.TextField(default=None, null=True)
	changes_since_last = models.TextField(default=None, null=True)

class APIKeys(models.Model):
	key = models.TextField(default=None)
	user = models.TextField(default=None, null=True)
	authorized_tables = models.TextField(default=None, null=True)

class NessusData(models.Model):
	data = models.TextField(default=None)
	date = models.TextField(default=None, null=True)
	scan_id = models.TextField(default=None, null=True)

class TelegramData(models.Model):
	channel = models.TextField(default=None, null=True)
	message = models.TextField(default=None, null=True)
	message_data = models.TextField(default=None, null=True)
	message_id = models.TextField(default=None, null=True)
	message_date = models.TextField(default=None, null=True)
	date_added = models.TextField(default=None, null=True)

class TelegramDataIDs(models.Model):
    channel_link = models.TextField(unique=True)
    last_message_id = models.BigIntegerField()

class HelseCERTBlockList(models.Model):
    query_url = models.TextField(default=None)
    data = models.JSONField(default=dict) 
    comment = models.TextField(default=None, null=True)
    date_added = models.DateTimeField(auto_now_add=True)