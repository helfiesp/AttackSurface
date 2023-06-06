from django.db import models

# Create your models here.
class OKDomains(models.Model):
	domain = models.TextField(default=None)
	registrar = models.TextField(default=None, null=True)
	server = models.TextField(default=None, null=True)
	urlscan = models.TextField(default=None, null=True)
	system = models.TextField(default=None, null=True)
	system_owner = models.TextField(default=None, null=True)
	comments = models.TextField(default=None, null=True)
	vulnerabilities = models.TextField(default=None, null=True)
	changes_since_last = models.TextField(default=None, null=True)
