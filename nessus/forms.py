from django import forms
from .models import OKDomains

class OKDomainsForm(forms.Form):
    domain = forms.CharField(max_length=255, required=True)
    registrar = forms.CharField(max_length=255, required=False)
    server = forms.CharField(max_length=255, required=False)
    system = forms.CharField(max_length=255, required=False)
    system_owner = forms.CharField(max_length=255, required=False)
    comments = forms.CharField(max_length=255, required=False)
    vulnerabilities = forms.CharField(max_length=255, required=False)