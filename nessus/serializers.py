from rest_framework import serializers
from .models import OKDomains  # Replace with the actual model import

class OKDomainsSerializer(serializers.ModelSerializer):
    class Meta:
        model = OKDomains
        fields = '__all__'  # Include all fields from your model