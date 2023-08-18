"""
URL configuration for scanner project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from nessus.views import *
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.index, name='index'),
    
    path('domains', views.AttackSurfaceDomains,name="domains"),
    path('domains/insert', views.InsertOKDomain,name="domains_insert"),
    path('domains/urlscan', views.DomainURLScan,name="domains_urlscan"),
    path('domains/ip_check', views.DomainIPCheck,name="domains_ip_check"),
    path('domains/nmap_scan_domain', views.NMAPDomainScan, name='nmap_domain_scan'),
    path('domains/ip_geolocation_lookup', views.IPGeoLookup, name='ip_geolocation_lookup'),
    path('domains/update_comments/<int:pk>/', views.UpdateDomainComments, name='update_comments'),

    path('nessus/scan', views.NessusScan,name="nessus_scan"),
    path('nessus/data', views.NessusDataView,name="nessus_data_view"),

    path('domains/check', views.CheckDomain,name="check_domain"),

    # API
    path('api/domains/all', views.APIViewAllOKDomains, name="ViewAllOKDomains"),
    path('api/domains/search/<str:domain>', views.APIViewDomain, name="ViewDomain"),
    path('api/keys/add', views.AddApiKey, name="add_api_key"),
    path('api/keys/all', views.view_api_keys, name="all_api_keys"),
    path('api/keys/change_authorized_table/<int:api_key_id>/', views.change_authorized_tables, name='change_authorized_tables'),
    path('api/nessus/data/all', views.APIViewAllNessusData, name="view_all_nessus_data"),


]
