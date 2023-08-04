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

]
