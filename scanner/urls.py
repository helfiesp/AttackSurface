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
    
    # API
    path('api/domains/all', views.APIViewAllOKDomains, name="ViewAllOKDomains"),
    path('api/domains/search/<str:domain>', views.APIViewDomain, name="ViewDomain"),
    path('api/keys/add', views.AddApiKey, name="add_api_key"),
    path('api/keys/all', views.view_api_keys, name="all_api_keys"),
    path('api/keys/change_authorized_table/<int:api_key_id>/', views.change_authorized_tables, name='change_authorized_tables'),
    path('api/nessus/data/all', views.APIViewAllNessusData, name="view_all_nessus_data"),
    path('api/nessus/data/all_ips', views.APIViewAllNessusDataIPS, name="view_all_nessus_data_ips"),
    path('api/telegram/all', views.APIViewAllTelegramData, name="ViewAllTelegramData"),
    path('api/helsecert/blocklist', views.APIViewHelseCERTBlockList, name="APIViewHelseCERTBlockList"),
    path('api/helsecert/blocklist/queries', views.APIViewAvailableQueryURLs, name="APIViewAvailableQueryURLs"),
]
