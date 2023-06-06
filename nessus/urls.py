from django.urls import include, path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('domains', views.AttackSurfaceDomains,name="domains"),
    path('domains/insert', views.InsertOKDomain,name="domains_insert"),
]
