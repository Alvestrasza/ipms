from django.urls import path

from .views import DiscoveryJobDetailView, DiscoveryJobListView


app_name = "discovery"

urlpatterns = [
    path("", DiscoveryJobListView.as_view(), name="job-list"),
    path("<uuid:pk>/", DiscoveryJobDetailView.as_view(), name="job-detail"),
]
