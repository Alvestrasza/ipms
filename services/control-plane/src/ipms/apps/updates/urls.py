# File Name: urls.py
# Version: v0.1.0
# Created: 2026-09-13
# Last Modified: 2026-09-13
# Author: Alice Endelgard
# Organization: Alvestrasza Corporation
# Description: Fixed WSUS metadata reception and tenant comparison routes.
from django.urls import path

from . import views

urlpatterns = [
    path("update-sources/", views.SourceListView.as_view()),
    path("update-sources/<uuid:pk>/", views.SourceDetailView.as_view()),
    path("update-sources/<uuid:pk>/rotate-token/", views.SourceRotateView.as_view()),
    path("update-sources/<uuid:pk>/snapshots/", views.SnapshotReceiveView.as_view()),
    path("update-sources/<uuid:pk>/comparison/", views.ComparisonView.as_view()),
    path("update-sources/<uuid:pk>/servers/<uuid:server_id>/updates/", views.ServerUpdatesView.as_view()),
]
