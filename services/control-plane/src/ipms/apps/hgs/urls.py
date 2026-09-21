# File Name: urls.py
# Version: v0.1.0 | Created: 2026-09-19 | Last Modified: 2026-09-19
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Fixed HGS Portal API routes.
from django.urls import path
from .views import HgsActionView, HgsDeploymentListView, HgsDeploymentView, HgsOverviewView

urlpatterns = [
    path("", HgsOverviewView.as_view()),
    path("deployments/", HgsDeploymentListView.as_view()),
    path("deployments/<uuid:pk>/", HgsDeploymentView.as_view()),
    *[path(f"deployments/<uuid:pk>/{operation}/", HgsActionView.as_view(operation=operation))
      for operation in ("inspect", "execute", "cancel", "reconcile", "resolve")],
]
