# File Name: urls.py
# Version: v0.1.0 | Created: 2026-09-14 | Last Modified: 2026-09-14
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Modular Security API routes.
from django.urls import path
from .views import BaselineListView, BaselineSystemListView

urlpatterns = [
    path("baselines/", BaselineListView.as_view(), name="security-baselines"),
    path("baselines/<slug:baseline_id>/systems/", BaselineSystemListView.as_view(), name="security-baseline-systems"),
]
