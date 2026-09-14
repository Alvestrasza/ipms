# File Name: urls.py
# Version: v0.1.0 | Created: 2026-09-14 | Last Modified: 2026-09-14
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Modular Security API routes.
from django.urls import path
from .views import BaselineListView, BaselineSystemListView
from .administration import BaselineSettingsView, BaselineSettingView
from .scan_views import BaselineScansView, BaselineFindingsView
from .domains import DomainSettingsView, DomainSettingView
from .gpo_views import DomainGpoImportsView

urlpatterns = [
    path('domain-settings/', DomainSettingsView.as_view(), name='security-domain-settings'),
    path('domain-settings/<uuid:domain_id>/', DomainSettingView.as_view(), name='security-domain-setting'),
    path('domain-settings/<uuid:domain_id>/gpo-imports/', DomainGpoImportsView.as_view(), name='security-domain-gpo-imports'),
    path("baseline-settings/", BaselineSettingsView.as_view(), name="security-baseline-settings"),
    path("baseline-settings/<slug:baseline_id>/", BaselineSettingView.as_view(), name="security-baseline-setting"),
    path("baselines/", BaselineListView.as_view(), name="security-baselines"),
    path("baselines/<slug:baseline_id>/systems/", BaselineSystemListView.as_view(), name="security-baseline-systems"),
    path("baselines/<slug:baseline_id>/scans/", BaselineScansView.as_view(), name="security-baseline-scans"),
    path("baselines/<slug:baseline_id>/systems/<uuid:system_id>/findings/", BaselineFindingsView.as_view(), name="security-baseline-findings"),
]
