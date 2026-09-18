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
from .gpo_production import ManagedGposView, GpoPreflightsView, ManagedJobDetailView
from .gpo_approvals import GpoApprovalPolicyView, GpoDomainAuthorizationView, GpoApproveView
from .gpo_reconciliation import GpoReconciliationsView, GpoReconciliationAcceptView

from .gpo_overrides import OverrideView, OverrideDetailView, OverrideCatalogView
from .collections import (
    DeviceCollectionsView, DeviceCollectionView, PolicyCollectionsView,
    PolicyCollectionView, PolicyCollectionPreviewView, PolicyCollectionDeploymentsView,
)

urlpatterns = [
    path('device-collections/', DeviceCollectionsView.as_view(), name='security-device-collections'),
    path('device-collections/<uuid:collection_id>/', DeviceCollectionView.as_view(), name='security-device-collection'),
    path('policy-collections/', PolicyCollectionsView.as_view(), name='security-policy-collections'),
    path('policy-collections/<uuid:collection_id>/', PolicyCollectionView.as_view(), name='security-policy-collection'),
    path('policy-collections/<uuid:collection_id>/preview/', PolicyCollectionPreviewView.as_view(), name='security-policy-collection-preview'),
    path('policy-collections/<uuid:collection_id>/deployments/', PolicyCollectionDeploymentsView.as_view(), name='security-policy-collection-deployments'),
    path('overrides/', OverrideView.as_view(), name='security-overrides'),
    path('overrides/<uuid:override_id>/', OverrideDetailView.as_view(), name='security-override'),
    path('override-catalog/', OverrideCatalogView.as_view(), name='security-override-catalog'),
    path('gpo-imports/<uuid:job_id>/reconciliations/', GpoReconciliationsView.as_view(), name='security-gpo-reconciliations'),
    path('gpo-imports/<uuid:job_id>/reconciliations/<uuid:reconciliation_id>/accept/', GpoReconciliationAcceptView.as_view(), name='security-gpo-reconciliation-accept'),
    path('domain-settings/<uuid:domain_id>/managed-gpos/', ManagedGposView.as_view(), name='security-managed-gpos'),
    path('domain-settings/<uuid:domain_id>/gpo-preflights/', GpoPreflightsView.as_view(), name='security-gpo-preflights'),
    path('gpo-imports/<uuid:job_id>/', ManagedJobDetailView.as_view(), name='security-gpo-job-detail'),
    path('gpo-approval-policy/', GpoApprovalPolicyView.as_view(), name='security-gpo-approval-policy'),
    path('domain-settings/<uuid:domain_id>/gpo-authorization/', GpoDomainAuthorizationView.as_view(), name='security-gpo-authorization'),
    path('gpo-imports/<uuid:job_id>/approve/', GpoApproveView.as_view(), name='security-gpo-approve'),
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
