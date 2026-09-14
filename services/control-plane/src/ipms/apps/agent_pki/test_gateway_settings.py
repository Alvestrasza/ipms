# File Name: test_gateway_settings.py
# Version: v0.1.1 | Last Modified: 2026-09-14
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Validate real gateway initialization separately from portal settings.
import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase


class AgentGatewaySettingsTests(SimpleTestCase):
    def test_security_receiver_loads_with_real_gateway_settings(self) -> None:
        environment = {
            **os.environ,
            "DJANGO_SETTINGS_MODULE": "ipms_control_plane.settings.gateway",
            "IPMS_GATEWAY_SECRET_KEY": "test-gateway-secret",
            "IPMS_AGENT_PKI_MASTER_KEY": "test-agent-pki-key",
            "IPMS_AGENT_WINDOWS_PACKAGE_PATH": "/tmp/ipms-agent.zip",
            "IPMS_AGENT_WINDOWS_PACKAGE_SHA256": "a" * 64,
            "IPMS_AGENT_WINDOWS_VERSION": "0.2.31",
            "IPMS_DATABASE_NAME": "unused_gateway_import_test",
            "IPMS_DATABASE_USER": "test-only",
            "IPMS_DATABASE_PASSWORD": "test-only",
            "IPMS_DATABASE_HOST": "127.0.0.1",
        }
        # A separate process must initialize the actual service app registry;
        # the parent test settings already register all Control Plane models.
        result = subprocess.run(
            [sys.executable, "-c", "\n".join((
                "import django",
                "django.setup()",
                "from ipms.apps.security.scans import security_exchange",
                "from ipms.apps.security.gpo_jobs import security_gpo_exchange",
                "from ipms.apps.security.models import GpoImportJob, DomainSecuritySettings",
                "from ipms.apps.security.models import BaselineScanJob, BaselineAssessment",
                "assert callable(security_exchange)",
                "assert callable(security_gpo_exchange)",
                "assert GpoImportJob._meta.get_field('domain').related_model is DomainSecuritySettings",
                "assert BaselineScanJob._meta.get_field('assessment').related_model is BaselineAssessment",
            ))],
            env=environment, capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_gateway_settings_include_pinned_agent_artifact(self) -> None:
        settings_path = (
            Path(__file__).resolve().parents[3]
            / "ipms_control_plane"
            / "settings"
            / "gateway.py"
        )
        environment = {
            "IPMS_GATEWAY_SECRET_KEY": "test-gateway-secret",
            "IPMS_AGENT_PKI_MASTER_KEY": "test-agent-pki-key",
            "IPMS_AGENT_WINDOWS_PACKAGE_PATH": "/tmp/ipms-agent.zip",
            "IPMS_AGENT_WINDOWS_PACKAGE_SHA256": "a" * 64,
            "IPMS_AGENT_WINDOWS_VERSION": "0.1.36",
            "IPMS_DATABASE_NAME": "ipms",
            "IPMS_DATABASE_USER": "ipms",
            "IPMS_DATABASE_PASSWORD": "test-password",
            "IPMS_DATABASE_HOST": "127.0.0.1",
        }
        spec = importlib.util.spec_from_file_location(
            "ipms_gateway_settings_contract",
            settings_path,
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        with mock.patch.dict(os.environ, environment, clear=True):
            spec.loader.exec_module(module)

        self.assertEqual(module.AGENT_WINDOWS_PACKAGE_PATH, "/tmp/ipms-agent.zip")
        self.assertEqual(module.AGENT_WINDOWS_PACKAGE_SHA256, "a" * 64)
        self.assertEqual(module.AGENT_WINDOWS_VERSION, "0.1.36")
