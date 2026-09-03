import importlib.util
import os
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase


class AgentGatewaySettingsTests(SimpleTestCase):
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
            "IPMS_AGENT_WINDOWS_VERSION": "0.1.33",
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
        self.assertEqual(module.AGENT_WINDOWS_VERSION, "0.1.33")
