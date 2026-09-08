"""Independent field-policy tests; no host connection or VM mutation."""

from copy import deepcopy

from django.test import SimpleTestCase

from ipms.apps.core.exceptions import PublicApiError
from .hyperv_management_schema import validate_parameters, validate_settings_change


class SettingsFieldPolicyTests(SimpleTestCase):
    def setUp(self):
        self.snapshot = {
            "schema_version": 2,
            "state": "running",
            "settings": {
                "name": "Test VM",
                "notes": "Original",
                "processor": {"count": 4},
                "memory": {
                    "startup_mib": 2048,
                    "minimum_mib": 1024,
                    "maximum_mib": 4096,
                    "dynamic_enabled": True,
                },
            },
        }

    def patch(self, section, values, state="running"):
        return {"section": section, "values": values, "expected_state": state}

    def check(self, parameters, allowed):
        original = deepcopy(self.snapshot)
        if allowed:
            validate_parameters("settings_update", parameters)
            validate_settings_change(parameters, self.snapshot)
        else:
            with self.assertRaises(PublicApiError):
                validate_parameters("settings_update", parameters)
                validate_settings_change(parameters, self.snapshot)
        self.assertEqual(self.snapshot, original)

    def test_online_fields_and_direction(self):
        for section, values, allowed in (
            ("general", {"name": "Renamed"}, True),
            ("general", {"notes": "Updated"}, True),
            ("processor", {"count": 8}, False),
            ("memory", {"minimum_mib": 512}, True),
            ("memory", {"maximum_mib": 8192}, True),
            ("memory", {"minimum_mib": 1536}, False),
            ("memory", {"maximum_mib": 3072}, False),
            ("memory", {"startup_mib": 3072}, False),
            ("memory", {"dynamic_enabled": False}, False),
            ("memory", {"maximum_mib": 8192, "startup_mib": 2048}, False),
        ):
            with self.subTest(section=section, values=values):
                self.check(self.patch(section, values), allowed)

    def test_static_or_unknown_memory_is_not_assumed_hot_capable(self):
        for mode in (False, None):
            self.snapshot["settings"]["memory"]["dynamic_enabled"] = mode
            self.check(self.patch("memory", {"maximum_mib": 8192}), False)
            self.check(self.patch("memory", {"startup_mib": 3072}), False)

    def test_stopped_patch_merges_and_validates_memory_tuple(self):
        self.snapshot["state"] = "stopped"
        self.check(self.patch("processor", {"count": 8}, "stopped"), True)
        self.check(self.patch("memory", {"startup_mib": 3072}, "stopped"), True)
        self.check(self.patch("memory", {"startup_mib": 8192}, "stopped"), False)
        self.check(
            self.patch("memory", {"startup_mib": 8192, "maximum_mib": 8192}, "stopped"),
            True,
        )

    def test_state_binding_and_legacy_fail_closed(self):
        for state in ("paused", "saved", "unknown", "stopped"):
            self.snapshot["state"] = state
            self.check(self.patch("general", {"notes": "Updated"}), False)
        self.snapshot["state"] = "running"
        self.snapshot["schema_version"] = 1
        self.check(self.patch("general", {"notes": "Updated"}), False)
        legacy = {
            "section": "general",
            "values": {"name": "Test VM", "notes": "Updated"},
        }
        self.check(legacy, False)
        self.snapshot["state"] = "stopped"
        self.check(legacy, True)

    def test_unknown_values_not_defaulted_and_unrelated_unknown_does_not_block(self):
        self.snapshot["settings"]["name"] = None
        self.check(self.patch("general", {"notes": "Updated"}), True)
        self.check(self.patch("general", {"name": "Renamed"}), False)
        self.snapshot["settings"]["memory"]["startup_mib"] = None
        self.check(self.patch("memory", {"maximum_mib": 8192}), False)

    def test_empty_unchanged_and_injected_fields_rejected(self):
        for section, values in (
            ("general", {}),
            ("general", {"name": "Test VM"}),
            ("general", {"name": "  "}),
            ("general", {"notes": "bad\x7f"}),
            ("memory", {"maximum_mib": True}),
            ("memory", {"maximum_mib": 1.5}),
            ("memory", {"maximum_mib": 2**40 + 1}),
            ("memory", {"maximum_mib": 8192, "InstanceID": "forbidden"}),
            ("network", {"switch": "forbidden"}),
        ):
            with self.subTest(section=section, values=values):
                self.check(self.patch(section, values), False)
