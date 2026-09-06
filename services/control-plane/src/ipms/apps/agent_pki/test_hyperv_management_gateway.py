"""Wire-boundary tests; no provider or live management system is contacted."""

from types import SimpleNamespace
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.test import SimpleTestCase

from .gateway import _management_exchange, _parse_http_request, _unique_management_json


class ManagementGatewayTests(SimpleTestCase):
    def setUp(self):
        self.enrollment = SimpleNamespace(device_uri="urn:ipms:agent:test")
        self.envelope = {
            "type": "hyperv_management", "device_uri": self.enrollment.device_uri,
            "correlation_id": "management-test", "action": "poll",
        }

    def test_route_remains_bounded(self):
        path, _, length = _parse_http_request(
            b"POST /v1/hyperv-management HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n"
        )
        self.assertEqual((path, length), ("/v1/hyperv-management", 100))
        with self.assertRaises(ValidationError):
            _parse_http_request(b"POST /v1/hyperv-management HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 65537\r\n\r\n")

    def test_duplicate_keys_at_every_depth_are_rejected(self):
        for body in (b'{"action":"poll","action":"claim"}', b'{"parameters":{"id":"a","id":"b"}}'):
            with self.subTest(body=body), self.assertRaises(ValidationError):
                _unique_management_json(body)

    @patch("ipms.apps.agent_pki.hyperv_management.offer_management_job", return_value=None)
    def test_poll_does_not_grant_execution(self, offer):
        self.assertEqual(_management_exchange(self.enrollment, self.envelope), {
            "type": "accepted", "correlation_id": "management-test", "management_job": None,
        })
        offer.assert_called_once_with(self.enrollment)

    @patch("ipms.apps.agent_pki.hyperv_management.claim_management_job")
    @patch("ipms.apps.agent_pki.hyperv_management.offer_management_job")
    def test_unknown_fields_identity_or_action_cannot_dispatch(self, offer, claim):
        for changes in ({"command": "arbitrary"}, {"device_uri": "another-agent"},
                        {"type": "inventory"}, {"action": "execute"}, {"action": []},
                        {"correlation_id": ""}, {"correlation_id": "x" * 129}):
            with self.subTest(changes=changes), self.assertRaises(ValidationError):
                _management_exchange(self.enrollment, {**self.envelope, **changes})
        offer.assert_not_called()
        claim.assert_not_called()

    @patch("ipms.apps.agent_pki.hyperv_management.claim_management_job", return_value={"authorized": False, "mode": "observe"})
    def test_claim_preserves_denied_execution(self, claim):
        document = {**self.envelope, "action": "claim", "job_id": "job", "input_digest": "digest"}
        result = _management_exchange(self.enrollment, document)
        self.assertIs(result["management_claim"]["authorized"], False)
        claim.assert_called_once_with(self.enrollment, job_id="job", input_digest="digest")

    @patch("ipms.apps.agent_pki.hyperv_management.record_management_result")
    def test_result_settlement_does_not_offer_another_job(self, record):
        document = {**self.envelope, "action": "result", "job_id": "job", "status": "failed",
                    "phase": "completed", "progress": 100, "result_code": "provider_failed", "snapshot": None}
        self.assertEqual(_management_exchange(self.enrollment, document), {
            "type": "accepted", "correlation_id": "management-test",
        })
        record.assert_called_once_with(self.enrollment, job_id="job", status="failed",
                                       phase="completed", progress=100, result_code="provider_failed", snapshot=None)
