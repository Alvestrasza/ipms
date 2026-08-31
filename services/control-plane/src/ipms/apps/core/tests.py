import uuid
from unittest.mock import patch

from django.db import DatabaseError
from django.test import TestCase, override_settings
from django.urls import reverse


class PublicEndpointTests(TestCase):
    def test_api_information_is_public_and_versioned(self) -> None:
        response = self.client.get(reverse("core:api-information"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                "name": "IPMS Control Plane API",
                "version": "v1",
                "application_version": "0.1.14",
            },
        )

    def test_liveness_is_public(self) -> None:
        response = self.client.get(reverse("core:liveness"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})

    def test_valid_correlation_identifier_is_preserved(self) -> None:
        correlation_id = uuid.uuid4()
        response = self.client.get(
            reverse("core:liveness"),
            headers={"X-Correlation-ID": str(correlation_id)},
        )

        self.assertEqual(response.headers["X-Correlation-ID"], str(correlation_id))

    def test_invalid_correlation_identifier_is_replaced(self) -> None:
        response = self.client.get(
            reverse("core:liveness"),
            headers={"X-Correlation-ID": "not-a-valid-uuid"},
        )

        uuid.UUID(response.headers["X-Correlation-ID"])

    def test_readiness_checks_the_database(self) -> None:
        response = self.client.get(reverse("core:readiness"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})

    @override_settings(
        ALLOWED_HOSTS=["127.0.0.1"],
        SECURE_SSL_REDIRECT=True,
        SECURE_PROXY_SSL_HEADER=("HTTP_X_FORWARDED_PROTO", "https"),
    )
    def test_internal_https_proxy_request_is_not_redirected(self) -> None:
        response = self.client.get(
            reverse("core:readiness"),
            headers={"Host": "127.0.0.1", "X-Forwarded-Proto": "https"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})

    @override_settings(DEBUG=False)
    @patch("ipms.apps.core.views.connection.cursor", side_effect=DatabaseError)
    def test_readiness_failure_is_generic(self, mocked_cursor) -> None:
        response = self.client.get(reverse("core:readiness"))

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {"status": "unavailable"})
