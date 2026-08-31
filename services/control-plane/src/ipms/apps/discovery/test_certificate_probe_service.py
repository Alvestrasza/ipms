import os
import threading
from http.server import ThreadingHTTPServer
from unittest.mock import patch

from django.test import SimpleTestCase

from .certificate_probe_service import CertificateProbeHandler
from .certificates import CertificateObservation, request_bmc_certificate_probe


class CertificateProbeServiceTests(SimpleTestCase):
    def test_authenticated_local_boundary_returns_normalized_observation(self) -> None:
        expected = CertificateObservation(
            fingerprint_sha256="ab" * 32,
            subject="CN=synthetic-bmc",
            issuer="CN=synthetic-ca",
            serial_number="01",
            valid_from="2026-01-01T00:00:00+00:00",
            valid_until="2027-01-01T00:00:00+00:00",
            dns_names=("synthetic.invalid",),
            trusted_by_system=False,
        )
        server = ThreadingHTTPServer(("127.0.0.1", 0), CertificateProbeHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        with (
            patch.dict(os.environ, {"IPMS_CERTIFICATE_PROBE_TOKEN": "boundary-token"}),
            patch(
                "ipms.apps.discovery.certificate_probe_service.probe_bmc_certificate",
                return_value=expected,
            ),
        ):
            thread.start()
            try:
                actual = request_bmc_certificate_probe(
                    "https://192.0.2.10/",
                    timeout=5,
                    port=server.server_port,
                    token="boundary-token",
                )
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
        self.assertEqual(actual, expected)
