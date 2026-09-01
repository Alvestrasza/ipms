import ipaddress
import socket
import ssl
from unittest.mock import MagicMock, call, patch

from django.test import SimpleTestCase

from .certificates import (
    CertificateProbeError,
    _peer_certificate_from_addresses,
    _private_addresses,
    probe_windows_http_endpoint,
)


class CertificateAddressFailoverTests(SimpleTestCase):
    def test_private_addresses_preserve_resolver_order_and_remove_duplicates(self) -> None:
        with patch(
            "ipms.apps.discovery.certificates.socket.getaddrinfo",
            return_value=[
                (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fd00::10", 5985, 0, 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.254.0.4", 5985)),
                (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fd00::10", 5985, 0, 0)),
            ],
        ):
            addresses = _private_addresses("host.example.invalid", 5985)

        self.assertEqual(
            addresses,
            (ipaddress.ip_address("fd00::10"), ipaddress.ip_address("10.254.0.4")),
        )

    @patch("ipms.apps.discovery.certificates._peer_certificate")
    def test_certificate_probe_uses_next_address_after_connection_failure(
        self,
        peer_certificate: MagicMock,
    ) -> None:
        addresses = (
            ipaddress.ip_address("fd00::10"),
            ipaddress.ip_address("10.254.0.4"),
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        peer_certificate.side_effect = [OSError("unreachable"), b"certificate"]

        certificate = _peer_certificate_from_addresses(
            hostname="host.example.invalid",
            port=5986,
            addresses=addresses,
            context=context,
            timeout=5,
        )

        self.assertEqual(certificate, b"certificate")
        self.assertEqual(peer_certificate.call_count, 2)

    @patch("ipms.apps.discovery.certificates.http.client.HTTPConnection")
    @patch("ipms.apps.discovery.certificates._private_addresses")
    def test_windows_http_probe_uses_ipv4_after_unreachable_ipv6(
        self,
        private_addresses: MagicMock,
        http_connection: MagicMock,
    ) -> None:
        private_addresses.return_value = (
            ipaddress.ip_address("fd00::10"),
            ipaddress.ip_address("10.254.0.4"),
        )
        ipv6 = MagicMock()
        ipv6.request.side_effect = OSError("unreachable")
        ipv4 = MagicMock()
        ipv4.getresponse.return_value.status = 405
        http_connection.side_effect = [ipv6, ipv4]

        observation = probe_windows_http_endpoint(
            "http://host.example.invalid:5985/wsman",
            timeout=5,
        )

        self.assertTrue(observation.reachable)
        self.assertEqual(
            http_connection.call_args_list,
            [
                call("fd00::10", 5985, timeout=5),
                call("10.254.0.4", 5985, timeout=5),
            ],
        )
        ipv6.close.assert_called_once_with()
        ipv4.close.assert_called_once_with()

    @patch("ipms.apps.discovery.certificates.http.client.HTTPConnection")
    @patch("ipms.apps.discovery.certificates._private_addresses")
    def test_windows_http_probe_reports_timeout_when_all_addresses_time_out(
        self,
        private_addresses: MagicMock,
        http_connection: MagicMock,
    ) -> None:
        private_addresses.return_value = (
            ipaddress.ip_address("fd00::10"),
            ipaddress.ip_address("10.254.0.4"),
        )
        first = MagicMock()
        first.request.side_effect = socket.timeout()
        second = MagicMock()
        second.request.side_effect = socket.timeout()
        http_connection.side_effect = [first, second]

        with self.assertRaisesRegex(CertificateProbeError, "connection_timeout"):
            probe_windows_http_endpoint(
                "http://host.example.invalid:5985/wsman",
                timeout=5,
            )
