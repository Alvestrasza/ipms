import hashlib
import http.client
import ipaddress
import json
import socket
import ssl
from urllib.parse import urlsplit


class PinnedHttpsError(Exception):
    pass


class _PinnedAddressHttpsConnection(http.client.HTTPSConnection):
    def __init__(
        self,
        hostname: str,
        port: int,
        address: str,
        *,
        timeout: int,
        context: ssl.SSLContext,
    ):
        super().__init__(hostname, port, timeout=timeout, context=context)
        self._validated_address = address

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._validated_address, self.port),
            self.timeout,
            self.source_address,
        )
        if self._tunnel_host:
            self._tunnel()
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


def _private_addresses(hostname: str, port: int) -> tuple[str, ...]:
    try:
        addresses = tuple(
            dict.fromkeys(
                item[4][0]
                for item in socket.getaddrinfo(
                    hostname,
                    port,
                    type=socket.SOCK_STREAM,
                )
            )
        )
    except socket.gaierror as exc:
        raise PinnedHttpsError("target_unresolved") from exc
    if not addresses:
        raise PinnedHttpsError("target_unresolved")
    for address in addresses:
        parsed = ipaddress.ip_address(address)
        if (
            not parsed.is_private
            or parsed.is_loopback
            or parsed.is_link_local
            or parsed.is_multicast
            or parsed.is_reserved
            or parsed.is_unspecified
        ):
            raise PinnedHttpsError("target_not_private")
    return addresses


class PinnedHttpsClient:
    def __init__(self, base_url: str, fingerprint_sha256: str, *, timeout: int = 20):
        parsed = urlsplit(base_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("A valid HTTPS connector URL is required.")
        self.hostname = parsed.hostname
        self.port = parsed.port or 443
        self.base_path = parsed.path.rstrip("/")
        self.fingerprint = fingerprint_sha256.lower()
        if len(self.fingerprint) != 64:
            raise ValueError("A SHA-256 certificate fingerprint is required.")
        try:
            int(self.fingerprint, 16)
        except ValueError as exc:
            raise ValueError("A SHA-256 certificate fingerprint is required.") from exc
        self.timeout = timeout

    def request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        if (
            method not in {"GET", "POST"}
            or not path.startswith("/")
            or "\r" in path
            or "\n" in path
        ):
            raise ValueError("The connector request is invalid.")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        request_headers = dict(headers or {})
        request_headers.setdefault("Host", self.hostname)
        connection_failed = False
        for address in _private_addresses(self.hostname, self.port):
            connection = _PinnedAddressHttpsConnection(
                self.hostname,
                self.port,
                address,
                timeout=self.timeout,
                context=context,
            )
            try:
                connection.connect()
                certificate = (
                    connection.sock.getpeercert(binary_form=True)
                    if connection.sock
                    else None
                )
                if (
                    not certificate
                    or hashlib.sha256(certificate).hexdigest() != self.fingerprint
                ):
                    raise PinnedHttpsError("certificate_changed")
                connection.request(
                    method,
                    f"{self.base_path}{path}",
                    body=body,
                    headers=request_headers,
                )
                response = connection.getresponse()
                content_length = response.getheader("Content-Length")
                if content_length and int(content_length) > 2 * 1024 * 1024:
                    raise PinnedHttpsError("response_too_large")
                payload = response.read(2 * 1024 * 1024 + 1)
                if len(payload) > 2 * 1024 * 1024:
                    raise PinnedHttpsError("response_too_large")
                return (
                    response.status,
                    {key.lower(): value for key, value in response.getheaders()},
                    payload,
                )
            except PinnedHttpsError:
                raise
            except (OSError, ssl.SSLError, http.client.HTTPException, ValueError):
                connection_failed = True
            finally:
                connection.close()
        if connection_failed:
            raise PinnedHttpsError("connection_failed")
        raise PinnedHttpsError("connection_failed")

    def json_get(self, path: str, *, authorization: str = "") -> dict:
        headers = {"Accept": "application/json"}
        if authorization:
            headers["Authorization"] = authorization
        status, _, payload = self.request("GET", path, headers=headers)
        if status != 200:
            raise PinnedHttpsError("api_request_failed")
        try:
            document = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PinnedHttpsError("api_response_invalid") from exc
        if not isinstance(document, dict):
            raise PinnedHttpsError("api_response_invalid")
        return document
