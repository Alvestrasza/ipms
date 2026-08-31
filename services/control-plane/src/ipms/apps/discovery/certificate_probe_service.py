from __future__ import annotations

import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .certificates import CertificateProbeError, probe_bmc_certificate


MAX_REQUEST_BYTES = 4096


class CertificateProbeHandler(BaseHTTPRequestHandler):
    server_version = "IPMSCertificateProbe/1"

    def log_message(self, format: str, *args) -> None:
        # Do not emit target addresses or certificate contents to the journal.
        return

    def _response(self, status: int, document: dict) -> None:
        body = json.dumps(document, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        expected = os.environ.get("IPMS_CERTIFICATE_PROBE_TOKEN", "")
        supplied = self.headers.get("Authorization", "")
        if not expected or not hmac.compare_digest(supplied, f"Bearer {expected}"):
            self._response(403, {"error": "certificate_probe_forbidden"})
            return
        if self.path != "/probe":
            self._response(404, {"error": "certificate_probe_not_found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if not 0 < length <= MAX_REQUEST_BYTES:
            self._response(400, {"error": "certificate_probe_invalid_request"})
            return
        try:
            document = json.loads(self.rfile.read(length))
            base_url = str(document["base_url"])
            timeout = float(document["timeout"])
            if not 5 <= timeout <= 60:
                raise ValueError
        except (
            KeyError,
            TypeError,
            ValueError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ):
            self._response(400, {"error": "certificate_probe_invalid_request"})
            return
        try:
            observation = probe_bmc_certificate(base_url, timeout=timeout)
        except CertificateProbeError as exc:
            self._response(422, {"error": exc.code})
            return
        self._response(200, observation.public_document())


def main() -> None:
    port = int(os.environ.get("IPMS_CERTIFICATE_PROBE_PORT", "8010"))
    if not os.environ.get("IPMS_CERTIFICATE_PROBE_TOKEN", ""):
        raise SystemExit("IPMS_CERTIFICATE_PROBE_TOKEN is required")
    server = ThreadingHTTPServer(("127.0.0.1", port), CertificateProbeHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
