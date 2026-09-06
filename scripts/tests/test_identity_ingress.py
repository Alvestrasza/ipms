"""Exercise the tracked identity rate limit in an isolated loopback nginx.

No live service, certificate, credentials, database, or upstream is used.
"""

import http.client
import json
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Stub(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(204)
        self.end_headers()

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.do_GET()

    def log_message(self, *_args):
        pass


@unittest.skipUnless(shutil.which("nginx"), "nginx is required")
class IdentityIngressTests(unittest.TestCase):
    def test_tracked_limit_uses_json_and_leaves_account_reads_available(self):
        template = Path(__file__).resolve().parents[2] / "deploy/standalone/nginx-ipms.conf.template"
        upstream = ThreadingHTTPServer(("127.0.0.1", 0), Stub)
        thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        thread.start()
        with tempfile.TemporaryDirectory(prefix="ipms-identity-ingress-") as directory:
            root = Path(directory)
            with socket.socket() as port_probe:
                port_probe.bind(("127.0.0.1", 0))
                port = port_probe.getsockname()[1]
            config = template.read_text(encoding="utf-8")
            config = re.sub(r"^\s*(?:listen|ssl_[a-z_]+|access_log|error_log) .*?;\s*$", "", config, flags=re.M)
            config = config.replace("server {", f"server {{\nlisten 127.0.0.1:{port};", 1)
            config = config.replace("@@PUBLIC_HOST@@", "localhost")
            config = config.replace("include proxy_params;", "include /etc/nginx/proxy_params;")
            config = re.sub(r"http://127\.0\.0\.1:(?:8000|3000|9420)", f"http://127.0.0.1:{upstream.server_port}", config)
            candidate = root / "nginx.conf"
            candidate.write_text(
                f"daemon off; master_process off; pid {root}/nginx.pid; error_log stderr crit;\n"
                "events { worker_connections 64; }\nhttp { access_log off;\n"
                f"client_body_temp_path {root}/body; proxy_temp_path {root}/proxy;\n{config}\n}}\n",
                encoding="utf-8",
            )
            process = subprocess.Popen(["nginx", "-p", f"{root}/", "-c", str(candidate)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                for _ in range(100):
                    if process.poll() is not None:
                        self.fail(process.communicate()[1].decode())
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                            break
                    except OSError:
                        time.sleep(0.02)
                routes = [
                    "/api/v1/auth/account/rename/",
                    "/api/v1/auth/account/password/",
                    "/api/v1/auth/users/11111111-1111-4111-8111-111111111111/rename/",
                    "/api/v1/auth/users/11111111-1111-4111-8111-111111111111/password/",
                ]
                statuses = []
                for index in range(6):
                    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                    connection.request("POST", routes[index % len(routes)], "{}", {"Content-Type": "application/json"})
                    response = connection.getresponse()
                    statuses.append(response.status)
                    body = response.read()
                    if response.status == 429:
                        self.assertEqual(json.loads(body)["error"]["code"], "rate_limited")
                        self.assertEqual(response.getheader("Retry-After"), "60")
                    connection.close()
                self.assertEqual(statuses, [204, 204, 204, 204, 429, 429])
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                connection.request("GET", "/api/v1/auth/account/")
                self.assertEqual(connection.getresponse().status, 204)
                connection.close()
            finally:
                process.terminate()
                process.communicate(timeout=5)
                upstream.shutdown()
                upstream.server_close()


if __name__ == "__main__":
    unittest.main()
