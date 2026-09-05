"""Exercise the adapted guacd against synthetic TLS peers, never real systems.

Requires cryptography and a staged native-console build. Dummy credentials only;
reports counts/booleans, never wire payloads. No CA store or host configuration
is modified. Every network listener is ephemeral and loopback-only.
"""
import argparse
import asyncio
import contextlib
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

VM = "11111111-2222-4333-8444-555555555555"


def certificate(directory, name, *, issuer=None, ca=False, start=-1, end=1):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(subject)
               .issuer_name(issuer[0].subject if issuer else subject)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now + timedelta(days=start))
               .not_valid_after(now + timedelta(days=end))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
               .add_extension(x509.SubjectAlternativeName([x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))]), critical=False))
    cert = builder.sign(issuer[1] if issuer else key, hashes.SHA256())
    cert_path, key_path = directory / f"{name}.pem", directory / f"{name}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    os.chmod(key_path, 0o600)
    return cert, key, cert_path, key_path


def guac(*values):
    return (",".join(f"{len(str(value))}.{value}" for value in values) + ";").encode()


async def instruction(reader):
    result = []
    while True:
        prefix = await asyncio.wait_for(reader.readuntil(b"."), 10)
        assert len(prefix) <= 7 and prefix[:-1].isdigit()
        size = int(prefix[:-1])
        assert size <= 65536
        result.append((await reader.readexactly(size)).decode("ascii"))
        end = await reader.readexactly(1)
        if end == b";":
            return result
        assert end == b","


async def close(writer):
    writer.close()
    with contextlib.suppress(Exception):
        await asyncio.wait_for(writer.wait_closed(), 2)


async def exercise(port, peer_cert, approved, *, marker="true", tls12_only=False):
    observed = {"pdu": False, "tls": False, "application_bytes": 0, "connected": False,
                "peer_error": "", "tls_version": ""}
    completed = asyncio.Event()
    peers = set()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if tls12_only:
        context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(peer_cert[2], peer_cert[3])

    async def peer(reader, writer):
        task = asyncio.current_task()
        peers.add(task)
        try:
            observed["connected"] = True
            header = await asyncio.wait_for(reader.readexactly(4), 8)
            size = struct.unpack("<I", header)[0]
            assert 20 <= size <= 256
            packet = header + await reader.readexactly(size - 4)
            assert packet[4:16] == struct.pack("<III", 0, 2, 0)
            assert struct.unpack("<H", packet[16:18])[0] * 2 == len(packet[18:])
            assert packet[18:].decode("utf-16-le") in (VM + "\x00", VM + ";EnhancedMode=0\x00")
            observed["pdu"] = True
            # VMConnect preconnection disables X.224 security negotiation.
            await writer.start_tls(context, ssl_handshake_timeout=8)
            observed["tls"] = True
            observed["tls_version"] = writer.get_extra_info("ssl_object").version()
            data = await asyncio.wait_for(reader.read(16384), 8)
            observed["application_bytes"] = len(data)
        except (Exception, asyncio.CancelledError) as error:
            # Exception type only: never print TLS/RDP bytes, even in a failure.
            observed["peer_error"] = type(error).__name__
        finally:
            await close(writer)
            completed.set()
            peers.discard(task)

    server = await asyncio.start_server(peer, "127.0.0.1", 0)
    target_port = server.sockets[0].getsockname()[1]
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(guac("select", "rdp"))
        await writer.drain()
        args = await instruction(reader)
        assert args[0] == "args" and "ipms-strict-certificate" in args
        params = {"hostname": "127.0.0.1", "port": str(target_port), "security": "vmconnect",
                  "preconnection-blob": VM, "preconnection-id": "0", "username": "synthetic-console-user",
                  "password": "synthetic-not-a-real-password", "domain": "",
                  "ipms-strict-certificate": marker, "cert-fingerprints": approved,
                  "ignore-cert": "false", "cert-tofu": "false", "disable-auth": "false",
                  "disable-copy": "true", "disable-paste": "true", "disable-audio": "true",
                  "enable-drive": "false", "enable-printing": "false", "timeout": "5"}
        values = [name if name.startswith("VERSION_") else params.get(name, "") for name in args[1:]]
        writer.write(guac("size", 1024, 768, 96) + guac("audio") + guac("video") + guac("image", "image/png") + guac("connect", *values))
        await writer.drain()
        async def consume():
            while await reader.read(65536):
                pass
        drain = asyncio.create_task(consume())
        peer_done = asyncio.create_task(completed.wait())
        try:
            await asyncio.wait((peer_done, drain), timeout=12, return_when=asyncio.FIRST_COMPLETED)
            if not peer_done.done() and observed["connected"]:
                # A rejected certificate can close guacd before the server's
                # TLS state machine has reported that close. Preserve its result.
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(asyncio.shield(peer_done), 2)
        finally:
            drain.cancel()
            peer_done.cancel()
            await asyncio.gather(drain, peer_done, return_exceptions=True)
    finally:
        await close(writer)
        server.close()
        await server.wait_closed()
        outstanding = tuple(peers)
        for task in outstanding:
            task.cancel()
        await asyncio.gather(*outstanding, return_exceptions=True)
    return observed


async def main(prefix, adaptation):
    with tempfile.TemporaryDirectory(prefix="ipms-native-certificate-tests-") as temporary:
        directory = Path(temporary)
        good = certificate(directory, "approved")
        changed = certificate(directory, "changed")
        root = certificate(directory, "synthetic-root", ca=True)
        signed = certificate(directory, "ca-signed", issuer=root)
        expired = certificate(directory, "expired", start=-3, end=-1)
        future = certificate(directory, "future", start=1, end=3)
        pin = lambda fixture: "sha256:" + fixture[0].fingerprint(hashes.SHA256()).hex()
        harness = directory / "verify-certificate"
        subprocess.run(["cc", "-O2", "-Wall", "-Wextra", "-Werror", "-I", str(adaptation),
                        str(adaptation / "certificate-test.c"), "-o", str(harness), "-lcrypto"], check=True)
        cases = [("approved", pin(good), good, 0, 2), ("mismatch", pin(good), changed, 0, 0),
                 ("ca-mismatch", pin(good), signed, 0, 0), ("expired", pin(expired), expired, 0, 0),
                 ("future", pin(future), future, 0, 0), ("redirect", pin(good), good, 1, 0),
                 ("empty-pin", "", good, 0, 0), ("wildcard", "sha256:*", good, 0, 0),
                 ("pin-list", pin(good) + "," + pin(changed), good, 0, 0)]
        for name, approved, fixture, flags, expected in cases:
            result = subprocess.check_output([str(harness), approved, str(fixture[2]), str(flags)], text=True)
            assert int(result) == expected, name
        subprocess.run(["openssl", "verify", "-CAfile", str(root[2]), str(signed[2])], check=True, stdout=subprocess.DEVNULL)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        environment = os.environ.copy()
        environment["LD_LIBRARY_PATH"] = str(prefix / "lib")
        environment["HOME"] = str(directory)
        environment["XDG_CONFIG_HOME"] = str(directory / "config")
        environment["SSL_CERT_FILE"] = str(root[2])
        with (directory / "guacd.log").open("wb") as log:
            process = subprocess.Popen([str(prefix / "sbin/guacd"), "-f", "-b", "127.0.0.1", "-l", str(port), "-L", "info"],
                                       env=environment, stdout=log, stderr=log, start_new_session=True)
            try:
                for _ in range(100):
                    if process.poll() is not None:
                        raise AssertionError("staged guacd exited before fixture: " + (directory / "guacd.log").read_text(errors="replace")[-2000:])
                    try:
                        _, writer = await asyncio.open_connection("127.0.0.1", port)
                        await close(writer)
                        break
                    except OSError:
                        await asyncio.sleep(0.05)
                else:
                    raise AssertionError("staged guacd did not listen: " + (directory / "guacd.log").read_text(errors="replace")[-2000:])
                results = {}
                for name, approved, fixture in [("approved", pin(good), good),
                                                ("approved-tls12", pin(good), good),
                                                ("changed", pin(good), changed),
                                                ("ca-trusted-mismatch", pin(good), signed),
                                                ("expired", pin(expired), expired), ("future", pin(future), future)]:
                    try:
                        result = await exercise(port, fixture, approved, tls12_only=name == "approved-tls12")
                    except Exception as error:
                        raise AssertionError("synthetic adapter fixture failed: " + (directory / "guacd.log").read_text(errors="replace")[-2000:]) from error
                    results[name] = result
                    if name.startswith("approved"):
                        assert result["pdu"] and result["tls"] and result["application_bytes"] > 0, (name, result, (directory / "guacd.log").read_text(errors="replace")[-4000:])
                        if name == "approved-tls12":
                            assert result["tls_version"] == "TLSv1.2", result
                    else:
                        assert result["pdu"] and result["application_bytes"] == 0, (name, result)
                print(json.dumps({"helper_cases": len(cases), "actual_guacd": results}, sort_keys=True))
            finally:
                import signal
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=10)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--prefix", required=True, type=Path)
    parser.add_argument("--adaptation", required=True, type=Path)
    arguments = parser.parse_args()
    asyncio.run(main(arguments.prefix.resolve(), arguments.adaptation.resolve()))
