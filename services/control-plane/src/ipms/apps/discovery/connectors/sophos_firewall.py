from dataclasses import dataclass
from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException
from xml.sax.saxutils import escape
from xml.etree.ElementTree import ParseError

from .pinned_https import PinnedHttpsClient, PinnedHttpsError


class SophosConnectorError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class SophosObservation:
    name: str
    software_version: str
    interfaces: list[dict]
    details: dict


def discover_sophos(
    client: PinnedHttpsClient,
    username: str,
    password: str,
) -> SophosObservation:
    xml_request = (
        "<Request><Login><Username>"
        + escape(username)
        + "</Username><Password>"
        + escape(password)
        + "</Password></Login><Get><Interface/></Get></Request>"
    ).encode()
    boundary = b"ipms-sophos-api-boundary"
    request = (
        b"--" + boundary + b"\r\n"
        b'Content-Disposition: form-data; name="reqxml"\r\n'
        b"Content-Type: application/xml\r\n\r\n"
        + xml_request
        + b"\r\n--"
        + boundary
        + b"--\r\n"
    )
    try:
        status, _, payload = client.request(
            "POST",
            "/webconsole/APIController",
            body=request,
            headers={
                "Content-Type": f"multipart/form-data; boundary={boundary.decode()}",
                "Accept": "application/xml",
            },
        )
    except PinnedHttpsError as exc:
        raise SophosConnectorError(str(exc)) from exc
    if status != 200:
        raise SophosConnectorError("api_request_failed")
    try:
        root = ElementTree.fromstring(
            payload,
            forbid_dtd=True,
            forbid_entities=True,
            forbid_external=True,
        )
    except (DefusedXmlException, ParseError, ValueError) as exc:
        raise SophosConnectorError("api_response_invalid") from exc
    statuses = [
        (element.text or "").strip().casefold()
        for element in root.iter()
        if element.tag.rsplit("}", 1)[-1].casefold() == "status"
    ]
    if not any("success" in value for value in statuses):
        raise SophosConnectorError("authentication_failed")
    interfaces = []
    for item in (
        element
        for element in root.iter()
        if element.tag.rsplit("}", 1)[-1] == "Interface"
    ):
        values = {
            child.tag.rsplit("}", 1)[-1]: (child.text or "")[:255]
            for child in item
            if len(child) == 0
        }
        name = values.get("Name") or values.get("Hardware") or values.get("Interface")
        if name and len(interfaces) < 256:
            interfaces.append(
                {
                    "name": name[:128],
                    "zone": values.get("Zone", "")[:128],
                    "ip_address": values.get("IPAddress", "")[:128],
                    "status": values.get("Status", "")[:64],
                }
            )
    return SophosObservation(
        name="Sophos Firewall",
        software_version=(root.attrib.get("APIVersion") or "")[:255],
        interfaces=interfaces,
        details={
            "api_version": (root.attrib.get("APIVersion") or "")[:64],
            "interface_count": len(interfaces),
        },
    )
