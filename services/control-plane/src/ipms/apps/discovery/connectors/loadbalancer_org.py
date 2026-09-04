import base64
import json
from dataclasses import dataclass

from .pinned_https import PinnedHttpsClient, PinnedHttpsError


class LoadbalancerConnectorError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class LoadbalancerObservation:
    name: str
    model: str
    software_version: str
    serial_number: str
    uptime_seconds: int | None
    interfaces: list[dict]
    details: dict


def discover_loadbalancer(
    client: PinnedHttpsClient,
    username: str,
    password: str,
    api_key: str,
) -> LoadbalancerObservation:
    if not api_key:
        raise LoadbalancerConnectorError("api_key_unavailable")
    authorization = "Basic " + base64.b64encode(
        f"{username}:{password}".encode()
    ).decode()
    encoded_api_key = base64.b64encode(api_key.encode()).decode()
    request = json.dumps(
        {"lbcli": [{"action": "address", "function": "get"}]},
        separators=(",", ":"),
    ).encode()
    try:
        status, _, payload = client.request(
            "POST",
            "/api/v2/",
            body=request,
            headers={
                "Accept": "application/json",
                "Authorization": authorization,
                "Content-Type": "application/json",
                "X-LB-APIKEY": encoded_api_key,
            },
        )
    except PinnedHttpsError as exc:
        raise LoadbalancerConnectorError(str(exc)) from exc
    if status in {401, 403}:
        raise LoadbalancerConnectorError("authentication_failed")
    if status != 200:
        raise LoadbalancerConnectorError("api_request_failed")
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LoadbalancerConnectorError("api_response_invalid") from exc
    if not isinstance(document, dict) or "lbapi" not in document:
        raise LoadbalancerConnectorError("api_response_invalid")
    return LoadbalancerObservation(
        name="",
        model="Loadbalancer.org ADC",
        software_version="",
        serial_number="",
        uptime_seconds=None,
        interfaces=[],
        details={"api_status": "reachable", "address_inventory": "collected"},
    )
