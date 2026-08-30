import uuid
from collections.abc import Callable

from django.http import HttpRequest, HttpResponse


CORRELATION_HEADER = "X-Correlation-ID"


class CorrelationIdMiddleware:
    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        supplied_value = request.headers.get(CORRELATION_HEADER, "")
        try:
            correlation_id = uuid.UUID(supplied_value)
        except (ValueError, AttributeError):
            correlation_id = uuid.uuid4()

        request.correlation_id = correlation_id
        response = self.get_response(request)
        response[CORRELATION_HEADER] = str(correlation_id)
        return response
