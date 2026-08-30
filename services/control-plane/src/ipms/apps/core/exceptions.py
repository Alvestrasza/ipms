from typing import Any

from rest_framework.response import Response
from rest_framework.views import exception_handler


ERROR_CODES = {
    400: "invalid_request",
    401: "authentication_failed",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    429: "rate_limited",
}


def ipms_exception_handler(exc: Exception, context: dict[str, Any]) -> Response | None:
    response = exception_handler(exc, context)
    if response is None:
        return None

    request = context.get("request")
    correlation_id = getattr(request, "correlation_id", None)
    error_code = ERROR_CODES.get(response.status_code, "request_failed")
    response.data = {
        "error": {
            "code": error_code,
            "message": "The request could not be completed.",
            "correlation_id": str(correlation_id) if correlation_id else None,
        }
    }
    return response
