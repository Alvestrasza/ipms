from django.db import DatabaseError, connection
from django.http import JsonResponse
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.status import HTTP_503_SERVICE_UNAVAILABLE


@api_view(["GET"])
@authentication_classes([])
@permission_classes([AllowAny])
def api_information(request: Request) -> Response:
    return Response(
        {
            "name": "IPMS Control Plane API",
            "version": "v1",
            "application_version": "0.2.12",
        }
    )


@api_view(["GET"])
@authentication_classes([])
@permission_classes([AllowAny])
def liveness(request: Request) -> Response:
    return Response({"status": "ok"})


@api_view(["GET"])
@authentication_classes([])
@permission_classes([AllowAny])
def readiness(request: Request) -> Response:
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
    except DatabaseError:
        return Response(
            {"status": "unavailable"},
            status=HTTP_503_SERVICE_UNAVAILABLE,
        )
    return Response({"status": "ok"})


def csrf_failure(request, reason="") -> JsonResponse:
    correlation_id = getattr(request, "correlation_id", None)
    response = JsonResponse(
        {
            "error": {
                "code": "csrf_failed",
                "message": "The request could not be completed.",
                "correlation_id": str(correlation_id) if correlation_id else None,
            }
        },
        status=403,
    )
    if correlation_id:
        response["X-Correlation-ID"] = str(correlation_id)
    return response
