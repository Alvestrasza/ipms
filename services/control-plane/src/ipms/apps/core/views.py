from django.db import DatabaseError, connection
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.status import HTTP_503_SERVICE_UNAVAILABLE


@api_view(["GET"])
@authentication_classes([])
@permission_classes([AllowAny])
def api_information(request: Request) -> Response:
    return Response({"name": "IPMS Control Plane API", "version": "v1"})


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
