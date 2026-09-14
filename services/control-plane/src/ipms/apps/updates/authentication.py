# File Name: authentication.py
# Version: v0.1.0
# Created: 2026-09-13
# Last Modified: 2026-09-13
# Author: Alice Endelgard
# Organization: Alvestrasza Corporation
# Description: Source-bound write-only authentication for WSUS metadata ingress.
import hashlib
import hmac
import secrets

from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed

from .models import UpdateSource


def token_digest(token):
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def issue_token(source):
    token = f"{source.id}.{secrets.token_urlsafe(32)}"
    source.token_hash = token_digest(token)
    source.save(update_fields=("token_hash",))
    return token


class SourcePrincipal:
    is_authenticated = True


class WsusSourceAuthentication(BaseAuthentication):
    def authenticate_header(self, request):
        return "Bearer"

    def authenticate(self, request):
        try:
            header = get_authorization_header(request).decode("ascii")
            scheme, token = header.split(" ")
            if scheme != "Bearer" or len(token) > 128:
                raise ValueError()
            source = UpdateSource.objects.select_related("tenant").get(
                id=request.parser_context["kwargs"]["pk"], enabled=True, tenant__status="active"
            )
            if not hmac.compare_digest(source.token_hash, token_digest(token)):
                raise ValueError()
        except (ValueError, UnicodeError, UpdateSource.DoesNotExist) as exc:
            raise AuthenticationFailed("Invalid source credential.") from exc
        return SourcePrincipal(), source
