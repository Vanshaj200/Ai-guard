import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app import require_admin


def _request(host: str, token: str | None = None) -> Request:
    headers = [(b"x-admin-token", token.encode())] if token is not None else []
    return Request({"type": "http", "method": "POST", "path": "/", "headers": headers, "client": (host, 1234)})


def test_no_token_configured_allows_localhost_only(monkeypatch):
    monkeypatch.delenv("ADMIN_TOKEN", raising=False)
    require_admin(_request("127.0.0.1"))  # local development works without a token
    with pytest.raises(HTTPException) as exc:
        require_admin(_request("10.0.0.5"))  # a deployed backend fails closed
    assert exc.value.status_code == 403


def test_token_configured_requires_matching_header(monkeypatch):
    monkeypatch.setenv("ADMIN_TOKEN", "s3cret-token")
    require_admin(_request("10.0.0.5", "s3cret-token"))
    for bad in (None, "", "wrong"):
        with pytest.raises(HTTPException) as exc:
            require_admin(_request("10.0.0.5", bad))
        assert exc.value.status_code == 401
    # Even localhost needs the token once one is configured
    with pytest.raises(HTTPException):
        require_admin(_request("127.0.0.1"))
