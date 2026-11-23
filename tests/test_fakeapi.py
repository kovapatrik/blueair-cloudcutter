"""The fake provisioning API."""

from __future__ import annotations

import http.client
import json

from blueair_cloudcutter.fakeapi import FakeApiServer


def _post(port: int, path: str) -> dict:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("POST", path, body=b"{}", headers={"Content-Length": "2"})
        response = conn.getresponse()
        body = response.read()
        assert response.status == 200
        return json.loads(body)
    finally:
        conn.close()


def test_auth_and_register_responses():
    server = FakeApiServer(host="127.0.0.1", port=0).start()
    try:
        auth = _post(server.port, "/prod/c/authenticate?client_id=x")
        assert auth["token_type"] == "Bearer"
        assert "access_token" in auth

        register = _post(server.port, "/prod/c/register-device-hash")
        assert "Activated" in register["message"]
    finally:
        server.stop()


def test_urls_use_ap_gateway():
    server = FakeApiServer(host="127.0.0.1", port=0).start()
    try:
        api, auth = server.urls("192.168.50.1")
        assert api == f"http://192.168.50.1:{server.port}/prod"
        assert auth.endswith("/prod/c/authenticate")
    finally:
        server.stop()


def test_wait_for_both_provisioning_calls():
    server = FakeApiServer(host="127.0.0.1", port=0).start()
    try:
        assert not server.wait_for_provisioning(0.1)
        _post(server.port, "/prod/c/authenticate")
        assert not server.wait_for_provisioning(0.1)
        _post(server.port, "/prod/c/register-device-hash")
        assert server.wait_for_provisioning(0.1)
    finally:
        server.stop()
