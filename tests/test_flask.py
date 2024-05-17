# Copyright 2021 AccelByte Inc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for `iam_python_sdk.flask` module."""

import json

from flask import Flask, current_app

from iam_python_sdk.client import DefaultClient
from iam_python_sdk.flask import IAM, validate_referer_with_subdomain, validate_subdomain_with_namespace

from .mock import iam_mock, client_token


def test_init_iam(flask_app: Flask) -> None:
    with flask_app.app_context():
        iam = current_app.extensions.get("flask_iam")
        assert isinstance(iam, IAM)
        assert isinstance(iam.client, DefaultClient)
    with flask_app.test_request_context():
        iam = current_app.extensions.get("flask_iam")
        assert isinstance(iam, IAM)
        assert isinstance(iam.client, DefaultClient)


@iam_mock
def test_unprotected_endpoint(flask_app: Flask) -> None:
    with flask_app.test_client() as c:
        resp = c.get('/')
        data = json.loads(resp.data)
        assert data['status'] == 'unprotected'


@iam_mock
def test_protected_endpoint(flask_app: Flask) -> None:
    with flask_app.test_client() as c:
        # No token
        resp = c.get('/protected')
        assert resp.status_code == 401
        # Invalid headers token
        resp = c.get('/protected', headers={"Authorization": "Bearer invalid_token"})
        assert resp.status_code == 401
        # Valid headers token
        resp = c.get('/protected', headers={"Authorization": f"Bearer {client_token['access_token']}"})
        assert resp.status_code == 200
        # Invalid cookies token
        c.set_cookie("localhost", "access_token", "invalid_token")
        resp = c.get('/protected')
        assert resp.status_code == 401
        # Valid cookies token
        c.set_cookie("localhost", "access_token", client_token['access_token'])
        resp = c.get('/protected')
        assert resp.status_code == 200


@iam_mock
def test_protected_with_csrf_endpoint(flask_app: Flask) -> None:
    # Redirect URI: https://example.com
    with flask_app.test_client() as c:
        c.set_cookie("localhost", "access_token", client_token['access_token'])
        # Valid referer header
        resp = c.get('/protected_with_csrf', headers={"Referer": "https://example.com"})
        assert resp.status_code == 200
        # Invalid referer header
        resp = c.get('/protected_with_csrf', headers={"Referer": "http://foo.bar"})
        assert resp.status_code == 401


@iam_mock
def test_protected_with_csrf_endpoint_with_subdomain(flask_app: Flask) -> None:
    flask_app.config["IAM_SUBDOMAIN_VALIDATION_ENABLE"] = True

    # Redirect URI: https://example.com
    with flask_app.test_client() as c:
        c.set_cookie("localhost", "access_token", client_token['access_token'])
        # Valid referer header with subdomain
        resp = c.get('/protected_with_csrf', headers={"Referer": "https://sdktest.example.com"})
        assert resp.status_code == 200
        # Invalid referer header
        resp = c.get('/protected_with_csrf', headers={"Referer": "http://test.foo.bar"})
        assert resp.status_code == 401
        # Invalid scheme
        resp = c.get('/protected_with_csrf', headers={"Referer": "http://example.com"})
        assert resp.status_code == 401
        # Invalid domain
        resp = c.get('/protected_with_csrf', headers={"Referer": "https://example.net"})
        assert resp.status_code == 401


@iam_mock
def test_protected_with_cors_endpoint(flask_app: Flask) -> None:
    with flask_app.test_client() as c:
        c.set_cookie("localhost", "access_token", client_token['access_token'])
        resp = c.options(
            '/protected_with_cors',
            headers={"Origin": "http://127.0.0.1",
                     "Access-Control-Request-Method": "POST",
                     "Access-Control-Request-Headers": "Device-Id"
                     }
        )
        assert resp.status_code == 200
        # Preflight options have empty body response
        assert resp.get_json() is None
        # Assert default CORS header
        assert resp.headers.get("Access-Control-Allow-Origin", "") == "http://127.0.0.1"
        # Assert override CORS header
        assert resp.headers.get("Access-Control-Allow-Headers", "").find("Device-Id") != -1


def test_validate_referer_with_subdomain():
    # Assert wrong URL
    assert validate_referer_with_subdomain("wrongaddress", "anotherwrong") == False
    assert validate_referer_with_subdomain("https://example.com", "wrongaddress") == False
    assert validate_referer_with_subdomain("wrongaddress", "https://example.com") == False
    # Assert mismatch scheme
    assert validate_referer_with_subdomain("http://example.com", "https://example.com") == False
    # Assert mismatch domain
    assert validate_referer_with_subdomain("https://example.com", "https://example.net") == False

    # Assert exact match
    assert validate_referer_with_subdomain("https://example.com", "https://example.com") == True
    # Assert subdomain match
    assert validate_referer_with_subdomain("https://test.example.com", "https://example.com") == True


def test_validate_subdomain_with_namespace():
    # Assert valid subdomain
    assert validate_subdomain_with_namespace("example.com", "foo", []) == True
    # Assert valid subdomain with valid namespace
    assert validate_subdomain_with_namespace("foo.example.com", "foo", []) == True
    assert validate_subdomain_with_namespace("foo.bar.example.com", "foo", []) == True
    # Assert invalid subdomain
    assert validate_subdomain_with_namespace("bar.example.com", "foo", []) == False
    # Assert excluded namespace
    assert validate_subdomain_with_namespace("foo.example.com", "foo", ["foo"]) == True
    assert validate_subdomain_with_namespace("foo.example.com", "foo", ["bar"]) == True
    assert validate_subdomain_with_namespace("bar.example.com", "foo", ["bar"]) == False
