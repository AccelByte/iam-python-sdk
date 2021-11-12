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
from iam_python_sdk.flask import IAM

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
        assert resp.status_code == 403
        # Valid headers token
        resp = c.get('/protected', headers={"Authorization": f"Bearer {client_token['access_token']}"})
        assert resp.status_code == 200
        # Invalid cookies token
        c.set_cookie("localhost", "access_token", "invalid_token")
        resp = c.get('/protected')
        assert resp.status_code == 403
        # Valid cookies token
        c.set_cookie("localhost", "access_token", client_token['access_token'])
        resp = c.get('/protected')
        assert resp.status_code == 200


@iam_mock
def test_protected_with_csrf_endpoint(flask_app: Flask) -> None:
    with flask_app.test_client() as c:
        c.set_cookie("localhost", "access_token", client_token['access_token'])
        # Valid referer header
        resp = c.get('/protected_with_csrf', headers={"Referer": "http://127.0.0.1"})
        assert resp.status_code == 200
        # Invalid referer header
        resp = c.get('/protected_with_csrf', headers={"Referer": "http://foo.bar"})
        assert resp.status_code == 403


@iam_mock
def test_protected_with_cors_endpoint(flask_app: Flask) -> None:
    with flask_app.test_client() as c:
        c.set_cookie("localhost", "access_token", client_token['access_token'])
        resp = c.options('/protected_with_cors', headers={"Referer": "http://127.0.0.1"})
        assert resp.status_code == 200
        # Preflight options have empty body response
        assert resp.get_json() is None
        # Assert default CORS header
        assert resp.headers.get("Access-Control-Allow-Origin", "") == "*"
        # Assert override CORS header
        assert resp.headers.get("Access-Control-Allow-Headers", "").find("Device-Id") != -1
