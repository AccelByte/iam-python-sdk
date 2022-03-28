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

"""Tests for `iam_python_sdk.fastapi` module."""

import json, pytest

from fastapi import FastAPI
from fastapi.testclient import TestClient

from iam_python_sdk.async_client import AsyncClient
from iam_python_sdk.fastapi import IAM

from .mock import iam_mock, client_token


@iam_mock
def test_init_iam(fastapi_app: FastAPI) -> None:
    with TestClient(fastapi_app):
        assert isinstance(fastapi_app.state.iam, IAM)
        assert isinstance(fastapi_app.state.iam.client, AsyncClient)


@iam_mock
def test_unprotected_endpoint(fastapi_app: FastAPI) -> None:
    with TestClient(fastapi_app) as c:
        resp = c.get('/')
        data = resp.json()
        assert data['status'] == 'unprotected'


@iam_mock
def test_protected_endpoint(fastapi_app: FastAPI) -> None:
    with TestClient(fastapi_app) as c:
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
        # c.set_cookie("localhost", "access_token", "invalid_token")
        resp = c.get('/protected', cookies={"access_token": "invalid_token"})
        assert resp.status_code == 403
        # Valid cookies token
        resp = c.get('/protected', cookies={'access_token': client_token['access_token']})
        assert resp.status_code == 200


@iam_mock
def test_protected_with_csrf_endpoint(fastapi_app: FastAPI) -> None:
    with TestClient(fastapi_app) as c:
        # Valid referer header
        resp = c.get('/protected_with_csrf', headers={"Referer": "http://127.0.0.1"}, cookies={"access_token": client_token['access_token']})
        assert resp.status_code == 200
        # Invalid referer header
        resp = c.get('/protected_with_csrf', headers={"Referer": "http://foo.bar"}, cookies={"access_token": client_token['access_token']})
        assert resp.status_code == 403


@iam_mock
def test_protected_with_cors_endpoint(fastapi_app: FastAPI) -> None:
    with TestClient(fastapi_app) as c:
        resp = c.options('/protected_with_cors', headers={"Origin": "http://127.0.0.1", "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "Device-Id"}, cookies={"access_token": client_token['access_token']})
        assert resp.status_code == 200
        # Preflight options have empty body response
        assert resp.text == 'OK'
        # # Assert default CORS header
        assert resp.headers.get("Access-Control-Allow-Origin", "") == "http://127.0.0.1"
        # Assert override CORS header
        assert resp.headers.get("Access-Control-Allow-Headers", "").find("Device-Id") != -1
