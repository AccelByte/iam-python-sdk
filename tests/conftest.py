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

"""Conftest module."""


import pytest
from flask import Flask, jsonify

from iam_python_sdk.client import NewDefaultClient
from iam_python_sdk.config import Config
from iam_python_sdk.flask import IAM, token_required

from .mock import iam_mock, IAM_BASE_URL, client_id, client_secret


@pytest.fixture
def client(request: pytest.FixtureRequest):
    cfg = Config(
        BaseURL=IAM_BASE_URL,
        ClientID=client_id,
        ClientSecret=client_secret,
    )
    client = NewDefaultClient(cfg)

    return client


@pytest.fixture
def flask(request: pytest.FixtureRequest):
    app = Flask("test_app")

    app.config["IAM_BASE_URL"] = IAM_BASE_URL
    app.config["IAM_CLIENT_ID"] = client_id
    app.config["IAM_CLIENT_SECRET"] = client_secret

    iam = IAM()
    with iam_mock:
        iam.init_app(app)

    @app.route('/')
    def unprotected():
        return jsonify({'status': 'unprotected'})

    @app.route('/protected')
    @token_required({"resource": "ADMIN:NAMESPACE:{namespace}:CLIENT", "action": 2}, {"{namespace}": "sdktest"})
    def protected():
        return jsonify({'status': 'protected'})

    return app
