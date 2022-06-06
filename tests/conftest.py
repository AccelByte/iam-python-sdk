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


import flask, fastapi, pytest

from iam_python_sdk.client import NewDefaultClient
from iam_python_sdk.async_client import NewAsyncClient
from iam_python_sdk.config import Config
from iam_python_sdk.flask import IAM as Flask_IAM
from iam_python_sdk.fastapi import IAM as FastAPI_IAM
from iam_python_sdk.fastapi import Settings

from .mock import client_id, client_secret, iam_base_url, iam_mock, flask_mock, fastapi_mock


@pytest.fixture
def iam_client():
    cfg = Config(
        BaseURL=iam_base_url,
        ClientID=client_id,
        ClientSecret=client_secret,
    )
    client = NewDefaultClient(cfg)

    return client


@pytest.fixture
def flask_app():
    app = flask.Flask("test_app")

    app.config["SERVER_NAME"] = "iam.mock"
    app.config["TESTING"] = True

    app.config["IAM_BASE_URL"] = iam_base_url
    app.config["IAM_CLIENT_ID"] = client_id
    app.config["IAM_CLIENT_SECRET"] = client_secret
    app.config["IAM_CORS_ENABLE"] = True

    app.register_blueprint(flask_mock)

    iam = Flask_IAM()
    with iam_mock:  # type: ignore
        iam.init_app(app)

    return app


@pytest.fixture
async def async_iam_client():
    cfg = Config(
        BaseURL=iam_base_url,
        ClientID=client_id,
        ClientSecret=client_secret,
    )
    client = NewAsyncClient(cfg)
    yield client
    await client.httpClient.close()


@pytest.fixture
async def fastapi_app():
    config = Settings(
        iam_base_url=iam_base_url,  # type: ignore
        iam_client_id=client_id,  # type: ignore
        iam_client_secret=client_secret,  # type: ignore
        iam_cors_enable=True,  # type: ignore
        iam_cors_headers="Device-Id,Device-Os,Device-Type"  # type: ignore
    )

    app = fastapi.FastAPI()

    # Grant token on FastAPI startup
    @app.on_event("startup")
    async def startup_event():
        app.state.iam = FastAPI_IAM(app, config)

    app.include_router(fastapi_mock)

    return app
