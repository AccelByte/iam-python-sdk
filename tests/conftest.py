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
from iam_python_sdk.client import NewDefaultClient
from iam_python_sdk.config import Config

from .mock import IAM_BASE_URL, client_id, client_secret


@pytest.fixture
def client(request: pytest.FixtureRequest):
    cfg = Config(
        IAM_BASE_URL,
        ClientID=client_id,
        ClientSecret=client_secret,
    )
    client = NewDefaultClient(cfg)

    return client
