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

"""Tests for `iam_python_sdk.client` module."""

import pytest

from iam_python_sdk.cache import Cache
from iam_python_sdk.client import DefaultClient, HttpClient
from iam_python_sdk.config import Config
from iam_python_sdk.models import JWTClaims, Permission
from iam_python_sdk.errors import ClientTokenGrantError, NoLocalValidationError, StartLocalValidationError, \
    ValidateScopeError

from .mock import iam_mock, role_id


def test_NewDefaultClient(client: DefaultClient) -> None:
    assert isinstance(client.config, Config)
    assert isinstance(client.httpClient, HttpClient)
    assert isinstance(client.rolePermissionCache, Cache)
    assert isinstance(client.clientInfoCache, Cache)


@iam_mock
def test_ClientTokenGrant(client: DefaultClient) -> None:
    try:
        client.ClientTokenGrant()
        assert client._tokenRefreshActive is True
    except ClientTokenGrantError:
        assert False


@iam_mock
def test_ClientToken(client: DefaultClient) -> None:
    assert client.ClientToken() == ""
    client.ClientTokenGrant()
    assert client.ClientToken() != ""


@iam_mock
def test_StartLocalValidation(client: DefaultClient) -> None:
    try:
        client.StartLocalValidation()
        assert client._localValidationActive is True
    except StartLocalValidationError:
        assert False


@iam_mock
def test_ValidateAccessToken(client: DefaultClient) -> None:
    client.ClientTokenGrant()
    assert client.ValidateAccessToken(client.ClientToken()) is True
    assert client.ValidateAccessToken("This is an invalid token") is False


@iam_mock
def test_ValidateAndParseClaims(client: DefaultClient) -> None:
    client.ClientTokenGrant()
    # Raise error if StartLocalValidation not called yet
    with pytest.raises(NoLocalValidationError):
        jwt_claims = client.ValidateAndParseClaims(client.ClientToken())

    client.StartLocalValidation()
    jwt_claims = client.ValidateAndParseClaims(client.ClientToken())
    assert isinstance(jwt_claims, JWTClaims)


@iam_mock
def test_ValidatePermission(client: DefaultClient) -> None:
    client.ClientTokenGrant()
    client.StartLocalValidation()
    claims = client.ValidateAndParseClaims(client.ClientToken())
    required_permission = Permission.loads(
        {"Action": 2, "Resource": "ADMIN:NAMESPACE:{namespace}:CLIENT"}
    )
    permission_resource = {"{namespace}": "sdktest"}
    valid_permission = client.ValidatePermission(
        claims, required_permission, permission_resource
    )
    assert valid_permission is True


@iam_mock
def test_ValidateRole(client: DefaultClient) -> None:
    client.ClientTokenGrant()
    client.StartLocalValidation()
    claims = client.ValidateAndParseClaims(client.ClientToken())
    assert client.ValidateRole(role_id, claims) is True
    assert client.ValidateRole("Invalid role", claims) is False


@iam_mock
def test_ValidateAudience(client: DefaultClient) -> None:
    client.ClientTokenGrant()
    client.StartLocalValidation()
    claims = client.ValidateAndParseClaims(client.ClientToken())
    aud_status = client.ValidateAudience(claims)
    assert aud_status is None


@iam_mock
def test_ValidateScope(client: DefaultClient) -> None:
    client.ClientTokenGrant()
    client.StartLocalValidation()
    claims = client.ValidateAndParseClaims(client.ClientToken())
    assert client.ValidateScope(claims, 'account') is None
    # Raise error if invalid scope
    with pytest.raises(ValidateScopeError):
        client.ValidateScope(claims, 'Invalid scope')


@iam_mock
def test_UserPhoneVerificationStatus(client: DefaultClient) -> None:
    client.ClientTokenGrant()
    client.StartLocalValidation()

    claims = client.ValidateAndParseClaims(client.ClientToken())
    assert client.UserPhoneVerificationStatus(claims) is False

    setattr(claims, "Jflgs", 7)
    assert client.UserPhoneVerificationStatus(claims) is True


@iam_mock
def test_UserEmailVerificationStatus(client: DefaultClient) -> None:
    client.ClientTokenGrant()
    client.StartLocalValidation()

    claims = client.ValidateAndParseClaims(client.ClientToken())
    assert client.UserEmailVerificationStatus(claims) is False

    setattr(claims, "Jflgs", 7)
    assert client.UserEmailVerificationStatus(claims) is True


@iam_mock
def test_UserAnonymousStatus(client: DefaultClient) -> None:
    client.ClientTokenGrant()
    client.StartLocalValidation()

    claims = client.ValidateAndParseClaims(client.ClientToken())
    assert client.UserAnonymousStatus(claims) is False

    setattr(claims, "Jflgs", 7)
    assert client.UserAnonymousStatus(claims) is True


@iam_mock
def test_HasBan(client: DefaultClient) -> None:
    client.ClientTokenGrant()
    client.StartLocalValidation()

    claims = client.ValidateAndParseClaims(client.ClientToken())
    assert client.HasBan(claims, "Test Ban") is False


@iam_mock
def test_GetRolePermission(client: DefaultClient) -> None:
    client.ClientTokenGrant()

    assert isinstance(client.GetRolePermissions(role_id), list)
    assert client.GetRolePermissions("This is an invalid roleId") == []

    assert isinstance(client.rolePermissionCache.get(role_id), list)
    assert client.rolePermissionCache.get("This is an invalid roleId") is None


@iam_mock
def test_GetClientInformation(client: DefaultClient) -> None:
    client.ClientTokenGrant()
    client_info = client.GetClientInformation("sdktest", client.config.ClientID)
    assert client_info is not None
    assert client_info == client.clientInfoCache.get(client.config.ClientID)


@iam_mock
def test_HealthCheck(client: DefaultClient) -> None:
    client.ClientTokenGrant()
    assert client.HealthCheck() is False
    client.StartLocalValidation()
    assert client.HealthCheck() is True
