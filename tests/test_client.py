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


def test_NewDefaultClient(iam_client: DefaultClient) -> None:
    assert isinstance(iam_client.config, Config)
    assert isinstance(iam_client.httpClient, HttpClient)
    assert isinstance(iam_client.rolePermissionCache, Cache)
    assert isinstance(iam_client.clientInfoCache, Cache)


@iam_mock
def test_ClientTokenGrant(iam_client: DefaultClient) -> None:
    try:
        iam_client.ClientTokenGrant()
        assert iam_client._tokenRefreshActive is True
    except ClientTokenGrantError:
        assert False


@iam_mock
def test_ClientToken(iam_client: DefaultClient) -> None:
    assert iam_client.ClientToken() == ""
    iam_client.ClientTokenGrant()
    assert iam_client.ClientToken() != ""


@iam_mock
def test_StartLocalValidation(iam_client: DefaultClient) -> None:
    try:
        iam_client.StartLocalValidation()
        assert iam_client._localValidationActive is True
    except StartLocalValidationError:
        assert False


@iam_mock
def test_ValidateAccessToken(iam_client: DefaultClient) -> None:
    iam_client.ClientTokenGrant()
    assert iam_client.ValidateAccessToken(iam_client.ClientToken()) is True
    assert iam_client.ValidateAccessToken("This is an invalid token") is False


@iam_mock
def test_ValidateAndParseClaims(iam_client: DefaultClient) -> None:
    iam_client.ClientTokenGrant()
    # Raise error if StartLocalValidation not called yet
    with pytest.raises(NoLocalValidationError):
        jwt_claims = iam_client.ValidateAndParseClaims(iam_client.ClientToken())

    iam_client.StartLocalValidation()
    jwt_claims = iam_client.ValidateAndParseClaims(iam_client.ClientToken())
    assert isinstance(jwt_claims, JWTClaims)


@iam_mock
def test_ValidatePermission(iam_client: DefaultClient) -> None:
    iam_client.ClientTokenGrant()
    iam_client.StartLocalValidation()
    claims = iam_client.ValidateAndParseClaims(iam_client.ClientToken())
    required_permission = Permission.loads(
        {"Action": 2, "Resource": "ADMIN:NAMESPACE:{namespace}:ANALYTICS"}
    )
    permission_resource = {"{namespace}": "sdktest"}
    valid_permission = iam_client.ValidatePermission(
        claims, required_permission, permission_resource
    )
    assert valid_permission is True


@iam_mock
def test_ValidateRole(iam_client: DefaultClient) -> None:
    iam_client.ClientTokenGrant()
    iam_client.StartLocalValidation()
    claims = iam_client.ValidateAndParseClaims(iam_client.ClientToken())
    assert iam_client.ValidateRole(role_id, claims) is True
    assert iam_client.ValidateRole("Invalid role", claims) is False


@iam_mock
def test_ValidateAudience(iam_client: DefaultClient) -> None:
    iam_client.ClientTokenGrant()
    iam_client.StartLocalValidation()
    claims = iam_client.ValidateAndParseClaims(iam_client.ClientToken())
    aud_status = iam_client.ValidateAudience(claims)
    assert aud_status is None


@iam_mock
def test_ValidateScope(iam_client: DefaultClient) -> None:
    iam_client.ClientTokenGrant()
    iam_client.StartLocalValidation()
    claims = iam_client.ValidateAndParseClaims(iam_client.ClientToken())
    assert iam_client.ValidateScope(claims, 'account') is None
    # Raise error if invalid scope
    with pytest.raises(ValidateScopeError):
        iam_client.ValidateScope(claims, 'Invalid scope')


@iam_mock
def test_UserPhoneVerificationStatus(iam_client: DefaultClient) -> None:
    iam_client.ClientTokenGrant()
    iam_client.StartLocalValidation()

    claims = iam_client.ValidateAndParseClaims(iam_client.ClientToken())
    assert iam_client.UserPhoneVerificationStatus(claims) is False

    setattr(claims, "Jflgs", 7)
    assert iam_client.UserPhoneVerificationStatus(claims) is True


@iam_mock
def test_UserEmailVerificationStatus(iam_client: DefaultClient) -> None:
    iam_client.ClientTokenGrant()
    iam_client.StartLocalValidation()

    claims = iam_client.ValidateAndParseClaims(iam_client.ClientToken())
    assert iam_client.UserEmailVerificationStatus(claims) is False

    setattr(claims, "Jflgs", 7)
    assert iam_client.UserEmailVerificationStatus(claims) is True


@iam_mock
def test_UserAnonymousStatus(iam_client: DefaultClient) -> None:
    iam_client.ClientTokenGrant()
    iam_client.StartLocalValidation()

    claims = iam_client.ValidateAndParseClaims(iam_client.ClientToken())
    assert iam_client.UserAnonymousStatus(claims) is False

    setattr(claims, "Jflgs", 7)
    assert iam_client.UserAnonymousStatus(claims) is True


@iam_mock
def test_HasBan(iam_client: DefaultClient) -> None:
    iam_client.ClientTokenGrant()
    iam_client.StartLocalValidation()

    claims = iam_client.ValidateAndParseClaims(iam_client.ClientToken())
    assert iam_client.HasBan(claims, "Test Ban") is False


@iam_mock
def test_GetRolePermission(iam_client: DefaultClient) -> None:
    iam_client.ClientTokenGrant()

    assert isinstance(iam_client.GetRolePermissions(role_id), list)
    assert iam_client.GetRolePermissions("This is an invalid roleId") == []

    assert isinstance(iam_client.rolePermissionCache.get(role_id), list)
    assert iam_client.rolePermissionCache.get("This is an invalid roleId") is None


@iam_mock
def test_GetClientInformation(iam_client: DefaultClient) -> None:
    iam_client.ClientTokenGrant()
    client_info = iam_client.GetClientInformation("sdktest", iam_client.config.ClientID)
    assert client_info is not None
    assert client_info == iam_client.clientInfoCache.get(iam_client.config.ClientID)


@iam_mock
def test_HealthCheck(iam_client: DefaultClient) -> None:
    iam_client.ClientTokenGrant()
    assert iam_client.HealthCheck() is False
    iam_client.StartLocalValidation()
    assert iam_client.HealthCheck() is True
