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

"""Tests for `iam_python_sdk.async_client` module."""

import pytest

from iam_python_sdk.cache import Cache
from iam_python_sdk.async_client import AsyncClient, HttpClient
from iam_python_sdk.config import Config
from iam_python_sdk.models import JWTClaims, Permission
from iam_python_sdk.errors import ClientTokenGrantError, NoLocalValidationError, StartLocalValidationError, \
    ValidateScopeError

from .mock import iam_mock, role_id


def test_NewAsyncClient(async_iam_client: AsyncClient) -> None:
    assert isinstance(async_iam_client.config, Config)
    assert isinstance(async_iam_client.httpClient, HttpClient)
    assert isinstance(async_iam_client.rolePermissionCache, Cache)
    assert isinstance(async_iam_client.clientInfoCache, Cache)


@pytest.mark.asyncio
@iam_mock
async def test_ClientTokenGrant(async_iam_client: AsyncClient) -> None:
    try:
        await async_iam_client.ClientTokenGrant()
        assert async_iam_client._tokenRefreshActive is True
    except ClientTokenGrantError:
        assert False


@pytest.mark.asyncio
@iam_mock
async def test_ClientToken(async_iam_client: AsyncClient) -> None:
    assert await async_iam_client.ClientToken() == ""
    await async_iam_client.ClientTokenGrant()
    assert await async_iam_client.ClientToken() != ""


@pytest.mark.asyncio
@iam_mock
async def test_StartLocalValidation(async_iam_client: AsyncClient) -> None:
    try:
        await async_iam_client.StartLocalValidation()
        assert async_iam_client._localValidationActive is True
    except StartLocalValidationError:
        assert False


@pytest.mark.asyncio
@iam_mock
async def test_ValidateAccessToken(async_iam_client: AsyncClient) -> None:
    await async_iam_client.ClientTokenGrant()
    assert await async_iam_client.ValidateAccessToken(await async_iam_client.ClientToken()) is True
    assert await async_iam_client.ValidateAccessToken("This is an invalid token") is False


@pytest.mark.asyncio
@iam_mock
async def test_ValidateAndParseClaims(async_iam_client: AsyncClient) -> None:
    await async_iam_client.ClientTokenGrant()
    # Raise error if StartLocalValidation not called yet
    with pytest.raises(NoLocalValidationError):
        jwt_claims = await async_iam_client.ValidateAndParseClaims(await async_iam_client.ClientToken())

    await async_iam_client.StartLocalValidation()
    jwt_claims = await async_iam_client.ValidateAndParseClaims(await async_iam_client.ClientToken())
    assert isinstance(jwt_claims, JWTClaims)


@pytest.mark.asyncio
@iam_mock
async def test_ValidatePermission(async_iam_client: AsyncClient) -> None:
    await async_iam_client.ClientTokenGrant()
    await async_iam_client.StartLocalValidation()
    claims = await async_iam_client.ValidateAndParseClaims(await async_iam_client.ClientToken())
    required_permission = Permission.loads(
        {"Action": 2, "Resource": "ADMIN:NAMESPACE:{namespace}:ANALYTICS"}
    )
    permission_resource = {"{namespace}": "sdktest"}
    valid_permission = await async_iam_client.ValidatePermission(
        claims, required_permission, permission_resource
    )
    assert valid_permission is True


@pytest.mark.asyncio
@iam_mock
async def test_ValidateRole(async_iam_client: AsyncClient) -> None:
    await async_iam_client.ClientTokenGrant()
    await async_iam_client.StartLocalValidation()
    claims = await async_iam_client.ValidateAndParseClaims(await async_iam_client.ClientToken())
    assert await async_iam_client.ValidateRole(role_id, claims) is True
    assert await async_iam_client.ValidateRole("Invalid role", claims) is False


@pytest.mark.asyncio
@iam_mock
async def test_ValidateAudience(async_iam_client: AsyncClient) -> None:
    await async_iam_client.ClientTokenGrant()
    await async_iam_client.StartLocalValidation()
    claims = await async_iam_client.ValidateAndParseClaims(await async_iam_client.ClientToken())
    aud_status = await async_iam_client.ValidateAudience(claims)
    assert aud_status is None


@pytest.mark.asyncio
@iam_mock
async def test_ValidateScope(async_iam_client: AsyncClient) -> None:
    await async_iam_client.ClientTokenGrant()
    await async_iam_client.StartLocalValidation()
    claims = await async_iam_client.ValidateAndParseClaims(await async_iam_client.ClientToken())
    assert await async_iam_client.ValidateScope(claims, 'account') is None
    # Raise error if invalid scope
    with pytest.raises(ValidateScopeError):
        await async_iam_client.ValidateScope(claims, 'Invalid scope')


@pytest.mark.asyncio
@iam_mock
async def test_UserPhoneVerificationStatus(async_iam_client: AsyncClient) -> None:
    await async_iam_client.ClientTokenGrant()
    await async_iam_client.StartLocalValidation()

    claims = await async_iam_client.ValidateAndParseClaims(await async_iam_client.ClientToken())
    assert await async_iam_client.UserPhoneVerificationStatus(claims) is False

    setattr(claims, "Jflgs", 7)
    assert await async_iam_client.UserPhoneVerificationStatus(claims) is True


@pytest.mark.asyncio
@iam_mock
async def test_UserEmailVerificationStatus(async_iam_client: AsyncClient) -> None:
    await async_iam_client.ClientTokenGrant()
    await async_iam_client.StartLocalValidation()

    claims = await async_iam_client.ValidateAndParseClaims(await async_iam_client.ClientToken())
    assert await async_iam_client.UserEmailVerificationStatus(claims) is False

    setattr(claims, "Jflgs", 7)
    assert await async_iam_client.UserEmailVerificationStatus(claims) is True


@pytest.mark.asyncio
@iam_mock
async def test_UserAnonymousStatus(async_iam_client: AsyncClient) -> None:
    await async_iam_client.ClientTokenGrant()
    await async_iam_client.StartLocalValidation()

    claims = await async_iam_client.ValidateAndParseClaims(await async_iam_client.ClientToken())
    assert await async_iam_client.UserAnonymousStatus(claims) is False

    setattr(claims, "Jflgs", 7)
    assert await async_iam_client.UserAnonymousStatus(claims) is True


@pytest.mark.asyncio
@iam_mock
async def test_HasBan(async_iam_client: AsyncClient) -> None:
    await async_iam_client.ClientTokenGrant()
    await async_iam_client.StartLocalValidation()

    claims = await async_iam_client.ValidateAndParseClaims(await async_iam_client.ClientToken())
    assert await async_iam_client.HasBan(claims, "Test Ban") is False


@pytest.mark.asyncio
@iam_mock
async def test_GetRolePermission(async_iam_client: AsyncClient) -> None:
    await async_iam_client.ClientTokenGrant()

    assert isinstance(await async_iam_client.GetRolePermissions(role_id), list)
    assert await async_iam_client.GetRolePermissions("This is an invalid roleId") == []

    assert isinstance(async_iam_client.rolePermissionCache.get(role_id), list)
    assert async_iam_client.rolePermissionCache.get("This is an invalid roleId") is None


@pytest.mark.asyncio
@iam_mock
async def test_GetClientInformation(async_iam_client: AsyncClient) -> None:
    await async_iam_client.ClientTokenGrant()
    client_info = await async_iam_client.GetClientInformation("sdktest", async_iam_client.config.ClientID)
    assert client_info is not None
    assert client_info == async_iam_client.clientInfoCache.get(async_iam_client.config.ClientID)


@pytest.mark.asyncio
@iam_mock
async def test_HealthCheck(async_iam_client: AsyncClient) -> None:
    await async_iam_client.ClientTokenGrant()
    assert await async_iam_client.HealthCheck() is False
    await async_iam_client.StartLocalValidation()
    assert await async_iam_client.HealthCheck() is True
