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

"""IAM Python SDK client module."""

import backoff, httpx, json

from typing import Dict, List, Union
from .cache import Cache
from .config import Config
from .config import CLIENT_INFO_EXPIRATION, GET_ROLE_PATH, VERIFY_PATH, MAX_BACKOFF_TIME, GRANT_PATH
from .errors import ClientTokenGrantError, GetRolePermissionError, HTTPClientError, \
    RefreshAccessTokenError, ValidateAccessTokenError
from .models import ClientInformation, JWTClaims, Permission, Role, TokenResponse
from .log import logger


def backoff_giveup_handler(backoff) -> None:
    try:
        raise
    except httpx.HTTPStatusError as e:
        raise HTTPClientError(f"endpoint returned status code: {e.response.status_code}") from e
    except httpx.RequestError as e:
        raise HTTPClientError("unable to do HTTP request") from e
    except Exception as e:
        raise HTTPClientError("unable to create new HTTP request") from e


class HttpClient:
    """HttpClient class to do http request."""

    def get(self, *args, **kwargs) -> httpx.Response:
        return self.request("GET", *args, **kwargs)

    def post(self, *args, **kwargs) -> httpx.Response:
        return self.request("POST", *args, **kwargs)

    @backoff.on_exception(
        backoff.expo, (httpx.HTTPStatusError, httpx.RequestError),
        max_time=MAX_BACKOFF_TIME, on_giveup=backoff_giveup_handler
    )
    def request(self, method: str = "GET", *args, **kwargs) -> httpx.Response:
        resp = httpx.request(method, *args, **kwargs)
        if resp.status_code >= 500:
            resp.raise_for_status()

        return resp


class DefaultClient:
    """Default Client class."""

    def __init__(self, config: Config,
                 rolePermissionCache: Cache,
                 clientInfoCache: Cache,
                 httpClient: HttpClient
                 ) -> None:
        self.config = config
        self.httpClient = httpClient
        self.rolePermissionCache = rolePermissionCache
        self.clientInfoCache = clientInfoCache
        self.clientAccessToken = ""

    def ClientTokenGrant(self) -> None:
        """Starts client token grant to get client bearer token for role caching

        Raises:
            ClientTokenGrantError: exception response format error
            ClientTokenGrantError: exceptions http request error
        """
        try:
            resp = self.httpClient.post(self.config.BaseURL + GRANT_PATH,
                                        data={'grant_type': 'client_credentials'},
                                        auth=(self.config.ClientID, self.config.ClientSecret)
                                        )
            if not resp.is_success:
                logger.error(
                    f"unable to grant client token: error code : {resp.status_code}, "
                    f"error message : {resp.reason_phrase}"
                )
                return None

            token_response = TokenResponse.loads(resp.json())
            self.clientAccessToken = token_response.AccessToken
            logger.info("token grant success")
            # TODO: Background refresh token
        except (json.JSONDecodeError, ValueError) as e:
            raise ClientTokenGrantError("unable to unmarshal response body") from e
        except HTTPClientError as e:
            raise ClientTokenGrantError(f"{e.message}") from e

    def RefreshAccessToken(self) -> None:
        """Refresh user token"

        Raises:
            RefreshAccessTokenError: exception failed to refresh token
        """
        try:
            self.ClientTokenGrant()
            logger.info("client token refreshed")
        except ClientTokenGrantError as e:
            raise RefreshAccessTokenError("unable to refresh token") from e

    def ClientToken(self) -> str:
        """Returns client access token

        Returns:
            str: token
        """
        return self.clientAccessToken

    def StartLocalValidation(self) -> None:
        """Starts thread to refresh JWK and revocation list periodically this enables local token validation

        Returns:
            object: error
        """
        pass

    def ValidateAccessToken(self, accessToken: str) -> bool:
        """Validates access token by calling IAM service

        Args:
            accessToken (str): access token

        Raises:
            ValidateAccessTokenError: exception failed to refresh token
            ValidateAccessTokenError: exceptions http request error

        Returns:
            bool: access token validity status
        """
        try:
            resp = self.httpClient.post(self.config.BaseURL + VERIFY_PATH,
                                        data={'token': accessToken},
                                        auth=(self.config.ClientID, self.config.ClientSecret)
                                        )
            if resp.status_code == 401:
                logger.error("unauthorized")
                # Refresh Token
                self.RefreshAccessToken()
                return self.ValidateAccessToken(accessToken)

            elif not resp.is_success:
                logger.error(
                    f"unable to validate access token: error code : {resp.status_code}, "
                    f"error message : {resp.reason_phrase}"
                )
                return False

            logger.info("token is valid")
            return True

        except RefreshAccessTokenError as e:
            raise ValidateAccessTokenError("unable to validate token") from e
        except HTTPClientError as e:
            raise ValidateAccessTokenError(f"{e.message}") from e

    def ValidateAndParseClaims(self, accessToken: str) -> Union[JWTClaims, None]:
        """Validates access token locally and returns the JWT claims contained in the token

        Args:
            accessToken (str): access token

        Returns:
            Union[JWTClaims, None]: JWT claims or None
        """
        pass

    def ValidatePermission(self, claims: JWTClaims, requiredPermission: Permission,
                           permissionResources: Dict[str, str]) -> bool:
        """Validates if an access token has right for a specific permission

        Args:
            claims (JWTClaims): JWT claims
            requiredPermission (Permission): permission to access resource, example:
                {Resource: "NAMESPACE:{namespace}:USER:{userId}", Action: 2}
            permissionResources (Dict[str, str]): resource string to replace the `{}` placeholder in
                `requiredPermission`, example: p["{namespace}"] = "accelbyte"

        Returns:
            bool: permission status
        """
        return False

    def ValidateRole(self, requiredRoleID: str, claims: JWTClaims) -> bool:
        """Validates if an access token has a specific role

        Args:
            requiredRoleID (str): role ID that required
            claims (JWTClaims): JWT claims

        Returns:
            bool: role validity status
        """
        return False

    def UserPhoneVerificationStatus(self, claims: JWTClaims) -> bool:
        """Gets user phone verification status on access token

        Args:
            claims (JWTClaims): JWT claims

        Returns:
            bool: user phone verification status
        """
        return False

    def UserEmailVerificationStatus(self, claims: JWTClaims) -> bool:
        """Gets user email verification status on access token

        Args:
            claims (JWTClaims): JWT claims

        Returns:
            bool: user email verification status
        """
        return False

    def UserAnonymousStatus(self, claims: JWTClaims) -> bool:
        """Gets user anonymous status on access token

        Args:
            claims (JWTClaims): JWT claims

        Returns:
            bool: user anonymous status
        """
        return False

    def HasBan(self, claims: JWTClaims, banType: str) -> bool:
        """Validates if certain ban exist

        Args:
            claims (JWTClaims): JWT claims
            banType (str): ban type

        Returns:
            bool: ban status
        """
        return False

    def HealthCheck(self) -> bool:
        """Lets caller know the health of the IAM client

        Returns:
            bool: health status
        """
        return False

    def ValidateAudience(self, claims: JWTClaims) -> None:
        """Validate audience of user access token

        Args:
            claims (JWTClaims): JWT claims
        """
        pass

    def ValidateScope(self, claims: JWTClaims, scope: str) -> None:
        """Validate scope of user access token

        Args:
            claims (JWTClaims): JWT claims
            scope (str): role scope
        """
        pass

    def GetRolePermissions(self, roleID: str) -> Union[List[Permission], None]:
        """Get permssions of a role

        Args:
            roleID (str): role id

        Raises:
            GetRolePermissionError: exception failed to refresh token
            GetRolePermissionError: exception response format error
            GetRolePermissionError: exceptions http request error

        Returns:
            Union[List[Permission], None]: list of permissions or None
        """
        try:
            # Try to get from cache first
            role_permissions = self.rolePermissionCache.get(roleID)
            if role_permissions:
                return role_permissions

            # Get permissions
            resp = self.httpClient.get(self.config.BaseURL + GET_ROLE_PATH + "/" + roleID,
                                       headers={"Authorization": f"Bearer {self.clientAccessToken}"}
                                       )
            if resp.status_code == 401:
                logger.error("unauthorized")
                # Refresh Token
                self.RefreshAccessToken()
                return self.GetRolePermissions(roleID)
            elif resp.status_code == 403:
                logger.error("forbidden")
                return None
            elif resp.status_code == 404:
                logger.error("not found")
                return None
            elif not resp.is_success:
                logger.error(
                    f"unexpected error: {resp.status_code}"
                )
                return None

            role = Role.loads(resp.json())
            self.rolePermissionCache[roleID] = role.Permissions
            return role.Permissions

        except RefreshAccessTokenError as e:
            raise GetRolePermissionError("unable to get role perms") from e
        except (json.JSONDecodeError, ValueError) as e:
            raise GetRolePermissionError("unable to unmarshal response body") from e
        except HTTPClientError as e:
            raise GetRolePermissionError(f"{e.message}") from e

    def GetClientInformation(self, namespace: str, clientID: str) -> Union[ClientInformation, None]:
        """Gets IAM client information, it will look into cache first, if not found then fetch it to IAM.

        Args:
            namespace (str): namespace
            clientID (str): client ID

        Returns:
            Union[ClientInformation, None]: client information or None
        """
        pass


class NewDefaultClient(DefaultClient):
    def __init__(self, config: Config) -> None:
        self.config = config
        self.httpClient = HttpClient()
        self.rolePermissionCache = Cache(config.RolesCacheExpirationTime)
        self.clientInfoCache = Cache(CLIENT_INFO_EXPIRATION)
        if config.Debug:
            logger.setLevel(10)
        super().__init__(self.config, self.rolePermissionCache,
                         self.clientInfoCache, self.httpClient)
