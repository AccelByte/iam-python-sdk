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

import backoff, httpx, json, jwt

from threading import RLock
from typing import Any, Dict, List, Union

from .bloom import BloomFilter
from .cache import Cache
from .config import Config
from .config import CLIENT_INFO_EXPIRATION, CLIENT_INFORMATION_PATH, GET_ROLE_PATH, GRANT_PATH, JWKS_PATH, \
    MAX_BACKOFF_TIME, REVOCATION_LIST_PATH, SCOPE_SEPARATOR, VERIFY_PATH
from .errors import ClientTokenGrantError, GetClientInformationError, GetJWKSError, GetRevocationListError, \
    GetRolePermissionError, HTTPClientError, InvalidTokenSignatureKeyError, NilClaimError, NoLocalValidationError, \
    RefreshAccessTokenError, StartLocalValidationError, TokenRevokedError, UserRevokedError, ValidateAccessTokenError, \
    ValidateAndParseClaimsError, ValidateAudienceError, ValidateJWTError, ValidatePermissionError, ValidateScopeError
from .models import ClientInformation, JWTClaims, Permission, RevocationList, Role, TokenResponse
from .log import logger
from .utils import parse_nanotimestamp


RESOURCE_NAMESPACE: str = "NAMESPACE"
RESOURCE_USER: str = "USER"


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
        self.__lock = RLock()
        self.__clientAccessToken = ""
        self.__localValidationActive = False
        self.__keys = {}
        self.__revokedUsers = {}
        self.__revocationFilter = None
        self.config = config
        self.httpClient = httpClient
        self.rolePermissionCache = rolePermissionCache
        self.clientInfoCache = clientInfoCache

    def __set_key(self, k: str, value: Any) -> None:
        with self.__lock:
            self.__keys[k] = value

    def __get_key(self, k: str) -> Any:
        with self.__lock:
            return self.__keys.get(k)

    def __set_revoked_user(self, k: str, value: str) -> None:
        with self.__lock:
            self.__revokedUsers[k] = parse_nanotimestamp(value)

    def __get_revoked_user(self, k: str) -> Any:
        with self.__lock:
            return self.__revokedUsers.get(k)

    def __set_revocation_filter(self, filer: BloomFilter) -> None:
        with self.__lock:
            self.__revocationFilter = filer

    def __refreshAccessToken(self) -> None:
        """Refresh user token"

        Raises:
            RefreshAccessTokenError: exception failed to refresh token
        """
        try:
            self.ClientTokenGrant()
            logger.info("client token refreshed")
        except ClientTokenGrantError as e:
            raise RefreshAccessTokenError("unable to refresh token") from e

    def __getJWKS(self) -> None:
        try:
            resp = self.httpClient.get(self.config.BaseURL + JWKS_PATH,
                                       auth=(self.config.ClientID, self.config.ClientSecret)
                                       )
            if not resp.is_success:
                logger.warning(
                    f"unable to get JWKS: error code {resp.status_code},"
                    f"error message: {resp.reason_phrase}"
                )

            jwks = jwt.PyJWKSet(resp.json().get("keys", []))
            for jwk in jwks.keys:
                self.__set_key(jwk.key_id, jwk.key)

        except (json.JSONDecodeError, ValueError) as e:
            raise GetJWKSError("unable to unmarshal response body") from e
        except (jwt.InvalidKeyError, jwt.PyJWKSetError) as e:
            raise GetJWKSError("unable to generate public key") from e
        except HTTPClientError as e:
            raise GetJWKSError(f"{e.message}") from e

    def __getRevocationList(self) -> None:
        try:
            resp = self.httpClient.get(self.config.BaseURL + REVOCATION_LIST_PATH,
                                       auth=(self.config.ClientID, self.config.ClientSecret)
                                       )

            if not resp.is_success:
                logger.warning(
                    f"unable to get JWKS: error code {resp.status_code},"
                    f"error message: {resp.reason_phrase}"
                )

            revocation_list = RevocationList.loads(resp.json())
            self.__set_revocation_filter(revocation_list.RevokedTokens)
            for revoked_user in revocation_list.RevokedUsers:
                self.__set_revoked_user(revoked_user.Id, revoked_user.RevokedAt)

        except (json.JSONDecodeError, ValueError) as e:
            raise GetRevocationListError("unable to unmarshal response body") from e
        except HTTPClientError as e:
            raise GetRevocationListError(f"{e.message}") from e

    def __validateJWT(self, token: str) -> Union[JWTClaims, None]:
        if not token:
            raise ValueError("invalid token")

        web_token = jwt.get_unverified_header(token)
        if not web_token.get("kid"):
            raise InvalidTokenSignatureKeyError("invalid header")

        public_key = self.__get_key(web_token.get("kid"))
        if not public_key:
            raise ValueError("invalid key")

        claims = None
        try:
            claims = jwt.decode(token, public_key, algorithms=["RS256"], options={"verify_exp": True})
            jwt_claims = JWTClaims.loads(claims)
        except jwt.DecodeError as e:
            raise ValidateJWTError("unable to deserialize JWT claims") from e
        except jwt.ExpiredSignatureError as e:
            raise ValidateJWTError("unable to validate JWT") from e

        return jwt_claims

    def __userRevoked(self, user_id: str, issued_at: int) -> bool:
        time_revoked = self.__get_revoked_user(user_id)
        if time_revoked:
            return time_revoked >= issued_at
        return False

    def __tokenRevoked(self, access_token: str) -> bool:
        # TODO: Check if access_token maybe in revoked tokens bloom filter
        return False

    def __resourceAllowed(self, accessPermissionResource: str, requiredPermissionResource: str) -> bool:
        required_perm_res_sections = requiredPermissionResource.split(":")
        required_perm_res_section_len = len(required_perm_res_sections)
        access_perm_res_sections = accessPermissionResource.split(":")
        access_perm_res_section_len = len(access_perm_res_sections)
        min_section_len = access_perm_res_section_len

        if min_section_len > required_perm_res_section_len:
            min_section_len = required_perm_res_section_len

        for i in range(0, min_section_len):
            user_section = access_perm_res_sections[i]
            required_section = required_perm_res_sections[i]

            if user_section != required_section and user_section != "*":
                return False

        if access_perm_res_section_len == required_perm_res_section_len:
            return True

        if access_perm_res_section_len < required_perm_res_section_len:
            if access_perm_res_sections[access_perm_res_section_len - 1] == "*":
                if access_perm_res_section_len < 2:
                    return True

                segment = access_perm_res_sections[access_perm_res_section_len - 2]

                if segment == RESOURCE_NAMESPACE or segment == RESOURCE_USER:
                    return False

                return True
            return False

        for i in range(required_perm_res_section_len, access_perm_res_section_len):
            if access_perm_res_sections[i] != "*":
                return False

        return True

    def __permissionAllowed(self, grantedPermissions: List[Permission], requiredPermission: Permission) -> bool:
        for granted_permission in grantedPermissions:
            granted_action = granted_permission.Action
            if granted_permission.is_scheduled():
                granted_action = granted_permission.Schedaction

            if self.__resourceAllowed(granted_permission.Resource, requiredPermission.Resource) and \
               (granted_action & requiredPermission.Action == requiredPermission.Action):
                return True

        return False

    def __applyUserPermissionResourceValues(self, grantedPermissions: List[Permission],
                                            claims: JWTClaims, allowedNamespace: str) -> List[Permission]:
        if not allowedNamespace:
            allowedNamespace = claims.Namespace

        for granted_permission in grantedPermissions:
            granted_permission.Resource = granted_permission.Resource.replace("{userId}", claims.Sub)
            granted_permission.Resource = granted_permission.Resource.replace("{namespace}", allowedNamespace)

        return grantedPermissions

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
                logger.warning(
                    f"unable to grant client token: error code : {resp.status_code}, "
                    f"error message : {resp.reason_phrase}"
                )

            token_response = TokenResponse.loads(resp.json())
            self.__clientAccessToken = token_response.AccessToken
            logger.info("token grant success")

            # TODO: Background refresh token

        except (json.JSONDecodeError, ValueError) as e:
            raise ClientTokenGrantError("unable to unmarshal response body") from e
        except HTTPClientError as e:
            raise ClientTokenGrantError(f"{e.message}") from e

    def ClientToken(self) -> str:
        """Returns client access token

        Returns:
            str: token
        """
        return self.__clientAccessToken

    def StartLocalValidation(self) -> None:
        """Starts thread to refresh JWK and revocation list periodically this enables local token validation"""
        try:
            self.__getJWKS()
            self.__getRevocationList()
            self.__localValidationActive = True

            # TODO: Background refresh JWKS and Revocation list

        except GetJWKSError as e:
            raise StartLocalValidationError("unable to get JWKS") from e
        except GetRevocationListError as e:
            raise StartLocalValidationError("unable to get revocation list") from e

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
                logger.warning("unauthorized")
                # Refresh Token
                self.__refreshAccessToken()
                return self.ValidateAccessToken(accessToken)

            elif not resp.is_success:
                logger.warning(
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
        if self.__localValidationActive is not True:
            raise NoLocalValidationError

        jwt_claims = None
        try:
            jwt_claims = self.__validateJWT(accessToken)
        except (ValueError, InvalidTokenSignatureKeyError, ValidateJWTError) as e:
            raise ValidateAndParseClaimsError("unable to validate JWT") from e

        if jwt_claims and self.__userRevoked(jwt_claims.Sub, jwt_claims.Iat):
            raise UserRevokedError("user (owner) of JWT is revoked")

        if jwt_claims and self.__tokenRevoked(accessToken):
            raise TokenRevokedError("token is revoked")

        return jwt_claims

    def ValidatePermission(self, claims: Union[JWTClaims, None], requiredPermission: Permission,
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
        if not claims:
            raise NilClaimError("claim is nil")

        for placeholder, value in permissionResources.items():
            requiredPermission.Resource = requiredPermission.Resource.replace(placeholder, value)

        if self.__permissionAllowed(claims.Permissions, requiredPermission):
            logger.info("permission allowed to access resource")
            return True

        namespace_roles = claims.NamespaceRoles or []
        for namespace_role in namespace_roles:
            granted_role_permissions = []
            try:
                granted_role_permissions = self.GetRolePermissions(namespace_role.Roleid)
                granted_role_permissions = self.__applyUserPermissionResourceValues(
                    granted_role_permissions, claims, namespace_role.Namespace
                )

                if self.__permissionAllowed(granted_role_permissions, requiredPermission):
                    logger.info("permission allowed to access resource")
                    return True

            except GetRolePermissionError as e:
                raise ValidatePermissionError("unable to get role perms") from e

        roles = claims.Roles or []
        for role_id in roles:
            granted_role_permissions = []
            try:
                granted_role_permissions = self.GetRolePermissions(role_id)
                granted_role_permissions = self.__applyUserPermissionResourceValues(
                    granted_role_permissions, claims, ""
                )

                if self.__permissionAllowed(granted_role_permissions, requiredPermission):
                    logger.info("permission allowed to access resource")
                    return True
            except GetRolePermissionError as e:
                raise ValidatePermissionError("unable to get role perms") from e

        logger.info("permission not allowed to access resource")
        return False

    def ValidateRole(self, requiredRoleID: str, claims: Union[JWTClaims, None]) -> bool:
        """Validates if an access token has a specific role

        Args:
            requiredRoleID (str): role ID that required
            claims (JWTClaims): JWT claims

        Returns:
            bool: role validity status
        """
        if not claims:
            raise NilClaimError("claim is nil")

        if requiredRoleID in claims.Roles:
            logger.info("role allowed to access resource")
            return True

        logger.warning("role not allowed to access resource")
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
        if not claims:
            raise NilClaimError("claim is nil")
        
        for ban in claims.Bans:
            if ban.Ban == banType:
                logger.info("user banned")
                return True

        logger.info("user not banned")
        return False

    def HealthCheck(self) -> bool:
        """Lets caller know the health of the IAM client

        Returns:
            bool: health status
        """
        return False

    def ValidateAudience(self, claims: Union[JWTClaims, None]) -> None:
        """Validate audience of user access token

        Args:
            claims (JWTClaims): JWT claims
        """
        if not claims:
            raise NilClaimError("claim is nil")

        # no need to check if no audience found in the claims. https://tools.ietf.org/html/rfc7519#section-4.1.3
        audience = getattr(claims, "Aud")
        if not audience:
            logger.warning("no audience found in the token. Skipping the audience validation")
            return None

        try:
            client_info = self.GetClientInformation(claims.Namespace, self.config.ClientID)
            if getattr(client_info, "Baseuri") not in claims.Aud:
                raise ValidateAudienceError("audience is not valid")

            logger.info("audience is valid")
            return None

        except GetClientInformationError as e:
            raise ValidateAudienceError("get client detail returns error") from e

    def ValidateScope(self, claims: Union[JWTClaims, None], reqScope: str) -> None:
        """Validate scope of user access token

        Args:
            claims (JWTClaims): JWT claims
            reqScope (str): required role scope
        """
        if not claims:
            raise NilClaimError("claim is nil")

        scopes = claims.Scope.split(SCOPE_SEPARATOR)
        if reqScope not in scopes:
            raise ValidateScopeError("invalid scope")

        logger.info("scope valid")

    def GetRolePermissions(self, roleID: str) -> List[Permission]:
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
                                       headers={"Authorization": f"Bearer {self.__clientAccessToken}"}
                                       )
            if resp.status_code == 401:
                logger.warning("unauthorized")
                # Refresh Token
                self.__refreshAccessToken()
                return self.GetRolePermissions(roleID)
            elif resp.status_code == 403:
                logger.warning("forbidden")
                return []
            elif resp.status_code == 404:
                logger.warning("not found")
                return []
            elif not resp.is_success:
                logger.warning(
                    f"unexpected error: {resp.status_code}"
                )
                return []

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
        # Try to get from cache first
        cached_client_info = self.clientInfoCache.get(clientID)
        if cached_client_info:
            return cached_client_info

        # Get client informations
        try:
            resp = self.httpClient.get(self.config.BaseURL + CLIENT_INFORMATION_PATH % (namespace, clientID),
                                       headers={"Authorization": f"Bearer {self.__clientAccessToken}"}
                                       )
            if resp.status_code == 401:
                logger.warning("unauthorized")
                # Refresh Token
                self.__refreshAccessToken()
                return self.GetClientInformation(namespace, clientID)
            elif not resp.is_success:
                logger.warning(
                    f"unable to get client information: error code {resp.status_code},"
                    f"error message: {resp.reason_phrase}"
                )
                return None

            client_info = ClientInformation.loads(resp.json())
            self.clientInfoCache[clientID] = client_info
            return client_info

        except RefreshAccessTokenError as e:
            raise GetClientInformationError("unable to get client information") from e
        except (json.JSONDecodeError, ValueError) as e:
            raise GetClientInformationError("unable to unmarshal response body") from e
        except HTTPClientError as e:
            raise GetClientInformationError(f"{e.message}") from e


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
