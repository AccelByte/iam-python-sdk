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

"""Config module."""

JWKS_PATH: str = "/v3/oauth/jwks"
GRANT_PATH: str = "/v3/oauth/token"
REVOCATION_LIST_PATH: str = "/v3/oauth/revocationlist"
VERIFY_PATH: str = "/v3/oauth/verify"
GET_ROLE_PATH: str = "/v3/admin/roles"
CLIENT_INFORMATION_PATH: str = "/v3/admin/namespaces/%s/clients/%s"
DEFAULT_TOKEN_REFRESH_RATE: float = 0.8
MAX_BACKOFF_TIME: int = 65
DEFAULT_ROLE_CACHE_TIME: int = 60
DEFAULT_JWKS_REFRESH_INTERVAL: int = 60
DEFAULT_REVOCATION_LIST_REFRESH_INTERVAL: int = 60
CLIENT_INFO_EXPIRATION: int = 60
SCOPE_SEPARATOR: str = " "
DEFAULT_BASIC_SERVICE_BASE_URI = "http://justice-basic-service/basic"
GET_NAMESPACE_CONTEXT_PATH = "%s/v1/admin/namespaces/%s/context?activeOnly=%s"


class Config:
    """Config class."""
    def __init__(self, BaseURL: str = "", 
                 BasicBaseURL: str = DEFAULT_BASIC_SERVICE_BASE_URI,
                 ClientID: str = "",
                 ClientSecret: str = "",
                 RolesCacheExpirationTime: int = DEFAULT_ROLE_CACHE_TIME,
                 JWKSRefreshInterval: int = DEFAULT_JWKS_REFRESH_INTERVAL,
                 RevocationListRefreshInterval: int = DEFAULT_REVOCATION_LIST_REFRESH_INTERVAL,
                 Debug: bool = False) -> None:
        """Config class init.

        Args:
            BaseURL (str): Base IAM service URL
            ClientID (str): IAM Client ID
            ClientSecret (str): IAM Client secret
            RolesCacheExpirationTime (int): Roles cache expiration time in seconds
            JWKSRefreshInterval (int): JWKS refresh interval in seconds
            RevocationListRefreshInterval (int): Revocation list refresh interval in seconds
            Debug (bool): Debug mode
        """
        self.BaseURL = BaseURL
        self.ClientID = ClientID
        self.ClientSecret = ClientSecret
        self.RolesCacheExpirationTime = RolesCacheExpirationTime
        self.JWKSRefreshInterval = JWKSRefreshInterval
        self.RevocationListRefreshInterval = RevocationListRefreshInterval
        self.Debug = Debug
