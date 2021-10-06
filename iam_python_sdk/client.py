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

from typing import Dict, Tuple


class DefaultClient:
    """Default Client class."""
    def ClientTokenGrant(self) -> object:
        """Starts client token grant to get client bearer token for role caching

        Returns:
            object: error
        """
        pass

    def ClientToken(self) -> str:
        """Returns client access token

        Returns:
            str: token
        """
        pass

    def StartLocalValidation(self) -> object:
        """Starts thread to refresh JWK and revocation list periodically this enables local token validation

        Returns:
            object: error
        """
        pass

    def ValidateAccessToken(self, accessTokens: str) -> Tuple[bool, object]:
        """Validates access token by calling IAM service

        Args:
            accessTokens (str): access token

        Returns:
            Tuple[bool, object]: status, error
        """
        pass

    def ValidateAndParseClaims(self, accessToken: str) -> Tuple[object, object]:
        """Validates access token locally and returns the JWT claims contained in the token

        Args:
            accessToken (str): access token

        Returns:
            Tuple[object, object]: JWT claims, error
        """
        pass

    def ValidatePermission(self, claims: object, requiredPermission: object,
                           permissionResources: Dict[str, str]) -> Tuple[bool, object]:
        """Validates if an access token has right for a specific permission

        Args:
            claims (object): JWT claims
            requiredPermission (object): permission to access resource, example:
                {Resource: "NAMESPACE:{namespace}:USER:{userId}", Action: 2}
            permissionResources (Dict[str, str]): resource string to replace the `{}` placeholder in
                `requiredPermission`, example: p["{namespace}"] = "accelbyte"

        Returns:
            Tuple[bool, object]: status, error
        """
        pass

    def ValidateRole(self, requiredRoleID: str, claims: object) -> Tuple[bool, object]:
        """Validates if an access token has a specific role

        Args:
            requiredRoleID (str): role ID that required
            claims (object): JWT claims

        Returns:
            Tuple[bool, object]: status, error
        """
        pass

    def UserPhoneVerificationStatus(self, claims: object) -> Tuple[bool, object]:
        """Gets user phone verification status on access token

        Args:
            claims (object): JWT claims

        Returns:
            Tuple[bool, object]: status, error
        """
        pass

    def UserEmailVerificationStatus(self, claims: object) -> Tuple[bool, object]:
        """Gets user email verification status on access token

        Args:
            claims (object): JWT claims

        Returns:
            Tuple[bool, object]: status, error
        """
        pass

    def UserAnonymousStatus(self, claims: object) -> Tuple[bool, object]:
        """Gets user anonymous status on access token

        Args:
            claims (object): JWT claims

        Returns:
            Tuple[bool, object]: status, error
        """
        pass

    def HasBan(self, claims: object, banType: str) -> bool:
        """Validates if certain ban exist

        Args:
            claims (object): JWT claims
            banType (str): ban type

        Returns:
            bool: status
        """
        pass

    def HealthCheck(self) -> bool:
        """Lets caller know the health of the IAM client

        Returns:
            bool: status
        """
        pass

    def ValidateAudience(self, claims: object) -> object:
        """Validate audience of user access token

        Args:
            claims (object): JWT claims

        Returns:
            object: error
        """
        pass

    def ValidateScope(self, claims: object, scope: str) -> object:
        """Validate scope of user access token

        Args:
            claims (object): JWT claims
            scope (str): role scope

        Returns:
            object: error
        """
        pass

    def GetRolePermissions(self, roleID: str) -> Tuple[object, object]:
        """Gets permissions of a role

        Args:
            roleID (str): role ID

        Returns:
            Tuple[object, object]: permission, error
        """
        pass

    def GetClientInformation(self, namespace: str, clientID: str) -> Tuple[object, object]:
        """Gets IAM client information, it will look into cache first, if not found then fetch it to IAM.

        Args:
            namespace (str): namespace
            clientID (str): client ID

        Returns:
            Tuple[object, object]: clien information, error
        """
        pass
