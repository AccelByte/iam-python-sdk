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

"""Model module."""

from typing import Any, List, Set
from datetime import datetime

from .utils import decode_model


class Model:
    """Base model class."""
    @classmethod
    def loads(cls, data: Any) -> Any:
        """Decode data to model

        Args:
            data (Any): data to decode

        Returns:
            Any: model object
        """
        return decode_model(data, cls())


class Permission(Model):
    """Holds information about the actions can be performed to the resource."""
    Resource: str = ""
    Action: int = -1
    ScheduleAction: int = -1
    CronSchedule: str = ""
    RangeSchedule: List[str] = [""]


class Role(Model):
    """Hold info about a user role."""
    RoleID: str = ""
    RoleName: str = ""
    Permissions: List[Permission] = [Permission()]


class NamespaceRole(Model):
    """Hold info about a namespace role."""
    RoleID: str = ""
    Namespace: str = ""


class JWTBan(Model):
    """Holds information about ban record in JWT."""
    Ban: str = ""
    EndDate: datetime = datetime.now()


class TokenResponse(Model):
    """Token response class on successful token request."""
    AccessToken: str = ""
    RefreshToken: str = ""
    ExpiresIn: str = ""
    TokenType: str = ""
    Roles: List[str] = [""]
    AcceptedPolicyVersion: List[str] = [""]
    NamespaceRoles: List[NamespaceRole] = [NamespaceRole()]
    Permissions: List[Permission] = [Permission()]
    Bans: List[JWTBan] = [JWTBan()]
    UserID: str = ""
    PlatformID: str = ""
    PlatformUserID: str = ""
    JusticeFlags: int = -1
    DisplayName: str = ""
    Namespace: str = ""
    IsComply: str = ""


class JWTClaims(Model):
    """Holds data stored in a JWT access token with additional Justice Flags field."""
    Namespace: str = ""
    DisplayName: str = ""
    Roles: List[str] = [""]
    AcceptedPolicyVersion: List[str] = [""]
    NamespaceRoles: List[NamespaceRole] = [NamespaceRole()]
    Permissions: List[Permission] = [Permission()]
    Bans: List[JWTBan] = [JWTBan()]
    JusticeFlags: int = -1
    Scope: str = ""
    Country: str = ""
    ClientID: str = ""
    IsComply: bool = False


class UserRevocationListRecord(Model):
    """Used to store revoked user data."""
    ID: str = ""
    RevokedAt: datetime = datetime.now()


class RevocationList(Model):
    """Contains revoked user and token."""
    RevokedTokens: Set[str] = {""}
    RevokedUsers: List[UserRevocationListRecord] = [UserRevocationListRecord()]


class ClientInformation(Model):
    """Holds client information."""
    ClientName: str = ""
    Namespace: str = ""
    RedirectURI: str = ""
    BaseURI: str = ""
