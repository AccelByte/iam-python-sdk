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

from typing import List


class TokenResponse:
    """Token response class on successful token request."""
    AccessToken: str = ""
    RefreshToken: str = ""
    ExpiresIn: str = ""
    TokenType: str = ""
    Roles: List[str] = []
    AcceptedPolicyVersion: List[str] = []
    NamespaceRoles: object = None  # NamespaceRole
    Permissions: object = None  # Permission
    Bans: object = None  # JWTBan
    UserID: str = ""
    PlatformID: str = ""
    PlatformUserID: str = ""
    JusticeFlags: int = -1
    DisplayName: str = ""
    Namespace: str = ""
    IsComply: str = ""


class Permission:
    """Holds information about the actions can be performed to the resource."""
    Resource: str = ""
    Action: int = -1
    ScheduleAction: int = -1
    CronSchedule: str = ""
    RangeSchedule: List[str] = []


class Role:
    """Hold info about a user role."""
    RoleID: str = ""
    RoleName: str = ""
    Permission: object = None  # Permission


class NamespaceRole:
    """Hold info about a namespace role."""
    RoleID: str = ""
    Namespace: str = ""


class JWTClaims:
    """Holds data stored in a JWT access token with additional Justice Flags field."""
    Namespace: str = ""
    DisplayName: str = ""
    Roles: List[str] = []
    AcceptedPolicyVersion: List[str] = []
    NamespaceRoles: List[object] = []  # NamespaceRole
    Permissions: List[object] = []  # Permission
    Bans: List[object] = []  # JWTBan
    JusticeFlags: int = -1
    Scope: str = ""
    Country: str = ""
    ClientID: str = ""
    IsComply: bool = False


class RevocationList:
    """Contains revoked user and token."""
    RevokedTokens: List[object] = []
    RevokedUsers: List[object] = []  # UserRevocationListRecord


class UserRevocationListRecord:
    """Used to store revoked user data."""
    ID: str = ""
    RevokedAt: object = None  # Timestamp


class JWTBan:
    """Holds information about ban record in JWT."""
    Ban: str = ""
    EndDate: object = None  # Timestamp


class ClientInformation:
    """Holds client information."""
    ClientName: str = ""
    Namespace: str = ""
    RedirectURI: str = ""
    BaseURI: str = ""
