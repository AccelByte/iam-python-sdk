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

from typing import Any, List
from crontab import CronTab
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
    Schedaction: int = -1
    Schedcron: str = ""
    Schedrange: List[str] = [""]

    def is_recurring(self) -> bool:
        try:
            cron = CronTab(self.Schedcron)
            next = cron.next(return_datetime=True)
            zero = datetime(1, 1, 1, 0, 0, 0)
            now = datetime.now()
            if next == zero or (isinstance(next, datetime) and (next - now).total_seconds() > 0):
                return False
        except (AttributeError, ValueError):
            return True

        return True

    def is_in_range(self) -> bool:
        try:
            start = CronTab(self.Schedrange[0])
            end = CronTab(self.Schedrange[1])
            next_start = start.next(return_datetime=True)
            next_end = end.next(return_datetime=True)
            zero = datetime(1, 1, 1, 0, 0, 0)
            now = datetime.now()

            if not next_start == zero and (isinstance(next_start, datetime) and (next_start - now).total_seconds() > 0):
                return False

            if next_end == zero:
                return False

        except (AttributeError, ValueError):
            return True

        return True

    def is_scheduled(self) -> bool:
        ok = False
        if self.Schedcron:
            ok = self.is_recurring()

        if ok:
            return ok

        if len(self.Schedrange) > 1:
            ok = self.is_in_range()

        return ok


class Role(Model):
    """Hold info about a user role."""
    IsWildcard: str = ""
    AdminRole: str = ""
    Roleid: str = ""
    Rolename: str = ""
    Permissions: List[Permission] = [Permission()]


class NamespaceRole(Model):
    """Hold info about a namespace role."""
    Roleid: str = ""
    Namespace: str = ""


class JWTBan(Model):
    """Holds information about ban record in JWT."""
    Ban: str = ""
    Enddate: str = ""


class TokenResponse(Model):
    """Token response class on successful token request."""
    AccessToken: str = ""
    RefreshToken: str = ""
    ExpiresIn: int = -1
    TokenType: str = ""
    Roles: List[str] = [""]
    AcceptedPolicyVersion: List[str] = [""]
    NamespaceRoles: List[NamespaceRole] = [NamespaceRole()]
    Permissions: List[Permission] = [Permission()]
    Bans: List[JWTBan] = [JWTBan()]
    UserId: str = ""
    PlatformId: str = ""
    PlatformUserId: str = ""
    Jflgs: int = -1
    DisplayName: str = ""
    Namespace: str = ""
    IsComply: str = ""


class JWTClaims(Model):
    """Holds data stored in a JWT access token with additional Justice Flags field."""
    Namespace: str = ""
    DisplayName: str = ""
    Roles: List[str] = [""]
    NamespaceRoles: List[NamespaceRole] = [NamespaceRole()]
    Permissions: List[Permission] = [Permission()]
    Bans: List[JWTBan] = [JWTBan()]
    Jflgs: int = -1
    Scope: str = ""
    Country: str = ""
    ClientId: str = ""
    IsComply: bool = False
    ParentNamespace: str = ""
    Ipf: str = ""  # IssuedPlatformFrom
    Ipo: str = ""  # IssuedPlatformOn
    Sp: str = ""  # SimultaneousPlatform
    UnionID: str = ""
    UnionNamespace: str = ""
    ExtendNamespace: str = ""
    Iss: str = ""
    Sub: str = ""
    Aud: List[str] = [""]
    Exp: int = -1
    Nbf: int = -1
    Iat: int = -1
    Jti: str = ""


class BloomFilterJSON(Model):
    K: int = 0
    M: int = 0
    Bits: List[int] = [0]


class UserRevocationListRecord(Model):
    """Used to store revoked user data."""
    Id: str = ""
    RevokedAt: str = ""


class RevocationList(Model):
    """Contains revoked user and token."""
    RevokedTokens: BloomFilterJSON = BloomFilterJSON()
    RevokedUsers: List[UserRevocationListRecord] = [UserRevocationListRecord()]


class ClientInformation(Model):
    """Holds client information."""
    Clientname: str = ""
    Namespace: str = ""
    Redirecturi: str = ""
    Baseuri: str = ""


class NamespaceContext(Model):
    Type: str = ""
    StudioNamespace: str = ""
