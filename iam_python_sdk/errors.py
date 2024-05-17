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

"""Error module."""


class Error(Exception):
    """Base error class."""
    def __init__(self, message: str = "") -> None:
        if message:
            self.message = message
        super().__init__(self.message)


class UnauthorizedError(Error):
    message = "access unauthorized, make sure you have valid client access token using ClientTokenGrant"


class ForbiddenError(Error):
    message = "access forbidden, make sure you have client creds that has sufficient permission"


class UserRevokedError(Error):
    message = "user has been revoked"


class TokenRevokedError(Error):
    message = "token has been revoked"


class NilClaimError(Error):
    message = "claims is nil"


class InvalidAudError(Error):
    message = "audience doesn't match the client's base uri. access denied"


class InvalidScopeError(Error):
    message = "insufficient scope"


class EmptyTokenError(Error):
    message = "token is empty"


class InvalidTokenSignatureKeyError(Error):
    message = "invalid token signature key ID"


class RoleNotFoundError(Error):
    message = "role not found"


class NoLocalValidationError(Error):
    message = "local validation is not active, activate by calling StartLocalValidation()"


class HTTPClientError(Error):
    pass


class ClientTokenGrantError(Error):
    pass


class ClientDelegateTokenGrantError(Error):
    pass


class RefreshAccessTokenError(Error):
    pass


class GetJWKSError(Error):
    pass


class GetRevocationListError(Error):
    pass


class StartLocalValidationError(Error):
    pass


class ValidatePermissionError(Error):
    pass


class ValidateAccessTokenError(Error):
    pass


class ValidateAndParseClaimsError(Error):
    pass


class ValidateJWTError(Error):
    pass


class ValidateScopeError(Error):
    pass


class ValidateAudienceError(Error):
    pass


class GetRolePermissionError(Error):
    pass


class GetClientInformationError(Error):
    pass


class GetNamespaceContextError(Error):
    pass
