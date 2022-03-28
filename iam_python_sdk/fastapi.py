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

"""FastAPI module."""
from pydantic import BaseSettings
from typing import Callable, List, Optional, Union
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, Request, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, APIKeyCookie

from .config import Config
from .async_client import AsyncClient, NewAsyncClient
from .errors import ClientTokenGrantError, EmptyTokenError, GetClientInformationError, StartLocalValidationError, \
    TokenRevokedError, UnauthorizedError, UserRevokedError, ValidateAndParseClaimsError
from .models import JWTClaims, Permission


class Settings(BaseSettings):
    """IAM settings class.
    """
    iam_base_url = ""
    iam_client_id = ""
    iam_client_secret = ""
    iam_token_locations = ["headers", "cookies"]
    iam_token_header_name = "Authorization"
    iam_token_header_type = "Bearer"
    iam_token_cookie_name = "access_token"
    iam_token_cookie_path = "/"
    iam_csrf_protection = True
    iam_strict_referer = True
    iam_cors_enable = False
    iam_cors_origin = "*"
    iam_cors_headers = "*"
    iam_cors_methods = "*"
    iam_cors_credentials = True


class IAM:
    """IAM FastAPI extensions class.
    """
    def __init__(self, app: Union[FastAPI, None] = None, config: Settings = Settings()) -> None:
        if app is not None:
            self.init_app(app, config)

    def init_app(self, app: FastAPI, config: Settings = Settings()) -> None:
        """Init IAM FastAPI extensions with FastAPI app.
        Client token grant and local validation will be executed once here,
        then the background thread will spawn to refresh token, jwks and revocation list.

        Args:
            app (Flask): Flask app instance
            config (Settings): Configuration object

        Raises:
            ValueError: Error if the requirement configs are not set
        """
        if not (
            config.iam_base_url and config.iam_client_id and config.iam_client_secret
        ):
            raise ValueError("IAM_BASE_URL, IAM_CLIENT_ID, IAM_CLIENT_SECRET need to set.")

        self.config = config

        self._set_default_errors(app)
        if self.config.iam_cors_enable:
            self._set_default_cors_headers(app)

        # Grant token on FastAPI startup
        @app.on_event("startup")
        async def startup_event():
            await self.grant_token()

    def _set_default_errors(self, app: FastAPI) -> None:
        @app.exception_handler(EmptyTokenError)
        async def handle_token_not_found(request: Request, exc: EmptyTokenError):
            return JSONResponse(
                status_code=401,
                content={"error": str(exc)}
            )

        @app.exception_handler(UnauthorizedError)
        async def handle_unauthorized(request: Request, exc: UnauthorizedError):
            return JSONResponse(
                status_code=403,
                content={"error": str(exc)}
            )

    def _set_default_cors_headers(self, app: FastAPI) -> None:
        allowed_origin = self.config.iam_cors_origin.split(',')
        allowed_headers = self.config.iam_cors_headers.split(',')
        allowed_methods = self.config.iam_cors_methods.split(',')
        allow_credentials = bool(self.config.iam_cors_credentials)

        app.add_middleware(
            CORSMiddleware,
            allow_origins=allowed_origin,
            allow_credentials=allow_credentials,
            allow_methods=allowed_methods,
            allow_headers=allowed_headers,
        )

    async def grant_token(self) -> Union[AsyncClient, None]:
        config = Config(
            BaseURL=self.config.iam_base_url,
            ClientID=self.config.iam_client_id,
            ClientSecret=self.config.iam_client_secret,
        )
        client = NewAsyncClient(config)

        try:
            await client.ClientTokenGrant()
            await client.StartLocalValidation()
        except (ClientTokenGrantError, StartLocalValidationError):
            # Cant get access token from IAM
            raise

        self.client = client


async def validate_referer_header(request: Request, jwt_claims: JWTClaims) -> bool:
    """Validate referer header for CSRF protection

    Args:
        request (Request): FastAPI request object
        jwt_claims (JWTClaims): JWT Claim data from token

    Returns:
        bool: Is referrer header valid
    """
    try:
        iam = request.app.state.iam
    except AttributeError:
        raise RuntimeError(
            "You must initialize a IAM with on fastapi "
            "startup event before using this method"
        )

    try:
        client_info = await iam.client.GetClientInformation(jwt_claims.Namespace, jwt_claims.ClientId)
    except GetClientInformationError:
        return False

    if client_info and not client_info.Redirecturi:
        return True

    referer_header = request.headers.get('Referer')
    client_redirect_uris = client_info.Redirecturi.split(",") if client_info else []

    for redirect_uri in client_redirect_uris:
        if iam.config.iam_strict_referer:
            parsed_uri = urlparse(redirect_uri)
            redirect_uri = f"{parsed_uri.scheme}://{parsed_uri.netloc}"

        if referer_header and referer_header.startswith(redirect_uri):
            return True

    return False


def token_required(csrf_protect: Union[bool, None] = None) -> Callable:
    """Validate token in the FastAPI request. This method support headers and cookies with based token.

    Args:
        csrf_protect (bool): Validate referer for CSRF protection

    Raises:
        EmptyTokenError: Error if token is not found
        UnauthorizedError: Error if token permission is not sufficient

    Returns:
        JWTClaims: JWT claims data
    """
    async def _dependency(
        request: Request,
        bearer: Optional[HTTPAuthorizationCredentials] = Security(HTTPBearer(auto_error=False)),
        cookie: Optional[str] = Security(APIKeyCookie(name="access_token", auto_error=False)),
    ) -> JWTClaims:
        try:
            iam = request.app.state.iam
        except AttributeError:
            raise RuntimeError(
                "You must initialize a IAM with on fastapi "
                "startup event before using this method"
            )

        access_token = ""
        token_location = iam.config.iam_token_locations
        for location in token_location:
            # Get token from headers
            if location == "headers":
                if not bearer:
                    continue

                header_parts = bearer.credentials.split()
                access_token = header_parts[-1], "header"

            # Get token from cookies
            if location == "cookies":
                if cookie:
                    access_token = cookie, "cookie"

        if not access_token:
            raise EmptyTokenError("Token not found")

        try:
            jwt_claims = await iam.client.ValidateAndParseClaims(access_token[0])
        except (ValidateAndParseClaimsError, UserRevokedError, TokenRevokedError):
            raise UnauthorizedError("Token is invalid or revoked")

        if not jwt_claims:
            raise UnauthorizedError("Invalid referer header")

        # Validate referer header for cookie token
        validate_referer = csrf_protect if csrf_protect is not None \
            else iam.config.iam_csrf_protection

        if access_token[1] == "cookie" and validate_referer:
            if await validate_referer_header(request, jwt_claims) is not True:
                raise UnauthorizedError("Invalid referer header")

        return jwt_claims

    return _dependency


def permission_required(
    required_permission: Union[dict, Permission],
    permission_resource: dict = {},
    csrf_protect: Union[bool, None] = None
) -> Callable:
    """Validate permission in the token if it has required permission

    Args:
        required_permission (Union[dict, Permission]): The required permission
        permission_resource (dict, optional): The placeholder replacement if any. Defaults to {}.
        csrf_protect (Union[bool, None], optional): CSRF protect options. Defaults to None.

    Returns:
        Callable: _description_
    """
    async def _dependency(request: Request, jwt_claims: JWTClaims = Depends(token_required(csrf_protect))) -> JWTClaims:
        try:
            iam = request.app.state.iam
        except AttributeError:
            raise RuntimeError(
                "You must initialize a IAM with on fastapi "
                "startup event before using this method"
            )

        permission_required = None
        if isinstance(required_permission, dict):
            permission_required = Permission.loads(required_permission)

        if not isinstance(permission_required, Permission):
            raise UnauthorizedError("Permission error")

        is_permitted = await iam.client.ValidatePermission(
            jwt_claims, permission_required, permission_resource
        )

        if not is_permitted:
            raise UnauthorizedError("Token do not have required permissions")

        return jwt_claims

    return _dependency
