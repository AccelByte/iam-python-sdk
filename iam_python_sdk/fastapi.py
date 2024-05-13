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
from typing import Callable, Optional, Union, List
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, HTTPException, Request, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, APIKeyCookie

from .config import Config
from .async_client import NewAsyncClient
from .errors import Error as IAMError, ClientTokenGrantError, GetClientInformationError, \
    StartLocalValidationError, TokenRevokedError, UserRevokedError, ValidateAndParseClaimsError, ValidatePermissionError
from .http_errors import InsufficientPermissions, InternalServerError, InvalidRefererHeader, UnauthorizedAccess, \
    SubdomainMismatch
from .models import JWTClaims, Permission


# ---------- Exceptions ---------- #

class HTTPError(HTTPException):
    def __init__(self, http_code: int, error_code: int, message: str, description: Optional[str] = None) -> None:
        super().__init__(http_code, description)
        self.code = http_code
        self.error_code = error_code
        self.message = message
        self.description = description


# ---------- Extensions ---------- #


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
    iam_strict_referer = False
    iam_allow_subdomain_referer = False
    iam_subdomain_validation_enable = False
    iam_subdomain_validation_excluded_namespaces = []
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
            IAMError: Error if the requirement configs are not set
        """
        if not (
            config.iam_base_url and config.iam_client_id and config.iam_client_secret
        ):
            raise IAMError("IAM_BASE_URL, IAM_CLIENT_ID, IAM_CLIENT_SECRET need to set.")

        self.config = config

        self._set_default_errors(app)
        if self.config.iam_cors_enable:
            self._set_default_cors_headers(app)

        # Grant token on FastAPI startup
        @app.on_event("startup")
        async def startup_event():
            await self.grant_token()

    def _set_default_errors(self, app: FastAPI) -> None:
        @app.exception_handler(HTTPError)
        def handle_http_error(request: Request, error: HTTPError):
            return JSONResponse(
                status_code=error.code,
                content={'errorCode': error.error_code, 'errorMessage': f"{error.message}: {error.description}"}
            )

        @app.exception_handler(IAMError)
        def handle_iam_error(request: Request, error: IAMError):
            return JSONResponse(
                status_code=InternalServerError[0],
                content={'errorCode': InternalServerError[1], 'errorMessage': f"{InternalServerError[1]}: {str(error)}"}
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

    async def grant_token(self) -> None:
        """Generate oauth IAM token

        Raises:
            HTTPError: Unable to grant token
        """
        config = Config(
            BaseURL=self.config.iam_base_url,
            ClientID=self.config.iam_client_id,
            ClientSecret=self.config.iam_client_secret,
        )
        client = NewAsyncClient(config)

        try:
            await client.ClientTokenGrant()
            await client.StartLocalValidation()
        except (ClientTokenGrantError, StartLocalValidationError) as e:
            # Cant get access token from IAM
            raise HTTPError(*InternalServerError, description=f"unable to grant token: {str(e)}")

        self.client = client


# ---------- Dependencies ---------- #


async def validate_referer_header(request: Request, jwt_claims: JWTClaims) -> bool:
    """Validate referer header for CSRF protection

    Args:
        request (Request): FastAPI request object
        jwt_claims (JWTClaims): JWT Claim data from token

    Raises:
        IAMError: Error IAM init

    Returns:
        bool: Is referrer header valid
    """
    try:
        iam = request.app.state.iam
    except AttributeError:
        raise IAMError(
            "You must initialize a IAM with on fastapi "
            "startup event before using this method"
        )

    try:
        client_info = await iam.client.GetClientInformation(jwt_claims.Namespace, jwt_claims.ClientId)
    except GetClientInformationError:
        return False
    
    referer_header = request.headers.get('Referer')
    if iam.config.iam_subdomain_validation_enable and referer_header:
        referer_url = urlparse(referer_header)
        if not referer_url.netloc.startswith(jwt_claims.Namespace):
            return False

    if client_info and not client_info.Redirecturi:
        return True

    if iam.config.iam_subdomain_validation_enable and referer_header:
        referer_url = urlparse(referer_header)
        if not referer_url.netloc.startswith(jwt_claims.Namespace):
            return False
    
    if client_info and not client_info.Redirecturi:
        return True

    if referer_header:
        client_redirect_uris = client_info.Redirecturi.split(",") if client_info else []
        for redirect_uri in client_redirect_uris:
            if iam.config.iam_subdomain_validation_enable or iam.config.iam_allow_subdomain_referer:
                if validate_referer_with_subdomain(referer_header, redirect_uri):
                    return True
            else:
                parsed_redirect_uri = urlparse(redirect_uri)
                parsed_referer_header = urlparse(referer_header)
                if not iam.config.iam_strict_referer:
                    if parsed_redirect_uri.netloc == parsed_referer_header.netloc and referer_header.startswith(redirect_uri):
                        return True
                else:
                    if parsed_redirect_uri.netloc == parsed_referer_header.netloc:
                        return True

    return False


def validate_referer_with_subdomain(referer_header: str, client_redirect_uri: str) -> bool:
    """Validate referer header that have subdomain.

    Args:
        referer_header (str): Referer header string
        client_redirect_uri (str): Client redirect URI string

    Returns:
        bool: Referer header status
    """
    parsed_referer = urlparse(referer_header)
    parsed_redirect_uri = urlparse(client_redirect_uri)

    if parsed_referer.scheme == '' or parsed_redirect_uri.scheme == '':
        return False

    if parsed_referer.netloc == '' or parsed_redirect_uri.netloc == '':
        return False

    if parsed_referer.scheme != parsed_redirect_uri.scheme:
        return False

    return parsed_referer.netloc.endswith(parsed_redirect_uri.netloc)


def validate_subdomain_with_namespace(host: str, namespace: str, excluded_namespaces: List[str]) -> bool:
    """Validate subdomain against namespace

    Args:
        host (str): hostname
        namespace (str): namespace
        excluded_namespaces (List[str]): excluded namespace

    Returns:
        bool: Is subdomain is valid
    """
    host_part = host.split('.')

    # # url with subdomain should have at least 3 part, e.g. foo.example.com, otherwise we should not check it
    if len(host_part) < 3:
        return True
    
    subdomain = host_part[0]
    for excluded_namespace in excluded_namespaces:
        if excluded_namespace.lower() == namespace.lower():
            return True
    
    if namespace.lower() == subdomain.lower():
        return True

    return False


def access_token() -> Callable:
    """Get access token from request.

    Raises:
        IAMError: Error IAM init
        HTTPError: Error if token is not found

    Returns:
        JWTClaims: JWT claims data
    """

    async def _dependency(
        request: Request,
        bearer: Optional[HTTPAuthorizationCredentials] = Security(HTTPBearer(auto_error=False)),
        cookie: Optional[str] = Security(APIKeyCookie(name="access_token", auto_error=False)),
    ) -> tuple:
        try:
            iam = request.app.state.iam
        except AttributeError:
            raise IAMError(
                "You must initialize a IAM with on fastapi "
                "startup event before using this method"
            )

        access_token = None
        token_location = iam.config.iam_token_locations
        for location in token_location:
            # Get token from headers
            if location == "headers":
                if not bearer:
                    continue

                header_parts = bearer.credentials.split()
                access_token = header_parts[-1], "header"

            # Break loop if access token has been found in request header
            if access_token:
                break

            # Get token from cookies
            if location == "cookies":
                if cookie:
                    access_token = cookie, "cookie"

        if not access_token:
            raise HTTPError(*UnauthorizedAccess, description=f"Missing access token in {' or '.join(token_location)}")

        return access_token

    return _dependency


def token_required(csrf_protect: Union[bool, None] = None) -> Callable:
    """Validate token in the FastAPI request. This method support headers and cookies with based token.

    Args:
        csrf_protect (bool, None): Validate referer for CSRF protection

    Raises:
        IAMError: Error IAM init
        HTTPError: Error if token is invalid

    Returns:
        JWTClaims: JWT claims data
    """

    async def _dependency(
        request: Request,
        access_token: tuple = Depends(access_token()),
    ) -> JWTClaims:
        try:
            iam = request.app.state.iam
        except AttributeError:
            raise IAMError(
                "You must initialize a IAM with on fastapi "
                "startup event before using this method"
            )

        try:
            jwt_claims = await iam.client.ValidateAndParseClaims(access_token[0])
        except (ValidateAndParseClaimsError, UserRevokedError, TokenRevokedError) as e:
            raise HTTPError(*UnauthorizedAccess, description=str(e))

        if not jwt_claims:
            raise HTTPError(*UnauthorizedAccess, description=f"Invalid access token")

        # Validate referer header for cookie token
        validate_referer = csrf_protect if csrf_protect is not None \
            else iam.config.iam_csrf_protection

        if access_token[1] == "cookie" and validate_referer:
            if await validate_referer_header(request, jwt_claims) is not True:
                raise HTTPError(*InvalidRefererHeader, description="Invalid referrer header")
        
        if iam.config.iam_subdomain_validation_enable:
            excluded_namespaces = iam.config.iam_subdomain_validation_excluded_namespaces;
            if not validate_subdomain_with_namespace(request.url.netloc, jwt_claims.Namespace, excluded_namespaces):
                raise HTTPError(*SubdomainMismatch, description="Subdomain mismatch")

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

    Raises:
        IAMError: Error IAM init
        HTTPError: Error if JWT claims data is not sufficient to access required permission and resource

    Returns:
        Callable: _description_
    """

    async def _dependency(request: Request, jwt_claims: JWTClaims = Depends(token_required(csrf_protect))) -> None:
        try:
            iam = request.app.state.iam
        except AttributeError:
            raise IAMError(
                "You must initialize a IAM with on fastapi "
                "startup event before using this method"
            )

        permission_required = None
        is_permitted = False
        try:
            if isinstance(required_permission, dict):
                permission_required = Permission.loads(required_permission)

            if not isinstance(permission_required, Permission):
                raise ValueError('Invalid Permission')

            is_permitted = await iam.client.ValidatePermission(
                jwt_claims, permission_required, permission_resource
            )
        except (ValueError, ValidatePermissionError) as e:
            raise HTTPError(*InternalServerError, description=f"unable to validate permission: {str(e)}")

        if not is_permitted:
            raise HTTPError(
                *InsufficientPermissions, description="Access doesn't have required role permission(s)."
            )

    return _dependency
