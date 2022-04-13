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

"""Flask module."""

from functools import wraps
from typing import Optional, Union
from flask import current_app, Flask, request
from flask.helpers import make_response
from flask.wrappers import Response
from urllib.parse import urlparse
from werkzeug.exceptions import HTTPException

from .config import Config
from .client import DefaultClient, NewDefaultClient
from .errors import Error as IAMError, ClientTokenGrantError, GetClientInformationError, StartLocalValidationError, \
    TokenRevokedError, UserRevokedError, ValidateAndParseClaimsError, ValidatePermissionError
from .http_errors import InsufficientPermissions, InternalServerError, InvalidRefererHeader, UnauthorizedAccess
from .models import JWTClaims, Permission


# ---------- Exceptions ---------- #

class HTTPError(HTTPException):
    def __init__(self, http_code: int, error_code: int, message: str, description: Optional[str] = None) -> None:
        super().__init__(description)
        self.code = http_code
        self.error_code = error_code
        self.message = message
        self.description = description

# ---------- Extensions ---------- #


class IAM:
    """IAM Flask extensions class.
    """
    def __init__(self, app: Union[Flask, None] = None) -> None:
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        """Init IAM flask extensions with Flask app.
        Client token grant and local validation will be executed once here,
        then the background thread will spawn to refresh token, jwks and revocation list.

        Args:
            app (Flask): Flask app instance

        Raises:
            IAMError: Error if the requirement configs are not set
        """
        if not (
            app.config.get("IAM_BASE_URL") and app.config.get("IAM_CLIENT_ID") and app.config.get("IAM_CLIENT_SECRET")
        ):
            raise IAMError("IAM_BASE_URL, IAM_CLIENT_ID, IAM_CLIENT_SECRET need to set.")

        self._set_default_config(app)
        self._set_default_errors(app)

        self.client = self.grant_token(app)

        if not hasattr(app, "extensions"):
            app.extensions = {}

        app.extensions["flask_iam"] = self

        if app.config.get("IAM_CORS_ENABLE"):
            app.after_request(self._set_default_cors_headers)

    def _set_default_config(self, app: Flask) -> None:
        app.config.setdefault("IAM_TOKEN_LOCATIONS", ["headers", "cookies"])
        app.config.setdefault("IAM_TOKEN_HEADER_NAME", "Authorization")
        app.config.setdefault("IAM_TOKEN_HEADER_TYPE", "Bearer")
        app.config.setdefault("IAM_TOKEN_COOKIE_NAME", "access_token")
        app.config.setdefault("IAM_TOKEN_COOKIE_PATH", "/")
        app.config.setdefault("IAM_CSRF_PROTECTION", True)
        app.config.setdefault("IAM_STRICT_REFERER", False)
        app.config.setdefault("IAM_CORS_ENABLE", False)
        app.config.setdefault("IAM_CORS_ORIGIN", "*")
        app.config.setdefault("IAM_CORS_HEADERS", "*")
        app.config.setdefault("IAM_CORS_METHODS", "*")
        app.config.setdefault("IAM_CORS_CREDENTIALS", True)

    def _set_default_errors(self, app: Flask) -> None:
        @app.errorhandler(HTTPError)
        def handle_http_error(error):
            return {'errorCode': error.error_code, 'errorMessage': f"{error.message}: {error.description}"}, error.code

        @app.errorhandler(IAMError)
        def handle_iam_error(error):
            return {'errorCode': InternalServerError[1], 'errorMessage': f"{InternalServerError[1]}: {str(error)}"}, \
                InternalServerError[0]

    def _set_default_cors_headers(self, response: Response) -> Response:
        allowed_origin = current_app.config.get("IAM_CORS_ORIGIN")
        allowed_headers = current_app.config.get("IAM_CORS_HEADERS")
        allow_credentials = str(current_app.config.get("IAM_CORS_CREDENTIALS")).lower()
        allowed_methods = list(request.url_rule.methods or ()) if request.url_rule \
            else current_app.config.get("IAM_CORS_METHODS")

        if isinstance(allowed_methods, list):
            allowed_methods = ", ".join(allowed_methods)
        if isinstance(allowed_headers, list):
            allowed_headers = ", ".join(allowed_headers)

        response.headers.setdefault("Access-Control-Allow-Origin", allowed_origin)
        response.headers.setdefault("Access-Control-Allow-Headers", allowed_headers)
        response.headers.setdefault("Access-Control-Allow-Methods", allowed_methods)
        response.headers.setdefault("Access-Control-Allow-Credentials", allow_credentials)

        return response

    def grant_token(self, app: Flask) -> DefaultClient:
        """Generate oauth IAM token

        Args:
            app (Flask): Flask app

        Raises:
            HTTPError: Unable to grant token

        Returns:
            DefaultClient: IAM SDK default client object
        """
        config = Config(
            BaseURL=app.config["IAM_BASE_URL"],
            ClientID=app.config["IAM_CLIENT_ID"],
            ClientSecret=app.config["IAM_CLIENT_SECRET"],
        )
        client = NewDefaultClient(config)

        try:
            client.ClientTokenGrant()
            client.StartLocalValidation()
        except (ClientTokenGrantError, StartLocalValidationError) as e:
            # Cant get access token from IAM
            raise HTTPError(*InternalServerError, description=f"unable to grant token: {str(e)}")

        return client

    def validate_referer_header(self, jwt_claims: JWTClaims) -> bool:
        """Validate referer header for CSRF protection

        Args:
            jwt_claims (JWTClaims): JWT claims data

        Returns:
            bool: Is referer header valid or not
        """
        try:
            client_info = self.client.GetClientInformation(jwt_claims.Namespace, jwt_claims.ClientId)
        except GetClientInformationError:
            return False

        if client_info and not client_info.Redirecturi:
            return True

        referer_header = request.referrer
        client_redirect_uris = client_info.Redirecturi.split(",") if client_info else []

        for redirect_uri in client_redirect_uris:
            if not current_app.config.get("IAM_STRICT_REFERER"):
                parsed_uri = urlparse(redirect_uri)
                redirect_uri = f"{parsed_uri.scheme}://{parsed_uri.netloc}"

            if referer_header and referer_header.startswith(redirect_uri):
                return True

        return False

    def validate_token_in_request(self, validate_referer: bool) -> JWTClaims:
        """Validate token in the Flask request. This method support headers and cookies with based token.

        Args:
            validate_referer (bool): Validate referer for CSRF protection

        Raises:
            HTTPError: Error if token is not found or invalid

        Returns:
            JWTClaims: JWT claims data
        """
        access_token = ""
        token_location = current_app.config.get("IAM_TOKEN_LOCATIONS", [])
        for location in token_location:
            # Get token from headers
            if location == "headers":
                auth_name = current_app.config.get("IAM_TOKEN_HEADER_NAME")
                auth_type = current_app.config.get("IAM_TOKEN_HEADER_TYPE")

                auth_header = request.headers.get(auth_name, None)
                if not auth_header:
                    continue

                header_parts = auth_header.split()
                if not auth_type:
                    access_token = header_parts[0], "header"
                else:
                    access_token = header_parts[1], "header"

            # Get token from cookies
            if location == "cookies":
                cookie_name = current_app.config.get("IAM_TOKEN_COOKIE_NAME")
                auth_cookie = request.cookies.get(cookie_name)
                if auth_cookie:
                    access_token = auth_cookie, "cookie"

        if not access_token:
            raise HTTPError(*UnauthorizedAccess, description=f"Missing access token in {' or '.join(token_location)}")

        try:
            jwt_claims = self.client.ValidateAndParseClaims(access_token[0])
        except (ValidateAndParseClaimsError, UserRevokedError, TokenRevokedError) as e:
            raise HTTPError(*UnauthorizedAccess, description=str(e))

        if not jwt_claims:
            raise HTTPError(*UnauthorizedAccess, description=f"Invalid access token")

        # Validate referer header for cookie token
        if access_token[1] == "cookie" and validate_referer:
            if self.validate_referer_header(jwt_claims) is not True:
                raise HTTPError(*InvalidRefererHeader, description="Invalid referrer header")

        return jwt_claims

    def validate_permission(self, jwt_claims: JWTClaims,
                            required_permission: Union[dict, Permission],
                            permission_resource: dict
                            ) -> bool:
        """Validate permission from JWT claims data.

        Args:
            jwt_claims (JWTClaims): JWT claims data
            required_permission (Union[dict, Permission]): Required permission that needed,
                can be in dict or Permission format.
            permission_resource (dict): Optional permission resource if needed

        Raises:
            HTTPError: Error if JWT claims data is not sufficient to access required permission and resource

        Returns:
            bool: Permission status
        """

        try:
            if isinstance(required_permission, dict):
                required_permission = Permission.loads(required_permission)

            if not isinstance(required_permission, Permission):
                raise ValueError('Invalid Permission')

            is_permitted = self.client.ValidatePermission(jwt_claims, required_permission, permission_resource)

        except (ValueError, ValidatePermissionError) as e:
            raise HTTPError(*InternalServerError, description=f"unable to validate permission: {str(e)}")

        return is_permitted


# ---------- Decorators ---------- #


def permission_required(required_permission: dict, permission_resource: dict = {},
                        csrf_protect: Union[bool, None] = None):
    """The decorator to protect endpoint using IAM service.

    Args:
        required_permission (dict): Required permission with format {"resource": xxx, "action": n}
        permission_resource (dict, optional): Optional permission resource if needed with format
            {"{xxx}": "xxx replacement"}. Defaults to {}.
        csrf_protect (bool): CSRF protection (Note: CSRF protect is available only on cookie token).
            Defaults to IAM_CSRF_PROTECTION config.

        Raises:
            IAMError: Error IAM init
            HTTPError: Insufficient permission

        Returns:
            Callable: Wrapped function
    """
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            iam = current_app.extensions.get("flask_iam")
            if not iam:
                raise IAMError(
                    "You must initialize a IAM with this flask "
                    "application before using this method"
                )

            validate_referer = csrf_protect if csrf_protect is not None \
                else current_app.config.get("IAM_CSRF_PROTECTION")

            jwt_claims = iam.validate_token_in_request(validate_referer)
            is_permitted = iam.validate_permission(jwt_claims, required_permission, permission_resource)
            if not is_permitted:
                raise HTTPError(
                    *InsufficientPermissions, description="Access doesn't have required role permission(s)."
                )

            return fn(*args, **kwargs)

        return decorator

    return wrapper


def cors_options(headers: dict = {}, preflight_options: bool = True):
    """Decorator for set the CORS response header. This method will override
    default app-wide CORS options if it has enabled.

    Args:
        headers (dict, optional): CORS headers key and value to be added to the response. Defaults to {}.

    Returns:
        Callable: Wrapped functions.
    """
    def wrapper(fn):
        if preflight_options:
            fn.required_methods = getattr(fn, 'required_methods', set())
            fn.required_methods.add('OPTIONS')
            fn.provide_automatic_options = False

        @wraps(fn)
        def decorator(*args, **kwargs):
            if preflight_options and request.method == 'OPTIONS':
                response = current_app.make_default_options_response()
            else:
                response = make_response(fn(*args, **kwargs))

            for key, value in headers.items():
                if isinstance(value, list):
                    value = ", ".join(value)

                if isinstance(value, bool):
                    value = str(value).lower()

                response.headers.add(key, value)

            return response

        return decorator

    return wrapper
