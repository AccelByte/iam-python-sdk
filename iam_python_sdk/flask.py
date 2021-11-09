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
from typing import Union
from flask import current_app, jsonify, Flask, request

from .config import Config
from .client import DefaultClient, NewDefaultClient
from .errors import ClientTokenGrantError, EmptyTokenError, StartLocalValidationError, TokenRevokedError, \
    UnauthorizedError, UserRevokedError, ValidateAndParseClaimsError
from .models import JWTClaims, Permission


class IAM:
    """IAM Flask extensions class.
    """
    def __init__(self, app: Flask = None) -> None:
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask):
        """Init IAM flask extensions with Flask app.
        Client token grant and local validation will be executed once here,
        then the background thread will spawn to refresh token, jwks and revocation list.

        Args:
            app (Flask): Flask app instance

        Raises:
            ValueError: Error if the requirement configs are not set
        """
        if not (
            app.config.get("IAM_BASE_URL") and app.config.get("IAM_CLIENT_ID") and app.config.get("IAM_CLIENT_SECRET")
        ):
            raise ValueError("IAM_BASE_URL, IAM_CLIENT_ID, IAM_CLIENT_SECRET need to set.")

        self._set_default_config(app)
        self._set_default_errors(app)

        self.client = self._grant_token(app)

        if not hasattr(app, "extensions"):
            app.extensions = {}

        app.extensions["flask_iam"] = self

    def _set_default_config(self, app: Flask) -> None:
        app.config.setdefault("IAM_TOKEN_LOCATIONS", ["headers", "cookies"])
        app.config.setdefault("IAM_TOKEN_HEADER_NAME", "Authorization")
        app.config.setdefault("IAM_TOKEN_HEADER_TYPE", "Bearer")
        app.config.setdefault("IAM_TOKEN_COOKIE_NAME", "access_token")
        app.config.setdefault("IAM_TOKEN_COOKIE_PATH", "/")

    def _set_default_errors(self, app: Flask) -> None:
        @app.errorhandler(EmptyTokenError)
        def handle_token_not_found(error):
            return jsonify({"error": str(error)}), 401

        @app.errorhandler(UnauthorizedError)
        def handle_unauthorized(error):
            return jsonify({"error": str(error)}), 403

    def _grant_token(self, app: Flask) -> DefaultClient:
        config = Config(
            BaseURL=app.config["IAM_BASE_URL"],
            ClientID=app.config["IAM_CLIENT_ID"],
            ClientSecret=app.config["IAM_CLIENT_SECRET"],
        )
        client = NewDefaultClient(config)

        try:
            client.ClientTokenGrant()
            client.StartLocalValidation()
        except (ClientTokenGrantError, StartLocalValidationError):
            # Cant get access token from IAM
            raise

        return client

    def validate_token_in_request(self) -> Union[JWTClaims, None]:
        """Validate token in the Flask request. This method support headers and cookies with based token.

        Raises:
            EmptyTokenError: Error if token is not found
            UnauthorizedError: Error if token permission is not sufficient

        Returns:
            JWTClaims: JWT claims data
        """
        access_token = ""
        token_location = current_app.config.get("IAM_TOKEN_LOCATIONS")
        for location in token_location:
            if location == "headers":
                auth_name = current_app.config.get("IAM_TOKEN_HEADER_NAME")
                auth_type = current_app.config.get("IAM_TOKEN_HEADER_TYPE")

                auth_header = request.headers.get(auth_name, None)
                if not auth_header:
                    continue

                header_parts = auth_header.split()
                if not auth_type:
                    access_token = header_parts[0]
                else:
                    access_token = header_parts[1]

            if location == "cookies":
                cookie_name = current_app.config.get("IAM_TOKEN_COOKIE_NAME")
                auth_cookie = request.cookies.get(cookie_name)
                if auth_cookie:
                    access_token = auth_cookie

        if not access_token:
            raise EmptyTokenError("Token not found")

        try:
            jwt_claims = self.client.ValidateAndParseClaims(access_token)
        except (ValidateAndParseClaimsError, UserRevokedError, TokenRevokedError):
            raise UnauthorizedError("Token is invalid or revoked")

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
            UnauthorizedError: Error if JWT claims data is not sufficient to access required permission and resource

        Returns:
            bool: Permission status
        """

        if isinstance(required_permission, dict):
            required_permission = Permission.loads(required_permission)

        if not isinstance(required_permission, Permission):
            raise UnauthorizedError

        return self.client.ValidatePermission(jwt_claims, required_permission, permission_resource)


def token_required(required_permission: dict, permission_resource: dict = {}):
    """The decorator to protect endpoint using IAM service.

    Args:
        required_permission (dict): Required permission with format {"resource": xxx, "action": n}
        permission_resource (dict, optional): Optional permission resource if needed with format
            {"{xxx}": "xxx replacement"}. Defaults to {}.
    """
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            iam = current_app.extensions.get("flask_iam")
            if not iam:
                raise RuntimeError(
                    "You must initialize a IAM with this flask "
                    "application before using this method"
                )

            jwt_claims = iam.validate_token_in_request()
            is_valid = iam.validate_permission(jwt_claims, required_permission, permission_resource)

            if not is_valid:
                raise UnauthorizedError("Token do not have required permissions")

            return fn(*args, **kwargs)

        return decorator

    return wrapper
