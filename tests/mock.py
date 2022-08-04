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

"""Mock module."""

import httpx, fastapi, flask, json, jwt, respx, secrets, time

from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from urllib import parse

from iam_python_sdk.config import (
    CLIENT_INFORMATION_PATH,
    GET_ROLE_PATH,
    GRANT_PATH,
    JWKS_PATH,
    REVOCATION_LIST_PATH,
    VERIFY_PATH,
)

from iam_python_sdk.flask import permission_required as flask_permission_required
from iam_python_sdk.flask import cors_options as flask_cors_options
from iam_python_sdk.fastapi import permission_required as fastapi_permission_required

iam_base_url = "https://api.mock/iam"

rsa_algorithm = RSAAlgorithm(hash_alg="RS256")
rsa_private_key = rsa.generate_private_key(65537, 2048)
rsa_public_key = rsa_private_key.public_key()

key_id = secrets.token_hex(16)
role_id = secrets.token_hex(16)
client_id = secrets.token_hex(16)
client_secret = secrets.token_urlsafe(32)
namespace = "sdktest"

claims_data = {
    "bans": None,
    "client_id": client_id,
    "country": "",
    "display_name": "",
    "exp": int(time.time()) + 3600,
    "iat": int(time.time()),
    "is_comply": True,
    "jflgs": 0,
    "namespace": "sdktest",
    "namespace_roles": [
        {"namespace": "other", "roleId": role_id},
        {"namespace": "sdktest", "roleId": role_id},
    ],
    "permissions": [
        {"Action": 2, "Resource": "ROLE"},
        {"Action": 2, "Resource": "ADMIN:NAMESPACE:sdktest:CLIENT:{clientId}"},
        {"Action": 2, "Resource": "ADMIN:NAMESPACE:sdktest:CLIENT"},
    ],
    "roles": [role_id],
    "scope": "account commerce social publishing analytics",
}

client_token = {
    "access_token": jwt.encode(
        claims_data, rsa_private_key, algorithm="RS256", headers={"kid": key_id}
    ),
    "bans": [],
    "display_name": "",
    "expires_in": 3600,
    "is_comply": True,
    "jflgs": 0,
    "namespace": "sdktest",
    "namespace_roles": None,
    "permissions": [
        {"Resource": "ROLE", "Action": 2},
        {"Resource": "ADMIN:NAMESPACE:sdktest:CLIENT:{clientId}", "Action": 2},
        {"Resource": "ADMIN:NAMESPACE:sdktest:CLIENT", "Action": 2},
    ],
    "platform_id": "",
    "platform_user_id": "",
    "roles": None,
    "scope": "account commerce social publishing analytics",
    "token_type": "Bearer",
    "user_id": "",
    "xuid": "",
}

client_info = {
    "clientId": client_id,
    "clientName": "IAM Client Test",
    "namespace": "sdktest",
    "redirectUri": "https://example.com",
    "oauthClientType": "Confidential",
    "audiences": [],
    "baseUri": "",
    "clientPermissions": [
        {"resource": "ROLE", "action": 2},
        {"resource": "ADMIN:NAMESPACE:{namespace}:CLIENT:{clientId}", "action": 2},
        {"resource": "ADMIN:NAMESPACE:{namespace}:CLIENT", "action": 2},
    ],
    "createdAt": "2021-10-13T12:04:12.485691Z",
    "modifiedAt": "0001-01-01T00:00:00Z",
    "scopes": ["account", "commerce", "social", "publishing", "analytics"],
}

role_data = {
    "RoleId": role_id,
    "RoleName": "Role Test",
    "Permissions": [
        {"Action": 1, "Resource": "PERMISSION:PERMISSION"},
        {"Action": 3, "Resource": "PERMISSION"},
        {"Action": 2, "Resource": "ADMIN:NAMESPACE:{namespace}:ANALYTICS"},
    ],
    "IsWildcard": False,
}

jwk = json.loads(rsa_algorithm.to_jwk(rsa_public_key))
jwk["kid"] = key_id
jwks = {"keys": [jwk]}

revocation_list = {
    "revoked_tokens": {
        "m": 2432,
        "k": 17,
        "bits": [0, 0, 0, 0, 0, 0, 2048, 8796093022208, 2048, 8796093024256, 8796093022208, 2048, 8796093024256, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 134217728, 576460752303423488, 0, 576460752437641216, 576460752303423488, 134217728, 576460752437641216, 0, 0, 0, 0, 0, 0, 0],
    },
    "revoked_users": [
        {
            "id": "4156e19046cc48bb8e95f5b3bea00c78",
            "revoked_at": "2021-10-17T17:05:49.556462544Z",
        },
        {
            "id": "d81d993c766e4d869cf5ead7d239b7c6",
            "revoked_at": "2021-10-17T17:06:54.651398651Z",
        },
        {
            "id": "ff748b57b9314c589ce9957fbc35ff31",
            "revoked_at": "2021-10-17T17:12:14.19559528Z",
        },
    ],
}

# IAM Mock API
iam_mock = respx.mock(assert_all_called=False)


# Client token grant mock api
@iam_mock.post(url=iam_base_url + GRANT_PATH)
def get_token(request):
    return httpx.Response(200, json=client_token)


# Get JWKS mock api
@iam_mock.get(url=iam_base_url + JWKS_PATH)
def get_jwks(request):
    return httpx.Response(200, json=jwks)


# Get revocation list mock api
@iam_mock.get(url=iam_base_url + REVOCATION_LIST_PATH)
def get_revocation_list(request):
    return httpx.Response(200, json=revocation_list)


# Validate access token mock api
@iam_mock.post(url=iam_base_url + VERIFY_PATH)
def verify_token(request):
    request_data = parse.parse_qs(request.content.decode("ascii"))
    access_token = request_data.get("token")
    if access_token and (access_token[0] == client_token.get("access_token")):
        return httpx.Response(200)
    return httpx.Response(400)


# Get client information mock api
@iam_mock.get(url=iam_base_url + CLIENT_INFORMATION_PATH % (namespace, client_id))
def get_client_info(request):
    return httpx.Response(200, json=client_info)


# Get role permission mock api
@iam_mock.get(url__regex=iam_base_url + GET_ROLE_PATH + "/" + r"(?P<role>\w+)")
def role_api(request, role):
    if role != role_id:
        return httpx.Response(404)
    return httpx.Response(200, json=role_data)


# Flask mock
flask_mock = flask.Blueprint("flask_mock", __name__)


@flask_mock.route('/')
def flask_unprotected():
    return flask.jsonify({'status': 'unprotected'})


@flask_mock.route('/protected')
@flask_permission_required({"resource": "ADMIN:NAMESPACE:{namespace}:CLIENT", "action": 2}, {"{namespace}": "sdktest"}, False)
def flask_protected():
    return flask.jsonify({'status': 'protected'})


@flask_mock.route('/protected_with_csrf')
@flask_permission_required({"resource": "ADMIN:NAMESPACE:{namespace}:CLIENT", "action": 2}, {"{namespace}": "sdktest"})
def flask_protected_with_csrf():
    return flask.jsonify({'status': 'protected'})


@flask_mock.route('/protected_with_cors', methods=["POST"])
@flask_cors_options({"Access-Control-Allow-Headers": ["Device-Id", "Device-Os", "Device-Type"]})
def flask_protected_with_cors():
    return flask.jsonify({'status': 'protected'})


# FastAPI mock
fastapi_mock = fastapi.APIRouter()


@fastapi_mock.get('/')
def fastapi_unprotected():
    return fastapi.responses.JSONResponse(content={'status': 'unprotected'})


@fastapi_mock.get('/protected', dependencies=[fastapi.Depends(fastapi_permission_required({"resource": "ADMIN:NAMESPACE:{namespace}:CLIENT", "action": 2}, {"{namespace}": "sdktest"}, False))])
def fastapi_protected():
    return fastapi.responses.JSONResponse(content={'status': 'protected'})


@fastapi_mock.get('/protected_with_csrf', dependencies=[fastapi.Depends(fastapi_permission_required({"resource": "ADMIN:NAMESPACE:{namespace}:CLIENT", "action": 2}, {"{namespace}": "sdktest"}))])
def fastapi_protected_with_csrf():
    return fastapi.responses.JSONResponse(content={'status': 'protected'})


@fastapi_mock.post('/protected_with_cors')
def fastapi_protected_with_cors():
    return fastapi.responses.JSONResponse(content={'status': 'protected'})
