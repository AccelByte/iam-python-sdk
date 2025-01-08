# Copyright 2025 AccelByte Inc
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

import unittest
from unittest.mock import Mock, patch

from flask import Flask

from iam_python_sdk.client import DefaultClient, JWTClaims
from iam_python_sdk.flask import IAM, HTTPError
from iam_python_sdk.models import ClientInformation


class TestInvalidRefererHeader(unittest.TestCase):
    @patch("iam_python_sdk.flask.NewDefaultClient")
    def setUp(self, mock_new_client):
        """
        Common test setup with mocked client initialization
        """
        # Given a Flask application with IAM configuration
        self.app = Flask(__name__)
        self.app.config.update(
            {
                "IAM_BASE_URL": "http://iam-test.local",
                "IAM_CLIENT_ID": "test-client",
                "IAM_CLIENT_SECRET": "test-secret",
                "IAM_TOKEN_LOCATIONS": ["cookies"],
                "IAM_TOKEN_COOKIE_NAME": "access_token",
                "IAM_CSRF_PROTECTION": True,
                "IAM_STRICT_REFERER": True,
            }
        )

        # Mock the client initialization
        self.mock_client = Mock(spec=DefaultClient)
        mock_new_client.return_value = self.mock_client

        # Initialize IAM with mocked client
        self.iam = IAM(self.app)

        # And prepared JWT claims
        self.jwt_claims = JWTClaims()
        self.jwt_claims.Namespace = "test-namespace"
        self.jwt_claims.ClientId = "test-client-id"

        # And prepared client information
        self.client_info = ClientInformation()
        self.client_info.Redirecturi = "https://allowed-domain.com/callback"

    def test_missing_referer_header_should_raise_error(self):
        """
        Given a request without a referer header
        When validating the token
        Then it should raise an HTTPError with appropriate error codes
        """
        # Given
        ctx = self.app.test_request_context(
            "/",
            headers={"Cookie": "access_token=test-token"},
            environ_base={"HTTP_REFERER": ""},
        )
        self.mock_client.ValidateAndParseClaims.return_value = self.jwt_claims
        self.mock_client.GetClientInformation.return_value = self.client_info

        # When/Then
        with ctx:
            with self.assertRaises(HTTPError) as context:
                self.iam.validate_token_in_request(validate_referer=True)

            error = context.exception
            self.assertEqual(error.code, 401)
            self.assertEqual(error.error_code, 20023)
            self.assertIn("Invalid referrer header", error.description)

    def test_wrong_domain_in_referer_header_should_raise_error(self):
        """
        Given a request with a referer header from an unauthorized domain
        When validating the token
        Then it should raise an HTTPError with appropriate error codes
        """
        # Given
        ctx = self.app.test_request_context(
            "/",
            headers={"Cookie": "access_token=test-token"},
            environ_base={"HTTP_REFERER": "https://malicious-domain.com"},
        )
        self.mock_client.ValidateAndParseClaims.return_value = self.jwt_claims
        self.mock_client.GetClientInformation.return_value = self.client_info

        # When/Then
        with ctx:
            with self.assertRaises(HTTPError) as context:
                self.iam.validate_token_in_request(validate_referer=True)

            error = context.exception
            self.assertEqual(error.code, 401)
            self.assertEqual(error.error_code, 20023)
            self.assertIn("Invalid referrer header", error.description)

    def test_malformed_referer_url_should_raise_error(self):
        """
        Given a request with a malformed referer URL
        When validating the token
        Then it should raise an HTTPError with appropriate error codes
        """
        # Given
        ctx = self.app.test_request_context(
            "/",
            headers={"Cookie": "access_token=test-token"},
            environ_base={"HTTP_REFERER": "not-a-valid-url"},
        )
        self.mock_client.ValidateAndParseClaims.return_value = self.jwt_claims
        self.mock_client.GetClientInformation.return_value = self.client_info

        # When/Then
        with ctx:
            with self.assertRaises(HTTPError) as context:
                self.iam.validate_token_in_request(validate_referer=True)

            error = context.exception
            self.assertEqual(error.code, 401)
            self.assertEqual(error.error_code, 20023)
            self.assertIn("Invalid referrer header", error.description)

    def test_empty_client_redirect_uri_should_allow_any_referer(self):
        """
        Given a client with no configured redirect URIs
        When validating the token with any referer
        Then it should allow the request
        """
        # Given
        ctx = self.app.test_request_context(
            "/",
            headers={"Cookie": "access_token=test-token"},
            environ_base={"HTTP_REFERER": "https://any-domain.com"},
        )
        empty_client_info = ClientInformation()
        empty_client_info.Redirecturi = ""
        self.mock_client.ValidateAndParseClaims.return_value = self.jwt_claims
        self.mock_client.GetClientInformation.return_value = empty_client_info

        # When
        with ctx:
            result = self.iam.validate_token_in_request(validate_referer=True)

        # Then
        self.assertEqual(result, self.jwt_claims)

    def test_valid_referer_header_should_succeed(self):
        """
        Given a request with a valid referer header
        When validating the token
        Then it should complete successfully
        """
        # Given
        ctx = self.app.test_request_context(
            "/",
            headers={"Cookie": "access_token=test-token"},
            environ_base={"HTTP_REFERER": "https://allowed-domain.com/callback"},
        )
        self.mock_client.ValidateAndParseClaims.return_value = self.jwt_claims
        self.mock_client.GetClientInformation.return_value = self.client_info

        # When
        with ctx:
            result = self.iam.validate_token_in_request(validate_referer=True)

        # Then
        self.assertEqual(result, self.jwt_claims)

    def test_changing_referer_mid_process_should_succeed(self):
        """
        Given an initial request with a valid referer and cached client info
        When the client's redirect URIs are updated and a request comes from a new valid domain
        Then the request should succeed using the cached and updated client info
        """
        # Given - Initial setup with first domain
        initial_client_info = ClientInformation()
        initial_client_info.Redirecturi = "https://allowed-domain.com/callback"

        initial_ctx = self.app.test_request_context(
            "/",
            headers={"Cookie": "access_token=test-token"},
            environ_base={"HTTP_REFERER": "https://allowed-domain.com/callback"},
        )
        self.mock_client.ValidateAndParseClaims.return_value = self.jwt_claims
        self.mock_client.GetClientInformation.return_value = initial_client_info

        # First request should succeed and cache the client info
        with initial_ctx:
            result = self.iam.validate_token_in_request(validate_referer=True)
            self.assertEqual(result, self.jwt_claims)

            # Verify GetClientInformation was called once
            self.mock_client.GetClientInformation.assert_called_once_with(
                self.jwt_claims.Namespace, self.jwt_claims.ClientId
            )

        # Clear the cache to simulate expiration
        self.iam.client_info_cache.clear()

        # When - Client info is updated with new redirect URI
        updated_client_info = ClientInformation()
        updated_client_info.Redirecturi = "https://new-domain.com/callback"
        self.mock_client.GetClientInformation.reset_mock()
        self.mock_client.GetClientInformation.return_value = updated_client_info

        # Create new request from the new domain
        new_domain_ctx = self.app.test_request_context(
            "/",
            headers={"Cookie": "access_token=test-token"},
            environ_base={"HTTP_REFERER": "https://new-domain.com/callback"},
        )

        # Then - The request should succeed with new client info
        with new_domain_ctx:
            result = self.iam.validate_token_in_request(validate_referer=True)
            self.assertEqual(result, self.jwt_claims)

            # Verify GetClientInformation was called again (after cache clear)
            self.mock_client.GetClientInformation.assert_called_once_with(
                self.jwt_claims.Namespace, self.jwt_claims.ClientId
            )


if __name__ == "__main__":
    unittest.main()
