==============
IAM Python SDK
==============


.. image:: https://img.shields.io/pypi/v/iam-python-sdk
        :target: https://pypi.python.org/pypi/iam-python-sdk
        :alt: PyPI Status

.. image:: https://img.shields.io/github/workflow/status/accelbyte/iam-python-sdk/Test%20Package?label=testing
        :target: https://github.com/accelbyte/iam-python-sdk/actions
        :alt: GitHub Workflow Status

.. image:: https://img.shields.io/pypi/pyversions/iam-python-sdk
        :target: https://pypi.python.org/pypi/iam-python-sdk
        :alt: Python Version

.. image:: https://img.shields.io/pypi/l/iam-python-sdk
        :target: https://github.com/AccelByte/iam-python-sdk/blob/main/LICENSE
        :alt: License


AccelByte IAM Python SDK is a software development kit to help python developers build their own services/apps
that makes use of AccelByte User Account Management services [https://accelbyte.io/user-account-management/].


* Free software: `Apache Software License 2.0 <https://github.com/AccelByte/iam-python-sdk/blob/main/LICENSE>`_
* Documentation: https://accelbyte.github.io/iam-python-sdk


Features
--------

* Client token grant and validation
* Sync and async client
* Validate access token live on IAM service and local using JWKs
* Get role and validate permission
* Validate scope, role and audience
* Verify ban, phone and email user status
* Background refresh token, jwks and revocation list
* Flask and FastAPI framework support with CSRF protection and CORS options
