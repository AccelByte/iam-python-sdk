=====
Usage
=====

Prerequisite
============

IAM Python SDK implement OAuth 2.0 specifications with client credetial flow. Before you can use IAM Python SDK,
you need to get ``Client ID``, ``Client Secret`` and ``Base IAM URL`` from your Admin Portal (AP). To get these values,
please read more on this `documentation <https://docs.accelbyte.io/guides/access/iam-client.html>`_

.. note::
    The ``Base IAM URL`` should be like: **[your-domain]/iam** wherein **[your-domain]** is the base URL of your accelbyte services.
    It can be a sub-domain of accelbyte domain or your own custom domain, e.g.: **https://demo.accelbyte.io/iam**

Init IAM client
===============

To use iam-python-sdk in a project, first you need to initiate IAM client:

.. code-block:: python

    from iam_python_sdk import Config, NewDefaultClient

    config = Config(
        BaseURL="<Base IAM URL>",  # e.g.: https://demo.accelbyte.io/iam
        ClientID="<Client ID>",
        ClientSecret="<Client Secret>",
    )
    client = NewDefaultClient(config)

Grant access token
==================

To get access token, you need to call `ClientTokenGrant` method:

.. code-block:: python

    from iam_python_sdk.errors import ClientTokenGrantError

    try:
        client.ClientTokenGrant()
        # Client token grant success
    except ClientTokenGrantError as e:
        # Cant get access token from IAM
        pass

You can check the access token using `ClientToken` function:

.. code-block:: python

    access_token = client.ClientToken()

.. note::
    You can use this **access token** to access many AccelByte services
    based on permission and role that you have set before on AP.

Validate access token
=====================

There are two methods to validate access token. 
First, you can validate access token live on IAM service using `ValidateAccessToken` function: 

.. code-block:: python

    from iam_python_sdk.errors import ValidateAccessTokenError

    try:
        is_token_valid = client.ValidateAccessToken(access_token)
        if is_token_valid:
            # Token is valid
            pass
    except ValidateAccessTokenError as e:
        # Cant validate access token on IAM service
        pass

Second, you can validate access token localy using JWKs and revocation list.
To do local validation, once you need to enable local validation using `StartLocalValidation` method:

.. code-block:: python

    from iam_python_sdk.errors import StartLocalValidationError

    try:
        client.StartLocalValidation()
    except StartLocalValidationError as e:
        # Cant enable local validation
        pass

Then, you can validate access token locally using `ValidateAndParseClaims` function:

.. code-block:: python

    from iam_python_sdk.errors import NoLocalValidationError, ValidateAndParseClaimsError

    try:
        claims = client.ValidateAndParseClaims(access_token)
        # Access token is valid
    except NoLocalValidationError as e:
        # You need to call StartLocalValidation method once
        pass
    except ValidateAndParseClaimsError as e:
        # Cant validate and parse claim locally
        pass

.. note::
    Store the **claims** output if you need to validate it's permission, role, or other properties.

Validate permission
===================

For example, you have a resource permission that needs *NAMESPACE:{namespace}:USER:{userId}* resource string and 4 [UPDATE] action to access.

Using claims you can verify if the token owner is allowed to access the resource using `ValidatePermission` function:

.. code-block:: python

    from iam_python_sdk.errors import ValidatePermissionError

    try:
        required_permission = Permission.loads(
            {"Action": 4, "Resource": "NAMESPACE:{namespace}:USER:{userId}"}
        )
        permission_resource = {"{namespace}": "sample-namespace", "{userId}": "sample-userid"}
        valid_permission = client.ValidatePermission(
            claims, required_permission, permission_resource
        )
        if valid_permission:
            # Permission is valid and token owner is allowed to access the resource
            pass
    except ValidatePermissionError as e:
        # Cant get role permission from IAM service
        pass


Validate role and scope
=======================

To validate token owner have a required role ID, you can use `ValidateRole` function:

.. code-block:: python

    required_role_id = 'sample_role_id_12345'
    valid_role = client.ValidateRole(required_role_id, claims)
    if valid_role:
        # Role is valid and token owner have the required role id
        pass

To validate token owner have required scope, you can use `ValidateScope` method:

.. code-block:: python

    from iam_python_sdk.errors import ValidateScopeError

    try:
        required_scope = 'sample_scope'
        client.ValidateScope(required_scope, claims)
        # Scope is valid and token owner have the required scope
    except ValidateScopeError as e:
        # Scope is invalid
        pass

Check Ban
=========

To check if user have been banned, you can use `HasBan` function:

.. code-block:: python

    ban_status = client.HasBan(claims, 'sample-ban-type')
    if ban_status:
        # User have been banned
        pass

Validate audience
=================

To validate JWT claims have a valid audience, you can use `ValidateAudience` method:

.. code-block:: python

    from iam_python_sdk.errors import ValidateAudienceError

    try:
        client.ValidateAudience(claims)
        # JWT claims have valid audience
    except ValidateAudienceError as e:
        # JWT claims have invalid audience
        pass

.. note::
    If no audience is found in the claims, `ValidateAudience` method will not check the audience 
    and assume that the audience in JWT claims is valid [https://tools.ietf.org/html/rfc7519#section-4.1.3]

Verify user info
================

Email status
------------

You can check user email verification status using `UserEmailVerificationStatus` function:

.. code-block:: python

    email_verified = client.UserEmailVerificationStatus(claims)
    if email_verified:
        # User's email have been verified
        pass

Phone status
------------

You can check user phone verification status using `UserPhoneVerificationStatus` function:

.. code-block:: python

    phone_verified = client.UserPhoneVerificationStatus(claims)
    if phone_verified:
        # User's phone have been verified
        pass

Anonymity status
----------------

You can check user anonymity status using `UserAnonymousStatus` function:

.. code-block:: python

    user_anonymous = client.UserAnonymousStatus(claims)
    if user_anonymous:
        # User is anonymous
        pass
