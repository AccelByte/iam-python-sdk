==========
Frameworks
==========

Flask
=====

Usage
-----

To use iam-python-sdk on Flask frameworks, you have to init the iam-python-sdk Flask extensions:

.. code-block:: python

    from flask import Flask
    from iam_python_sdk.flask import IAM

    app = Flask(__name__)

    app.config["IAM_BASE_URL"] = "<Base IAM URL>"
    app.config["IAM_CLIENT_ID"] = "<Client ID>"
    app.config["IAM_CLIENT_SECRET"] = "<Client Secret>"

    iam = IAM(app)

Or you can init with `Flask factory pattern`_:

.. code-block:: python

    from flask import Flask
    from iam_python_sdk.flask import IAM

    iam = IAM()

    def create_app():
        app = Flask(__name__)

        app.config["IAM_BASE_URL"] = "<Base IAM URL>"
        app.config["IAM_CLIENT_ID"] = "<Client ID>"
        app.config["IAM_CLIENT_SECRET"] = "<Client Secret>"

        iam.init_app(app)

        return app

.. _Flask factory pattern: https://flask.palletsprojects.com/en/latest/patterns/appfactories/

Then you can protect your endpoint with *token_required* decorator from unauthorized access:

.. code-block:: python

    @app.route('/protected')
    @token_required(
        {"Action": 4, "Resource": "NAMESPACE:{namespace}:USER:{userId}"},
        {"{namespace}": "sample-namespace", "{userId}": "sample-userid"},
        csrf_protect=True
    )
    def get_protected_endpoint():
        return 'You have authorized access!'

By default, *token_required* decorator will check the access token on the Authorization header with Bearer type.
You can customize these default configurations according to your service/apps needs:

.. code-block:: python

    app.config["IAM_TOKEN_LOCATIONS"] = ["headers", "cookies"]
    app.config["IAM_TOKEN_HEADER_NAME"] = "Authorization"
    app.config["IAM_TOKEN_HEADER_TYPE"] = "Bearer"
    app.config["IAM_TOKEN_COOKIE_NAME"] = "access_token"
    app.config["IAM_TOKEN_COOKIE_PATH"] = "/"
    app.config["IAM_CSRF_PROTECTION"] = True
    app.config["IAM_STRICT_REFERER"] = True

.. note::
    This module has been tested with Flask default WSGI server for development.
    For production use, this module has been tested with *Gunicorn* and *uWSGI*.
    You can use Gunicorn with sync and gthread worker. Since this SDK use multithreading, please
    make sure you enable the thread support with **--enable-threads** options when you use uWSGI.
    
    For more information about Flask deployment, please read more information `here <https://flask.palletsprojects.com/en/latest/deploying/>`_

CORS Options
------------

This module support CORS options to set CORS header response. You can set the CORS headers with the *cors_options* decorator.

.. code-block:: python

    @app.route('/cors', methods=["GET", "POST"])
    @cors_options({"Access-Control-Allow-Headers": ["Device-Id", "Device-Os", "Device-Type"]})
    def get_cors_endpoint():
        return 'You access a CORS page!'

The sample response of this endpoint would be like:

.. code-block:: console

    HTTP/1.1 200 OK
    Date: Fri, 12 Nov 2021 01:15:39 GMT
    Server: Nginx
    Access-Control-Allow-Origin: *
    Access-Control-Allow-Methods: GET, POST, OPTIONS
    Access-Control-Allow-Headers: Device-Id, Device-Os, Device-Type
    Access-Control-Allow-Credentials: true
    .......

.. note::
    You can read more about CORS specification `here <https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS>`_

You can also set the default CORS headers for all endpoints with Flask application-wide config.

.. code-block:: python

    app.config["IAM_CORS_ENABLE"] = True
    app.config["IAM_CORS_ORIGIN"] = "*"
    app.config["IAM_CORS_HEADERS"] = "*"
    app.config["IAM_CORS_METHODS"] = "*"
    app.config["IAM_CORS_CREDENTIALS"] = True

.. note::
    These default configs will be overridden by the decorator *cors_options* for specific endpoints.
