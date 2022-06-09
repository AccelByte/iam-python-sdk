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

Then you can protect your endpoint with *permission_required* decorator from unauthorized access:

.. code-block:: python

    @app.route('/protected')
    @permission_required(
        {"Action": 4, "Resource": "NAMESPACE:{namespace}:USER:{userId}"},
        {"{namespace}": "sample-namespace", "{userId}": "sample-userid"},
        csrf_protect=True
    )
    def get_protected_endpoint():
        return 'You have authorized access!'

By default, *permission_required* decorator will check the access token on the Authorization header with Bearer type.
You can customize these default configurations according to your service/apps needs:

.. code-block:: python

    app.config["IAM_TOKEN_LOCATIONS"] = ["headers", "cookies"]
    app.config["IAM_TOKEN_HEADER_NAME"] = "Authorization"
    app.config["IAM_TOKEN_HEADER_TYPE"] = "Bearer"
    app.config["IAM_TOKEN_COOKIE_NAME"] = "access_token"
    app.config["IAM_TOKEN_COOKIE_PATH"] = "/"
    app.config["IAM_CSRF_PROTECTION"] = True
    app.config["IAM_STRICT_REFERER"] = False
    app.config["IAM_ALLOW_SUBDOMAIN_REFERER"] = False

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


FastAPI
=======

Usage
-----

To use iam-python-sdk on FastAPI frameworks, you have to init the iam-python-sdk when FastAPI app started:

.. code-block:: python

    from fastapi import FastAPI
    from iam_python_sdk.fastapi import IAM, Settings

    app = FastAPI()

    @app.on_event("startup")
    async def startup_event():
        config = Settings(
            iam_base_url="<Base IAM URL>",
            iam_client_id="<Client ID>",
            iam_client_secret="<Client Secret>",
        )
        app.state.iam = IAM(app, config)

Then you can protect your endpoint with *permission_required* dependency from unauthorized access:

.. code-block:: python

    from iam-python-sdk.fastapi import permission_required

    @app.get('/protected', dependencies=[
        Depends(
            permission_required(
                {"resource": "ADMIN:NAMESPACE:{namespace}:CLIENT", "action": 2},
                {"{namespace}": "sdktest"},
                csrf_protect=True
            )
        )
    ])
    def get_protected_endpoint():
        return 'You have authorized access!'

By default, *permission_required* dependency will check the access token on the Authorization header with Bearer type.
You can customize these default configurations according to your service/apps needs:

.. code-block:: python

    settings.iam_base_url = ""
    settings.iam_client_id = ""
    settings.iam_client_secret = ""
    settings.iam_token_locations = ["headers", "cookies"]
    settings.iam_token_header_name = "Authorization"
    settings.iam_token_header_type = "Bearer"
    settings.iam_token_cookie_name = "access_token"
    settings.iam_token_cookie_path = "/"
    settings.iam_csrf_protection = True
    settings.iam_strict_referer = False
    settings.iam_allow_subdomain_referer = False

.. note::
    This module has been tested with FastAPI default uvicorn server for development.
    For production use, this module has been tested with *Gunicorn*.
    You can use Gunicorn with ``uvicorn.workers.UvicornWorker`` class worker.

    For more information about FastAPI deployment, please read more information `here <https://fastapi.tiangolo.com/deployment/server-workers/>`_

CORS Middleware
---------------

This module support CORS middleware to set CORS header response. You can set the CORS headers with these settings.

.. code-block:: python

    settings.iam_cors_enable = False
    settings.iam_cors_origin = "*"
    settings.iam_cors_headers = "*"
    settings.iam_cors_methods = "*"
    settings.iam_cors_credentials = True

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
