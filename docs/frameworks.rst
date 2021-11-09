==========
Frameworks
==========

Flask
=====

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
        {"{namespace}": "sample-namespace", "{userId}": "sample-userid"}
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
