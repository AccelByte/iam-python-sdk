.. highlight:: shell

============
Installation
============


Requirements
------------
Before install iam-python-sdk, please make sure these requirements have been installed on your environments:

* Python >= 3.6 (tested on Python 3.6, 3.7, 3.8 and 3.9)
* PIP > 19.0

If you don't have `pip`_ installed, this `Python installation guide`_ can guide
you through the process.

.. _pip: https://pip.pypa.io
.. _Python installation guide: http://docs.python-guide.org/en/latest/starting/installation/


Stable release
--------------

To install iam-python-sdk, run this command in your terminal:

.. code-block:: console

    $ pip install iam-python-sdk

This is the preferred method to install iam-python-sdk, as it will always install the most recent stable release.


Frameworks
----------

To install iam-python-sdk with *Flask* frameworks support, run this command in your terminal:

.. code-block:: console

    $ pip install 'iam-python-sdk[flask]'

This will install flask frameworks with the latest stable version.

To install iam-python-sdk with *FastAPI* frameworks support, run this command in your terminal:

.. code-block:: console

    $ pip install 'iam-python-sdk[fastapi]'

This will install fastapi frameworks with the latest stable version.


From sources
------------

The sources for iam-python-sdk can be downloaded from the `Github repo`_.

You can either clone the public repository:

.. code-block:: console

    $ git clone git://github.com/accelbyte/iam-python-sdk

Or download the `tarball`_:

.. code-block:: console

    $ curl -OJL https://github.com/accelbyte/iam-python-sdk/tarball/master

Once you have a copy of the source, you can install it with:

.. code-block:: console

    $ python setup.py install


.. _Github repo: https://github.com/accelbyte/iam-python-sdk
.. _tarball: https://github.com/accelbyte/iam-python-sdk/tarball/master
