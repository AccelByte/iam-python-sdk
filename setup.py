#!/usr/bin/env python

"""The setup script."""

from setuptools import setup, find_packages

with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = history_file.read()

requirements = ['Click>=7.0', 'backoff==1.11.1', 'httpx>=1.0.0b0']

test_requirements = ['pytest>=3', ]

setup(
    author="AccelByte",
    author_email='dev@accelbyte.net',
    python_requires='>=3.6',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
    description="Iam Python SDK",
    entry_points={
        'console_scripts': [
            'iam=iam_python_sdk.cli:main',
        ],
    },
    install_requires=requirements,
    license="Apache Software License 2.0",
    long_description=readme + '\n\n' + history,
    include_package_data=True,
    keywords=['iam_python_sdk', 'accelbyte', 'iam'],
    name='iam-python-sdk',
    packages=find_packages(include=['iam_python_sdk', 'iam_python_sdk.*']),
    test_suite='tests',
    tests_require=test_requirements,
    url='https://github.com/accelbyte/iam_python_sdk',
    version='0.1.0',
    zip_safe=False,
)
