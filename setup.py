#!/usr/bin/env python

"""The setup script."""

from setuptools import setup, find_packages

with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('CHANGELOG.rst') as changelog_file:
    changelog = changelog_file.read()

requirements = [
    'Click>=7.1.2,<8.1.0',
    'backoff==1.11.1',
    'httpx==0.22.0',
    'httpcore==0.14.5',
    'pyjwt[crypto]==2.4.0',
    'crontab==0.23.0',
    'bitarray==2.3.4',
    'mmh3==3.0.0'
]

test_requirements = ['pytest==6.2.4', 'pytest-asyncio==0.16.0', 'respx==0.19.2']

optional_requirements = {
    "flask": ["Flask>=1.0,<3.0"],
    "fastapi": ["fastapi<=0.90.1"]
}

setup(
    author="Analytics AccelByte",
    author_email='justice-analytics-team@accelbyte.net',
    python_requires='>=3.6',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],
    description="AccelByte IAM Python SDK",
    entry_points={
        'console_scripts': [
            'iam=iam_python_sdk.cli:main',
        ],
    },
    install_requires=requirements,
    extras_require=optional_requirements,
    license="Apache Software License 2.0",
    long_description=readme + '\n\n' + changelog,
    long_description_content_type='text/x-rst',
    include_package_data=True,
    keywords=['iam_python_sdk', 'accelbyte', 'iam'],
    name='iam-python-sdk',
    packages=find_packages(include=['iam_python_sdk', 'iam_python_sdk.*']),
    test_suite='tests',
    tests_require=test_requirements,
    url='https://accelbyte.github.io/iam-python-sdk',
    version='1.4.3',
    zip_safe=False,
)
