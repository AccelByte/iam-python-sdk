#!/usr/bin/env python

"""The setup script."""

from setuptools import setup, find_packages

with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('CHANGELOG.rst') as changelog_file:
    changelog = changelog_file.read()

requirements = ['Click>=7.0', 'backoff==1.11.1', 'httpx>=1.0.0b0', 'pyjwt[crypto]==2.2.0', 'crontab==0.23.0']

test_requirements = ['pytest>=3', 'respx==0.18.0']

extras_require = {
    "flask": ["Flask>=1.0"]
}

setup(
    author="Analytics AccelByte",
    author_email='justice-analytics-team@accelbyte.net',
    python_requires='>=3.6',
    classifiers=[
        'Development Status :: 4 - Beta',
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
    version='0.10.0',
    zip_safe=False,
)
