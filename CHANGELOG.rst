=========
Changelog
=========
1.4.3 (2025-09-25)
------------------

* Update pyjwt to 2.4.0

1.4.2 (2025-01-08)
------------------

* Add referer header cache

1.4.1 (2024-05-17)
------------------

* Fixing user permission expand issue 

1.3.3 (2022-08-04)
------------------

* Fixing cookie token issue
* Refactor getting access token function
* Fixing CORS handler

1.3.2 (2022-06-30)
------------------

* Fixing multiple namespace_role permission validation
* Disable default verify aud by pyjwt
* Reformat logging

1.3.1 (2022-06-14)
------------------

* Code cleaning

1.3.0 (2022-06-10)
------------------

* Add option for allowing referer header validation with subdomain

1.2.3 (2022-06-06)
------------------

* Fixing memory leak issue.

1.2.2 (2022-04-18)
------------------

* Fixing null revoked users issue.

1.2.1 (2022-04-13)
------------------

* Change default IAM strict referer validation to false.

1.2.0 (2022-04-11)
------------------

* Standardize error response.

1.1.0 (2022-03-28)
------------------

* Add asyncio client support.
* Add FastAPI frameworks support.

1.0.0 (2021-11-25)
------------------

* Add bloom filter support for token revocation.

0.12.0 (2021-11-19)
-------------------

* Add Flask CSRF support.
* Add Flask CORS options.

0.10.1 (2021-11-10)
-------------------

* Fixing Flask support extra requirements.

0.10.0 (2021-11-05)
-------------------

* Add backgroud refresh token, jwks and revocation list.
* Add Flask framework support.

0.8.0 (2021-10-22)
------------------

* Add has ban, email and phone verification status.

0.7.0 (2021-10-17)
------------------

* Add get client information, validate scope, role and audience.

0.5.0 (2021-10-12)
------------------

* Add start local validation and validate parse and claims.

0.3.0 (2021-10-05)
------------------

* Add get role and validate permission.

0.1.0 (2021-09-09)
------------------

* Add client token grant & validate access token.
