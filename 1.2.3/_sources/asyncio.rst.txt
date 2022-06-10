=======
Asyncio
=======

iam-python-sdk support concurrency with asyncio client.
All default client functions have asyncio coroutine versions.
You can use async and await on the async functions.

Here is sample of how you can use the iam-python-sdk asyncio client:

.. code-block:: python

    import asyncio

    from iam_python_sdk import Config, NewAsyncClient
    from iam_python_sdk.errors import ClientTokenGrantError

    config = Config(
        BaseURL="<Base IAM URL>",  # e.g.: https://demo.accelbyte.io/iam
        ClientID="<Client ID>",
        ClientSecret="<Client Secret>",
    )
    client = NewAsyncClient(config)

    async def grant_token():
        try:
            await client.ClientTokenGrant()
            # Client token grant success
        except ClientTokenGrantError as e:
            # Cant get access token from IAM
            pass

    loop = asyncio.get_event_loop()
    coro = asyncio.ensure_future(main(), loop=loop)
    loop.run_until_complete(coro)
