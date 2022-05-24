# Copyright 2021 AccelByte Inc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Task module."""

import asyncio
from threading import RLock, Timer
from typing import Any, Callable, Union

from .log import logger


class Task:
    """Task module for background task.
    """
    def __init__(self, interval: Union[int, float], function: Callable[..., Any], repeat: bool = True, *args, **kwargs) -> None:
        self._lock = RLock()
        self._timer = None
        self._status = 'STOPPED'
        self.interval = interval
        self.function = function
        self.repeat = repeat
        self.args = args
        self.kwargs = kwargs
        self.error = None

        if kwargs.pop('autostart', True):
            self.start()

    @property
    def status(self) -> str:
        with self._lock:
            return self._status

    @status.setter
    def status(self, status) -> None:
        with self._lock:
            self._status = status

    def _run(self) -> None:
        try:
            self.status = 'RUNNING'
            self.function(*self.args, **self.kwargs)
        except Exception as e:
            # We catch all exceptions here because we dont know what error will occur on background task
            logger.error(e)
            self.error = e

        if self.repeat:
            self.start()
        else:
            self.stop()

    def start(self) -> None:
        """Start the thread in background(daemon).
        """
        if self.repeat or self.status == 'STOPPED':
            self.status = 'WAITING'
            self._timer = Timer(self.interval, self._run)
            self._timer.daemon = True
            self._timer.start()

    def stop(self) -> None:
        """Stop the background task.
        """
        self.status = 'STOPPED'
        if self._timer:
            self._timer.cancel()


class AsyncTask:
    """AsyncTask module for background task.
    """
    def __init__(self, interval: Union[int, float], function: Callable[..., Any], repeat: bool = True, *args, **kwargs) -> None:
        self._lock = RLock()
        self._timer = None
        self._status = 'STOPPED'
        self.interval = interval
        self.function = function
        self.task = None
        self.repeat = repeat
        self.args = args
        self.kwargs = kwargs
        self.error = None

        if kwargs.pop('autostart', True):
            self.start()

    @property
    def status(self) -> str:
        with self._lock:
            return self._status

    @status.setter
    def status(self, status) -> None:
        with self._lock:
            self._status = status

    async def _run(self) -> None:
        while self.status == 'STOPPED' or self.repeat:
            try:
                # Waiting
                self.status = 'WAITING'
                await asyncio.sleep(self.interval)
                # Running function
                self.status = 'RUNNING'
                await self.function(*self.args, **self.kwargs)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                # We catch all exceptions here because we dont know what error will occur on background task
                logger.error(e)
                self.error = e
        else:
            self.stop()

    def start(self) -> None:
        """Start the the background task.
        """
        if self.status == 'STOPPED':
            try:
                self.task = asyncio.ensure_future(self._run())
            finally:
                self.stop()

    def stop(self) -> None:
        """Stop the background task.
        """
        self.status = 'STOPPED'

        if self.task:
            self.task.cancel()
