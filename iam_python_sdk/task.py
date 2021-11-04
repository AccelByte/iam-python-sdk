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


from threading import RLock, Timer
from typing import Any, Callable, Union


class Task:
    def __init__(self, interval: Union[int, float], function: Callable[..., Any], *args, **kwargs) -> None:
        self._lock = RLock()
        self._timer = None
        self.interval = interval
        self.function = function
        self.args = args
        self.kwargs = kwargs
        self.status = 'STOP'

        if kwargs.pop('autostart', True):
            self.start()

    def _run(self):
        with self._lock:
            self.status = 'RUNNING'

        self.function(*self.args, **self.kwargs)
        self.start(repeat=True)

    def start(self, repeat=False):
        with self._lock:
            if repeat or self.status == 'STOP':
                self.status = 'WAITING'
                self._timer = Timer(self.interval, self._run)
                self._timer.daemon = True
                self._timer.start()

    def stop(self):
        with self._lock:
            self.status = 'STOP'
            if self._timer:
                self._timer.cancel()
