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

"""Cache module."""

from collections import OrderedDict
from threading import RLock
from time import time
from typing import Any, AnyStr, Callable


class Cache(OrderedDict):
    """Cache class that implement OrderedDict with thread safe feature.

    Args:
        OrderedDict ([type]): dict subclass that remembers the order entries were added.
    """
    def __init__(self, ttl: int = None, load_func: Callable = None, *args, **kwargs) -> None:
        self._ttl = ttl
        self._lock = RLock()
        self._load_func = load_func
        super().__init__(*args, **kwargs)
        self.update(*args, **kwargs)

    def is_expired(self, key: AnyStr, when: int = None) -> bool:
        """Check if cache key is expired.

        Args:
            key (AnyStr): cache key
            when (int, optional): added time if needed. Defaults to None.

        Returns:
            bool: expired status
        """
        with self._lock:
            at = time() + when if when else time()
            expire, value = super().__getitem__(key)
            if expire and expire < at:
                return True
            return False

    def __setitem__(self, key: AnyStr, value: Any) -> None:
        with self._lock:
            expire = time() + self._ttl if self._ttl else self._ttl
            super().__setitem__(key, (expire, value))

    def __getitem__(self, key: AnyStr) -> Any:
        with self._lock:
            try:
                value = super().__getitem__(key)[1]
                return value
            except KeyError as e:
                if not self._load_func:
                    raise e
                value, ttl = self._load_func(key)
                self.set(key, value, ttl)

            if self.is_expired(key):
                if not self._load_func:
                    self.__delitem__(key)
                    raise KeyError
                else:
                    value, ttl = self._load_func(key)
                    self.set(key, value, ttl)

            return super().__getitem__(key)[1]

    def __delitem__(self, key: AnyStr) -> None:
        with self._lock:
            super().__delitem__(key)

    def set(self, key: AnyStr, value: Any, ttl: int = None) -> None:
        """Set cache value

        Args:
            key (AnyStr): cache key
            value (Any): cache value
            ttl (int, optional): time to live in seconds. Defaults to None.
        """
        with self._lock:
            if ttl:
                expire = time() + ttl
            elif self._ttl:
                expire = time() + self._ttl
            else:
                expire = None
            super().__setitem__(key, (expire, value))

    def get(self, key: AnyStr, default=None) -> Any:
        """Get cache value by key.

        Args:
            key (AnyStr): cache key
            default (Any, optional): Default value if cache key is not found. Defaults to None.

        Returns:
            Any: cache value
        """
        try:
            return self[key]
        except KeyError:
            return default
