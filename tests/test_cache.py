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

"""Tests for `iam_python_sdk.cache` module."""

from iam_python_sdk.cache import Cache


def test_set_get_item():
    cache = Cache(60, x=1)
    cache['y'] = 2
    cache.set('z', 3)
    assert cache['x'] == 1
    assert cache['y'] == 2
    assert cache.get('z') == 3


def test_is_expired():
    cache = Cache(60, x=1)
    cache['y'] = 2
    cache.set('z', 3, 30)
    assert cache.is_expired('x') is False
    assert cache.is_expired('y', 30) is False
    assert cache.is_expired('z', 35) is True


def test_load_func():
    cache = Cache(load_func=lambda x: (x, 60))
    assert cache['x'] == 'x'
