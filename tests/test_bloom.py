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

"""Tests for `iam_python_sdk.bloom` module."""

from iam_python_sdk.bloom import BloomFilter

from .mock import revocation_list


def test_filter_contains():
    bloom_filter = BloomFilter()
    bits = revocation_list["revoked_tokens"]["bits"]
    k = revocation_list["revoked_tokens"]["k"]
    m = revocation_list["revoked_tokens"]["m"]
    bloom_filter.loads(bits, k, m)
    assert bloom_filter.contains("test_item") is True
    assert bloom_filter.contains("foo") is False
