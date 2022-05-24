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

"""Bloom filter module."""

import mmh3, struct

from bitarray import bitarray


class BloomFilter:
    """Bloom Filer class."""

    def __init__(self) -> None:
        self.K: int = 0
        self.M: int = 0
        self.Bits: bitarray = bitarray(endian="little")

    def _get_index(self, item: str, k: int, m: int) -> list:
        """Get the index of bitarray to be set

        Args:
            item (str): String of item
            k (int): Hash number
            m (int): Number of bits

        Returns:
            list: Index to be set
        """
        indexes = []
        h1, h2 = mmh3.hash64(item, signed=False)  # Hash the data with mmh3 algorithm
        combined = h1 & 0xffffffffffffffff  # Convert to unsigned int 64-bit

        # Get the index number to set
        for i in range(k):
            indexes.insert(i, (combined & 0x7fffffffffffffff) % m)
            combined += h2

        return indexes

    def loads(self, bits: list, k: int, m: int):
        """Loads bitarray from bitset go format

        Args:
            bits (list): List of unpacked bits struct
            k (int): Hash number
            m (int): Number of bits
        """
        bitset = struct.pack("Q" * len(bits), *bits)
        bitarr = bitarray(endian="little")
        bitarr.frombytes(bitset)

        self.Bits = bitarr
        self.K = k
        self.M = m

    def insert(self, item: str) -> None:
        # TODO: Insert item to the bloom filter
        pass

    def contains(self, item: str) -> bool:
        """Check of item is in a BloomFilter

        Args:
            item (str): String of item

        Returns:
            bool: Status of item in a BloomFilter
        """
        indexes = self._get_index(item, self.K, self.M)
        for i in indexes:
            # If one index is false, then the item is not in the filter
            # because bloom filter have no false negative
            if not self.Bits[i]:
                return False
        # If all indexes is true, the item might be in the filter
        # because bloom filter can have false positive
        return True
