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

"""Tests for `iam_python_sdk.utils` module."""


from typing import List
from iam_python_sdk.utils import decode_model, parse_nanotimestamp


class CityModel:
    Name: str = ""
    Country: str = ""


class PhoneModel:
    Number: str = ""


class PersonModel:
    Id: str = ""
    Name: str = ""
    City: CityModel = CityModel()
    Phones: List[PhoneModel] = [PhoneModel()]


def test_decode_model():
    data = {
        "id": "12345",
        "name": "Jhon",
        "city": {"name": "Yogyakarta"},
        "phones": [{"number": "+6234567890"}],
    }
    obj = decode_model(data, PersonModel())
    assert isinstance(obj, PersonModel)
    assert obj.Name == "Jhon"

    assert isinstance(obj.City, CityModel)
    assert obj.City.Name == "Yogyakarta"

    assert isinstance(obj.Phones[0], PhoneModel)
    assert obj.Phones[0].Number == "+6234567890"


def test_parse_nanotimestamp():
    data = "2020-02-02T02:02:02.02020202Z"
    timestamp = parse_nanotimestamp(data)
    assert isinstance(timestamp, float)
    assert timestamp == 1580608922.02
