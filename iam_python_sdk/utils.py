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

"""Utils module."""

import copy, json
from datetime import datetime
from typing import Any, Union


def decode_model(data: Union[str, list, dict], model: object) -> Any:
    """Decode model data from response json.

    Args:
        data (Union[str, list, dict]): A list, a dict or a string of json response.
        model (object): Model object.

    Raises:
        ValueError: Data error if none or empty.
        ValueError: Model error if not an object.
        ValueError: Data error if not a list, a dict or a string json.

    Returns:
        object: Model instance with data.
    """

    if not data:
        raise ValueError("The data is either none or empty.")

    if not model or isinstance(model, str):
        raise ValueError("The model should be an object type.")

    models = []

    if isinstance(data, list):
        # If data is a list
        for d in data:
            obj = copy.copy(model)
            results = decode_model(d, obj)
            models.append(results)

        return models

    elif isinstance(data, dict):
        # If data is a dict
        obj = copy.copy(model)

        for k, v in data.items():
            key = k.title().replace('_', '')

            if not isinstance(v, dict) and not isinstance(v, list):
                setattr(obj, key, v)

            elif isinstance(v, list):
                # Recursive list
                try:
                    attr = getattr(obj, key)
                    if isinstance(attr[0], (str, int, float, bool)):  # Simple type
                        setattr(obj, key, v)
                    else:  # Other type
                        result = decode_model(v, attr[0])
                        setattr(obj, key, result)
                except Exception:
                    pass

            elif isinstance(v, dict):
                # Recursive dict
                try:
                    attr = getattr(obj, key)
                    result = decode_model(v, attr)
                    setattr(obj, key, result)
                except Exception:
                    pass

        return obj

    elif isinstance(data, str):
        # If data is a string
        return decode_model(json.loads(data), model)

    else:
        raise ValueError("Data should be a list, a dict or a json string.")


def parse_nanotimestamp(s: str) -> Union[int, float]:
    """Parse datetime string with nanoseconds

    Args:
        s (str): datetime string

    Returns:
        datetime: datetime object
    """
    tz = ""
    if s[-1] == "Z":
        # Add explicit UTC timezone
        tz = "Z+0000"
    # Get milliseconds and convert it to unix timestamp
    return datetime.strptime(s[0:23] + tz, "%Y-%m-%dT%H:%M:%S.%fZ%z").timestamp()
