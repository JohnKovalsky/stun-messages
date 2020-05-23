import sys
import math
import json
import base64
from typing import Tuple
from os.path import join
from unittest.mock import MagicMock

DEFAULT_BYTES_PER_LINE = 4


def print_bytes(data:bytearray, bytes_per_line:int = DEFAULT_BYTES_PER_LINE)->None:
    for i in range(math.ceil(len(data) // bytes_per_line)):
        print(" ".join(f"{d:02x}" for d in data[i * bytes_per_line:(i + 1) * bytes_per_line]), end="\t")
        print(f"{i*bytes_per_line}:{(i+1)*bytes_per_line - 1}")


def read_json_testcase_file(input_filepath:str)->Tuple[bytes, dict]:
    with open(input_filepath, "r") as input_file:
        json_data = json.load(input_file)
        hexdata = json_data["data"]
        data = base64.b64decode(hexdata)
        del json_data["data"]
        return data, json_data


def read_data_testcase_file(input_filepath:str)->bytes:
    with open(input_filepath, "rb") as input_file:
        data = input_file.read()
        return data

