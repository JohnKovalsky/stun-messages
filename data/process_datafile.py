import sys
import json
import base64
from os.path import join, dirname, splitext, basename, exists
import argparse

sys.path.insert(1, join(sys.path[0], '../tests'))
from common import print_bytes, read_json_testcase_file, \
    read_data_testcase_file


def read_testcase_file_bytes(input_filepath):
    ext = splitext(input_filepath)[1]
    assert ext == ".json" or ext == ".data"
    if ext == ".json":
        return read_json_testcase_file(input_filepath)[0]
    elif ext == ".data":
        return read_data_testcase_file(input_filepath)
    else:
        raise Exception("Unsupported input file format. Can be .json or .data only")


def write_json_testcase_file(output_filepath, data, extra_fields=None):
    assert isinstance(data, bytes) or isinstance(data, bytearray)

    print(f"Writing data to binary file at '{output_filepath}'")
    testcase_fields = extra_fields or {}

    with open(output_filepath, "w+") as output_file:
        output_file.write(json.dumps(
            {
                "data" : base64.b64encode(data).decode("ASCII"),
                "length" : len(data),
                **testcase_fields,
            },
            indent=4
        ))


def write_data_testcase_file(output_filepath, data):
    assert isinstance(data, bytes) or isinstance(data, bytearray)

    print(f"Writing data to binary file at '{output_filepath}'")
    with open(output_filepath, "w+b") as output_file:
        output_file.write(data)


def print_action(**args):
    input_filepath = args["input_filepath"]
    data = read_testcase_file_bytes(input_filepath)
    print_bytes(data)


def convert_action(input_filepath):
    raise NotImplementedException()


def extract_action(**args):
    input_filepath = args["input_filepath"]
    output_format = args["format"]
    data = read_testcase_file_bytes(input_filepath)
    
    assert output_format == "json" or output_format == "data"
    output_filepath = args.get("output", None)
    
    if output_filepath is None:
        output_filepath = splitext(input_filepath)[0] + "." + output_format

    force = args.get("force", False)
    offset = args.get("offset", None) or 0
    length = args.get("length", None) or len(data) 
    end = offset + length
    
    print(f"Extracting data bytes from {offset} to {end}")

    assert offset >= 0
    assert offset < len(data)
    assert end <= len(data)
    
    if not force and exists(output_filepath):
        raise Exception("Output file exists, use --force to overwrite")

    data = data[offset : end]

    if output_format == "json":
        extra_fields = {
            "source" : basename(input_filepath),
            "offset" : offset,
            "length" : length,
        }

        write_json_testcase_file(output_filepath, data, extra_fields=extra_fields)

    elif output_format == "data":
        write_data_testcase_file(output_filepath, data)
    else: 
        raise Exception(f"Unknown output format {output_format}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process data test file")
    action_subparsers = parser.add_subparsers(title="action", dest="action", required=True)

    convert_parser = action_subparsers.add_parser(
        "convert", 
        help="convert data binary file to json",
    )
    convert_parser.set_defaults(function=convert_action)
    convert_parser.add_argument("input_filepath", help="input filepath")

    print_parser = action_subparsers.add_parser(
        "print",
        help="print binary content of data file"
    )
    print_parser.set_defaults(function=print_action)
    print_parser.add_argument("input_filepath", help="file to print")
    extract_parser = action_subparsers.add_parser(
        "extract",
        help="extract fragment of binary data from data file" 
    )

    extract_parser.set_defaults(function=extract_action)
    extract_parser.add_argument("input_filepath", help="file to extract from")
    extract_parser.add_argument("--offset", help="byte offset where to start extraction", type=int)
    extract_parser.add_argument("--length", help="total bytes to extract", type=int)
    extract_parser.add_argument("--format", help="output format", choices=["json", "data"], required=True)
    extract_parser.add_argument("-f", "--force", help="force output file overwrite", action='store_true')
    extract_parser.add_argument("-o", "--output", help="output filepath")

    args = parser.parse_args()
    function = args.function
    function(**vars(args))
