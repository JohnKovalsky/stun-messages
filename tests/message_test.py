import sys
from struct import unpack, pack
from unittest import TestCase, main
from os.path import join, normpath, dirname
from common import read_json_testcase_file, try_parse_hex_or_int, print_bytes

sys.path.insert(1, join(sys.path[0], '../'))
import turnclient
from turnclient import MessageMethod, MessageClass, Message, \
        _encode_message_header, _decode_message_header

MAGIC_COOKIE = 0x2112A442

DATA_DIR = join(normpath(dirname(__file__)), "..", "data")

def load_message_testcase(testcase_name:str):
    data, json_fields = read_json_testcase_file(join(DATA_DIR, testcase_name))
    message_fields = json_fields["message_fields"]

    if "method" in message_fields:
        message_fields["method"] = try_parse_hex_or_int(message_fields["method"])

    if "message_class" in message_fields:
        message_fields["message_class"] = try_parse_hex_or_int(message_fields["message_class"])

    message_header = data[0:20]
    message_payload = data[20:]
    return message_header, message_payload, message_fields


class MessageTest(TestCase):

    def test_ctor(self):
        message_method = MessageMethod.Bind
        message_class = MessageClass.Request
        attributes = []

        message = Message(message_method, message_class, attributes)

        self.assertEqual(message.method, message_method)
        self.assertIsInstance(message.method, int)
        self.assertEqual(message.message_class, message_class)
        self.assertEqual(message.attributes, attributes)

        message = Message(message_method, message_class)

        self.assertEqual(message.method, message_method)
        self.assertEqual(message.message_class, message_class)
        self.assertEqual(message.attributes, [])

    def test_message_method_valid_range(self):
        valid_methods = [0x0001, 0xFFFF]
        message_class = MessageClass.Request

        for message_method in valid_methods:
            message = Message(message_method, message_class)

    def test_message_method_out_of_range(self):
        message_method = 0x1FFFF
        message_class = MessageClass.Request

        self.assertRaises(AssertionError, Message, message_method, message_class)

        message_method = -1
        message_class = MessageClass.Request

        self.assertRaises(AssertionError, Message, message_method, message_class)

    def test_message_valid_class_values(self):
        message_method = 0x0001
        valid_classes = list(MessageClass)

        for message_class in valid_classes:
            message = Message(message_method, message_class)

    def test_message_invalid_class_valued(self):
        message_method = 0x0001
        invalid_classes = [None, 1, 12]

        for message_class in invalid_classes:
            self.assertRaises(AssertionError, Message, message_method, message_class)

    def test_message_attributes_property(self):
        message_method = MessageMethod.Bind.value
        message_class = MessageClass.Request
        attributes = [
                turnclient.SoftwareAttribute("Software"), 
                turnclient.MessageIntegrityAttribute(b"\x12"*20)
            ]

        message = Message(message_method, message_class, attributes=attributes)

        self.assertEqual(message.attributes, attributes)


class EncoderTest(TestCase):

    def test_encode_zero_header(self):
        method = 0x0
        message_class = 0x0
        transaction_id = 0x0
        message_length = 0x0

        encoded_header = _encode_message_header(message_class, method, message_length, transaction_id)

        self.assertIsInstance(encoded_header, bytes)
        self.assertEqual(len(encoded_header), 20)
        self.assertEqual(encoded_header, b"\x00" * 4 + MAGIC_COOKIE.to_bytes(4, "big") + b"\x00" * 12)

    def test_encode_request_header(self):
        header, payload, message_fields = load_message_testcase("bind-request-packet.json")
        method = message_fields["method"]
        message_class = message_fields["message_class"]
        message_length = len(payload)
        transaction_id = message_fields["transaction_id"] 

        encoded_header = _encode_message_header(message_class, method, message_length, transaction_id)
        
        self.assertIsInstance(encoded_header, bytes)
        self.assertEqual(len(encoded_header), 20)
        self.assertEqual(encoded_header, header)

    def test_encode_response_header(self):
        header, payload, message_fields = load_message_testcase("bind-response-success-packet.json")
        method = message_fields["method"]
        message_class = message_fields["message_class"]
        transaction_id = message_fields["transaction_id"]
        message_length = len(payload)

        encoded_header = _encode_message_header(message_class, method, message_length, transaction_id)

        self.assertIsInstance(encoded_header, bytes)
        self.assertEqual(len(encoded_header), 20)
        self.assertEqual(encoded_header, header)

    def test_encode_header_valid_message_class(self):
        method = 0x0001
        message_classes = list(MessageClass)
        message_length = 12 
        transaction_id = 0

        for message_class in message_classes:
            encoded_header = _encode_message_header(message_class, method, message_length, transaction_id)
            message_type = int.from_bytes(encoded_header[0:2], "big")
            self.assertEqual(len(encoded_header), 20)
            self.assertEqual(message_class, message_type & 0x0110) 
        
    def test_encode_header_invalid_message_class(self):
        method = 0x0001
        message_classes = [ 0x12, -1, None, "asd" ]
        transaction_id = 123
        message_length = 13

        for message_class in message_classes:
            self.assertRaises(
                AssertionError,
                _encode_message_header,
                message_class, method, message_length, transaction_id
            )

    def test_encode_header_invalid_method(self):
        invalid_methods = [ -1, 0xFFFF, 0x2FFF]
        message_class = MessageClass.Request
        message_length = 12
        transaction_id = 123

        for method in invalid_methods:
            self.assertRaises(
                AssertionError,
                _encode_message_header,
                message_class,
                method,
                message_length,
                transaction_id
            )

    def test_encode_header_valid_method(self):
        method_type_pairs = [
            (0b0, 0b0),
            (0b111111111111, 0b11111011101111),
            (0b101010101010, 0b10101001001010),
            (0b010101010101, 0b01010010100101),
        ]
        message_class = MessageClass.Request
        message_length = 13
        transaction_id = 123

        for method, message_type in method_type_pairs:
            encoded_header = _encode_message_header(
                message_class,
                method,
                message_length,
                transaction_id
            )

            message_type_decoded = int.from_bytes(encoded_header[0:2], "big")
            self.assertEqual(len(encoded_header), 20)
            self.assertIsInstance(encoded_header, bytes)
            self.assertEqual(message_type_decoded, message_type)

    def test_encode_header_invalid_length(self):
        method = 0x0001
        message_class = MessageClass.Request
        transaction_id = 123
        invalid_message_lengths = [-1, 0x1FFFF]

        for message_length in invalid_message_lengths:
            data_description = f"case for message_length={message_length}"

            with self.assertRaises(AssertionError, msg=data_description):
                _encode_message_header(
                    message_class,
                    method,
                    message_length,
                    transaction_id
                )
           
    def test_encode_header_valid_transaction_id(self):
        transaction_ids = [0, 1, 2**96 - 1]
        method = 0x0001
        message_class = MessageClass.Request
        message_length = 12

        for transaction_id in transaction_ids:
            data_description = f"case for transaction_id={transaction_id}"

            encoded_header = _encode_message_header(
                message_class,
                method,
                message_length,
                transaction_id
            )

            transaction_id_bytes = encoded_header[8:]
            transaction_id_decoded = int.from_bytes(transaction_id_bytes, "big")
            self.assertEqual(len(encoded_header), 20, data_description)
            self.assertIsInstance(encoded_header, bytes, data_description)
            self.assertEqual(transaction_id_decoded, transaction_id, data_description)
            
    def test_encode_header_invalid_transaction_id(self):
        method = 0x0001
        message_class = MessageClass.Request
        message_length = 12
        invalid_transaction_ids = [-1, int.from_bytes(b"\xFF" * 12, "big") + 1]

        for transaction_id in invalid_transaction_ids:
            self.assertRaises(
                (AssertionError, OverflowError),
                _encode_message_header,
                message_class,
                method,
                message_length,
                transaction_id
            )


class DecoderTest(TestCase):

    def _sample_header(self, message_type, message_length, transaction_id):
        return pack(
            "!HHL",
            message_type & 0x3FFF,
            message_length,
            MAGIC_COOKIE,
        ) + transaction_id.to_bytes(12, "big")

    def test_decode_header_invalid_bytes_length(self):
        encoded_header = b"\x00" * 21

        with self.assertRaises(AssertionError):
            fields = _decode_message_header(encoded_header)
        
        encoded_header = b"\x00" * 19 

        with self.assertRaises(AssertionError):
            fields = _decode_message_header(encoded_header)

    def test_decode_header_wrong_magick(self):
        encoded_header = b"\x01" * 20

        with self.assertRaises(AssertionError):
            fields = _decode_message_header(encoded_header)

    def test_decode_header_wrong_padding(self):
        encoded_header = (
            b"\xFF" #two first bits should be zero
            + b"\x00" * 3 
            + MAGIC_COOKIE.to_bytes(4, "big") 
            + b"\x01" * 12
        )

        with self.assertRaises(AssertionError):
            fields = _decode_message_header(encoded_header)

    def test_decode_header_invalid_input_type(self):
        encoded_header = "\0" * 20

        with self.assertRaises(TypeError):
            fields = _decode_message_header(encoded_header)

    def test_decode_header_message_class(self):
        message_classes = list(MessageClass)
        message_length = 0
        transaction_id = 123

        for message_class in message_classes:
            encoded_header = self._sample_header(
                message_class,
                message_length,
                transaction_id
            )

            decoded_message_class, _, _, _ = _decode_message_header(
                encoded_header
            )
            #TODO: check other fields

            self.assertEqual(decoded_message_class, message_class)

    def test_decode_header_message_length(self):
        #TODO: finish this testcase
        message_type = 0x0000
        message_lengths = [0, 0x1, 0x0100, 0xFFFF]
        transaction_id = 132

        for message_length in message_lengths:
            encoded_header = self._sample_header(
                message_type,
                message_length,
                transaction_id
            )

            decoded_message_class, _, _, _ = _decode_message_header(
                encoded_header
            )

            self.assertEqual(decoded_message_class, message_class)
        


if __name__ == "__main__":
    exit(main())
