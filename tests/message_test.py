import sys
from struct import unpack, pack
from unittest import TestCase, main
from unittest.mock import MagicMock, patch
from os.path import join, normpath, dirname
from common import read_json_testcase_file, try_parse_hex_or_int, print_bytes

sys.path.insert(1, join(sys.path[0], '../'))
import stunmsg
from stunmsg import MessageMethod, MessageClass, Message, \
        UnknownAttribute, \
        encode, \
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


def load_testcase_attributes(testcase_fields):
    attribute_dicts = testcase_fields["attributes"]
    assert isinstance(attribute_dicts, list)
    
    attributes = []
    
    for attribute_dict in attribute_dicts:
        assert isinstance(attribute_dict, dict)
        attribute_type = try_parse_hex_or_int(attribute_dict["attribute_type"])
        attribute_length = try_parse_hex_or_int(attribute_dict["attribute_length"])
        ATTRIBUTE_PARSERS = stunmsg.ATTRIBUTE_PARSERS
        if attribute_type in ATTRIBUTE_PARSERS:
            _, attribute_class = ATTRIBUTE_PARSERS[attribute_type]
        else:
            attribute_class = UnknownAttribute
 
        attribute_fields = attribute_dict["attribute_fields"]
        attribute = attribute_class(**attribute_fields)

        attributes.append(attribute)

    return attributes


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

    def test_message_invalid_class_values(self):
        message_method = 0x0001
        invalid_classes = [None, 1, 12]

        for message_class in invalid_classes:
            self.assertRaises(AssertionError, Message, message_method, message_class)

    def test_message_attributes_property(self):
        message_method = MessageMethod.Bind.value
        message_class = MessageClass.Request
        attributes = [
                stunmsg.SoftwareAttribute("Software"), 
                stunmsg.MessageIntegrityAttribute(b"\x12"*20)
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

    def test_encode_testcase_header(self):
        testcases = [
            "bind-request-packet.json",
            "bind-response-success-packet.json",
            "bind-response-error-401-packet.json"
        ]

        for testcase in testcases:
            header, payload, message_fields = load_message_testcase(testcase)
            method = message_fields["method"]
            message_class = message_fields["message_class"]
            message_length = len(payload)
            transaction_id = message_fields["transaction_id"] 

            encoded_header = _encode_message_header(
                message_class, 
                method, 
                message_length, 
                transaction_id
            )
            
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

    def test_encode_message_invalid_argument(self):
        with self.assertRaises(AssertionError):
            encode(None)

        with self.assertRaises(AssertionError):
            encode("asd")

    def test_encode_message_assembly_header(self):
        message_class = MessageClass.Indication
        method = MessageMethod.Bind

        message = Message(
            message_class=message_class,
            method=method,
            attributes=[]
        )

        with patch("stunmsg._encode_message_header") as encode_header_mock:
            with patch("stunmsg.encode_attribute") as encode_attribute_mock:
                fake_header = b"\x00" * 20
                encode_header_mock.return_value = fake_header
                
                encoded_message = encode(message)

                encode_header_mock.assert_called_once()
                encode_header_args = encode_header_mock.call_args[0]

                self.assertEqual(encode_header_args[0], message_class)
                self.assertEqual(encode_header_args[1], method)
                self.assertEqual(encode_header_args[2], 0)
                self.assertIsInstance(encode_header_args[3], int)
                encode_attribute_mock.assert_not_called()
                self.assertEqual(encoded_message, fake_header) 

    def test_encode_message_attribute(self):
        #TODO: finish this testcase
        message_class = MessageClass.Indication
        method = MessageMethod.Bind

        message = Message(
            message_class=message_class,
            method=method,
            attributes=[]
        )

        with patch("stunmsg._encode_message_header") as encode_header_mock:
            with patch("stunmsg.encode_attribute") as encode_attribute_mock:
                fake_header = b"\x00" * 20
                encode_header_mock.return_value = fake_header
                
                encoded_message = encode(message)

                encode_header_mock.assert_called_once()
                encode_header_args = encode_header_mock.call_args[0]

                self.assertEqual(encode_header_args[0], message_class)
                self.assertEqual(encode_header_args[1], method)
                self.assertEqual(encode_header_args[2], 0)
                self.assertIsInstance(encode_header_args[3], int)
                encode_attribute_mock.assert_not_called()
                self.assertEqual(encoded_message, fake_header) 

    def test_encode_message_testcases(self):
        #TODO: finish encoding tests for response messages
        #       when encoding of all attributes will be implemented
        testcases = [
                "bind-request-packet.json",
                #"bind-response-success-packet.json",
                #"bind-response-error-401-packet.json",
        ]
        
        for testcase in testcases:
            msg = f"for testcase {testcase}"
            header, payload, fields = load_message_testcase(testcase)
            attributes = load_testcase_attributes(fields)
             
            message = Message(
                message_class=MessageClass(fields["message_class"]),
                method=fields["method"],
                attributes=attributes
            )

            encoded_message = encode(message)

            self.assertEqual(encoded_message[0:8], header[0:8], msg=msg)
            self.assertEqual(encoded_message[20:], payload, msg=msg)


class DecoderTest(TestCase):

    def _sample_header(self, message_type, message_length, transaction_id):
        return pack(
            "!HHL",
            message_type & 0x3FFF,
            message_length,
            MAGIC_COOKIE,
        ) + transaction_id.to_bytes(12, "big")

    def test_decode_testcases_header(self):
        testcases = [
            "bind-request-packet.json",
            "bind-response-success-packet.json",
            "bind-response-error-401-packet.json",
        ]

        for testcase in testcases:
            msg = f"in testcase '{testcase}'"
            header, payload, message_fields = load_message_testcase(testcase)
            
            fields = _decode_message_header(header)
            
            message_class   = fields[0]
            method          = fields[1]
            message_length  = fields[2]
            transaction_id  = fields[3]

            self.assertIsInstance(fields, tuple, msg)
            self.assertEqual(len(fields), 4, msg)
            self.assertEqual(message_class, message_fields["message_class"], msg)
            self.assertEqual(method, message_fields["method"], msg)
            self.assertEqual(message_length, len(payload), msg)
            self.assertEqual(transaction_id, message_fields["transaction_id"])

    def test_decode_bind_success_response_header(self):
        header, payload, message_fields = load_message_testcase("bind-request-packet.json")

        fields = _decode_message_header(header)

        message_class   = fields[0]
        method          = fields[1]
        message_length  = fields[2]
        transaction_id  = fields[3]

        self.assertIsInstance(fields, tuple)
        self.assertEqual(len(fields), 4)
        self.assertEqual(message_class, message_fields["message_class"])
        self.assertEqual(method, message_fields["method"])
        self.assertEqual(message_length, len(payload))

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

            fields = _decode_message_header(
                encoded_header
            )
            decoded_message_class   = fields[0]
            decoded_method          = fields[1]
            decoded_message_length  = fields[2]
            decoded_transaction_id  = fields[3]

            self.assertEqual(decoded_message_class, message_class)
            self.assertEqual(decoded_method, 0x0)
            self.assertEqual(decoded_message_length, message_length)
            self.assertEqual(decoded_transaction_id, transaction_id)

    def test_decode_header_message_length(self):
        message_type = 0x0000
        message_lengths = [0, 0x1, 0x0100, 0xFFFF]
        transaction_id = 132

        for message_length in message_lengths:
            encoded_header = self._sample_header(
                message_type,
                message_length,
                transaction_id
            )

            fields = _decode_message_header(
                encoded_header
            )
            decoded_message_class   = fields[0]
            decoded_method          = fields[1]
            decoded_message_length  = fields[2]
            decoded_transaction_id  = fields[3]

            self.assertEqual(decoded_message_class, message_type)
            self.assertEqual(decoded_method, message_type)
            self.assertEqual(decoded_message_length, message_length)
            self.assertEqual(decoded_transaction_id, transaction_id)
        
    def test_decode_header_message_length(self):
        message_type = 0x0000
        message_length = 0x0 
        transaction_ids = [
            0,
            1,
            0xC,
            int.from_bytes(b"\xFF" * 12, "big"),
            int.from_bytes(b"\xCC" * 12, "big"),
        ] 

        for transaction_id in transaction_ids:
            encoded_header = self._sample_header(
                message_type,
                message_length,
                transaction_id
            )

            fields = _decode_message_header(
                encoded_header
            )
            decoded_message_class   = fields[0]
            decoded_method          = fields[1]
            decoded_message_length  = fields[2]
            decoded_transaction_id  = fields[3]

            self.assertEqual(decoded_message_class, message_type)
            self.assertEqual(decoded_method, message_type)
            self.assertEqual(decoded_message_length, message_length)
            self.assertEqual(decoded_transaction_id, transaction_id)

    def test_decode_header_message_length(self):
        type_method_class_triple = [
            (0b0, 0b0, 0b0),
            (0b11111111111111, 0x0110, 0xFFF),
            (0b10101101011010, 0x0110, 0xAAA),
            (0b10101001001010, 0x0000, 0xAAA),
        ]
        message_length = 0x0 
        transaction_id = 123

        for message_type, message_class, method in type_method_class_triple:
            encoded_header = self._sample_header(
                message_type,
                message_length,
                transaction_id
            )

            fields = _decode_message_header(
                encoded_header
            )
            decoded_message_class   = fields[0]
            decoded_method          = fields[1]
            decoded_message_length  = fields[2]
            decoded_transaction_id  = fields[3]

            self.assertEqual(decoded_message_class, message_class)
            self.assertEqual(decoded_method, method)
            self.assertEqual(decoded_message_length, message_length)
            self.assertEqual(decoded_transaction_id, transaction_id)


if __name__ == "__main__":
    exit(main())
