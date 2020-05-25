import sys
from struct import unpack
from unittest import TestCase, main
from os.path import join, normpath, dirname
from common import read_json_testcase_file 

sys.path.insert(1, join(sys.path[0], '../'))
from turnclient import MessageMethod, MessageClass, Message, \
        _encode_message_header

DATA_DIR = join(normpath(dirname(__file__)), "..", "data")

def load_message_testcase(testcase_name:str):
    data, json_fields = read_json_testcase_file(join(DATA_DIR, testcase_name))
    message_fields = json_fields["message_fields"]
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


class EncoderTest(TestCase):

    def test_encode_header(self):
        message_header, message_payload, message_fields = load_message_testcase("bind-request-header.json")
        message_method = message_fields["method"]
        message_class = message_fields["message_class"]
        message_length = len(message_payload)
        transaction_id = message_fields["transaction_id"] 

        encoded_header = _encode_message_header(message_class, message_method, message_length, transaction_id)
        
        self.assertIsInstance(encoded_header, bytes)
        self.assertEqual(len(encoded_header), 20)
        self.assertEqual(encoded_header, message_header)

        

if __name__ == "__main__":
    exit(main())
