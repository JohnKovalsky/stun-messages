import sys
from struct import unpack, pack
from os.path import join, dirname, normpath
from unittest import TestCase, main
from unittest.mock import MagicMock, Mock, patch
from common import print_bytes, read_json_testcase_file, read_data_testcase_file

sys.path.insert(1, join(sys.path[0], '../'))
from stunmsg import MappedAddressAttribute, XorMappedAddressAttribute, \
        AttributeType, RealmAttribute, SoftwareAttribute, NonceAttribute, \
        Attribute, UnknownAttribute, encode_attribute, decode_attribute, \
        _encode_attribute_header, _decode_attribute_header
    

DATA_DIR = join(normpath(dirname(__file__)), "..", "data")


def load_attribute_testcase(testcase_name):
    data, json_fields = read_json_testcase_file(join(DATA_DIR, testcase_name)) 
    
    attribute_fields = json_fields["attribute_fields"] 
    attribute_header = data[:4]

    attribute_type, attribute_length = unpack("!HH", attribute_header)
    attribute_payload = data[4:4 + attribute_length]

    attribute_fields["attribute_type"] = attribute_type

    return attribute_payload, attribute_fields


class MappedAddressAttributeTest(TestCase):

    def test_ctor(self):
        address = "127.0.0.1"
        port = 1234
        family = 1

        # full argument list
        attribute = MappedAddressAttribute(address=address, port=port, family=family)
        self.assertEqual(attribute.address, address)
        self.assertEqual(attribute.port, port)
        self.assertEqual(attribute.family, family)
        self.assertEqual(attribute.attribute_type, AttributeType.MappedAddress)

        # default arguments
        attribute = MappedAddressAttribute(address=address, port=port)

        self.assertEqual(attribute.address, address)
        self.assertEqual(attribute.port, port)
        self.assertEqual(attribute.family, MappedAddressAttribute.AddressFamily.IPv4)

    def test_parse(self):
        attribute_payload, attribute_fields = load_attribute_testcase("mapped-address-attribute.json") 

        attribute = MappedAddressAttribute.decode(attribute_payload)
        
        self.assertEqual(attribute.attribute_type, attribute_fields["attribute_type"])
        self.assertEqual(attribute.address, attribute_fields["address"])
        self.assertEqual(attribute.port, attribute_fields["port"])
        self.assertEqual(attribute.family, attribute_fields["family"])


class XorMappedAttributeTest(TestCase):
    
    def test_ctor(self):
        address = "127.0.0.1"
        port = 1234
        family = XorMappedAddressAttribute.AddressFamily.IPv4
        
        attribute = XorMappedAddressAttribute(address, port)
        
        self.assertEqual(attribute.address, address)
        self.assertEqual(attribute.port, port)
        self.assertEqual(attribute.family, family)
        self.assertEqual(attribute.attribute_type, AttributeType.XorMappedAddress)

        family = XorMappedAddressAttribute.AddressFamily.IPv6
        attribute = XorMappedAddressAttribute(address, port, family = family)

        self.assertEqual(attribute.address, address)
        self.assertEqual(attribute.port, port)
        self.assertEqual(attribute.family, family)

    def test_parse(self):
        attribute_payload, attribute_fields = load_attribute_testcase("xor-mapped-address-attribute.json") 

        attribute = XorMappedAddressAttribute.decode(attribute_payload)
        
        self.assertEqual(attribute.attribute_type, attribute_fields["attribute_type"])
        self.assertEqual(attribute.address, attribute_fields["address"])
        self.assertEqual(attribute.port, attribute_fields["port"])
        self.assertEqual(attribute.family, attribute_fields["family"])


class SoftwareAttributeTest(TestCase):

    def test_ctor(self):
        software = "software"

        attribute = SoftwareAttribute(software=software)

        self.assertEqual(attribute.software, software)
        self.assertEqual(attribute.attribute_type, AttributeType.Software)

    def test_decode(self):
        attribute_payload, attribute_fields = load_attribute_testcase("software-attribute.json") 

        attribute = SoftwareAttribute.decode(attribute_payload)

        self.assertEqual(attribute.attribute_type, attribute_fields["attribute_type"])
        self.assertEqual(attribute.software, attribute_fields["software"])


class RealmAttributeTest(TestCase):

    def test_ctor(self):
        realm = "61db60b4e71e98c1"
        
        attribute = RealmAttribute(realm=realm)

        self.assertEqual(attribute.realm, realm)
        self.assertEqual(attribute.attribute_type, AttributeType.Realm)


    def test_parse(self):
        attribute_payload, attribute_fields = load_attribute_testcase("realm-attribute.json")
        
        attribute = RealmAttribute.decode(attribute_payload)

        self.assertEqual(attribute.attribute_type, attribute_fields["attribute_type"])
        self.assertEqual(attribute.realm, "realm")


class NonceAttributeTest(TestCase):

    def test_ctor(self):
        nonce = "9367b9fbef"
        
        attribute = NonceAttribute(nonce=nonce)

        self.assertEqual(attribute.nonce, nonce)
        self.assertEqual(attribute.attribute_type, AttributeType.Nonce)

    def test_decode(self):
        attribute_payload, attribute_fields = load_attribute_testcase("nonce-attribute.json")

        attribute = NonceAttribute.decode(attribute_payload)

        self.assertEqual(attribute.attribute_type, attribute_fields["attribute_type"])
        self.assertEqual(attribute.nonce, attribute_fields["nonce"])


class AttributeEncoder(TestCase):

    def test_encode_attribute_header_type(self):
        attribute_types = [0, 1, 0xFF, 0xFFFF]
        attribute_length = 12
        
        for attribute_type in attribute_types:
            header = _encode_attribute_header(attribute_type, attribute_length)
            
            self.assertIsInstance(header, bytes)
            self.assertEqual(len(header), 4)
            self.assertEqual(attribute_type, int.from_bytes(header[0:2], "big"))
            self.assertEqual(attribute_length, int.from_bytes(header[2:4], "big"))

    def test_encode_attribute_header_length(self):
        attribute_type = 0xAACC
        attribute_lengths = [0, 1, 0xFF, 0xFFFF]

        for attribute_length in attribute_lengths:
            header = _encode_attribute_header(attribute_type, attribute_length)
            
            self.assertIsInstance(header, bytes)
            self.assertEqual(len(header), 4)
            self.assertEqual(attribute_type, int.from_bytes(header[0:2], "big"))
            self.assertEqual(attribute_length, int.from_bytes(header[2:4], "big"))

    def test_encode_attribute_header_invalid_length(self):
        attribute_type = 0xCCAA
        attribute_lengths = [-1, 0x1FFFF]

        for attribute_length in attribute_lengths:

            with self.assertRaises(AssertionError):
                header = _encode_attribute_header(attribute_type, attribute_length)

    def test_encode_attribute_header_invalid_type(self):
        attribute_types = [-1, 0x1FFFF]
        attribute_length = 123

        for attribute_type in attribute_types:

            with self.assertRaises(AssertionError):
                header = _encode_attribute_header(attribute_type, attribute_length) 

    def test_encode_invalid_attribute(self):
        invalid_attributes = [None, "attribute"]

        for attribute in invalid_attributes:
            with self.assertRaises(AssertionError):
                encode_attribute(attribute)

    def test_require_attribute_encode_to_bytes(self):
        attribute = MagicMock(spec=Attribute)
        attribute.encode = MagicMock(return_value="invalid return type")

        with self.assertRaises(AssertionError):
            encode_attribute(attribute)

    def test_attribute_encode(self):
        attribute_type = 0x13
        attribute_payload = b"sample encode value"
        payload_size = len(attribute_payload)
        attribute = Mock(
            spec=Attribute, 
            **{'attribute_type': attribute_type}
        )
        attribute.encode = MagicMock(return_value=attribute_payload)

        encoded_attribute = encode_attribute(attribute)

        self.assertEqual(int.from_bytes(encoded_attribute[0:2], "big"), attribute_type)
        self.assertEqual(int.from_bytes(encoded_attribute[2:4], "big"), payload_size)
        self.assertEqual(encoded_attribute[4: 4 + payload_size], attribute_payload)

    def test_attribute_encode_padding(self):
        attribute_type = 0x23
        payload_sizes = [4, 5, 6, 7, 8,]

        for payload_size in payload_sizes:
            msg = f"for payload_size={payload_size}"
            attribute_payload = b"a" * payload_size
            payload_size = len(attribute_payload)
            attribute = Mock(
                spec=Attribute, 
                **{'attribute_type': attribute_type}
            )
            attribute.encode = MagicMock(return_value=attribute_payload)

            encoded_attribute = encode_attribute(attribute)
            
            decoded_attribute_type = int.from_bytes(encoded_attribute[0:2], "big")
            decoded_attribute_length = int.from_bytes(encoded_attribute[2:4], "big")

            self.assertEqual(decoded_attribute_type, attribute_type, msg=msg)
            self.assertEqual(decoded_attribute_length, payload_size, msg=msg)
            self.assertEqual(
                encoded_attribute[4:4 + payload_size], 
                attribute_payload, 
                msg=msg
            )
            self.assertEqual(len(encoded_attribute) % 4, 0, msg=msg)
            padding_size = (-payload_size) % 4
            self.assertEqual(
                encoded_attribute[-padding_size if padding_size else 99:], 
                b"\x00" * padding_size, 
                msg=msg
            )

            
class AttributeDecoder(TestCase):

    def _prepare_header(self, attribute_type, attribute_length):
        return pack("!HH", attribute_type, attribute_length)

    def test_decode_header_invalid_argument(self):
        data = "string data"

        with self.assertRaises(AssertionError):
            _decode_attribute_header(data)

    def test_decode_header_data_too_short(self):
        data = b"\x00" * 3

        with self.assertRaises(AssertionError):
            _decode_attribute_header(data)

    def test_decode_header_attribute_length(self):
        attribute_lengths = [0, 1, 0x0F, 0xF0, 0xFF] 
        attribute_type = 0x01

        for attribute_length in attribute_lengths:
            msg = f"for attribute_length={attribute_length}"

            data = self._prepare_header(attribute_type, attribute_length)

            decoded_type, decoded_length = _decode_attribute_header(data)

            self.assertEqual(decoded_type, attribute_type, msg=msg)
            self.assertEqual(decoded_length, attribute_length, msg=msg)

    def test_decode_header_attribute_type(self):
        attribute_length = 13
        attribute_types = [0, 1, 0x0F, 0xF0, 0xFF]
        
        for attribute_type in attribute_types:
            msg = f"for attribute_type={attribute_type}"

            data = self._prepare_header(attribute_type, attribute_length)

            decoded_type, decoded_length = _decode_attribute_header(data)

            self.assertEqual(decoded_type, attribute_type, msg=msg)
            self.assertEqual(decoded_length, attribute_length, msg=msg)

    def test_decode_attribute_parse_by_type(self):
        attribute_type = 0x13

        payload = b"sample payload bytes"
        attribute_length = len(payload)
        header = self._prepare_header(attribute_type, attribute_length)

        data = header + payload
        
        fake_attribute = MagicMock(Attribute)

        with patch("stunmsg.ATTRIBUTE_PARSERS", new_callable=dict) as attribute_parsers:
            attribute_decode_method = Mock(return_value=fake_attribute) 
            attribute_parsers[attribute_type] = (attribute_decode_method, Attribute)
            attribute, decoded_payload_length, decoded_padding_length = decode_attribute(data)

            self.assertIsInstance(attribute, Attribute)
            self.assertEqual(attribute, fake_attribute)
            attribute_decode_method.assert_called_with(payload)
            self.assertEqual(decoded_payload_length, attribute_length)
            self.assertEqual(decoded_padding_length, 0)

    def test_decode_attribute_parse_padding(self):
        attribute_type = 0x15

        payload_size_padding_pairs = [
            (16, 0),
            (17, 3),
            (18, 2),
            (19, 1),
            (20, 0),
        ]
        
        with patch("stunmsg.ATTRIBUTE_PARSERS", new_callable=dict) as attribute_parsers:
            attribute_decode_method = Mock(return_value=MagicMock(Attribute))
            attribute_parsers[attribute_type] = (attribute_decode_method, Attribute)
            
            for payload_length, padding_length in payload_size_padding_pairs:
                payload = b"\x61" * payload_length
                header = self._prepare_header(attribute_type, payload_length)

                data = header + payload

                attribute, decoded_payload_length, decoded_padding_length = decode_attribute(data)

                self.assertIsInstance(attribute, Attribute)
                attribute_decode_method.assert_called_with(payload)
                self.assertEqual(decoded_payload_length, payload_length)
                self.assertEqual(decoded_padding_length, padding_length)
    
    def test_decode_unknown_attribute(self):
        attribute_type = 0xFF

        payload = b"sample payload bytes"
        attribute_length = len(payload)
        
        header = self._prepare_header(attribute_type, attribute_length)
        data = header + payload
        
        attribute, decoded_payload_length, decoded_padding_length = decode_attribute(data)

        self.assertIsInstance(attribute, UnknownAttribute)
        self.assertEqual(attribute.payload, payload)
        self.assertEqual(attribute.attribute_type, attribute_type)
        self.assertEqual(decoded_payload_length, attribute_length)
        self.assertEqual(decoded_padding_length, 0)


if __name__ == "__main__":
    exit(main())
