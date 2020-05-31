import sys
from struct import unpack
from os.path import join, dirname, normpath
from unittest import TestCase, main
from common import print_bytes, read_json_testcase_file, read_data_testcase_file

sys.path.insert(1, join(sys.path[0], '../'))
from turnclient import MappedAddressAttribute, XorMappedAddressAttribute, \
        AttributeType, RealmAttribute, SoftwareAttribute, NonceAttribute, \
        _encode_attribute_header

DATA_DIR = join(normpath(dirname(__file__)), "..", "data")
print(f"DATA_DIR = {DATA_DIR}")


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


if __name__ == "__main__":
    exit(main())
