from struct import pack, unpack
from typing import List, NewType, Tuple
from enum import IntEnum, Enum
from types import SimpleNamespace
import random
import types
import math
import sys
import hmac
import hashlib
import socket
import logging

# rfc5389
# rfc5780

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG, format="%(asctime)-15s %(message)s")

int16 = NewType("int16", int)

b = b"123412341"

MAGIC_COOKIE = 0x2112A442


class MessageMethod(IntEnum):
    Bind:int16        = 0x0001
    Allocate:int16    = 0x0003

    @staticmethod
    def try_convert(value:int):
        try:
            return MessageMethod(value)
        except ValueError:
            return None


class MessageClass(IntEnum):
    Request =       0x0000
    Response =      0x0100
    Indication =    0x0010
    Error =         0x0110


ATTRIBUTE_PARSERS = {}


class AttributeType(IntEnum):

    MappedAddress:int16     = 0x0001
    Username:int16          = 0x0006
    MessageIntegrity:int16  = 0x0008
    ErrorCode:int16         = 0x0009
    Realm:int16             = 0x0014
    Nonce:int16             = 0x0015
    XorMappedAddress:int16  = 0x0020

    Software:int16          = 0x8022
    ResponseOrigin:int16    = 0x802B
    OtherAddress:int16      = 0x802C

    @staticmethod
    def try_convert(value:int):
        try:
            return AttributeType(value)
        except ValueError:
            return None


def attribute(attribute_type):
    def attribute_decorator(Cls):
        assert isinstance(attribute_type, (AttributeType, int))
        assert hasattr(Cls, "decode")

        attribute_type_value = int(attribute_type) # convert to int in case of using IntEnum
        
        decode_method = getattr(Cls, "decode")
        assert isinstance(decode_method, types.FunctionType)

        logger.debug(f"Adding parser to attribute 0x{attribute_type:x}")
        assert attribute_type_value not in ATTRIBUTE_PARSERS
        ATTRIBUTE_PARSERS[attribute_type_value] = decode_method

        setattr(Cls, "__attribute_type__", attribute_type_value) 

        return Cls
    return attribute_decorator


class Attribute():
    
    __attribute_type__:int16 = None
    
    def __ini__(self, data:bytearray):
        self.data = data
    
    @property
    def attribute_type(self)->int:
        return self.__attribute_type__

    @property
    def attribute_name(self)->str:
        return AttributeType.try_parse(self.attribute_type)

    def validate(self)->bool:
        return True

    def encode(self)->bytearray:
        return self.data

    @staticmethod
    def decode(data:bytearray):
        return AttributeValue(data)


class StringAttribute(Attribute):

    def __init__(self, value:str):
        self._value = value

    def __unicode__(self):
        return self._value

    def __repr__(self):
        return f"<{self.__class__.__name__} {self._value}>"

    def encode(self):
        return self._value.encode("UTF-8") 

    @staticmethod
    def decode_string(data:bytearray):
        return data.decode("UTF-8")


@attribute(attribute_type=AttributeType.Software)
class SoftwareAttribute(StringAttribute):
   
    def __init__(self, software:str):
        super().__init__(software)

    @property
    def software(self):
        return self._value

    @staticmethod
    def decode(data:bytearray):
        return SoftwareAttribute(super(SoftwareAttribute, SoftwareAttribute).decode_string(data))


class QStringAttribute(StringAttribute):
    pass


@attribute(attribute_type=AttributeType.Nonce)
class NonceAttribute(QStringAttribute):
    
    def __init__(self, nonce:str):
        super().__init__(nonce)

    @property
    def nonce(self):
        return self._value

    @staticmethod
    def decode(data:bytearray):
        return NonceAttribute(super(NonceAttribute, NonceAttribute).decode_string(data))


@attribute(attribute_type=AttributeType.Realm)
class RealmAttribute(QStringAttribute):
    
    def __init__(self, realm:str):
        super().__init__(realm)

    @property
    def realm(self):
        return self._value

    @staticmethod
    def decode(data:bytearray):
        return RealmAttribute(super(RealmAttribute, RealmAttribute).decode_string(data))


@attribute(attribute_type=AttributeType.MappedAddress)
class MappedAddressAttribute(Attribute):
    
    class AddressFamily(IntEnum):
        IPv4 = 1
        IPv6 = 2

    def __init__(self, address:str, port:int16, family:AddressFamily=AddressFamily.IPv4):
        self.address = address
        self.port = port
        self.family = family

    def encode(self):
        octets = map(int, self.address.split("."))
        #TODO: missing address family
        return pack("BBBB!H", *octets, self.port)
    
    def __unicode__(self):
        return f"{self.address}:{self.port}"

    def __repr__(self):
        return f"<{self.__class__.__name__} {self.address}:{self.port}>"

    @staticmethod
    def decode_address(data:bytearray):
        _, family, port, oc0, oc1, oc2, oc3 = unpack("!BBHBBBB", data)
        assert oc0 < 256 and oc1 < 256 and oc2 < 256 and oc3 < 256
        return (f"{oc0}.{oc1}.{oc2}.{oc3}", port, family)

    @staticmethod
    def decode(data:bytearray):
        return MappedAddressAttribute(*MappedAddressAttribute.decode_address(data))


@attribute(attribute_type=AttributeType.XorMappedAddress)
class XorMappedAddressAttribute(MappedAddressAttribute):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def encode(self):
        address_data = super().encode(self)
        # TODO: xor by magick cookie
        return address_data

    @staticmethod 
    def decode(data:bytearray):
        #print(data, len(data))
        _, family, port, octets = unpack("!BBHI", data)
        octets = octets ^ MAGIC_COOKIE
        port = port ^ ((MAGIC_COOKIE & 0xFFFF0000) >> 16)
        address = f"{(octets & 0xFF000000) >> 24}." \
                  f"{(octets & 0xFF0000) >> 16}." \
                  f"{(octets & 0xFF00) >> 8}."\
                  f"{octets & 0xFF}"
        return XorMappedAddressAttribute(address, port, family)


@attribute(attribute_type=AttributeType.OtherAddress)
class OtherAddressAttribute(MappedAddressAttribute):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @staticmethod
    def decode(data:bytearray):
        return OtherAddressAttribute(*MappedAddressAttribute.decode_address(data))


@attribute(attribute_type=AttributeType.ResponseOrigin)
class ResponseOriginAttribute(MappedAddressAttribute):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @staticmethod
    def decode(data:bytearray):
        return ResponseOriginAttribute(*MappedAddressAttribute.decode_address(data))


@attribute(attribute_type=AttributeType.MessageIntegrity)
class MessageIntegrityAttribute(Attribute):

    def __init__(self, digest:bytes):
        assert isinstance(digest, (bytes, bytearray))
        assert len(digest) == 20
        self.digest = digest

    def encode(self)->bytearray:
        return self.digest


@attribute(attribute_type=AttributeType.ErrorCode)
class ErrorCodeValue(Attribute):

    def __init__(self, error_code:int, reason:str):
        self.error_code = error_code
        self.reason = reason
        assert self.error_code >= 300 and self.error_code <= 699

    def __unicode__(self):
        return f"{self.error_code}:{self.reason}" 

    def __repr__(self):
        return f"<{self.__class__.__name__} {self.error_code}:{self.reason}>"

    def encode(self):
        number = self.error_code % 100
        class_v = self.error_code // 100

        data = pack("!I", (class_v << 8) | (number & 0xFF))
        data += self.reason.encode("UTF-8")
        return data

    @staticmethod
    def decode(data:bytearray):
        padding_and_code = unpack("!I", data[0:4])[0]
        code_v = (padding_and_code & 0x700) >> 8
        number = padding_and_code & 0xFF
        assert number >= 0 and number < 100
        assert code_v >= 3 and code_v <=6

        error_code = code_v * 100 + number

        reason_bytes = data[4:]
        reason = reason_bytes.decode("UTF-8")

        return ErrorCodeValue(error_code, reason)


class Message():
    method:int16 = None
    message_class:MessageClass = None
    length:int16 = 0
    attributes:List[Attribute]

    def __init__(self, method:int, message_class:MessageClass, attributes:List[attribute]=None):
        assert isinstance(message_class, MessageClass)
        assert isinstance(attributes, (list, type(None)))
        assert isinstance(method, (int, MessageMethod))
        assert message_class >= 0 and message_class <= 0xFFFF
        assert method >= 0 and method <= 0xFFFF

        self.method = int(method)
        self.message_class = message_class
        self.attributes = attributes or []

    @property
    def method_name(self)->str:
        return MessageMethod.try_convert(self.method)


class Credentials():
    
    def generate_key(self):
        raise NotImplemented()

    def make_hash(self, message_bytes:bytearray)->bytes:
        key = self.generate_key()
        return hmac.digest(key, message_bytes, "SHA1")


class LongTermCredentials(Credentials):
    
    def __init__(self, username:str, password:str, realm:str):
        self.password = password
        self.username = username
        self.realm = realm

    def generate_key(self)->bytes:
        # TODO: apply SASLprep to password
        return hashlib.md5(
            self.username +
            ":" +
            self.realm +
            ":" +
            self.password
        )


class ShortTermCredentials(Credentials):
    
    def __init__(self, username:str, password:str):
        self.username = username
        self.password = password

    def generate_key(self)->bytes:
        #TODO: apply SASLprep
        return hashlib.md5(
            self.password
        )


def _encode_message_header(
        message_class:int16, 
        message_method:int16, 
        message_length:int16, 
        transaction_id:int
    )->bytes:

    assert message_class in list(MessageClass)
    assert message_method >= 0 and message_method <= 0xFFF
    assert message_length >= 0 and message_length <= 0xFFFF
    assert transaction_id >= 0
    
    encoded_message_type = (
        ((message_method & 0x0F80) << 2)
        | ((message_method & 0x0070) << 1)
        | (message_method & 0x000F)
        | (message_class & 0x0110)
    )

    header = pack("!HH", encoded_message_type, message_length)
    header += pack("!L", MAGIC_COOKIE)
    header += int(transaction_id).to_bytes(12, "big", signed=False)
    #header += pack("!3L", transaction_id, transaction_id, transaction_id)
    return header


def __encode_attribute_header(attribute_type:int16, attribute_length:int16)->bytes:
    attribute_header = pack("!HH", attribute_type, attribute_length)
    return attribute_header


def encode_attribute(attribute:Attribute)->bytes:
   
    attribute_payload = attribute.encode()
    assert isinstance(attribute_payload, bytearray) \
            or isinstance(attribute_payload, bytes)

    attribute_length = len(attribute_payload)
    
    packet = _encode_message_header(attribute.attribute_type, attribute_length)
    packet += attribute_payload

    # add padding to aling to 4 bytes
    padding_length = (4 - attribute_length) % 4
    packet += b'\x00' * padding_length
    return packet


def encode(message:Message, credentials:Credentials=None)->bytearray:
    assert isinstance(message, Message)

    message_length = 0
    transaction_id = random.randint(0, 2**32 - 1)
    
    message_class:int16 = message.message_class
    message_method:int16 = message.method

    packet = _encode_message_header(
        message_class,
        message_method,
        0,
        transaction_id
    )

    assert len(packet) == 20

    for attribute in message.attributes:

        attribute_bytes = encode_attribute(attribute)
        packet += attribute_bytes
        message_length += len(attribute_bytes) 

    packet[2:4] = pack("!H", message_length)

    return packet
    

def _decode_message_header(data:bytes)->Tuple[MessageClass, int, int]:
    assert len(data) >= 20

    message_type, message_length, magic_cookie = unpack("!HHI", data[0:8])
    transaction_id  = unpack("!3L", data[8:20])
   
    assert (message_type & 0xC000) == 0x0
    assert magic_cookie == MAGIC_COOKIE
    assert (message_length + 20) == len(data)

    message_method = (
        (message_type & 0x000F)
        | ((message_type >> 1) & 0x0070)
        | ((message_type >> 2) & 0x0F80)
    )

    message_class = message_type & 0x0110
    
    return message_class, message_method, message_length, transaction_id


def __decode_attribute_header(data:bytes):
    assert len(data) >= 8

    attribute_type, attribute_length = unpack("!HH", data[0:4])
    return attribute_type, attribute_length


def decode_attribute(data:bytes):
    attribute_type, payload_length = __decode_attribute_header(data)
    data_idx = 4
   
    print(payload_length, data_idx, message_length, len(data))
    print(f"attribute_type={attribute_type:x} payload_length={payload_length}")
    
    assert payload_length <= len(data) - data_idx
    assert attribute_type in set(map(lambda x: x.value, AttributeType.__members__.values()))
    
    if attribute_type in ATTRIBUTE_PARSERS:
        assert attribute_type in ATTRIBUTE_PARSERS
        parser = ATTRIBUTE_PARSERS[attribute_type]
        attribute = parser(data[data_idx:data_idx + payload_length])
        
    #TODO: handle unknown arguments in two ways:
    # - if 'strict' mode is set then raise appriorate exception
    # - if no 'strict' mode is set, parse attribute as special 'unknown attribute'
    #   and let user do parsing
    else:
        print(f"UNKNOWN ATTRIBUTE OF TYPE {attribute_type:X}")
  
    padding_length = (4 - payload_length) % 4
    return attribute, payload_length, padding_length


def decode(data, credentials:Credentials=None):
    assert isinstance(data, bytes)
    data_length = len(data)
   
    message_class, message_method, transaction_id = _decode_message_header(data)

    attributes = []

    data_idx = 20
    while data_idx < data_length:
        #TODO: remove commented code below
        ### OLD ATTRIBUTE PARSING:
        #print(data[data_idx:data_idx + 4])
        #attribute_tyoe, attribute_length = __decode_attribute_header(data[data_idx:])
        #print(attribute_length, data_idx, message_length, len(data))
        #data_idx += 4
        #print(f"attribute_type={attribute_type:x} attribute_length={attribute_length}")
        #assert attribute_length <= (message_length - 20)
        #assert attribute_type in set(map(lambda x: x.value, AttributeType.__members__.values()))
        
        #print(AttributeType.__members__)

        #if attribute_type in ATTRIBUTE_PARSERS:
            #assert attribute_type in ATTRIBUTE_PARSERS
            #parser = ATTRIBUTE_PARSERS[attribute_type]
            #attribute = parser(data[data_idx:data_idx + attribute_length])
            
            #attributes.append(attribute)
        #else:
            #print(f"UNKNOWN ATTRIBUTE OF TYPE {attribute_type:X}")
        #data_idx += attribute_length

        #padding_length = (4 - attribute_length) % 4
        #data_idx += padding_length

        attribute, payload_length, padding_length = decode_attribute(data[data_idx:])
        if attribute:
            attributes.append(attribute)
        data_idx += 4 + payload_length + padding_length

    return Message(
        method=MessageMethod(message_method),
        message_class=MessageClass(message_class),
        attributes=attributes,
    )


if __name__ == "__main__":
    print("System byte order:", sys.byteorder)

    message = Message(
        method=MessageMethod.Bind,
        message_class=MessageClass.Request,
        attributes=[
           SoftwareAttribute("python turn client v0.0.1"),
        ]
    )

    data = encode(message)

    BYTES_PER_LINE = 4

    def print_bytes(data:bytearray):
        for i in range(math.ceil(len(data) // BYTES_PER_LINE)):
            print(" ".join(f"{d:02x}" for d in data[i * BYTES_PER_LINE:(i + 1) * BYTES_PER_LINE]))

    print_bytes(data)

    def load_packet_data_file(filepath:str):
        with open(filepath, "rb") as data_file:
            packet_data = data_file.read()
        return packet_data

    print("loading bind-request-success test case")
    packet_data = load_packet_data_file("data/bind-response-success-packet.data")
    print_bytes(packet_data)

    message = decode(packet_data)
    print(message)
    type_to_attribute = { a.attribute_type: a for a in message.attributes }
    print(f"Software = {type_to_attribute[AttributeType.Software].software or ''}")
    print(f"XorMappedAddress = {type_to_attribute[AttributeType.XorMappedAddress].address or ''}")

    send_over_network = False
    if send_over_network:
        local_ip = "127.0.0.1"
        local_port = 0
        print(f"sending data over network from {local_ip}:{local_port}")
        client_socket = socket.socket(family=socket.af_inet, type=socket.sock_dgram)

        client_socket.bind((local_ip, local_port))

        client_socket.sendto(data, ("127.0.0.1", 3478))

