import sys
import socket
import argparse
from turnclient import Message, MessageClass, MessageMethod, encode, decode
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

DEFAULT_LOCAL_ADDRESS= "0.0.0.0" 
DEFAULT_LOCAL_PORT = 0

DEFAULT_PORT = 3478

if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Simple stun client with optional long term credentials"
    )
    parser.add_argument(
        "-p", 
        "--port", 
        default=DEFAULT_PORT,
        dest="destination_port",
        help="Stun server port",
    )
    parser.add_argument(
        "--local-port", 
        default=DEFAULT_LOCAL_PORT,
        help="Local port to bind, will be used as source port in stun packets",
    )
    parser.add_argument(
        "--local-address", 
        default=DEFAULT_LOCAL_ADDRESS,
        help="Local address to bind, will be used as source address in stun packets",
    )
    parser.add_argument(
        "-u", 
        "--user",
        help="username used in long term credential",
    )
    parser.add_argument(
        "-c", 
        "--password",
        help="password used in long term credentials",
    )
    parser.add_argument(
        "destination_address", 
        help="Address of stun server"
    )

    #args = parser.parse_args()
    args = parser.parse_args(["127.0.0.1"])
    print(args)
    logger.debug("creating socket")
    client_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    client_socket.bind((args.local_address, args.local_port))
    address, port = client_socket.getsockname()
    
    if args.user or args.password:
        assert args.user and args.password, "You must provide user and password"
        raise NotImplemented()

    logger.info(f"sending data over network from {address}:{port}")
    bind_message = Message(
        message_class = MessageClass.Request,
        method = MessageMethod.Bind,
        attributes = []
    )

    bind_packet = encode(bind_message)

    client_socket.sendto(
        bind_packet, 
        (args.destination_address, args.destination_port)
    )
    client_socket.settimeout(5.0)

    try:
        response_packet = client_socket.recvfrom(4048)

    except socket.timeout:
        logging.error("waiting for server response timeouted")
        exit(1)

    response_message = decode(response_packet)
    print(response_message)
