#!/usr/bin/python
# -*- coding: utf-8 -*-
import math
import secrets
import struct
import sys
import socket

"""
CommunicationClient.py
written by Ville Kujala (ville.kujala@student.oulu.fi) on 28.04.2024 for the Introduction to Internet Coursework
Includes all optional parts (Encryption, Multipart messages and Parity)

Starts with a TCP connection to exchange necessary information to start UDP communication with the server.
in UDP receives and translates messages until EOM bit is set by the server.

Takes in arguments for server address, port and message, defaults are set in Main for the course server
"""

BUF_LEN = 2048      # Length of read buffer
KEY_AMOUNT = 20     # Amount of keys used in encryption
MSG_LEN = 64        # Length of each message block (for multipart messages)
USAGE = 'usage: \"<server address>\" <server port> \"<message>\"'

enc_keys = []
dec_keys = []
enc_keyNum = 0
dec_keyNum = 0


def send_and_receive_tcp(address: str, port: int, message: str) -> None:
    """
    responsible for exchanging necessary data via TCP to start UDP communication with the server

    :param address: address of the server
    :param port: server port
    :param message: initial message to the server
    """
    try:
        print(f"Connecting to {address}:{port}")
        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        soc.settimeout(3)
        soc.connect((address, port))
        enc = message.encode()
        soc.sendall(enc)

        rxBuf = soc.recv(BUF_LEN)
        rx_decoded = rxBuf.decode()
        if rx_decoded == "Not enough keys.\r\n":
            raise ValueError
        print(f"sending message: {message}")
        rec_message, CID, rest = rx_decoded.split(' ')
        port, keys = rest.split("\r\n", 1)
        print(rec_message)
        soc.close()

        get_dec_keys(rx_decoded, KEY_AMOUNT)

        send_and_receive_udp(address, port, CID)
        return
    except (TimeoutError, socket.gaierror):
        print("could not connect to TCP server")
        sys.exit(USAGE)
    except ValueError:
        print("Incorrect message format")
        sys.exit(USAGE)



def encrypt(message: str) -> str:
    """
    encrypts the message with enc_keys
    :param message:
    :return: encrypted message
    """
    new = ""
    global enc_keyNum
    if enc_keyNum < KEY_AMOUNT:
        key = enc_keys[enc_keyNum]
        for i in range(len(message)):
            new += chr((ord(message[i]) ^ ord(key[i])))
        enc_keyNum += 1
    else:
        new = message
    return new


def decrypt(message: str) -> str:
    """
    decrypts the message with dec_keys
    :param message:
    :return: decrypted message
    """
    new = ""
    global dec_keyNum
    if dec_keyNum < KEY_AMOUNT:
        key = dec_keys[dec_keyNum]
        for i in range(len(message)):
            new += chr((ord(message[i]) ^ ord(key[i])))
        dec_keyNum += 1
    else:
        new = message
    return new


def get_dec_keys(message: str, keyAmount: int) -> None:
    """
    gets decryption keys from message and inserts them into dec_keys
    :param message:
    :param keyAmount: amount of decryption keys to read
    """
    global dec_keys
    dec_keys = message.split("\r\n")[1:keyAmount + 1]


def gen_enc_keys(keyAmount: int) -> None:
    """
    generates 64 byte hex strings to use in encryption and adds them to enc_keys
    :param keyAmount: amount of keys to generate
    """
    for i in range(0, keyAmount):
        enc_keys.append(secrets.token_hex(32))


def send_and_receive_udp(address: str, port: int, CID: str) -> None:
    """
    handles UDP communication with the server until EOM bit is set by the server
    :param address: server address
    :param port: server port
    :param CID: Unique identifier for the client given by the server in TCP
    """
    try:
        ACK = True
        EOM = False
        soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        soc.settimeout(3)
        message = f"Hello from {CID}"

        sendUDP(ACK, CID, EOM, message, address, port, soc)
        while not EOM:
            ACK, CID, EOM, REMAIN, rxMessage = receiveUDP(soc)
            print(rxMessage)
            if not EOM:
                if not ACK:
                    message = "Send again"
                    sendUDP(ACK, CID, EOM, message, address, port, soc)
                else:
                    message = reverseWords(rxMessage)
                    sendUDP(ACK, CID, EOM, message, address, port, soc)

        return
    except TimeoutError:
        print("could not connect to UDP server")
        sys.exit(USAGE)


def receiveUDP(soc: socket) -> tuple[bool, str, bool, int, str]:
    """
    receives UDP messages and constructs the complete message from parts
    :param soc: server socket
    :return: tuple of ACK, CID, EOM, REMAIN and the constructed message
    """
    whole_message = ""
    while 1:
        rxBuf = soc.recv(BUF_LEN)
        CID, ACK, EOM, REMAIN, rxLen, message = struct.unpack("!8s??HH128s", rxBuf)
        message = message.decode()
        if not EOM:
            if not checkParity(message):
                ACK = False
            message = removeParity(message)
            message = message[:rxLen]
            message = decrypt(message)
        else:
            message = message[:rxLen]
        whole_message += message
        if REMAIN == 0:
            break
    CID = CID.decode()

    return ACK, CID, EOM, REMAIN, whole_message


def sendUDP(ACK: bool, CID: str, EOM: bool, message: str, address: str, port: int, soc: socket) -> None:
    """
    sends UDP messages to the server constructed from the data. If message is longer than MSG_LEN it will be sent
    in multiple parts. Parity bits are added to the messages, and they are encoded with enc_keys

    :param ACK: Whether parity of the last message was correct
    :param CID: Unique client identifier provided by the server
    :param EOM: boolean to keep track of the end of communication
    :param message: complete message to send to the server
    :param address: server address
    :param port: server port
    :param soc: server socket
    """
    print(message)
    messages = splitMessage(message)
    CID = str.encode(CID)
    port = int(port)
    REMAIN = len(message)
    for i in range(len(messages)):
        message = messages[i]
        message = encrypt(message)
        origLen = len(message)
        message = addParity(message)
        message = message.encode()
        REMAIN -= origLen
        data = struct.pack("!8s??HH128s", CID, ACK, EOM, REMAIN, origLen, message)
        soc.sendto(data, (address, port))


def splitMessage(message: str) -> list[str]:
    """
    if length of message is over MSG_LEN, splits the message into multiple parts
    :param message: complete message
    :return: list of message pieces of length MSG_LEN
    """
    messages = []
    if len(message) > MSG_LEN:
        pieceAmount = math.ceil(len(message) / MSG_LEN)
        for i in range(1, pieceAmount + 1):
            piece = message[(i - 1) * MSG_LEN:i * MSG_LEN]
            messages.append(piece)
    else:
        messages.append(message)

    return messages


def reverseWords(message: str) -> str:
    """
    reverses words of the message
    e.g. one two three becomes three two one

    :param message: message to reverse
    :return: message with words in reverse order
    """
    words = message.split()[::-1]
    ret = []
    for i in words:
        ret.append(i)
    return " ".join(ret)


def addParity(message: str) -> str:
    """
    adds Even parity to each character of the message
    :param message: message to add parity to
    :return: message with parity
    """
    parityMsg = ""
    for char in message:
        binChar = bin(ord(char))[2:]
        ones = binChar.count('1')
        binChar = int(binChar, 2)
        binChar = binChar << 1
        if ones % 2 != 0:
            binChar += 1
        parityMsg += chr(binChar)
    return parityMsg


def checkParity(message: str) -> bool:
    """
    checks if even parity of the message is correct
    :param message: message to check
    :return: true if parity is correct
    """
    for char in message:
        binChar = bin(ord(char))[2:]
        ones = binChar.count('1')
        if ones % 2 != 0:
            return False
    return True


def removeParity(message: str) -> str:
    """
    removes parity bits from the message
    :param message:
    :return: message with parity bits removed
    """
    cleanMessage = ""
    for char in message:
        bin_char = bin(ord(char))[2:]
        bin_char = int(bin_char, 2)
        bin_char = bin_char >> 1
        cleanMessage += chr(bin_char)
    return cleanMessage


def main():
    server_address = "195.148.20.105"
    server_tcp_port = 10000
    message = "HELLO ENC MUL PAR\r\n"

    try:
        # Get the server address, port and message from command line arguments
        if len(sys.argv) > 1:
            server_address = str(sys.argv[1])
            server_tcp_port = int(sys.argv[2])
            message = str(sys.argv[3]).encode('utf-8').decode('unicode_escape')
        else:
            print("No arguments given, starting with defaults")

        gen_enc_keys(KEY_AMOUNT)
        for i in range(0, KEY_AMOUNT):
            message = message + f"{enc_keys[i]}\r\n"
        message = message + ".\r\n"

    except (ValueError, IndexError):
        print("Incorrect arguments, please read the usage")
        sys.exit(USAGE)

    send_and_receive_tcp(server_address, server_tcp_port, message)


if __name__ == '__main__':
    # Call the main function when this script is executed
    main()
