#!/usr/bin/python
# -*- coding: utf-8 -*-
import math
import os
import secrets
import struct
# The modules required
import sys
import socket

'''
This is a template that can be used in order to get started. 
It takes 3 commandline arguments and calls function send_and_receive_tcp.
in haapa7 you can execute this file with the command: 
python3 CourseWorkTemplate.py <ip> <port> <message> 

Functions send_and_receive_tcp contains some comments.
If you implement what the comments ask for you should be able to create 
a functioning TCP part of the course work with little hassle.  

'''
BUF_LEN = 2048
KEY_AMOUNT = 20
MSG_LEN = 64
enc_keys = []
dec_keys = []
enc_keyNum = 0
dec_keyNum = 0


def send_and_receive_tcp(address, port, message):
    print("You gave arguments: {} {} {}".format(address, port, message))
    # create TCP socket
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # connect socket to given address and port
    soc.connect((address, port))
    # python3 sendall() requires bytes like object. encode the message with str.encode() command
    enc = message.encode()
    # send given message to socket
    soc.sendall(enc)
    # receive data from socket
    rxBuf = soc.recv(BUF_LEN)
    # data you received is in bytes format. turn it to string with .decode() command
    rx_decoded = rxBuf.decode()
    # Get your CID and UDP port from the message
    rec_message, CID, rest = rx_decoded.split(' ')
    port, keys = rest.split("\r\n", 1)
    # print received data
    print(rec_message)

    get_dec_keys(rx_decoded, KEY_AMOUNT)

    # close the socket
    soc.close()
    # Continue to UDP messaging. You might want to give the function some other parameters like the above mentioned cid and port.
    send_and_receive_udp(address, port, CID)
    return


def encrypt(message):
    new = ""
    global enc_keyNum
    if (enc_keyNum < KEY_AMOUNT):
        key = enc_keys[enc_keyNum]
        for i in range(len(message)):
            new += chr((ord(message[i]) ^ ord(key[i])))
        enc_keyNum += 1
    else:
        new = message
    return new


def decrypt(message):
    new = ""
    global dec_keyNum
    if (dec_keyNum < KEY_AMOUNT):
        key = dec_keys[dec_keyNum]
        for i in range(len(message)):
            new += chr((ord(message[i]) ^ ord(key[i])))
        dec_keyNum += 1
    else:
        new = message
    return new


def get_dec_keys(message, keyAmount):
    global dec_keys
    dec_keys = message.split("\r\n")[1:keyAmount + 1]


def gen_enc_keys(keyAmount):
    for i in range(0, keyAmount):
        enc_keys.append(secrets.token_hex(32))


def send_and_receive_udp(address, port, CID):
    '''
    Implement UDP part here.
    '''
    ACK = True
    EOM = False
    REMAIN = 0
    soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    message = "Hello from {}".format(CID)
    sendUDP(ACK, CID, EOM, REMAIN, message, address, port, soc)

    while not EOM:
        ACK, CID, EOM, REMAIN, rxMessage = receiveUDP(ACK, EOM, REMAIN, soc)
        print(rxMessage)
        if not EOM:
            if not ACK:
                message = "Send again"
                sendUDP(ACK, CID, EOM, REMAIN, message, address, port, soc)
            else:
                message = reverseWords(rxMessage)
                sendUDP(ACK, CID, EOM, REMAIN, message, address, port, soc)

    return


def receiveUDP(ACK, EOM, REMAIN, soc):
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


def sendUDP(ACK, CID, EOM, REMAIN, message, address, port, soc):
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


def splitMessage(message):
    messages = []
    if len(message) > MSG_LEN:
        pieceAmount = math.ceil(len(message) / MSG_LEN)
        for i in range(1, pieceAmount + 1):
            piece = message[(i - 1) * MSG_LEN:i * MSG_LEN]
            messages.append(piece)
    else:
        messages.append(message)

    return messages


def reverseWords(string):
    words = string.split()[::-1]
    ret = []
    for i in words:
        ret.append(i)
    return " ".join(ret)


def addParity(message):
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


def checkParity(message):
    for char in message:
        binChar = bin(ord(char))[2:]
        ones = binChar.count('1')
        if ones % 2 != 0:
            return False
    return True

def removeParity(message):
    cleanMessage = ""
    for char in message:
        bin_char = bin(ord(char))[2:]
        bin_char = int(bin_char, 2)
        bin_char = bin_char >> 1
        cleanMessage += chr(bin_char)
    return cleanMessage

def main():
    USAGE = 'usage: %s <server address> <server port> <message>' % sys.argv[0]
    try:
        # Get the server address, port and message from command line arguments

        # server_address = str(sys.argv[1])
        # server_tcpport = int(sys.argv[2])
        # message = str(sys.argv[3])
        server_address = "195.148.20.105"
        server_tcpport = 10000
        message = "HELLO ENC MUL PAR\r\n"
        gen_enc_keys(KEY_AMOUNT)
        for i in range(0, KEY_AMOUNT):
            message = message + f"{enc_keys[i]}\r\n"
        message = message + ".\r\n"
    except IndexError:
        print("Index Error")
    except ValueError:
        print("Value Error")
        # Print usage instructions and exit if we didn't get proper arguments
        sys.exit(USAGE)

    send_and_receive_tcp(server_address, server_tcpport, message)


if __name__ == '__main__':
    # Call the main function when this script is executed
    main()
