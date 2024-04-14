#!/usr/bin/python
# -*- coding: utf-8 -*-
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
    # print received data
    print(rx_decoded)
    # close the socket
    soc.close()
    # Get your CID and UDP port from the message
    rec_message, CID, UDP = rx_decoded.split(' ')
    # Continue to UDP messaging. You might want to give the function some other parameters like the above mentioned cid and port.
    send_and_receive_udp(address, UDP, CID)
    return


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
        rxBuf = soc.recv(BUF_LEN)
        CID, ACK, EOM, REMAIN, rxLen, message = struct.unpack("!8s??HH128s", rxBuf)
        CID = CID.decode()
        rxMessage = message[:rxLen].decode()
        print(rxMessage)
        message = reverseWords(rxMessage)
        sendUDP(ACK, CID, EOM, REMAIN, message, address, port, soc)

    return


def sendUDP(ACK, CID, EOM, REMAIN, message, address, port, soc):
    message = message.encode()
    CID = str.encode(CID)
    port = int(port)
    data = struct.pack("!8s??HH128s", CID, ACK, EOM, REMAIN, len(message), message)
    soc.sendto(data, (address, port))


def reverseWords(string):
    words = string.split()[::-1]
    ret = []
    for i in words:
        ret.append(i)
    return " ".join(ret)


def main():
    USAGE = 'usage: %s <server address> <server port> <message>' % sys.argv[0]

    try:
        # Get the server address, port and message from command line arguments

        # server_address = str(sys.argv[1])
        # server_tcpport = int(sys.argv[2])
        # message = str(sys.argv[3])
        server_address = "195.148.20.105"
        server_tcpport = 10000
        message = "HELLO\r\n"
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
