"""This class implements a client program that establish a TCP-like connection with the client program, and perform
the data transfer using UDP socket.

 The client establish a connection to the server using a three-way handshake.
 During the handshake, the server has to send its initial sequence number to the client.
 After establishing the connection, the client and the server will terminate the connection.

 Once connection established, the server and the client will communicate using the User Datagram Protocol (UDP) socket.

 @Author Feng Long: fxl306@case.edu
 @Date 04/22/2022

"""

import sys
from new_util import SimpleTCPSocket
import time


def main():
    if len(sys.argv) != 3:
        sys.exit("Usage: python simple-tcp-client.py SERVER-HOST-OR-IP PORT-NUMBER")
    receiver_ip = sys.argv[1]
    receiver_port = int(sys.argv[2])
    c_sock = SimpleTCPSocket()
    c_sock.connect(receiver_ip, receiver_port)
    # time.sleep(4)
    c_sock.close()


if __name__ == "__main__":
    main()
