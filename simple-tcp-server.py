"""This class implements a server program that establish a TCP-like connection with the client program, and perform
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


def main():
    """Parse command-line argument and call receiver function """
    if len(sys.argv) != 2:
        sys.exit("Usage: python simple-tcp-server.py [PORT-NUMBER]")
    server_port = int(sys.argv[1])
    s_sock = SimpleTCPSocket()
    s_sock.bind('', server_port)
    client_address = s_sock.accept()
    s_sock.close()


if __name__ == "__main__":
    main()
