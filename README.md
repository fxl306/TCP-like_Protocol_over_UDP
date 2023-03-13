This application implements a  simple TCP-like data transfer client and server applications, using UDP sockets as an unreliable transport. The client can establish and close the connection even though some packets are dropped or delayed. 

- The client and the server will communicate using the User Datagram Protocol (UDP) socket, which does not guarantee data delivery. 

-  The fixed retransmission timeout value 500 milliseconds 

- The client should establish a connection to the server using a three-way handshake. During the handshake, the server has to send its initial sequence number to the client. 

- After establishing the connection, the client and the server will terminate the connection. 

- When the server or the client is sending or receiving packets, four types of output messages  will be print out the screen:

  - Sending packets

    > "Sending packet" [Sequence number] ("Retransmission") ("SYNACK") ("FIN")

  - Receving packets

    > "Receiving packet" [ACK number]

    Examples: 

    - Server side:

      > Receiving packet 0
      > Sending packet 10101 SYNACK
      > Receiving packet 10102
      > Sending packet 10102 FIN
      > Receiving packet 10102
      > Sending packet 10103
      > Sending packet 10102 Retransmission
      > Sending packet 10102 Retransmission
      > Sending packet 10102 Retransmission
      > Receiving packet 10103

    - Client side: 

      > Sending packet 28796 0 SYN
      > Receiving packet 28797
      > Sending packet 28797
      > Sending packet 28798 FIN
      > Receiving packet 28798
      > Sending packet 28799
      > Sending packet 28798 Retransmission
      > Receiving packet 28799
      > Sending packet 28798 Retransmission
      > Sending packet 28798 Retransmission

- Packet retransmission should be triggered when the timer times out.

- TCP header format 

  - **Sequence Number **(16 bits): The sequence number of the first data octetin this packet (except when SYN is present). If SYN is present the
    sequence number is the initial sequence number (ISN) and the first data octet is ISN+1.

  - **Acknowledgement Number **(16 bits): If the ACK control bit is set this field contains the value of the next sequence number the sender of the
    segment is expecting to receive. Once a connection is established this isalways sent.

  - **Window** (16 bits): The number of data octets the sender of this packet is willing to accept. (This is not used in this project)

  - **Not Used** (13 bits): Must be zero.

  - **A **(ACK, 1 bit): Indicates that there the value of Acknowledgment
    Number field is valid

  - **S** (SYN, 1 bit): Synchronize sequence numbers (TCP connection establishment) 

  - **F** (FIN, 1 bit): No more data from sender (TCP connection termination) 

    