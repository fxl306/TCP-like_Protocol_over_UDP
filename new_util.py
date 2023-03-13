"""This class represents the tool box for the application of "TCP-like Protocol over UDP".
 The TCP header, the TCP-like three-way handshake connection and the UDP socket are defined here.

 @Author Feng Long: fxl306@case.edu
 @Date 04/22/2022

"""

from scapy.all import Packet
from scapy.all import ShortField, ByteField, BitFixedLenField, BitField
from socket import socket, AF_INET, SOCK_DGRAM, timeout
import random
import sys
import threading
import time
import errno
from socket import error as socket_error
from threading import Timer, Semaphore

MAX_SEQ = 30720
INIT_WINDOW = 1024
INIT_SSTHRESH = 15360
INTERVAL = 0.5
PACKET_SIZE = 1032
PAYLOAD_SIZE = 1024
LISTEN = 0
SYNSENT = 1
SYNRCVD = 2
ESTAB = 3
FIN_WAIT_1 = 4
FIN_WAIT_2 = 5
TIME_WAIT = 6
CLOSING = 7
CLOSE_WAIT = 8
LAST_ACK = 9


class Barrier:
    def __init__(self, n):
        self.n = n
        self.count = 0
        self.mutex = Semaphore(1)
        self.barrier = Semaphore(0)

    def wait(self):
        self.mutex.acquire()
        self.count = self.count + 1
        self.mutex.release()
        if self.count == self.n: self.barrier.release()
        self.barrier.acquire()
        self.barrier.release()


b = Barrier(2)


class TCPTimer():
    def __init__(self):
        self.t = None
        self.interval = INTERVAL
        self.timed_out = False
        self.isAlive = False

    def _timeout(self):
        self.timed_out = True

    def start(self):
        self.t = Timer(self.interval, self._timeout)
        self.isAlive = True
        self.t.start()

    def stop(self):
        self.t.cancel()
        self.isAlive = False


class SimpleTCPHeader(Packet):
    name = "SimpleTCPHeader"
    fields_desc = [
        ShortField("seq_num", 0),
        ShortField("ack_num", 0),
        ShortField("window", 0),
        BitField("unused", 0, 13),
        BitField("A", 0, 1),
        BitField("S", 0, 1),
        BitField("F", 0, 1)
    ]


class SimpleTCPSocket(object):
    def __init__(self):
        self.sock = socket(AF_INET, SOCK_DGRAM)
        # self.sock.setblocking(False)
        self.sock.settimeout(INTERVAL)
        self.window_size = INIT_WINDOW
        self.window = [None] * self.window_size
        self.send_base = 0
        self.next_seq = 0
        self.init_send_base = 0
        self.recv_base = 0
        self.init_recv_base = 0
        self.buffer_offset = 0
        self._send_to = None
        # self.sim_close = False
        self.prev_ack = False
        self.ssthresh = INIT_SSTHRESH
        self.state = None
        self.th = threading.Thread(target=self.handle_pkt)
        # self.th.daemon = True
        self.th.start()
        self.timer = TCPTimer()

    def bind(self, ip, port_num):
        self.sock.bind((ip, port_num))

    def _close(self):
        self.sock.close()

    def close(self):
        tcp_header = SimpleTCPHeader(seq_num=self.next_seq, ack_num=self.recv_base, window=self.window_size, F=1)
        fin_pkt = tcp_header / ""
        if self.state == ESTAB:
            self.state = FIN_WAIT_1
        if self.state == CLOSE_WAIT:
            self.state = LAST_ACK

        self.window[self.next_seq - self.init_send_base] = fin_pkt
        self.send_base = self.next_seq
        self.next_seq = self.next_seq + 1
        print("Sending packet {} {}".format(self.send_base, "FIN"))
        self.sock.sendto(bytes(fin_pkt), self._send_to)
        self.timer.start()

    def handle_pkt(self):
        while True:
            try:
                pkt, address = self.sock.recvfrom(PACKET_SIZE)
                pkt_header = SimpleTCPHeader(pkt[:8])
                # print("110 ", pkt_header.seq_num, pkt_header.ack_num, pkt_header.S, pkt_header.A, pkt_header.F, self.state)
                # print("111 ", self.send_base, self.next_seq)
                if self.send_base != 0 and self.send_base != self.next_seq and pkt_header.ack_num <= self.send_base:
                    self.handle_duplicate(pkt)
                # elif self.recv_base != 0 and pkt_header.seq_num > self.recv_base:
                #    # TODO: out-of-order packets
                #    print("received out-of-order packets", pkt_header.seq_num, self.recv_base)
                #    pass
                else:
                    if self.recv_base != 0 and pkt_header.seq_num > self.recv_base:
                        if pkt_header.A == 1:
                            self.prev_ack = True
                        else:
                            continue
                    if pkt_header.A == 1 and pkt_header.S == 1:
                        if self.timer.isAlive:
                            self.timer.stop()
                        self.handle_synack(pkt)
                    elif pkt_header.F == 1:
                        self.handle_fin(pkt)
                    elif pkt_header.A == 1:
                        self.handle_ack(pkt)
                    elif pkt_header.S == 1:
                        self.handle_syn(pkt, address)
            except timeout:
                if self.timer.isAlive and self.timer.timed_out:
                    self.timer.timed_out = False
                    self.retransmit_pkt(self.send_base)
            except socket_error as e:
                if e.errno == errno.EBADF:
                    break

    def handle_duplicate(self, pkt):
        pkt_header = SimpleTCPHeader(pkt[:8])
        if self.state == SYNRCVD and pkt_header.S == 1:
            # receive retransmitted SYN 
            synack_pkt = self.window[self.send_base - self.init_send_base]
            print("Sending packet {} {}".format(synack_pkt.seq_num, "Retransmission"))
            self.sock.sendto(bytes(synack_pkt), self._send_to)

        elif self.state == ESTAB:
            if pkt_header.A == 1 and pkt_header.S == 1:
                ack_pkt = self.window[pkt_header.ack_num - self.init_send_base]
                print("Sending packet {} {}".format(pkt_header.ack_num, "Retransmission"))
                self.sock.sendto(bytes(ack_pkt), self._send_to)

        elif (self.state == CLOSE_WAIT or self.state == TIME_WAIT or self.state == LAST_ACK) and pkt_header.F == 1:
            if self.state == TIME_WAIT:
                ack_pkt = self.window[self.send_base - self.init_send_base]
            else:
                ack_pkt = self.window[pkt_header.ack_num - self.init_send_base]
            ackpkt_header = SimpleTCPHeader(bytes(ack_pkt)[:8])
            print("Sending packet {} {}".format(ackpkt_header.seq_num, "Retransmission"))
            self.sock.sendto(bytes(ack_pkt), self._send_to)

        elif self.state == FIN_WAIT_1 and pkt_header.F == 1:
            self.sim_close = True
            print("Receiving packet {}".format(pkt_header.ack_num))
            tcp_header = SimpleTCPHeader(seq_num=self.next_seq, ack_num=pkt_header.seq_num + 1, window=self.window_size,
                                         A=1)
            ack_pkt = tcp_header / ""

            self.window[self.next_seq - self.init_send_base] = ack_pkt
            self.next_seq = self.next_seq + 1
            self.recv_base = pkt_header.seq_num + 1
            if self.prev_ack:
                self.state = TIME_WAIT
                self.prev_ack = False
                Timer(10, self._close).start()
            else:
                self.state = CLOSING

            self.sock.sendto(bytes(ack_pkt), self._send_to)
            print("Sending packet {}".format(self.next_seq - 1))

        elif (self.state == CLOSING or self.state == FIN_WAIT_2) and pkt_header.F == 1:
            print("Receiving packet {}".format(pkt_header.ack_num))
            # simultaneous FIN
            if self.state == CLOSING:
                ack_pkt = self.window[pkt_header.ack_num + 1 - self.init_send_base]
            else:
                tcp_header = SimpleTCPHeader(seq_num=pkt_header.ack_num, ack_num=pkt_header.seq_num + 1,
                                             window=self.window_size, A=1)
                ack_pkt = tcp_header / ""
            header = SimpleTCPHeader(bytes(ack_pkt)[:8])

            if self.state == FIN_WAIT_2:
                self.window[pkt_header.ack_num - self.init_send_base] = ack_pkt
                self.send_base = pkt_header.ack_num
                self.next_seq = self.next_seq + 1
                self.recv_base = pkt_header.seq_num + 1

            if (self.prev_ack and self.state == CLOSING) or self.state == FIN_WAIT_2:
                self.prev_ack = False
                self.state = TIME_WAIT
                if self.timer.isAlive:
                    self.timer.stop()
                Timer(10, self._close).start()

            self.sock.sendto(bytes(ack_pkt), self._send_to)
            print("Sending packet {}".format(header.seq_num))

        elif self.state == CLOSING and pkt_header.A == 1:
            print("Receiving packet {}".format(pkt_header.ack_num))
            self.state = TIME_WAIT
            if self.timer.isAlive:
                self.timer.stop()
            Timer(10, self._close).start()

    def retransmit_pkt(self, seq_num):
        pkt = self.window[seq_num - self.init_send_base]
        pkt_header = SimpleTCPHeader(bytes(pkt)[:8])
        print("Sending packet {} {}".format(seq_num, "Retransmission"))
        self.sock.sendto(bytes(pkt), self._send_to)
        self.timer.start()

    def handle_synack(self, pkt):
        pkt_header = SimpleTCPHeader(pkt[:8])
        print("Receiving packet {}".format(pkt_header.ack_num))
        if self.state == SYNSENT:
            tcp_header = SimpleTCPHeader(seq_num=pkt_header.ack_num, ack_num=pkt_header.seq_num + 1,
                                         window=self.window_size, A=1)
            ack_pkt = tcp_header / ""

            self.init_recv_base = pkt_header.seq_num
            self.send_base = pkt_header.ack_num
            self.next_seq = self.next_seq + 1
            self.window[self.send_base - self.init_send_base] = ack_pkt
            self.recv_base = pkt_header.seq_num + 1

            self.sock.sendto(bytes(ack_pkt), self._send_to)
            print("Sending packet {}".format(pkt_header.ack_num))
            self.state = ESTAB
            b.wait()

    def handle_syn(self, pkt, address):
        pkt_header = SimpleTCPHeader(pkt[:8])
        print("Receiving packet {}".format(pkt_header.ack_num))
        if self.state == LISTEN:
            # generate SYNACK packet
            rand_seq = random.randint(0, MAX_SEQ)
            tcp_header = SimpleTCPHeader(seq_num=rand_seq, ack_num=pkt_header.seq_num + 1, window=self.window_size, S=1,
                                         A=1)
            synack_pkt = tcp_header / ""

            self._send_to = address
            self.send_base = rand_seq
            self.next_seq = rand_seq + 1
            self.init_send_base = self.send_base
            self.init_recv_base = pkt_header.seq_num
            self.window[0] = synack_pkt

            self.sock.sendto(bytes(synack_pkt), address)
            print("Sending packet {} {}".format(rand_seq, "SYNACK"))
            self.state = SYNRCVD
            self.timer.start()

    def handle_ack(self, pkt):
        pkt_header = SimpleTCPHeader(pkt[:8])
        print("Receiving packet {}".format(pkt_header.ack_num))
        if self.state == SYNRCVD:
            self.state = ESTAB
            self.send_base = self.send_base + 1
            self.recv_base = pkt_header.seq_num + 1
            if self.timer.isAlive:
                self.timer.stop()
            b.wait()

        if self.state == FIN_WAIT_1:
            if self.timer.isAlive:
                self.timer.stop()
            self.recv_base = pkt_header.seq_num + 1
            self.state = FIN_WAIT_2

        if self.state == FIN_WAIT_2:
            self.recv_base = pkt_header.seq_num + 1

        if self.state == LAST_ACK:
            if self.timer.isAlive:
                self.timer.stop()
            self._close()

        if self.state == CLOSING:
            if self.timer.isAlive:
                self.timer.stop()
            self.state = TIME_WAIT
            self.send_base = self.next_seq - 1
            self.recv_base = pkt_header.seq_num + 1
            Timer(10, self._close).start()

    def handle_fin(self, pkt):
        pkt_header = SimpleTCPHeader(pkt[:8])
        print("Receiving packet {}".format(pkt_header.ack_num))
        if self.state == ESTAB or self.state == SYNRCVD:
            tcp_header = SimpleTCPHeader(seq_num=pkt_header.ack_num, ack_num=pkt_header.seq_num + 1,
                                         window=self.window_size, A=1)
            ack_pkt = tcp_header / ""

            self.send_base = pkt_header.ack_num
            self.next_seq = self.next_seq + 1
            self.window[self.send_base - self.init_send_base] = ack_pkt
            self.recv_base = pkt_header.seq_num + 1
            if (self.state == SYNRCVD):
                if self.timer.isAlive:
                    self.timer.stop()

            self.sock.sendto(bytes(ack_pkt), self._send_to)
            print("Sending packet {}".format(pkt_header.ack_num))
            if (self.state == SYNRCVD):
                b.wait()
            self.state = CLOSE_WAIT

        elif self.state == FIN_WAIT_1:
            # handle simultaneous close
            tcp_header = SimpleTCPHeader(seq_num=self.next_seq, ack_num=pkt_header.seq_num + 1, window=self.window_size,
                                         A=1)
            ack_pkt = tcp_header / ""

            self.window[self.next_seq - self.init_send_base] = ack_pkt
            self.next_seq = self.next_seq + 1
            self.recv_base = pkt_header.seq_num + 1
            # self.sim_close = True

            if self.prev_ack:
                self.prev_ack = False
                self.state = TIME_WAIT
                if self.timer.isAlive:
                    self.timer.stop()
                Timer(10, self._close).start()
            else:
                self.state = CLOSING

            self.sock.sendto(bytes(ack_pkt), self._send_to)
            print("Sending packet {}".format(pkt_header.ack_num))

        elif self.state == FIN_WAIT_2:
            tcp_header = SimpleTCPHeader(seq_num=pkt_header.ack_num, ack_num=pkt_header.seq_num + 1,
                                         window=self.window_size, A=1)
            ack_pkt = tcp_header / ""

            self.send_base = pkt_header.ack_num
            self.next_seq = self.next_seq + 1
            self.window[self.send_base - self.init_send_base] = ack_pkt
            self.recv_base = pkt_header.seq_num + 1

            self.sock.sendto(bytes(ack_pkt), self._send_to)
            print("Sending packet {}".format(pkt_header.ack_num))
            self.state = TIME_WAIT
            Timer(10, self._close).start()

    def connect(self, ip, port_num):
        rand_seq = random.randint(0, MAX_SEQ)
        tcp_header = SimpleTCPHeader(seq_num=rand_seq, window=self.window_size, S=1)
        syn_pkt = tcp_header / ""

        self.send_base = rand_seq
        self.next_seq = self.send_base + 1
        self._send_to = (ip, port_num)
        self.init_send_base = rand_seq
        self.window[0] = syn_pkt

        self.sock.sendto(bytes(syn_pkt), (ip, port_num))
        print("Sending packet {} {} {}".format(rand_seq, 0, "SYN"))
        self.state = SYNSENT
        self.timer.start()
        b.wait()

    def accept(self):
        self.state = LISTEN
        b.wait()
