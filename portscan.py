import argparse
import datetime
import socket
import struct
import time
from random import randint
import sys
from scapy.config import conf
from scapy.supersocket import L3RawSocket
from scapy.layers.inet import IP, TCP
from scapy.volatile import RandShort
from scapy.sendrecv import sr, sr1
from multiprocessing import Pool


class PortScanner:
    def __init__(self):
        self.input_data = self._create_parser()
        self.IP_ADDRESS = self.input_data.IP_ADDRESS
        self.timeout = self.input_data.timeout
        self.num_threads = self.input_data.num_threads
        self.verbose = self.input_data.verbose
        self.guess = self.input_data.guess
        self.ports = self._parse_ports(self.input_data.PORTS)

    # region input_parse
    @staticmethod
    def _create_parser():
        parser = argparse.ArgumentParser()
        parser.add_argument('IP_ADDRESS', help='ip for check', type=str, action='store')
        parser.add_argument('--timeout', default=2, type=float, help='response timeout (default 2s)')
        parser.add_argument('-j', '--num-threads', help='number of threads (default 10)', type=int, default=10)
        parser.add_argument('-v', '--verbose', action='store_true', default=False, help='verbose mode')
        parser.add_argument('-g', '--guess', action='store_true', default=False,
                            help='definition protocol of application level')
        parser.add_argument('PORTS', type=str, nargs='+', help='port range')
        return parser.parse_args()

    @staticmethod
    def _parse_ports(input_ports):
        ports = dict(udp=set(), tcp=set())
        lambda_filter = lambda a, b: range(a, b + 1)
        for port_el in input_ports:
            protocol = port_el[:3]
            arg_range = port_el[4:]
            new_ports = set()
            for port in arg_range.split(','):
                if '-' in port:
                    new_range = port.split('-')
                    new_ports.update(set(lambda_filter(int(new_range[0]), int(new_range[1]))))
                else:
                    new_ports.add(int(port))

            ports[protocol].update(new_ports)
        return ports

    # endregion

    def scan_open_ports(self):
        with Pool(self.num_threads) as pool:
            pool.map(self.scan_open_tcp_ports, self.ports['tcp'])
        with Pool(self.num_threads) as pool:
            pool.map(self.scan_open_udp_ports, self.ports['udp'])

    # region UDP
    def scan_open_udp_ports(self, port):
        id = randint(1, 65535)
        protocols = dict(
            HTTP=b'GET / HTTP/1.1',
            DNS=struct.pack('!HHHHHH', id, 256, 1, 0, 0, 0) + b'\x06google\x03com\x00\x00\x01\x00\x01',
            ECHO=b'hello world'
        )
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.settimeout(self.timeout)
        for protocol, prot_value in protocols.items():
            try:
                udp_socket.sendto(prot_value, (self.IP_ADDRESS, port))
                data, conn = udp_socket.recvfrom(512)
                if data:
                    if self.guess:
                        prot_answer = self._define_udp_protocol(data, id, prot_value)
                        if prot_answer != '-':
                            print(f'UDP {port} {prot_answer}')
                            break
                    else:
                        print(f'UDP {port}')
                        break
            except socket.timeout as e:
                pass
        udp_socket.close()

    @staticmethod
    def _define_udp_protocol(data, id, req):
        if b'HTTP' in data[4:]:
            return 'HTTP'
        elif struct.pack('!H', id) in data:
            return 'DNS'
        elif data == req:
            return 'ECHO'
        else:
            return '-'

    # endregion

    # region TCP
    def scan_open_tcp_ports(self, port):
        if sys.platform == 'win32':
            conf.L3socket = L3RawSocket  # config for windows
        start_time = time.time()
        tcp_connect = sr1(IP(dst=self.IP_ADDRESS) / TCP(sport=RandShort(), dport=port, flags='S'),
                          timeout=self.timeout, verbose=0)
        if tcp_connect is None:
            # closed
            pass
        elif tcp_connect.haslayer(TCP):
            if tcp_connect.getlayer(TCP).flags == 0x12:
                sr(IP(dst=self.IP_ADDRESS) / TCP(sport=RandShort(), dport=port, flags='AR'), timeout=self.timeout,
                   verbose=0)
                elapsed_time = time.time() - start_time
                protocol_answer = ''
                if self.guess:
                    protocol_answer = tcp_connect.sprintf('%TCP.sport%')
                    if protocol_answer == 'domain':
                        protocol_answer = 'DNS'
                    else:
                        protocol_answer = protocol_answer.upper()

                self._handle_answer_for_open_tcp_port(elapsed_time, port, protocol_answer)

    def _handle_answer_for_open_tcp_port(self, elapsed_time, port, protocol_answer):
        if self.verbose and self.guess:
            print(f'TCP {port} {elapsed_time:0.3f} {protocol_answer}')
        elif self.verbose:
            print(f'TCP {port} {elapsed_time:0.3f}')
        elif self.guess:
            print(f'TCP {port} {protocol_answer}')
        else:
            print(f'TCP {port}')

    # endregion


def main():
    start_time = datetime.datetime.now()
    print(f'Starting PortScanner at {start_time}')
    portscan = PortScanner()
    portscan.scan_open_ports()
    print(f'\nDone: scanned in {datetime.datetime.now() - start_time}')


if __name__ == '__main__':
    main()
