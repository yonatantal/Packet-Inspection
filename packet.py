import uuid


class Packet:
    capture_types = {
        0: 'PREROUTING',
        1: 'INPUT',
        2: 'FORWARD',
        3: 'OUTPUT',
        4: 'POSTROUTING'
    }
    ether_types = {
        2048: 'IPv4',
        2054: 'ARP',
        34525: 'IPv6'
    }
    ip_protocol_types = {
        1: 'ICMP',
        6: 'TCP',
        17: 'UDP',
    }
    udp_types = {
        53: 'DNS',
        67: 'DHCP (server)',
        68: 'DHCP (client)',
    }
    tcp_types = {
        21: 'FTP',
        22: 'SSH',
        53: 'DNS',
        80: 'HTTP',
        443: 'HTTPS'
    }
    icmp_types = {
        0: 'Echo reply',
        3: 'Destination unreachable',
        5: 'Redirect message',
        8: 'Echo request',
        11: 'Time exceeded',
        12: 'Parameter problem'
    }
    arp_opcodes = {
        1: 'Request',
        2: 'Reply'
    }

    def __init__(self) -> None:

        self.capture_type = -1
        self.capture_time = -1.0

        self.ethernet = {
            'dst_mac': '',
            'src_mac': '',
            'ether_type': ''
        }
        self.ip = {
            'id': 0,
            'protocol': '',
            'src_ip': '',
            'dst_ip': '',
            'raw_data': []
        }
        self.tcp = {
            'src_port': 0,
            'dst_port': 0,
            'payload': '',
            'raw_data': []
        }
        self.udp = {
            'src_port': 0,
            'dst_port': 0,
            'payload': '',
            'raw_data': []
        }
        self.icmp = {
            'type': 0,
            'payload': '',
            'raw_data': []
        }
        self.arp = {
            'opcode': '',
            'sender_mac_address': '',
            'sender_ip_address': '',
            'target_mac_address': '',
            'target_ip_address': ''
        }

    def __str__(self) -> str:
        string = ''
        string += 'Packet Infomation:\n'
        string += 'Capture Info:\n'
        string += f'\tCapture type: {self.capture_type}\n'
        string += f'\tCapture time: {self.time}\n'

        string += 'Ethernet Header:\n'
        string += f'\tDestination MAC: {self.ethernet['dst_mac']}\n'
        string += f'\tSource MAC: {self.ethernet['src_mac']}\n'
        string += f'\tEther type: {self.ethernet['ether_type']}\n'

        match self.ethernet['ether_type']:
            case 'IPv4':
                string += self._ipv4_packet_to_str()
            case 'ARP':
                string += self._arp_packet_to_str()
            case 'Ipv6':
                string += self._ipv6_packet_to_str()
            case _:
                string += 'PROTOCOL NOT SUPPORTED'

        return string

    def _ipv4_packet_to_str(self) -> str:
        """
        Helper function for __str__. Return a string for the ipv4 packet  
        """
        string = 'IPv4 Header:\n'
        string += f'\tIdentification: {self.ip['id']}\n'
        string += f'\tProtocol: {self.ip['protocol']}\n'
        string += f'\tSource IP: {self.ip['src_ip']}\n'
        string += f'\tDestination MAC: {self.ip['dst_ip']}\n'

        match self.ip['protocol']:
            case 'TCP':
                string += 'TCP Header:\n'
                string += f'\tSource port: {self.tcp['src_port']}\n'
                string += f'\tDestination port: {self.tcp['dst_port']}\n'
                string += f'\tPayload: {self.tcp['payload']}\n'

            case 'UDP':
                string += 'UDP Header:\n'
                string += f'\tSource port: {self.udp['src_port']}\n'
                string += f'\tDestination port: {self.udp['dst_port']}\n'
                string += f'\tPayload: {self.udp['payload']}\n'

            case 'ICMP':
                string += 'ICMP Header:\n'
                string += f'\tType: {self.icmp['type']}\n'
                string += f'\tPayload: {self.icmp['payload']}\n'

            case _:
                return 'Protocol not supported'

        return string

    def _arp_packet_to_str(self) -> str:
        """
        Helper function for __str__. Return a string for the arp packet  
        """
        string = 'ARP Header:\n'
        string += f'\tOperation: {self.arp['opcode']}\n'

        string += f'\tSender MAC address: {self.arp['sender_mac_address']}\n'
        string += f'\tSender IP address: {self.arp['sender_ip_address']}\n'

        string += f'\tTarget MAC address: {self.arp['target_mac_address']}\n'
        string += f'\tTarget IP address: {self.arp['target_ip_address']}\n'

        return string

    def _ipv6_packet_to_str(self) -> str:
        """
        Helper function for __str__. Return a string for the ipv4 packet  
        """
        pass

    def _format_mac_address(self, mac) -> str:
        """
        Accapt a MAC address as string and returns it with ':'.
        Example: 123456ABCDEF -> 12:34:56:AB:CD:EF
        """
        return ':'.join([mac[i:i + 2] for i in range(0, len(mac), 2)])

    def _format_ip_address(self, ip) -> str:
        """
        Accapt a IPv4 address as 4 bytes and returns it with '.'.
        Example: [192, 168, 175, 1] -> 192.168.175.1
        """
        return '.'.join([str(byte) for byte in ip])

    def _get_byte_as_bits(self, byte: int) -> str:
        """
        Accept byte as integer and returns the value in str bits.
        Example: 42 -> '00101010'
        """
        return bin(byte)[2:].zfill(8)

    def _split_ip_protocol_payloads(self, raw_payload) -> tuple:
        """
        Takes both the IPv4 and protocol headers and returns them as seprates bytes list
        uses 'Header Length' (first hex char of the payload) as a separator
        """
        first_byte = self._get_byte_as_bits(raw_payload[0])
        # length of IP Header in double word -> 4 bytes in each double word
        ip_header_length = int(first_byte[4:], 2) * 4

        ip_payload = raw_payload[:ip_header_length]
        data_payload = raw_payload[ip_header_length:]

        return ip_payload, data_payload

    def _process_ip_header(self, raw_ip_payload) -> None:
        """
        Sets IPv4 protocol used, Source and Destnation IP addreses for the packet.
        Data requested as list of ip header payload bytes
        """
        self.ip['id'] = raw_ip_payload[4] * 256 + raw_ip_payload[5]
        self.ip['src_ip'] = self._format_ip_address(raw_ip_payload[12:16])
        self.ip['dst_ip'] = self._format_ip_address(raw_ip_payload[16:20])

        try:
            self.ip['protocol'] = self.ip_protocol_types[raw_ip_payload[9]]

        # here if protocol is unknown in 'ip_protocol_types'
        except NameError:
            self.ip['protocol'] = 'Unsupported Protocol'

        self.ip['raw_data'] = raw_ip_payload

    def _process_tcp_header(self, raw_tcp_payload) -> None:
        """
        Sets the TCP Source, Destination ports and Payload for the packet.
        Data requested as list of tcp payload bytes
        """

        # Sets the first byte as hundreds in hex form and the second byte as ones
        try:
            self.tcp['src_port'] = self.tcp_types[raw_tcp_payload[0] * 256 + raw_tcp_payload[1]]
        # here if tcp type is unknown in 'tcp_types'
        except KeyError:
            self.tcp['src_port'] = int(raw_tcp_payload[0] * 256 + raw_tcp_payload[1])

        try:
            self.tcp['dst_port'] = self.tcp_types[int(raw_tcp_payload[2] * 256 + raw_tcp_payload[3])]
        # here if tcp type is unknown in 'tcp_types'
        except KeyError:
            self.tcp['dst_port'] = int(raw_tcp_payload[2] * 256 + raw_tcp_payload[3])

        tcp_header_length_byte = self._get_byte_as_bits(raw_tcp_payload[12])
        tcp_header_length = int(tcp_header_length_byte[:4], 2) * 4

        try:
            self.tcp['payload'] = raw_tcp_payload[tcp_header_length:]
        except IndexError:
            self.tcp['payload'] = 'NO PAYLOAD'

        self.tcp['raw_data'] = raw_tcp_payload

    def is_fin_flag_up(self) -> bool:
        """
        Accept TCP data (headers + payload).
        return true if the FIN flag is up. (14th byte in data, FIN flag is the first bit)
        """
        tcp_flag = self.tcp['raw_data'][13]
        return bool(tcp_flag & 1)

    def _process_udp_header(self, raw_udp_payload) -> None:
        """
        Sets the UDP Source, Destination ports and Payload for the packet.
        Data requested as list of udp payload bytes
        """
        # Sets the first byte as hundreds in hex form and the second byte as ones
        try:
            self.udp['src_port'] = self.udp_types[raw_udp_payload[0] * 256 + raw_udp_payload[1]]
        # here if udp type is unknown in 'udp_types'
        except KeyError:
            self.udp['src_port'] = raw_udp_payload[0] * 256 + raw_udp_payload[1]

        try:
            self.udp['dst_port'] = self.udp_types[raw_udp_payload[2] * 256 + raw_udp_payload[3]]
        # here if udp type is unknown in 'udp_types'
        except KeyError:
            self.udp['dst_port'] = raw_udp_payload[2] * 256 + raw_udp_payload[3]

        try:
            self.udp['payload'] = raw_udp_payload[8:]
        except IndexError:
            self.udp['payload'] = 'NO PAYLOAD'

        self.udp['raw_data'] = raw_udp_payload

    def _process_icmp_header(self, raw_icmp_payload) -> None:
        """
        Sets the ICMP Type and Payload for the packet.
        Data requested as list of icmp payload bytes
        """
        try:
            self.icmp['type'] = self.icmp_types[raw_icmp_payload[0]]

        # here if icmp type is unknown in 'icmp_types'
        except KeyError:
            self.icmp['type'] = raw_icmp_payload[0]

        try:
            self.icmp['payload'] = raw_icmp_payload[8:]
        except IndexError:
            self.icmp['payload'] = 'NO PAYLOAD'

        self.icmp['raw_data'] = raw_icmp_payload

    def process_capture_info(self, raw_packet) -> None:
        """
        Set Capture Type and Capture Time for the packet
        """
        self.capture_type = self.capture_types[raw_packet.hook]
        self.time = raw_packet.get_timestamp()

    def process_ethernet_header(self, raw_packet) -> None:
        """
        Set Ethernet Type ,Source and Destination MAC address for the packet.
        Data requested as a NetfilterQueue.Packet
        """
        self.ethernet['dst_mac'] = self._format_mac_address(hex(uuid.getnode())[2:].zfill(12))

        try:
            self.ethernet['src_mac'] = self._format_mac_address(raw_packet.get_hw().hex()[:12])
        except AttributeError:
            self.ethernet['src_mac'] = 'NO MAC'

        try:
            self.ethernet['ether_type'] = self.ether_types[raw_packet.hw_protocol]

        # here if ether_type is unknown in 'ether_types'
        except NameError:
            self.ethernet['ether_type'] = f'Type {raw_packet.hw_protocol}'

    def process_ipv4_packet(self, raw_packet) -> None:
        """
        Process IPv4 packets. Accept a netfilterqueue.Packet as argument
        """
        raw_ip_payload, raw_protocol_payload = self._split_ip_protocol_payloads(raw_payload=raw_packet.get_payload())

        self._process_ip_header(raw_ip_payload)

        match self.ip['protocol']:
            case 'TCP':
                self._process_tcp_header(raw_protocol_payload)
            case 'UDP':
                self._process_udp_header(raw_protocol_payload)
            case 'ICMP':
                self._process_icmp_header(raw_protocol_payload)

    def process_arp_packet(self, raw_packet) -> None:
        """
        Process ARP packets. Accept a netfilterqueue.Packet as argument
        """
        raw_arp_payload = raw_packet.get_payload()

        self.arp['opcode'] = self.arp_opcodes[raw_arp_payload[6] * 256 + raw_arp_payload[7]]

        self.arp['sender_mac_address'] = self._format_mac_address(raw_arp_payload[8:14])
        self.arp['sender_ip_address'] = self._format_ip_address(raw_arp_payload[15:19])

        self.arp['target_mac_address'] = self._format_mac_address(raw_arp_payload[20:26])
        self.arp['sender_ip_address'] = self._format_ip_address(raw_arp_payload[27:31])

        if self.arp['opcode'] == 'Request':
            self.ethernet['dst_mac'] = 'FF:FF:FF:FF:FF:FF (Broadcast)'

    def process_ipv6_packet(self, raw_packet) -> None:
        """
        Process IPv6 packets. Accept a netfilterqueue.Packet as argument
        """
        pass

    def process_packet(self, raw_packet) -> None:
        """
        Accept a NetfilterQueue.Packet and process it
        """
        self.process_capture_info(raw_packet)
        self.process_ethernet_header(raw_packet)

        match self.ethernet['ether_type']:
            case 'IPv4':
                self.process_ipv4_packet(raw_packet)
            case 'ARP':
                self.process_arp_packet(raw_packet)
            case 'IPv6':
                self.process_ipv6_packet(raw_packet)
            case _:
                print('Unsupported ether_type packet...')
