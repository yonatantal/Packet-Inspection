import configparser, pcapkit, os, sys
from netfilterqueue import NetfilterQueue
from packet import Packet

def process_packet(raw_packet) -> None:
    """
    Accept a NetfilterQueue.Packet, capture it as 'processed_packet'
    If Succeed: adds the packet to 'captured_packets' and accept the raw_packet
    """
    print(raw_packet)
    processed_packet = Packet()

    processed_packet.process_capture_info(raw_packet)
    processed_packet.process_ethernet_header(raw_packet)
    
    match processed_packet.ethernet['ether_type']:
        case 'IPv4':
            processed_packet.process_ipv4_packet(raw_packet)
        case 'ARP':
            processed_packet.process_arp_packet(raw_packet)
        case 'IPv6':
            processed_packet.process_ipv6_packet(raw_packet)
        case _:
            print('Unsupported ether_type packet...')


    captured_packets.append(processed_packet)
    raw_packet.accept()
        


def extract_config_file(file_path: str) -> dict:
    """
    extract commands from .conf file into a dictioanry.
    each key in the dictionary is a command and the vaule is the vaule(s) in the file
    """
    file_parser = configparser.ConfigParser()
    with open(file_path, 'r') as f:
        file_parser.read_string('[HELPER]\n' + f.read())

    dictionary = {}
    for key in file_parser['HELPER']:
        dictionary[key] = file_parser['HELPER'][key].replace(' ', '').split(',')

    return dictionary

def get_commands_from_file(file_path : str) -> list:
    """
    transfer the commmands in the config file to iptables commands:
    returns a tuple with 2 lists: the commands for inserting the fillter and list with commands to delete the fillter
    """

    iptabels_insert_commands = []
    iptabels_delete_commands = []
    conf_file_commands_to_iptables = {
        'capture_ip' : ['--source ', '--destination '],
        'capture_mac' : ['-m mac --mac-source '],
        'capture_icmp_type' : ['-p icmp --icmp-type '],
        'capture_tcp_port' : ['-p tcp --sport ', '-p tcp --dport '],
        'capture_udp_port' : ['-p udp --sport ', '-p udp --dport ']

    }
    # in case of a vaule being 'any' in the .conf file, this dict is called instead of conf_file_commands_to_iptables
    conf_file_commands_to_iptables_any = {
        'capture_ip' : '--destination 192.168.175.0/24',
        'capture_mac' : '',
        'capture_icmp_type' : '-p icmp',
        'capture_tcp_port' : '-p tcp',
        'capture_udp_port' : '-p udp'

    }

    commands_from_file = extract_config_file('config.conf')

    for command in commands_from_file.keys():
        for vaule in commands_from_file[command]:
            if vaule == 'any':
                iptabels_insert_commands.append(f'sudo iptables -A INPUT {conf_file_commands_to_iptables_any[command]} -j NFQUEUE --queue-num 1000')
                iptabels_delete_commands.append(f'sudo iptables -D INPUT {conf_file_commands_to_iptables_any[command]} -j NFQUEUE --queue-num 1000')
                iptabels_insert_commands.append(f'sudo iptables -A OUTPUT {conf_file_commands_to_iptables_any[command]} -j NFQUEUE --queue-num 1000')
                iptabels_delete_commands.append(f'sudo iptables -D OUTPUT {conf_file_commands_to_iptables_any[command]} -j NFQUEUE --queue-num 1000')
            else:
                for action in conf_file_commands_to_iptables[command]:
                    iptabels_insert_commands.append(f'sudo iptables -A INPUT {action + vaule} -j NFQUEUE --queue-num 1000')
                    iptabels_delete_commands.append(f'sudo iptables -D INPUT {action + vaule} -j NFQUEUE --queue-num 1000')
                    iptabels_insert_commands.append(f'sudo iptables -A OUTPUT {action + vaule} -j NFQUEUE --queue-num 1000')
                    iptabels_delete_commands.append(f'sudo iptables -D OUTPUT {action + vaule} -j NFQUEUE --queue-num 1000')
    
    return (iptabels_insert_commands, iptabels_delete_commands)


def execute_os_commands(commands : list) -> None:
    for command in commands:
        print('Running command: ' + command)
        os.system(command)
        print('')
    


captured_packets = []

if __name__ == '__main__':

    iptabels_insert_commands, iptabels_delete_commands = get_commands_from_file('config.conf')
    execute_os_commands(iptabels_insert_commands)
    
    nfqueue = NetfilterQueue()
    nfqueue.bind(1000, process_packet)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        execute_os_commands(iptabels_delete_commands)
        print('')
    except Exception as e:
        print(e)
        execute_os_commands(iptabels_delete_commands)

    
    nfqueue.unbind()
    
    for pkt in captured_packets:
        print(pkt)
            
