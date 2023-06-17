import os
import json

import scapy.all as scapy
parameters = f'{os.getcwd()}\src\data\parameters.json'


class Utils:

    @staticmethod
    def get_victim_ip():
        file = open(parameters)
        return json.load(file)['victim_ip']

    @staticmethod
    def get_gateway_ip():
        file = open(parameters)
        return json.load(file)['gateway_ip']

    @staticmethod
    def get_attack_ip():
        file = open(parameters)
        return json.load(file)['attack_ip']

    @staticmethod
    def get_attack_mac():
        return scapy.Ether().src

    @staticmethod
    def get_mac(ip: str):
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
        return answered_list[0][1].hwsrc
