import scapy.all as scapy
from threading import Thread


class Sniffer(Thread):

    def __init__(self, monitor_callback):
        self.monitor_callback = monitor_callback
        Thread.__init__(self)

    def run(self):
        while True:
            try:
                scapy.sniff(prn=self.monitor_callback, filter="ip", store=0)
            except NameError:
                pass
