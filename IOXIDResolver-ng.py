#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : IOXIDResolver-ng.py
# Author             : Anh4ckin3 
# Date created       : 16 Dec 2024

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.dcerpc.v5.dcomrt import IObjectExporter
import sys
import argparse
import re

class IOXIDResolver_ng:
    def __init__(self, target_ip, username=None, password=None, domain=None):

        self.target_ip = target_ip
        self.username = username
        self.password = password
        self.domain = domain
        self.auth_level = RPC_C_AUTHN_LEVEL_NONE
        self.rpctransport = None

    def Identified_Adresse_type(slef, value):
        length = len(value.encode('utf-8')) 

        if '.' in value:
                return "IPv4"
        elif ":" in value:
            return "IPv6"
        else:
            return "Hostname"

    def set_authentication(self):

        if self.username and self.password:
            self.auth_level = RPC_C_AUTHN_LEVEL_PKT_PRIVACY
        else:
            self.auth_level = RPC_C_AUTHN_LEVEL_NONE

    def connect(self):

        try:
            string_binding = f'ncacn_ip_tcp:{self.target_ip}'
            self.rpctransport = transport.DCERPCTransportFactory(string_binding)

            if self.username and self.password:
                self.rpctransport.set_credentials(self.username, self.password, self.domain)

            portmap = self.rpctransport.get_dce_rpc()
            portmap.set_auth_level(self.auth_level)
            portmap.connect()
            return portmap
        except Exception as e:
            print(f"[-] Connexion error : {e}")
            sys.exit(1)

    def get_network_interfaces(self):

        try:
            portmap = self.connect()
            objExporter = IObjectExporter(portmap)
            bindings = objExporter.ServerAlive2()
            print(f'[+] ServerAlive2 methode return {len(bindings)} interface(s)')

            for binding in bindings:
                NetworkAddr = binding['aNetworkAddr']
                interface_type = self.Identified_Adresse_type(NetworkAddr)
                print(f'[+] aNetworkAddr addresse : {NetworkAddr} ({interface_type})')
        except Exception as e: 
            print(f"[-] Error while retrieving network interfaces : {e}")
            sys.exit(1) 
        
def main():

    banner = '''
|==========================|
|  IOXIDResolver Next Gen  |
|==========================|
'''

    parser = argparse.ArgumentParser(description="Network interface recovery via MSRPC and IObjectExporter.")
    parser.add_argument("-t", "--target", required=True, help="target IP")
    parser.add_argument("-u", "--username", help="username")
    parser.add_argument("-p", "--password", help="password")
    parser.add_argument("-d", "--domain", help="Domain")

    args = parser.parse_args()

    if args.username and args.password and args.domain:
        resolver = IOXIDResolver_ng(args.target, args.username, args.password, args.domain)
        resolver.set_authentication()
        print(banner)
        print('[.] Authenticed connection on MSRPC')
        print(f'[*] Retriev Network Interfaces for {args.target}...')
        interfaces = resolver.get_network_interfaces()
    else:
        resolver = IOXIDResolver_ng(args.target)
        resolver.set_authentication()
        print(banner)
        print('[.] Anonymous connection on MSRPC')
        print(f'[+] Retriev Network Interfaces for {args.target}...')
        interfaces = resolver.get_network_interfaces()


if __name__ == "__main__":
    main()
