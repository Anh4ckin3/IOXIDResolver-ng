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
from IOXIDResolverng.utils import identify_adresse_type

class IOXIDResolverNg:
    def __init__(self, target_ip, username=None, password=None, domain=None):

        self.target_ip = target_ip
        self.username = username
        self.password = password
        self.domain = domain
        self.auth_level = RPC_C_AUTHN_LEVEL_NONE
        self.rpc_transport = None

    def set_authentication(self):

        if self.username and self.password:
            self.auth_level = RPC_C_AUTHN_LEVEL_PKT_PRIVACY
        else:
            self.auth_level = RPC_C_AUTHN_LEVEL_NONE

    def connect(self):

        try:
            string_binding = f'ncacn_ip_tcp:{self.target_ip}'
            self.rpc_transport = transport.DCERPCTransportFactory(string_binding)

            if self.username and self.password:
                self.rpc_transport.set_credentials(self.username, self.password, self.domain)

            portmap = self.rpc_transport.get_dce_rpc()
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
                interface_type = identify_adresse_type(NetworkAddr)
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

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if args.username and args.password and args.domain:
        resolver = IOXIDResolverNg(args.target, args.username, args.password, args.domain)
        resolver.set_authentication()
        print(banner)
        print('[.] Authenticated connection on MSRPC')
        print(f'[*] Retrieve Network Interfaces for {args.target}...')
        resolver.get_network_interfaces()
    else:
        resolver = IOXIDResolverNg(args.target)
        resolver.set_authentication()
        print(banner)
        print('[.] Anonymous connection on MSRPC')
        print(f'[+] Retrieve Network Interfaces for {args.target}...')
        resolver.get_network_interfaces()


if __name__ == "__main__":
    main()
