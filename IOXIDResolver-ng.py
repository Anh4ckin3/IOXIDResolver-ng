from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.dcerpc.v5.dcomrt import IObjectExporter
import sys
import argparse
import ipaddress
import re

class IOXIDResolver_ng:
    def __init__(self, target_ip, username=None, password=None, domain=None):

        self.target_ip = target_ip
        self.username = username
        self.password = password
        self.domain = domain
        self.auth_level = RPC_C_AUTHN_LEVEL_NONE
        self.rpctransport = None

    def set_authentication(self, auth_level=""):

        if auth_level == "creds" and self.username and self.password:
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
            print(portmap)
            return portmap
        except Exception as e:
            print(f"[-] Connexion error : {e}")
            sys.exit(1)

    def get_network_interfaces(self):
        try:
            portmap = self.connect()
            objExporter = IObjectExporter(portmap)
            bindings = objExporter.ServerAlive2()

            interfaces = []
            for binding in bindings:
                NetworkAddr = binding['aNetworkAddr']
                interfaces.append(NetworkAddr)

            return interfaces
        except Exception as e:
            print(f"[-] Error while retrieving network interfaces : {e}")
            sys.exit(1)

    def Identitied_Adresse_type(self):
        interface = self.get_network_interfaces()
        
        for i in interface:
            try: 
                if isinstance(i, ipaddress.IPv4Address):
                    print("IPv4")
                elif isinstance(i, ipaddress.IPv6Address):
                    print("IPv6")
            except ValueError:
                pass 
            hostname_regex = re.compile(r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$')
            if hostname_regex.match(i):
                print("hostname")
            print("error")
            sys.exit(1)
        

            


def main():

    parser = argparse.ArgumentParser(description="Network interface recovery via MSRPC and IObjectExporter.")
    parser.add_argument("-t", "--target", required=True, help="target IP")
    parser.add_argument("-u", "--username", help="username")
    parser.add_argument("-p", "--password", help="password")
    parser.add_argument("-d", "--domain", help="Domain")
    parser.add_argument("-a", "--auth", choices=["none", "creds"], default="none", help="auth methode (anonymous by default)")

    args = parser.parse_args()

    match args.auth:
        case 'none':
            resolver = IOXIDResolver_ng(args.target)
            resolver.set_authentication(args.auth)
            print('[*] Anonymous connection on MSRPC')
            print(f'[+] Retriev Network Interfaces for {args.target}...')
            resolver.Identitied_Adresse_type()




        

if __name__ == "__main__":
    main()
