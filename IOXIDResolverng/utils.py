import ipaddress
import os
import sys


def identify_address_type(value: str) -> str:
    try:
        ip = ipaddress.ip_address(value)
        return "IPv4" if ip.version == 4 else "IPv6"
    except ValueError:
        return "Hostname"

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def get_ips_from_arg(arg):
    if os.path.isfile(arg):
        with open(arg, 'r') as f:
            ips = [line.strip() for line in f if line.strip()]
            return [ip for ip in ips if is_valid_ip(ip)]
    elif is_valid_ip(arg):
        return [arg]
    else:
        print(f"[-] Value '{arg}' is neither a valid IP address nor a valid file path.")
        sys.exit(1)