def identify_adresse_type(value):
    if '.' in value:
        return "IPv4"
    elif ":" in value:
        return "IPv6"
    else:
        return "Hostname"