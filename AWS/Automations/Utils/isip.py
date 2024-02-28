def isip(s):
    import ipaddress

    try:
        a = ipaddress.ip_address(s)
        return True
    except ValueError:
        return False
