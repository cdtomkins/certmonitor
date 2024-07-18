def handle_ssl_error(e, original_hostname, hostname, ip, port):
    return {
        "error": "SSLError",
        "message": str(e),
        "original_hostname": original_hostname,
        "hostname": hostname,
        "ip": ip,
        "port": port,
    }


def handle_socket_error(e, original_hostname, hostname, ip, port):
    return {
        "error": "SocketError",
        "message": str(e),
        "original_hostname": original_hostname,
        "hostname": hostname,
        "ip": ip,
        "port": port,
    }


def handle_unknown_error(e, original_hostname, hostname, ip, port):
    return {
        "error": "UnknownError",
        "message": str(e),
        "original_hostname": original_hostname,
        "hostname": hostname,
        "ip": ip,
        "port": port,
    }


def handle_dns_error(original_hostname, hostname, port):
    return {
        "error": "DNSResolutionError",
        "message": f"Unable to resolve hostname: {hostname}",
        "original_hostname": original_hostname,
        "hostname": hostname,
        "port": port,
    }
