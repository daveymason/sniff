import socket

def scan_ports(domain):
    common_ports = [21, 22, 25, 80, 443, 8080]
    open_ports = []
    banners = {}

    for port in common_ports:
        try:
            with socket.create_connection((domain, port), timeout=1) as sock:
                open_ports.append(port)
                # Try to grab the banner
                sock.send(b"HEAD / HTTP/1.1\r\nHost: %s\r\n\r\n" % domain.encode())
                banner = sock.recv(1024).decode().strip()
                banners[port] = banner
        except (socket.timeout, ConnectionRefusedError, socket.error) as e:
            continue

    return open_ports, banners
