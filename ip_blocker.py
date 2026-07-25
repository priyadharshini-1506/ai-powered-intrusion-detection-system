import os

def block_ip(ip):
    command = (
        f'netsh advfirewall firewall add rule '
        f'name="BLOCK_{ip}" dir=in action=block remoteip={ip}'
    )
    os.system(command)
    print(f"Blocked IP: {ip}")
