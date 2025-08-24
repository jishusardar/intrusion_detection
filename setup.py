import socket
import random

def get_host_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as e:
        return "127.0.0.1"

def get_free_port():
    s = socket.socket()
    s.bind(('', 0))
    port = s.getsockname()[1]
    s.close()
    return port

def write_to_file(ip, port, filename=".env"):
    with open(filename, "w") as f:
        f.write(f"my_ipadd={ip}\n")
        f.write(f"my_port={port}\n")

if __name__ == "__main__":
    try:
        ip = get_host_ip()
        port = get_free_port()
        write_to_file(ip, port)
        print("The Setup is Successful...")
    except Exception as m:
        print("Getting {m} Error...")
