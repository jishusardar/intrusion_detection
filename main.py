import pyshark
import netifaces
import ipaddress
import json
import requests
import base64
import logging
from pyshark.packet.packet import Packet
import httpx
import asyncio


logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')



class Data_Packet(object):
    def __init__(self, sniff_timestamp: str = '', layer: str = '', srcPort: str = '', dstPort: str = '',
                 ipSrc: str = '', ipDst: str = '', highest_layer='',location:str=''):
        self.sniff_timestamp = sniff_timestamp
        self.layer = layer
        self.srcPort = srcPort
        self.dstPort = dstPort
        self.ipSrc = ipSrc
        self.ipDst = ipDst
        self.highest_layer = highest_layer
        self.location=location


class apiServer(object):
    def __init__(self, ip: str, port: str):
        self.ip = ip
        self.port = port



server = apiServer('192.168.2.132', '8080')

intF = netifaces.gateways()['default'][netifaces.AF_INET][1]
capture = pyshark.LiveCapture(interface=intF)

async def geolocation(ip)->str:
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            response = await client.get(f'http://ip-api.com/json/{ip}')
            if response.status_code == 200:
                data = response.json()
                return data.get("org", "Unknown Org")
            else:
                return "Geo Lookup Failed"
    except Exception as e:
        return f"Geo Lookup failed Error:{e}"
    
def report(message: Data_Packet):
    try:
        json_data = json.dumps(message.__dict__).encode('utf-8')
        b64_payload = base64.b64encode(json_data).decode('utf-8')

        url = f"http://{server.ip}:{server.port}/api/"
        headers = {'Content-Type': 'application/json'}

        logging.info(f"Reporting packet: {message.__dict__}")
        response = requests.post(url, data=json_data, headers=headers)
        response.raise_for_status()

    except requests.exceptions.RequestException as err:
        logging.error(f"Failed to send packet data: {err}")


def is_api_server(packet: Packet, server: apiServer) -> bool:
    #Check if the packet is communicating with our API
    if hasattr(packet, 'ip') and hasattr(packet, 'tcp'):
        if ((packet.ip.src == server.ip or packet.ip.dst == server.ip) and
                (packet.tcp.dstport == server.port or packet.tcp.srcport == server.port)):
            return True
    return False


def is_private_ip(ip_address):
    #Check if IP is private
    ip = ipaddress.ip_address(ip_address)
    return ip.is_private

def is_external_network(ip_dst: str, interface: str) -> bool:
    """Check if destination IP is outside the local network subnet"""
    try:
        # Get IP and netmask of the interface
        iface_info = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]
        local_ip = iface_info['addr']
        netmask = iface_info['netmask']

        # Build the subnet
        network = ipaddress.IPv4Network(f"{local_ip}/{netmask}", strict=False)

        # Check if destination IP is within that subnet
        return ipaddress.IPv4Address(ip_dst) not in network

    except Exception as e:
        logging.error(f"Error checking external network: {e}")
        return False
def packetFilter(packet: Packet):
    if is_api_server(packet, server):
        return 

    if hasattr(packet, 'icmp'):
        p = Data_Packet()
        p.sniff_timestamp = packet.sniff_timestamp
        p.ipDst = packet.ip.dst
        p.ipSrc = packet.ip.src
        p.highest_layer = packet.highest_layer
        report(p)
        return

    if packet.transport_layer in ['TCP', 'UDP']:
        if hasattr(packet, 'ipv6'):
            for skip_layer in ['mdns', 'dhcpv6', 'ssdp', 'llmnr']:
                if hasattr(packet, skip_layer):
                    return

        if hasattr(packet, 'ip'):
            
            if is_private_ip(packet.ip.src) and is_private_ip(packet.ip.dst):
                p = Data_Packet()
                p.sniff_timestamp = packet.sniff_timestamp
                p.ipSrc = packet.ip.src
                p.ipDst = packet.ip.dst
                p.highest_layer = packet.highest_layer
                p.layer = packet.transport_layer
                p.location="Own Network"
                if hasattr(packet, 'udp'):
                    p.srcPort = packet.udp.srcport
                    p.dstPort = packet.udp.dstport
                if hasattr(packet, 'tcp'):
                    p.srcPort = packet.tcp.srcport
                    p.dstPort = packet.tcp.dstport

                report(p)
            elif is_external_network(packet.ip.dst, intF):
                logging.info(f"External Network Detected on Interface: ")
                et=Data_Packet()
                et.sniff_timestamp=packet.sniff_timestamp
                et.ipSrc=packet.ip.src
                et.ipDst=packet.ip.dst
                et.highest_layer=packet.highest_layer
                et.layer=packet.transport_layer
                et.location=asyncio.run(geolocation(packet.ip.dst))
                if hasattr(packet, 'udp'):
                    et.srcPort = packet.udp.srcport
                    et.dstPort = packet.udp.dstport
                if hasattr(packet, 'tcp'):
                    et.srcPort = packet.tcp.srcport
                    et.dstPort = packet.tcp.dstport
                
                report(et)
if __name__ == "__main__":
    logging.info(f"Starting capture on interface: {intF}")
    for packet in capture.sniff_continuously():
        packetFilter(packet)