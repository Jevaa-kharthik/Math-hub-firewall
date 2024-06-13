import socket
import threading
from scapy.all import sniff, ARP
import sqlite3
import ssl

# Define allowed IP addresses and ports

with open("ip.txt") as ip_file:
    allowed_ips = ip_file.read()
allowed_ports = 80

class Firewall:
    def __init__(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(('localhost', 12345))
        self.server_socket.listen(5)

    def handle_client(self, client_socket, addr):
        ip, port = addr
        print(f"Connection from {ip}:{port}")
        
        if ip not in allowed_ips or port not in allowed_ports:
            print(f"Connection from {ip}:{port} blocked")
            client_socket.close()
            return
        
        # Handle client request (for demonstration, echo back received data)
        data = client_socket.recv(1024)
        client_socket.sendall(data)
        
        client_socket.close()

    def start(self):
        print("Firewall started.")
        while True:
            client_socket, addr = self.server_socket.accept()
            client_handler = threading.Thread(target=self.handle_client, args=(client_socket, addr))
            client_handler.start()

# ARP Spoofing detection
def arp_spoof_detection(packet):
    if ARP in packet and packet[ARP].op == 2:
        print("ARP Spoofing Detected")

# SQL Injection prevention
def execute_query(query, params):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(query, params)
    result = cursor.fetchall()
    conn.commit()
    conn.close()
    return result

# SSL/TLS secure communication
def secure_server():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(5)

    while True:
        client_socket, addr = server_socket.accept()
        with context.wrap_socket(client_socket, server_side=True) as secure_socket:
            data = secure_socket.recv(1024)
            secure_socket.sendall(data)

if __name__ == "__main__":
    firewall = Firewall()
    arp_sniffer = threading.Thread(target=sniff, kwargs={'prn': arp_spoof_detection, 'filter': 'arp', 'store': 0})
    secure_server_thread = threading.Thread(target=secure_server)
    
    firewall.start()
    arp_sniffer.start()
    secure_server_thread.start()
