import tkinter as tk
import hashlib
import json
from tkinter import ttk
from tkinter import messagebox, scrolledtext
from tkinter.simpledialog import askstring
from datetime import datetime
import scapy.all as scapy
import subprocess
import threading
import socket
import sqlite3
import cryptography
from cryptography.fernet import Fernet
import networkx as nx
import matplotlib.pyplot as plt
from scapy.layers.inet import IP, TCP, UDP

# ===========================
# Monitoramento e Detecção
# ===========================

def detect_collisions(devices, output_text):
    """Detecta colisões na rede analisando dispositivos."""
    output_text.insert(tk.END, "Simulando colisões na rede...\n")
    collision_detected = False

    for device in devices:
        status_text, issue = analyze_device_status(device)

        if issue == 'high_latency' or issue == 'device_unreachable':
            collision_detected = True
            output_text.insert(tk.END, f"Colisão detectada: {device['ip']} - {status_text}\n")
            output_text.insert(tk.END, suggest_solution('collision_detected') + "\n")

    if not collision_detected:
        output_text.insert(tk.END, "Nenhuma colisão detectada.\n")
    output_text.yview(tk.END)

def packet_callback(packet):
    """Captura pacotes e analisa colisões."""
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "Outro"
        details = ""

        # Detectar colisões específicas
        if packet.haslayer(TCP):
            flags = packet[TCP].flags
            if "R" in flags:  # Pacote resetado
                details = "Pacote resetado"
            elif "S" in flags and not packet.ack:  # SYN sem ACK
                details = "SYN sem resposta"

        if details:
            # Salvar a colisão no banco de dados
            save_collision_to_db(src_ip, dst_ip, protocol, details)

            # Exibir informações na janela principal
            info = f"Colisão detectada:\nOrigem: {src_ip}\nDestino: {dst_ip}\nProtocolo: {protocol}\nDetalhes: {details}\n"
            capture_text.insert(tk.END, info + "\n")
            capture_text.yview(tk.END)


def capture_packets():
    """Inicia a captura de pacotes com detecção de colisões."""
    global capture_text

    # Verificar se a janela de captura já está aberta
    if not hasattr(capture_packets, "capture_window") or not capture_packets.capture_window.winfo_exists():
        capture_packets.capture_window = tk.Toplevel()
        capture_packets.capture_window.title("Captura de Pacotes")

        capture_text = scrolledtext.ScrolledText(capture_packets.capture_window, width=80, height=30)
        capture_text.pack(padx=10, pady=10)

        capture_thread = threading.Thread(target=lambda: scapy.sniff(prn=packet_callback, store=False))
        capture_thread.daemon = True
        capture_thread.start()
    else:
        capture_packets.capture_window.lift()
