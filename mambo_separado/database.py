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
# Configuração do Banco de Dados De Users
# ===========================

def initialize_authentication_db():
    """Inicializa a tabela de usuários no banco de dados."""
    connection = sqlite3.connect("auth.db")
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            action TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    connection.commit()
    connection.close()

def register_user(username, password):
    """Registra um novo usuário com senha criptografada."""
    connection = sqlite3.connect("auth.db")
    cursor = connection.cursor()
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        connection.commit()
        messagebox.showinfo("Registro", "Usuário registrado com sucesso!")
    except sqlite3.IntegrityError:
        messagebox.showerror("Erro", "Usuário já existe.")
    finally:
        connection.close()

def authenticate_user(username, password):
    """Verifica as credenciais do usuário."""
    connection = sqlite3.connect("auth.db")
    cursor = connection.cursor()
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, hashed_password))
    user = cursor.fetchone()
    connection.close()
    return user is not None

def log_access(username, action):
    """Registra ações no log de acesso."""
    encrypted_action = encrypt_data(action)
    connection = sqlite3.connect("auth.db")
    cursor = connection.cursor()
    cursor.execute("INSERT INTO access_logs (username, action) VALUES (?, ?)", (username, encrypted_action))
    connection.commit()
    connection.close()

def view_logs():
    """Exibe os registros de acesso."""
    connection = sqlite3.connect("auth.db")
    cursor = connection.cursor()
    cursor.execute("SELECT id, username, action, timestamp FROM access_logs")
    logs = cursor.fetchall()
    connection.close()

    log_window = tk.Toplevel()
    log_window.title("Registros de Acesso")

    log_text = tk.Text(log_window, width=80, height=20)
    log_text.pack(padx=10, pady=10)

    log_text.insert(tk.END, f"{'ID':<5} {'Usuário':<20} {'Ação':<30} {'Timestamp'}\n")
    log_text.insert(tk.END, "-" * 80 + "\n")
    for log in logs:
        decrypted_action = decrypt_data(log[2])
        log_text.insert(tk.END, f"{log[0]:<5} {log[1]:<20} {decrypted_action:<30} {log[3]}\n")


# ===========================
# Configuração do Banco de Dados de Dispositivos
# ===========================

def initialize_database():
    """Inicializa o banco de dados SQLite e cria as tabelas se não existirem."""
    connection = sqlite3.connect("network_devices.db")
    cursor = connection.cursor()

    # Excluir e recriar a tabela de dispositivos (opcional, caso necessário)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL UNIQUE,
            mac TEXT NOT NULL,
            hostname TEXT NOT NULL,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Criar a tabela de colisões
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS collisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT NOT NULL,
            destination_ip TEXT NOT NULL,
            protocol TEXT NOT NULL,
            details TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.commit()
    connection.close()


def save_device_to_db(device):
    #Salva ou atualiza informações de um dispositivo no banco de dados.
    connection = sqlite3.connect("network_devices.db")
    cursor = connection.cursor()
    encrypted_ip = encrypt_data(device['ip'])
    encrypted_mac = encrypt_data(device['mac'])
    encrypted_hostname = encrypt_data(device['hostname'])
    cursor.execute("""
        INSERT INTO devices (ip, mac, hostname, last_seen)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(ip) DO UPDATE SET
            mac=excluded.mac,
            hostname=excluded.hostname,
            last_seen=CURRENT_TIMESTAMP
    """, (encrypted_ip, encrypted_mac, encrypted_hostname))
    connection.commit()
    connection.close()

def clear_collision_records():
    """Apaga todos os registros de colisões da base de dados."""
    connection = sqlite3.connect("network_devices.db")
    cursor = connection.cursor()
    cursor.execute("DELETE FROM collisions")
    connection.commit()
    connection.close()

def save_collision_to_db(source_ip, destination_ip, protocol, details):
    """Salva informações de uma colisão no banco de dados."""
    connection = sqlite3.connect("network_devices.db")
    cursor = connection.cursor()
    cursor.execute("""
        INSERT INTO collisions (source_ip, destination_ip, protocol, details)
        VALUES (?, ?, ?, ?)
    """, (source_ip, destination_ip, protocol, details))
    connection.commit()
    connection.close()


def get_all_devices_from_db():
    #Recupera todos os dispositivos armazenados no banco de dados.
    connection = sqlite3.connect("network_devices.db")
    cursor = connection.cursor()
    cursor.execute("SELECT ip, mac, hostname, last_seen FROM devices")
    devices = cursor.fetchall()
    connection.close()

    decrypted_devices = []
    for device in devices:
        decrypted_devices.append({
            'ip': decrypt_data(device[0]),
            'mac': decrypt_data(device[1]),
            'hostname': decrypt_data(device[2]),
            'last_seen': device[3]
        })
    return decrypted_devices

# Inicializa a base de dados
initialize_database()