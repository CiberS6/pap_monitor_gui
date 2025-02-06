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
# Configurações e Segurança
# ===========================

# Gerar chave de criptografia para proteger dados sensíveis
def generate_and_save_key():
    with open("encryption_key.key", "wb") as key_file:
        key = Fernet.generate_key()
        key_file.write(key)

# Carregar a chave de criptografia
def load_key():
    with open("encryption_key.key", "rb") as key_file:
        return key_file.read()

# Certifique-se de que a chave seja carregada
try:
    key = load_key()
except FileNotFoundError:
    generate_and_save_key()
    key = load_key()

cipher_suite = Fernet(key)

# Função para criptografar texto
def encrypt_data(data):
    return cipher_suite.encrypt(data.encode())

# Função para descriptografar texto
def decrypt_data(encrypted_data):
    try:
        return cipher_suite.decrypt(encrypted_data).decode()
    except (cryptography.fernet.InvalidToken, AttributeError):
        # Retornar o dado como está se não estiver criptografado ou inválido
        return encrypted_data

encrypted_ip = encrypt_data("192.168.1.1")
encrypted_mac = encrypt_data("00:11:22:33:44:55")

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

# ===========================
# Funções de Rede
# ===========================

def scan_network(ip_range):
    """Escaneia a rede e retorna uma lista de dispositivos encontrados com IPs e nomes de máquina."""
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    devices = []
    for element in answered_list:
        device_info = {
            'ip': element[1].psrc,
            'mac': element[1].hwsrc,
            'hostname': get_hostname(element[1].psrc)
        }
        devices.append(device_info)

    return devices

def scan_multiple_networks(ip_ranges):
    """Escaneia múltiplos intervalos de IP."""
    all_devices = []
    for ip_range in ip_ranges.split(","):
        devices = scan_network(ip_range.strip())
        all_devices.extend(devices)
    return all_devices

def get_hostname(ip):
    """Tenta obter o nome do host a partir do IP."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        hostname = "Desconhecido"
    return hostname

def check_ping(host):
    """Verifica a latência usando o ping."""
    response = subprocess.run(['ping', '-n', '4', host], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if response.returncode == 0:
        output = response.stdout.decode()
        return True, output
    else:
        return False, response.stderr.decode()

def suggest_solution(issue):
    """Sugere soluções com base no tipo de problema."""
    solutions = {
        'high_latency': "Sugestões: \n1. Verifique o roteador. \n2. Verifique a largura de banda.",
        'packet_loss': "Sugestões: \n1. Verifique o cabo de rede. \n2. Tente reiniciar o dispositivo.",
        'device_unreachable': "Sugestões: \n1. Verifique as conexões do dispositivo. \n2. Reinicie o dispositivo.",
        'collision_detected': "Sugestões: \n1. Reduza dispositivos competindo pelo mesmo canal. \n2. Otimize a largura de banda.",
        'normal': "Nenhum problema detectado.",
    }
    return solutions.get(issue, "Solução desconhecida.")

def analyze_device_status(device, ip):
    """Analisa o status do dispositivo e retorna um texto de status."""
    ip = decrypt_data(device['ip'])
    is_reachable, ping_output = check_ping(ip)

    if not is_reachable:
        diagnostic_result = run_diagnostics(ip)
        messagebox.showinfo("Diagnóstico de Problema", f"Diagnóstico para {ip}:\n{diagnostic_result}")
    else:
        print(f"{ip} está online.")

    if is_reachable:
        avg_latency = None
        for line in ping_output.splitlines():
            if "Média" in line:
                avg_latency = float(line.split('=')[1].replace('ms', '').strip())
        
        if avg_latency and avg_latency > 100:
            return f"{ip} está acessível, mas com latência alta ({avg_latency} ms).", 'high_latency'
        else:
            return f"{ip} está acessível. Latência média: {avg_latency} ms.", 'normal'
    else:
        messagebox.showerror("Dispositivo Offline", f"O dispositivo com IP {ip} está offline!")
        return f"{ip} não está acessível.", 'device_unreachable'

def run_diagnostics(ip):
    """Executa diagnósticos para dispositivos offline."""
    diagnostics = []

    # Verificar conectividade com o gateway
    gateway_ip = "192.168.1.1"  # Exemplo
    is_gateway_reachable, _ = check_ping(gateway_ip)
    if not is_gateway_reachable:
        diagnostics.append("Problema no roteador: gateway inacessível.")

    # Verificar DNS
    try:
        socket.gethostbyname("www.google.com")
    except socket.gaierror:
        diagnostics.append("Problema de DNS: servidor DNS inacessível.")

    # Verificar se a rede local está funcionando
    is_network_reachable, _ = check_ping("8.8.8.8")
    if not is_network_reachable:
        diagnostics.append("Problema de rede: conectividade externa indisponível.")

    # Resultado final
    if not diagnostics:
        diagnostics.append("Nenhum problema identificado.")

    return "\n".join(diagnostics)

    
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


# ===========================
# Gerenciamento de Dados
# ===========================

def scan_and_save_network(ip_range):
    """Escaneia a rede e salva os dispositivos encontrados no banco de dados."""
    devices = scan_network(ip_range)
    for device in devices:
        save_device_to_db(device)
    return devices

def show_stored_devices():
    """Mostra os dispositivos armazenados no banco de dados."""
    stored_devices = get_all_devices_from_db()

    stored_window = tk.Toplevel()
    stored_window.title("Dispositivos Armazenados")

    stored_text = scrolledtext.ScrolledText(stored_window, width=80, height=30)
    stored_text.pack(padx=10, pady=10)

    stored_text.insert(tk.END, "Dispositivos Armazenados no Banco de Dados:\n")
    stored_text.insert(tk.END, f"{'IP':<20} {'MAC':<20} {'Hostname':<25} {'Última Vez Visto'}\n")
    stored_text.insert(tk.END, "-" * 100 + "\n")

    for device in stored_devices:
        ip, mac, hostname, last_seen = device
        stored_text.insert(tk.END, f"{ip:<20} {mac:<20} {hostname:<25} {last_seen}\n")

    stored_text.yview(tk.END)

def show_stored_collisions():
    """Mostra as colisões armazenadas no banco de dados."""
    connection = sqlite3.connect("network_devices.db")
    cursor = connection.cursor()
    cursor.execute("SELECT source_ip, destination_ip, protocol, details, timestamp FROM collisions")
    collisions = cursor.fetchall()
    connection.close()

    collision_window = tk.Toplevel()
    collision_window.title("Colisões Detectadas")

    collision_text = scrolledtext.ScrolledText(collision_window, width=80, height=30)
    collision_text.pack(padx=10, pady=10)

    collision_text.insert(tk.END, "Colisões Detectadas:\n")
    collision_text.insert(tk.END, f"{'Origem':<20} {'Destino':<20} {'Protocolo':<10} {'Detalhes':<30} {'Timestamp'}\n")
    collision_text.insert(tk.END, "-" * 100 + "\n")

    for collision in collisions:
        source_ip, destination_ip, protocol, details, timestamp = collision
        collision_text.insert(tk.END, f"{source_ip:<20} {destination_ip:<20} {protocol:<10} {details:<30} {timestamp}\n")

    collision_text.yview(tk.END)

    def delete_collisions():
        clear_collision_records()
        collision_text.delete(1.0, tk.END)
        collision_text.insert(tk.END, "Todos os registros de colisões foram excluídos.\n")
        collision_text.yview(tk.END)
    
    # Botão para excluir colisões
    delete_button = tk.Button(collision_window, text="Excluir Registros", command=delete_collisions)
    delete_button.pack(pady=5)

# ===========================
# Topologia de Rede
# ===========================

def create_network_topology(devices):
    """Cria o grafo de topologia da rede."""
    G = nx.Graph()
    G.add_node("Router", label="Router", color='red')

    for device in devices:
        device_name = f"{device['ip']} ({device['mac']})"
        G.add_node(device_name, label=device_name, color='skyblue')
        G.add_edge("Router", device_name)

    return G

def draw_network_topology():
    """Desenha a topologia da rede."""
    devices = scan_network("10.5.50.254/24")
    G = create_network_topology(devices)

    pos = nx.spring_layout(G)
    node_colors = [G.nodes[node].get('color', 'skyblue') for node in G.nodes()]
    labels = nx.get_node_attributes(G, 'label')

    plt.figure("Topologia de Rede")
    nx.draw(G, pos, labels=labels, with_labels=True, node_color=node_colors, font_size=8, node_size=800)
    plt.show()

def create_main_app(username=None):
    """Cria a interface gráfica principal usando Tkinter."""
    window = tk.Tk()
    window.title("Monitor de Rede")

    frame = tk.Frame(window)
    frame.pack(padx=10, pady=10)

    ip_entry = tk.Entry(frame, width=40)
    ip_entry.insert(0, "10.5.50.254/24")
    ip_entry.pack()

    output_text = scrolledtext.ScrolledText(frame, width=80, height=20)
    output_text.pack(pady=10)

    tk.Button(frame, text="Iniciar Monitoramento", 
              command=lambda: threading.Thread(target=detect_collisions, 
                    args=(scan_multiple_networks(ip_entry.get()), 
                        output_text)).start()).pack(pady=5)
    tk.Button(frame, text="Capturar Pacotes", command=capture_packets).pack(pady=5)
    tk.Button(frame, text="Visualizar Topologia", command=draw_network_topology).pack(pady=5)
    tk.Button(frame, text="Dispositivos Salvos no BD", command=show_stored_devices).pack(pady=5)
    tk.Button(frame, text="Mostrar Colisões", command=show_stored_collisions).pack(pady=5)

    window.geometry("900x600")
    window.mainloop()

# ===========================
# Interface de Autenticação
# ===========================

def login():
    """Tela de login para acessar o sistema."""
    def attempt_login():
        username = username_entry.get()
        password = password_entry.get()
        if authenticate_user(username, password):
            log_access(username, "Login bem-sucedido")
            messagebox.showinfo("Bem-vindo", f"Bem-vindo(a), {username}!")
            login_window.destroy()
        else:
            log_access(username, "Tentativa de login falhou")
            messagebox.showerror("Erro", "Credenciais inválidas!")


    login_window = tk.Tk()
    login_window.title("Login")

    tk.Label(login_window, text="Usuário:").pack(padx=10, pady=5)
    username_entry = tk.Entry(login_window, width=30)
    username_entry.pack()

    tk.Label(login_window, text="Senha:").pack(padx=10, pady=5)
    password_entry = tk.Entry(login_window, show="*", width=30)
    password_entry.pack()

    tk.Button(login_window, text="Entrar", command=attempt_login).pack(pady=10)
    tk.Button(login_window, text="Registrar", command=register).pack()

    login_window.mainloop()

def register():
    """Tela de registro de novo usuário."""
    def attempt_register():
        username = username_entry.get()
        password = password_entry.get()
        register_user(username, password)
        register_window.destroy()

    register_window = tk.Tk()
    register_window.title("Registrar Usuário")

    tk.Label(register_window, text="Usuário:").pack(padx=10, pady=5)
    username_entry = tk.Entry(register_window, width=30)
    username_entry.pack()

    tk.Label(register_window, text="Senha:").pack(padx=10, pady=5)
    password_entry = tk.Entry(register_window, show="*", width=30)
    password_entry.pack()

    tk.Button(register_window, text="Registrar", command=attempt_register).pack(pady=10)

    register_window.mainloop()

# ===========================
# Inicialização
# ===========================


if __name__ == "__main__":
    initialize_authentication_db()
    initialize_database()
    login()
    create_main_app()

