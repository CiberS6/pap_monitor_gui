import sqlite3
from cryptography.fernet import Fernet

# Carregar a chave de criptografia
def load_key():
    with open("encryption_key.key", "rb") as key_file:
        return key_file.read()

key = load_key()
cipher_suite = Fernet(key)

# Função para descriptografar dados
def decrypt_data(encrypted_data):
    try:
        return cipher_suite.decrypt(encrypted_data.encode()).decode()
    except Exception as e:
        return f"Erro ao descriptografar: {e}"

# Conectar ao banco e exibir dados descriptografados
def view_decrypted_devices():
    connection = sqlite3.connect("network_devices.db")
    cursor = connection.cursor()

    # Recuperar os dados criptografados
    cursor.execute("SELECT ip, mac, hostname, last_seen FROM devices")
    devices = cursor.fetchall()
    connection.close()

    # Descriptografar os dados e exibir
    print("Dados dos Dispositivos (Descriptografados):")
    print(f"{'IP':<20} {'MAC':<20} {'Hostname':<30} {'Última Vez Visto'}")
    print("-" * 80)
    for device in devices:
        ip = decrypt_data(device[0])
        mac = decrypt_data(device[1])
        hostname = decrypt_data(device[2])
        last_seen = device[3]
        print(f"{ip:<20} {mac:<20} {hostname:<30} {last_seen}")

# Executar a função
view_decrypted_devices()
