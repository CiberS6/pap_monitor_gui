import sqlite3
from cryptography.fernet import Fernet

# Carregar a chave de criptografia
def load_key():
    with open("encryption_key.key", "rb") as key_file:
        return key_file.read()

key = load_key()
cipher_suite = Fernet(key)

# Conectar ao banco de dados e migrar os dados
def encrypt_existing_data():
    connection = sqlite3.connect("network_devices.db")
    cursor = connection.cursor()

    # Buscar dados não criptografados
    cursor.execute("SELECT id, ip, mac, hostname FROM devices")
    devices = cursor.fetchall()

    for device in devices:
        device_id, ip, mac, hostname = device

        # Verificar se já está criptografado (ignorar se já for criptografia válida)
        try:
            cipher_suite.decrypt(ip.encode())
            continue  # Já está criptografado
        except:
            pass  # Não está criptografado

        # Criptografar dados
        encrypted_ip = cipher_suite.encrypt(ip.encode()).decode()
        encrypted_mac = cipher_suite.encrypt(mac.encode()).decode()
        encrypted_hostname = cipher_suite.encrypt(hostname.encode()).decode()

        # Atualizar o banco com os dados criptografados
        cursor.execute("""
            UPDATE devices
            SET ip = ?, mac = ?, hostname = ?
            WHERE id = ?
        """, (encrypted_ip, encrypted_mac, encrypted_hostname, device_id))

    connection.commit()
    connection.close()

encrypt_existing_data()
print("Migração concluída: dados criptografados.")
