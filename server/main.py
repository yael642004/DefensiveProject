import os
import socket
import threading
import uuid
import struct
import zlib

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

PORT_FILE = "port.info"
DEFAULT_PORT = 1369
SERVER_VERSION = 3
HOST = '0.0.0.0'

# In-memory storage for registered clients (RAM)
# Key: Username, Value: Dictionary containing client ID, public key,
# # and AES key
registered_clients = {}


def read_port():
    """
    Reads the server communication port from the 'port.info' file
    located in the working directory.
    If the file does not exist or an error occurs,
    it outputs a warning and returns
    the default port (1369) without crashing the application.
    :return: An integer representing the port number to bind the server to.
    """
    if os.path.exists(PORT_FILE):
        try:
            with open(PORT_FILE, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    return int(content)
        except Exception as e:
            print(f"Error reading the file: {PORT_FILE} {e}")
    else:
        print(f"The file- {PORT_FILE} was not found.")
    return DEFAULT_PORT


def handle_registration(payload: bytes) -> tuple:
    """
    Processes a client registration request (Code 825).
    Extracts the username from the payload, checks if it already exists, 
    and either registers the new client with a unique UUID
    or returns a failure code.
    :param payload: The raw binary payload containing the username.
    :return: A tuple of (response_code, response_payload).
    """
    username = payload.rstrip(b'\x00').decode('utf-8', errors='ignore')
    print(f"Received registration request for user: {username}")

    if username in registered_clients:
        print(f"Error: The username {username} already exists in the system")
        return 1601, b"\x00" * 16
    client_uuid = uuid.uuid4()
    client_uuid_bytes = client_uuid.bytes
    registered_clients[username] = {
        "id": client_uuid_bytes,
        "public_key": None,
        "aes_key": None
    }
    print(f"Registration successful for {username}. A unique ID was created")
    return 1600, client_uuid_bytes


def handle_public_key(payload: bytes) -> tuple:
    """
    Processes the public key exchange request (Code 826).
    Extracts the username and the RSA public key, stores them,
    generates a random AES key,
    encrypts the AES key using the client's public key,
    and returns the encrypted key.
    :param payload: The raw binary payload containing the username
    and public key.
    :return: A tuple of (response_code, response_payload).
    """
    username = payload[:255].rstrip(b'\x00').decode('utf-8', errors='ignore')
    public_key_bytes = payload[255:255+160]

    print(f"Received public key for user: {username}")

    if username not in registered_clients:
        print(f"Error: The username {username} does not exist in the system")
        return 1607, b"\x00" * 16
    client_id = registered_clients[username]["id"]
    registered_clients[username]["public_key"] = public_key_bytes 
    aes_key = get_random_bytes(32)
    registered_clients[username]["aes_key"] = aes_key
    try:
        public_key_object = RSA.import_key(public_key_bytes)
        cipher_rsa = PKCS1_OAEP.new(public_key_object)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
        print(f"AES key successfully generated and encrypted for {username}")
        return 1602, client_id + encrypted_aes_key
    except Exception as ex:
        print(f"Error during the asymmetric encryption process: {ex}")
        return 1607, client_id


def handle_reconnection(payload: bytes) -> tuple:
    """
    Processes a reconnection request for an already
    registered client (Code 827).
    Validates that the user exists and has a saved public key,
    generates a new AES key,
    encrypts it, and returns the encrypted key with code 1605,
    or rejects with 1606.
    :param payload: The raw binary payload containing the username.
    :return: A tuple of (response_code, response_payload).
    """
    username = payload.rstrip(b"\x00").decode('utf-8', errors='ignore')
    print(f"Reconnection request received for user: {username}")

    if username in registered_clients and\
            registered_clients[username]["public_key"]:
        client_id = registered_clients[username]["id"]
        public_key_bytes = registered_clients[username]["public_key"]

        aes_key = get_random_bytes(32)
        registered_clients[username]["aes_key"] = aes_key

        try:
            public_key_object = RSA.import_key(public_key_bytes)
            cipher_rsa = PKCS1_OAEP.new(public_key_object)
            encrypted_aes_key = cipher_rsa.encrypt(aes_key)

            print("Re-authentication approved and encrypted"
                  f"AES key sent for {username}.")
            return 1605, client_id + encrypted_aes_key 
        except Exception as ex:
            print(f"Error encrypting the AES key for reconnection: {ex}")
            return 1607, client_id
    else:
        print(f"Reconnection rejected for {username}")
        client_id = registered_clients.get(username, {}).get("id", b"\x00"*16)
        return 1606, client_id


def handle_file_upload(client_id_bytes: bytes, payload: bytes) -> tuple:
    """
    Processes a file upload request (Code 828).
    Extracts file metadata, decrypts the file content using the client's AES key,
    saves the file locally, calculates its CRC checksum, and returns code 1603.
    """
    try:
        # Content Size (4I), Orig File Size (4I), Packet Number (2H), Total Packets (2H), File Name (255s)
        content_size, orig_file_size, packet_num, total_packets = struct.unpack("<IIHH", payload[:12])
        file_name_bytes = payload[12:12+255]
        file_name = file_name_bytes.rstrip(b'\x00').decode('utf-8', errors='ignore')
        encrypted_content = payload[12+255:]

        print(f"Received packet number {packet_num} out of {total_packets} for the file: {file_name}")
        target_username = None
        aes_key = None
        for uname, data in registered_clients.items():
            if data["id"] == client_id_bytes:
                target_username = uname
                aes_key = data["aes_key"]
                break
        if not target_username or not aes_key:
            print("Error: The client is not identified or does not have an active AES key.")
            return 1607, client_id_bytes
        iv = b'\x00' * 16
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted_content = cipher_aes.decrypt(encrypted_content)
        decrypted_content = decrypted_content[:orig_file_size]

        file_path = os.path.join("received_files", file_name)
        with open(file_path, "wb") as f:
            f.write(decrypted_content)
        print(f"The file {file_name} was successfully decoded and saved.")

        crc_value = zlib.crc32(decrypted_content) & 0xFFFFFFFF

        response_payload = (
            client_id_bytes +
            struct.pack("<I", content_size) +
            file_name_bytes +
            struct.pack("<I", crc_value)
        )
        return 1603, response_payload
    except Exception as ex:
        print(f"Error handling file input: {ex}")
        return 1607, client_id_bytes
    

def handle_client(client_socket: socket.socket, client_address: tuple):
    """
    Handles communication with a single connected client in a dedicated thread.
    Parses incoming request headers and dispatches them
    to appropriate helper functions,
    then constructs the response header containing the server version,
    response code, and payload size.
    :param client_socket: The socket object for the connected client.
    :param client_address: A tuple containing the client's IP address and port.
    """
    print(f"Received a new connection from address: {client_address}")
    try:
        while True:
            header_data = client_socket.recv(23)

            if not header_data or len(header_data) < 23:
                print("Error in request structure")
                break

            client_id_bytes, version, code, payload_size = \
                struct.unpack("<16sBHI", header_data)
            payload = client_socket.recv(payload_size)

            if len(payload) < payload_size:
                print("Error in request structure")
                break

            response_code = 0
            response_payload = b""

            if code == 825:
                response_code, response_payload = handle_registration(payload)
            elif code == 826:
                response_code, response_payload = handle_public_key(payload)
            elif code == 827:
                response_code, response_payload = handle_reconnection(payload)
            elif code == 828:
                esponse_code, response_payload =\
                    handle_file_upload(client_id_bytes, payload)
            else:
                print(f"Warning: Unknown request code: {code}")
                break

            # Response Header:Version (1 byte) + Code (2 bytes)
            # + Payload Size (4 bytes) = 7 bytes
            res_header = struct.pack
            ("<BHI", SERVER_VERSION, response_code, len(response_payload))
            client_socket.sendall(res_header + response_payload)

    except Exception as e:
        print(f"Error handling client {client_address}: {e}")
    finally:
        client_socket.close()


def run_server():
    """
    Initializes the TCP server socket, binds it to the configured port, 
    creates the local directory for received files, and enters an infinite loop 
    accepting incoming client connections,
    spawning a new thread for each client.
    """
    port = read_port()
    os.makedirs("received_files", exist_ok=True)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_socket.bind({HOST, port})
        server_socket.listen(5)
        print(f"The server is active and using version {SERVER_VERSION}."
              "Listening on port {port}...")
        while True:
            client_socket, client_address = server_socket.accept()
            client_thread = threading.Thread(
                target=handle_client, args=(client_socket, client_address))
            client_thread.daemon = True
            client_thread.start()
    except Exception as e:
        print(f"Error starting the server: {e}")
    finally:
        server_socket.close()


if __name__ == "__main__":
    run_server()
