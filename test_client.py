import socket
import struct
import time
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

PORT = 1234
HOST = '127.0.0.1'
VERSION = 3

# POSIX cksum CRC table
CRC_TABLE = [
    0x00000000, 0x04c11db7, 0x09823b6e, 0x0d4326d9, 0x130476dc,
    0x17c56b6b, 0x1a864db2, 0x1e475005, 0x2608edb8, 0x22c9f00f,
    0x2f8ad6d6, 0x2b4bcb61, 0x350c9b64, 0x31cd86d3, 0x3c8ea00a,
    0x384fbdbd, 0x4c11db70, 0x48d0c6c7, 0x4593e01e, 0x4152fda9,
    0x5f15adac, 0x5bd4b01b, 0x569796c2, 0x52568b75, 0x6a1936c8,
    0x6ed82b7f, 0x639b0da6, 0x675a1011, 0x791d4014, 0x7ddc5da3,
    0x709f7b7a, 0x745e66cd, 0x9823b6e0, 0x9ce2ab57, 0x91a18d8e,
    0x95609039, 0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5,
    0xbe2b5b58, 0xbaea46ef, 0xb7a96036, 0xb3687d81, 0xad2f2d84,
    0xa9ee3033, 0xa4ad16ea, 0xa06c0b5d, 0xd4326d90, 0xd0f37027,
    0xdcb056fe, 0xd8714b49, 0xc6361b4c, 0xc2f706fb, 0xcf342022,
    0xcbf53d95, 0xf3ba8028, 0xf77b9d9f, 0xfa38bb46, 0xfef9a6f1,
    0xe0bef6f4, 0xe47feb43, 0xe93ccd9a, 0xede3d02d
]


def calculate_posix_cksum(data: bytes) -> int:
    crc = 0
    for byte in data:
        tbl_idx = ((crc >> 24) ^ byte) & 0xFF
        crc = ((crc << 8) & 0xFFFFFFFF) ^ (
            CRC_TABLE[tbl_idx % len(CRC_TABLE)]
            if tbl_idx < len(CRC_TABLE) else 0
        )

    length = len(data)
    length_bytes = bytearray()
    temp_len = length
    while temp_len > 0:
        length_bytes.append(temp_len & 0xFF)
        temp_len >>= 8
    if not length_bytes:
        length_bytes.append(0)

    for byte in length_bytes:
        tbl_idx = ((crc >> 24) ^ byte) & 0xFF
        crc = ((crc << 8) & 0xFFFFFFFF) ^ (
            CRC_TABLE[tbl_idx % len(CRC_TABLE)]
            if tbl_idx < len(CRC_TABLE) else 0
        )

    return ~crc & 0xFFFFFFFF


def run_client_with_retries():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((HOST, PORT))
        print("Connected to server.")

        # --- שלב 1: רישום (825) ---
        client_id = b"\x00" * 16
        unique_suffix = str(int(time.time()))[-4:]
        username_str = f"user{unique_suffix}"
        username = username_str.encode('utf-8') + b"\x00" * (
            255 - len(username_str)
        )

        reg_header = struct.pack(
            "<16sBHI", client_id, VERSION, 825, len(username)
        )
        client_socket.sendall(reg_header + username)
        response = client_socket.recv(1024)
        if len(response) >= 23:
            client_id = response[7:23]
            print("Registration successful.")

        # --- שלב 2: החלפת מפתחות (826) ---
        rsa_key = RSA.generate(1024)
        public_key_der = rsa_key.publickey().export_key(format='DER')
        pubkey_payload = username + public_key_der

        pub_header = struct.pack(
            "<16sBHI", client_id, VERSION, 826, len(pubkey_payload)
        )
        client_socket.sendall(pub_header + pubkey_payload)
        response_pub = client_socket.recv(1024)

        encrypted_aes_key = response_pub[23:]
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        aes_key = cipher_rsa.decrypt(encrypted_aes_key)
        print("AES key decrypted.")

        # --- שלב 3: העלאת קובץ ולולאת בדיקת CRC ---
        file_data = b"Hello, test file content for retry mechanism!"
        orig_file_size = len(file_data)
        client_cksum = calculate_posix_cksum(file_data)

        file_name_str = "test_file.txt"
        file_name_bytes = file_name_str.encode('utf-8') + b"\x00" * (
            255 - len(file_name_str)
        )

        MAX_RETRIES = 3
        success = False

        for attempt in range(1, MAX_RETRIES + 2):
            print(f"\n--- Upload Attempt {attempt} ---")

            padding_len = 16 - (len(file_data) % 16)
            padded_file_data = file_data + b"\x00" * padding_len
            content_size = len(padded_file_data)

            iv = b'\x00' * 16
            cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
            encrypted_content = cipher_aes.encrypt(padded_file_data)

            upload_payload = (
                struct.pack(
                    "<IIHH", content_size, orig_file_size, 1, 1
                ) +
                file_name_bytes +
                encrypted_content
            )

            upload_header = struct.pack(
                "<16sBHI", client_id, VERSION, 828, len(upload_payload)
            )
            client_socket.sendall(upload_header + upload_payload)
            response_upload = client_socket.recv(1024)

            server_cksum = struct.unpack("<I", response_upload[-4:])[0]
            print(
                f"Client cksum: {client_cksum}, "
                f"Server returned cksum: {server_cksum}"
            )

            if client_cksum == server_cksum:
                print("CRC match! Sending validation confirmation (900).")
                crc_header = struct.pack(
                    "<16sBHI", client_id, VERSION, 900,
                    len(file_name_bytes)
                )
                client_socket.sendall(crc_header + file_name_bytes)
                client_socket.recv(1024)
                success = True
                break
            else:
                if attempt <= MAX_RETRIES:
                    print(
                        f"CRC mismatch. Sending retry notification (901) "
                        f"- Attempt {attempt}"
                    )
                    retry_header = struct.pack(
                        "<16sBHI", client_id, VERSION, 901,
                        len(file_name_bytes)
                    )
                    client_socket.sendall(retry_header + file_name_bytes)
                else:
                    print(
                        "Max retries reached. Sending final abort report "
                        "(902)."
                    )
                    abort_header = struct.pack(
                        "<16sBHI", client_id, VERSION, 902,
                        len(file_name_bytes)
                    )
                    client_socket.sendall(abort_header + file_name_bytes)
                    client_socket.recv(1024)

        if success:
            print("\nFile transfer and validation completed successfully!")
        else:
            print("\nFile transfer failed after maximum retries.")


if __name__ == "__main__":
    run_client_with_retries()