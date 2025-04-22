import socket
import threading
import os
from encryption import Encryptor

# -----------------------
# Client Configuration
# -----------------------
HOST = '127.0.0.1'  # Server IP
PORT = 12345        # Port must match server

# -----------------------
# Connect to the server
# -----------------------
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))

# -----------------------
# Encryption
# -----------------------
encryptor = Encryptor()  # Create encryptor with default key
encryption_enabled = False

# -----------------------
# Receive messages and files
# -----------------------
def receive_messages():
    global encryption_enabled
    while True:
        try:
            message = client.recv(1024).decode('utf-8')
            
            # Check for encryption enabled notification
            if "ENCRYPTION_ENABLED" in message:
                encryption_enabled = True
                print("🔒 Secure messaging enabled - messages are encrypted")
                continue
            
            # Check if message is encrypted
            if message.startswith("ENC:"):
                # Remove the ENC: prefix and decrypt
                encrypted_part = message[4:].strip()
                message = encryptor.decrypt(encrypted_part)
            
            if message.startswith("FILE_INCOMING"):
                # Parse incoming file info
                parts = message.split("|")
                sender = parts[1]
                filename = parts[2]
                filesize = int(parts[3])

                # Receive file content
                with open("received_" + filename, "wb") as f:
                    bytes_read = 0
                    while bytes_read < filesize:
                        data = client.recv(min(1024, filesize - bytes_read))
                        if not data:
                            break
                        f.write(data)
                        bytes_read += len(data)

                print(f"[{sender}] sent you a file: {filename} (saved as received_{filename})")
            else:
                print(message)
        except:
            print("Error receiving message.")
            break

# -----------------------
# Send login and chat messages
# -----------------------
def send_messages():
    global encryption_enabled
    # Login process
    while True:
        print("Login with username:password")
        credentials = input("Enter login (username:password): ")
        client.send(credentials.encode('utf-8'))

        response = client.recv(1024).decode('utf-8')
        messages = response.strip().split("\n")
        welcome_received = False

        for msg in messages:
            print(msg.strip())
            if "Welcome" in msg:
                welcome_received = True

        if welcome_received:
            break

    # Chat interface instructions
    print("\n--- Secure Chat Started ---")
    print("Use:\n"
          "  @user Hello             → Unicast\n"
          "  @user1,user2 Hi there   → Multicast\n"
          "  Hello everyone!         → Broadcast\n"
          "  @file user file.txt     → Send file\n")
    print("🔒 Messages are encrypted end-to-end")

    # Chat loop
    while True:
        message = input()
        if message.startswith("@file"):
            try:
                parts = message.split(" ", 2)
                if len(parts) != 3:
                    print("Invalid file command. Use: @file username path_to_file")
                    continue

                _, target_user, filepath = parts
                if not os.path.exists(filepath):
                    print("File does not exist.")
                    continue

                filename = os.path.basename(filepath)
                filesize = os.path.getsize(filepath)

                # Send metadata
                header = f"FILE_SEND|{target_user}|{filename}|{filesize}"
                client.send(header.encode('utf-8'))

                # Send file content
                with open(filepath, "rb") as f:
                    while True:
                        data = f.read(1024)
                        if not data:
                            break
                        client.sendall(data)

                print(f"File '{filename}' sent to {target_user}.")
            except Exception as e:
                print(f"Failed to send file: {e}")
        else:
            # Encrypt the message if encryption is enabled
            if encryption_enabled:
                message = f"ENC:{encryptor.encrypt(message)}"
            client.send(message.encode('utf-8'))

# -----------------------
# Start threads for sending and receiving
# -----------------------
if __name__ == "__main__":
    receive_thread = threading.Thread(target=receive_messages)
    receive_thread.daemon = True
    receive_thread.start()

    send_thread = threading.Thread(target=send_messages)
    send_thread.daemon = True
    send_thread.start()
    
    # Keep the main thread running
    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("Exiting...")
