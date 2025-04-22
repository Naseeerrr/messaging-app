import socket
import threading
from encryption import Encryptor

# -----------------------
# Server Configuration
# -----------------------
HOST = '0.0.0.0'  # Accept connections from any machine
PORT = 12345      # Server port

# -----------------------
# Create and set up server socket
# -----------------------
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(5)
print(f"Server started on {HOST}:{PORT}")

# -----------------------
# Data Structures
# -----------------------
clients = {}  # {username: socket}
users = {"user1": "pass1", "user2": "pass2", "user3": "pass3"}  # Hardcoded credentials
CHAT_LOG_FILE = "chat_history.txt"

# -----------------------
# Encryption
# -----------------------
encryptor = Encryptor()  # Create encryptor with default key

# -----------------------
# Log chat messages
# -----------------------
def log_message(message):
    with open(CHAT_LOG_FILE, "a") as log_file:
        log_file.write(message + "\n")

# -----------------------
# Handle user authentication
# -----------------------
def authenticate(client_socket):
    client_socket.send("Login with username:password\n".encode('utf-8'))
    while True:
        credentials = client_socket.recv(1024).decode('utf-8').strip()
        if credentials and ":" in credentials:
            username, password = credentials.split(":", 1)
            if username in users and users[username] == password:
                client_socket.send(f"Welcome {username}!\n".encode('utf-8'))
                return username
        client_socket.send("Invalid credentials. Try again.\n".encode('utf-8'))

# -----------------------
# Handle file transfer
# -----------------------
def handle_file_transfer(sender, header, client_socket):
    try:
        _, target_user, filename, filesize = header.split("|")
        filesize = int(filesize)

        if target_user not in clients:
            client_socket.send(f"{target_user} is not online. File not delivered.\n".encode('utf-8'))
            return

        # Receive the file content
        file_data = b''
        while len(file_data) < filesize:
            chunk = client_socket.recv(min(1024, filesize - len(file_data)))
            if not chunk:
                break
            file_data += chunk

        # Notify recipient and forward file
        clients[target_user].send(f"FILE_INCOMING|{sender}|{filename}|{filesize}".encode('utf-8'))
        clients[target_user].sendall(file_data)

        client_socket.send(f"File '{filename}' sent to {target_user}.\n".encode('utf-8'))
        log_message(f"{sender} sent file '{filename}' to {target_user}")
    except Exception as e:
        print(f"File transfer error: {e}")
        client_socket.send("Error during file transfer.\n".encode('utf-8'))

# -----------------------
# Handle client communication
# -----------------------
def handle_client(client_socket):
    username = authenticate(client_socket)
    clients[username] = client_socket
    try:
        # Send encryption notification
        client_socket.send("ENCRYPTION_ENABLED\n".encode('utf-8'))
        
        while True:
            data = client_socket.recv(1024)
            if not data:
                break

            try:
                message = data.decode('utf-8').strip()
                original_message = message  # Store the original message for logging
                
                # Check if message is encrypted (starts with ENC:)
                if message.startswith("ENC:"):
                    # Remove the ENC: prefix and decrypt
                    encrypted_part = message[4:]
                    message = encryptor.decrypt(encrypted_part)
                
            except:
                continue

            # Handle incoming file
            if message.startswith("FILE_SEND|"):
                handle_file_transfer(username, message, client_socket)
                continue

            # Unicast or Multicast
            if message.startswith("@"):
                if " " in message:
                    parts = message.split(" ", 1)
                    target_info = parts[0][1:]
                    msg_body = parts[1]
                    targets = target_info.split(",")
                    
                    # Log the message before sending
                    log_message(f"{username} (to {target_info}): {msg_body}")
                    
                    for target in targets:
                        if target in clients:
                            # Encrypt the message before sending
                            encrypted_msg = f"ENC:{encryptor.encrypt(f'{username} (private): {msg_body}')}"
                            clients[target].send(f"{encrypted_msg}\n".encode('utf-8'))
                        else:
                            client_socket.send(f"User '{target}' is not online.\n".encode('utf-8'))
                else:
                    client_socket.send("Invalid message format. Use: @user message\n".encode('utf-8'))
            else:
                # Log broadcast message
                log_message(f"{username}: {message}")
                
                # Broadcast to all other users
                for user, sock in clients.items():
                    if user != username:
                        # Encrypt the message before sending
                        encrypted_msg = f"ENC:{encryptor.encrypt(f'{username}: {message}')}"
                        sock.send(f"{encrypted_msg}\n".encode('utf-8'))

    except Exception as e:
        print(f"Error handling client {username}: {e}")
    finally:
        client_socket.close()
        if username in clients:
            del clients[username]
        print(f"{username} has disconnected.")

# -----------------------
# Main server loop
# -----------------------
while True:
    client_socket, addr = server.accept()
    print(f"Connection from {addr}")
    thread = threading.Thread(target=handle_client, args=(client_socket,))
    thread.start()
