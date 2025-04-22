import socket
import threading
import os
import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
from encryption import Encryptor

class ChatClient:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat")
        self.root.geometry("500x400")
        self.client = None
        self.connected = False
        self.encryption_enabled = False
        self.encryptor = Encryptor()  # Create encryptor with default key
        
        # Login UI
        frame = tk.Frame(root)
        frame.pack(padx=10, pady=10)
        
        tk.Label(frame, text="Username:").grid(row=0, column=0, sticky=tk.W)
        self.username_entry = tk.Entry(frame)
        self.username_entry.grid(row=0, column=1)
        
        tk.Label(frame, text="Password:").grid(row=1, column=0, sticky=tk.W)
        self.password_entry = tk.Entry(frame, show="*")
        self.password_entry.grid(row=1, column=1)
        
        tk.Button(frame, text="Login", command=self.login).grid(row=2, column=0, columnspan=2, pady=5)
        self.status = tk.Label(frame, text="", fg="red")
        self.status.grid(row=3, column=0, columnspan=2)
    
    def login(self):
        try:
            # Connect to server
            self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client.connect(('127.0.0.1', 12345))
            
            # Wait for login prompt
            initial_prompt = self.client.recv(1024).decode('utf-8')
            
            # Send credentials
            username = self.username_entry.get()
            password = self.password_entry.get()
            self.client.send(f"{username}:{password}".encode('utf-8'))
            
            # Check response
            response = self.client.recv(1024).decode('utf-8')
            if "Welcome" in response:
                self.connected = True
                self.username = username
                self.setup_chat_ui()
                
                # Start receiving messages
                threading.Thread(target=self.receive_messages, daemon=True).start()
            else:
                self.status.config(text="Login failed")
        except Exception as e:
            self.status.config(text=f"Error: {str(e)}")
    
    def setup_chat_ui(self):
        # Remove login UI
        for widget in self.root.winfo_children():
            widget.destroy()
        
        # Chat display
        self.chat_display = scrolledtext.ScrolledText(self.root, state=tk.DISABLED)
        self.chat_display.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Message controls
        controls = tk.Frame(self.root)
        controls.pack(fill=tk.X, padx=10, pady=5)
        
        # Message type
        self.msg_type = tk.StringVar(value="broadcast")
        tk.Radiobutton(controls, text="Broadcast", variable=self.msg_type, value="broadcast").pack(side=tk.LEFT)
        tk.Radiobutton(controls, text="Unicast", variable=self.msg_type, value="unicast").pack(side=tk.LEFT)
        tk.Radiobutton(controls, text="Multicast", variable=self.msg_type, value="multicast").pack(side=tk.LEFT)
        
        # Encryption indicator
        self.encryption_label = tk.Label(controls, text="🔒 Encrypted", fg="green")
        self.encryption_label.pack(side=tk.RIGHT)
        
        # Recipient
        tk.Label(controls, text="To:").pack(side=tk.LEFT)
        self.recipient = tk.Entry(controls, width=10)
        self.recipient.pack(side=tk.LEFT)
        
        # Message input
        input_frame = tk.Frame(self.root)
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.message = tk.Entry(input_frame)
        self.message.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.message.bind("<Return>", lambda e: self.send_message())
        
        tk.Button(input_frame, text="Send", command=self.send_message).pack(side=tk.LEFT, padx=2)
        tk.Button(input_frame, text="File", command=self.send_file).pack(side=tk.LEFT)
        
        # Show welcome
        self.update_chat("--- Secure Chat Started ---")
        self.update_chat("Messages are encrypted end-to-end 🔒")
    
    def receive_messages(self):
        while self.connected:
            try:
                message = self.client.recv(1024).decode('utf-8')
                if not message:
                    break
                
                # Check for encryption enabled notification
                if "ENCRYPTION_ENABLED" in message:
                    self.encryption_enabled = True
                    continue
                
                # Check if message is encrypted
                if message.startswith("ENC:"):
                    # Remove the ENC: prefix and decrypt
                    encrypted_part = message[4:].strip()
                    message = self.encryptor.decrypt(encrypted_part)
                
                if message.startswith("FILE_INCOMING"):
                    # Handle file reception
                    parts = message.split("|")
                    sender, filename, filesize = parts[1], parts[2], int(parts[3])
                    
                    save_path = filedialog.asksaveasfilename(initialfile=f"received_{filename}")
                    if save_path:
                        # Receive file
                        with open(save_path, "wb") as f:
                            bytes_read = 0
                            while bytes_read < filesize:
                                data = self.client.recv(min(1024, filesize - bytes_read))
                                if not data:
                                    break
                                f.write(data)
                                bytes_read += len(data)
                        self.update_chat(f"Received file from {sender}: {filename}")
                    else:
                        # Skip file if canceled
                        bytes_read = 0
                        while bytes_read < filesize:
                            data = self.client.recv(min(1024, filesize - bytes_read))
                            bytes_read += len(data)
                else:
                    self.update_chat(message)
            except Exception as e:
                if self.connected:
                    self.connected = False
                    self.update_chat(f"Connection error: {str(e)}")
                break
    
    def send_message(self):
        if not self.connected:
            return
        
        message = self.message.get().strip()
        if not message:
            return
        
        try:
            msg_type = self.msg_type.get()
            
            # Prepare the message based on type
            if msg_type == "broadcast":
                send_msg = message
            else:
                recipient = self.recipient.get().strip()
                if not recipient:
                    messagebox.showerror("Error", "Enter recipient(s)")
                    return
                
                send_msg = f"@{recipient} {message}"
            
            # Encrypt the message if encryption is enabled
            if self.encryption_enabled:
                send_msg = f"ENC:{self.encryptor.encrypt(send_msg)}"
            
            self.client.send(send_msg.encode('utf-8'))
            self.message.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send message: {str(e)}")
    
    def send_file(self):
        if not self.connected:
            return
        
        recipient = self.recipient.get().strip()
        if not recipient or "," in recipient:
            messagebox.showerror("Error", "Specify a single recipient")
            return
        
        filepath = filedialog.askopenfilename()
        if not filepath:
            return
        
        try:
            filename = os.path.basename(filepath)
            filesize = os.path.getsize(filepath)
            
            # Send metadata
            self.client.send(f"FILE_SEND|{recipient}|{filename}|{filesize}".encode('utf-8'))
            
            # Send file
            with open(filepath, "rb") as f:
                while True:
                    data = f.read(1024)
                    if not data:
                        break
                    self.client.sendall(data)
            
            self.update_chat(f"File '{filename}' sent to {recipient}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send file: {str(e)}")
    
    def update_chat(self, message):
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.insert(tk.END, message + "\n")
        self.chat_display.see(tk.END)
        self.chat_display.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatClient(root)
    root.mainloop()
