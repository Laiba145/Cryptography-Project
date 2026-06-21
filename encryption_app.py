import os
import json
import hashlib
import base64
import random
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

USERS_FILE = "users.json"

# --- Crypto Utility Functions ---

def rotate_left(val, r_bits, max_bits=64):
    return ((val << r_bits) & ((1 << max_bits) - 1)) | (val >> (max_bits - r_bits))

def rotate_right(val, r_bits, max_bits=64):
    return (val >> r_bits) | ((val << (max_bits - r_bits)) & ((1 << max_bits) - 1))

def key_schedule(key):
    # Simplified key schedule placeholder (returns list of subkeys)
    subkeys = []
    for i in range(16):
        subkeys.append(rotate_left(key, i))
    return subkeys

def encrypt(plaintext_bytes, key_int):
    subkeys = key_schedule(key_int)
    block_size = 8  # 64 bits = 8 bytes
    padded = plaintext_bytes
    # Padding to multiple of 8 bytes with PKCS7
    pad_len = block_size - (len(padded) % block_size)
    padded += bytes([pad_len]) * pad_len

    ciphertext = b""
    for i in range(0, len(padded), block_size):
        block = int.from_bytes(padded[i:i+block_size], 'big')
        for k in subkeys:
            block = rotate_left(block ^ k, 3)
        ciphertext += block.to_bytes(block_size, 'big')
    return ciphertext

def decrypt(ciphertext_bytes, key_int):
    subkeys = key_schedule(key_int)
    block_size = 8
    plaintext = b""
    for i in range(0, len(ciphertext_bytes), block_size):
        block = int.from_bytes(ciphertext_bytes[i:i+block_size], 'big')
        for k in reversed(subkeys):
            block = rotate_right(block, 3) ^ k
        plaintext += block.to_bytes(block_size, 'big')
    # Remove padding
    pad_len = plaintext[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding")
    return plaintext[:-pad_len]

# --- RSA Digital Signature Functions ---

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key

def sign_message(private_key, message_bytes):
    h = SHA256.new(message_bytes)
    signature = pkcs1_15.new(private_key).sign(h)
    return signature

def verify_signature(public_key, message_bytes, signature):
    h = SHA256.new(message_bytes)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# --- User Database and Password Hashing with JSON Persistence ---

class UserDB:
    def __init__(self, filename=USERS_FILE):
        self.filename = filename
        self.users = {}  # username -> (salt_bytes, hashed_password_bytes)
        self.load_users()

    def load_users(self):
        if os.path.exists(self.filename):
            try:
                with open(self.filename, "r") as f:
                    data = json.load(f)
                    # Convert base64 strings back to bytes
                    for user, creds in data.items():
                        salt = base64.b64decode(creds['salt'])
                        hashed = base64.b64decode(creds['hash'])
                        self.users[user] = (salt, hashed)
            except Exception as e:
                print(f"Error loading users file: {e}")
                self.users = {}
        else:
            self.users = {}

    def save_users(self):
        # Convert bytes to base64 strings for JSON
        data = {}
        for user, (salt, hashed) in self.users.items():
            data[user] = {
                'salt': base64.b64encode(salt).decode('utf-8'),
                'hash': base64.b64encode(hashed).decode('utf-8')
            }
        try:
            with open(self.filename, "w") as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            print(f"Error saving users file: {e}")

    def add_user(self, username, password):
        if username in self.users:
            return False
        salt = os.urandom(16)
        hashed = self.hash_password(password, salt)
        self.users[username] = (salt, hashed)
        self.save_users()
        return True

    def verify_user(self, username, password):
        if username not in self.users:
            return False
        salt, stored_hash = self.users[username]
        return self.hash_password(password, salt) == stored_hash

    @staticmethod
    def hash_password(password, salt):
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

# --- Main Application ---

class CryptoApp:
    def __init__(self, master):
        self.master = master
        master.title("Custom Block Cipher + RSA Signature")
        master.geometry("700x650")
        master.resizable(False, False)

        self.user_db = UserDB()
        self.rsa_priv, self.rsa_pub = generate_rsa_keys()
        self.logged_in_user = None
        self.key_int = None
        self.dark_mode = False

        self.create_widgets()
        self.apply_theme()

    def create_widgets(self):
        font_label = ("Segoe UI", 11)
        font_entry = ("Segoe UI", 11)
        font_button = ("Segoe UI", 10, "bold")

        # Login Frame
        self.login_frame = tk.Frame(self.master)
        self.login_frame.pack(padx=15, pady=15)

        tk.Label(self.login_frame, text="Username:", font=font_label).grid(row=0, column=0, sticky="e", pady=5)
        tk.Label(self.login_frame, text="Password:", font=font_label).grid(row=1, column=0, sticky="e", pady=5)

        self.username_entry = tk.Entry(self.login_frame, font=font_entry)
        self.password_entry = tk.Entry(self.login_frame, font=font_entry, show="*")
        self.username_entry.grid(row=0, column=1, padx=10, pady=5)
        self.password_entry.grid(row=1, column=1, padx=10, pady=5)

        self.login_button = tk.Button(self.login_frame, text="Login", font=font_button, width=12, command=self.login)
        self.register_button = tk.Button(self.login_frame, text="Register", font=font_button, width=12, command=self.register)
        self.login_button.grid(row=2, column=0, pady=10)
        self.register_button.grid(row=2, column=1, pady=10)

        # Encryption Frame (hidden until login)
        self.enc_frame = tk.Frame(self.master)

        self.text_label = tk.Label(self.enc_frame, text="Enter text or load file:", font=font_label)
        self.text_label.pack(anchor="w", pady=(0,5))

        self.text_area = scrolledtext.ScrolledText(self.enc_frame, height=15, width=80, font=font_entry, wrap=tk.WORD)
        self.text_area.pack(pady=(0,10))

        btn_frame1 = tk.Frame(self.enc_frame)
        btn_frame1.pack(pady=5)

        self.load_file_button = tk.Button(btn_frame1, text="Load File", font=font_button, width=18, command=self.load_file)
        self.save_enc_button = tk.Button(btn_frame1, text="Encrypt and Save File", font=font_button, width=18, command=self.encrypt_and_save)
        self.load_enc_button = tk.Button(btn_frame1, text="Load Encrypted File and Decrypt", font=font_button, width=22, command=self.load_and_decrypt)

        self.load_file_button.grid(row=0, column=0, padx=7)
        self.save_enc_button.grid(row=0, column=1, padx=7)
        self.load_enc_button.grid(row=0, column=2, padx=7)

        # Key Management
        self.key_frame = tk.LabelFrame(self.enc_frame, text="Key Management", font=font_label, padx=10, pady=10)
        self.key_frame.pack(pady=10, fill="x")

        self.gen_key_button = tk.Button(self.key_frame, text="Generate New Key", font=font_button, width=20, command=self.generate_key)
        self.save_key_button = tk.Button(self.key_frame, text="Save Key to File", font=font_button, width=20, command=self.save_key_to_file)
        self.load_key_button = tk.Button(self.key_frame, text="Load Key from File", font=font_button, width=20, command=self.load_key_from_file)

        self.gen_key_button.grid(row=0, column=0, padx=5, pady=5)
        self.save_key_button.grid(row=0, column=1, padx=5, pady=5)
        self.load_key_button.grid(row=0, column=2, padx=5, pady=5)

        # RSA Signature Frame
        self.sig_frame = tk.LabelFrame(self.enc_frame, text="RSA Digital Signature", font=font_label, padx=10, pady=10)
        self.sig_frame.pack(pady=10, fill="x")

        self.sign_button = tk.Button(self.sig_frame, text="Sign Text", font=font_button, width=20, command=self.sign_text)
        self.verify_button = tk.Button(self.sig_frame, text="Verify Signature", font=font_button, width=20, command=self.verify_text_signature)
        self.show_pub_button = tk.Button(self.sig_frame, text="Show Public Key", font=font_button, width=20, command=self.show_public_key)

        self.sign_button.grid(row=0, column=0, padx=5, pady=5)
        self.verify_button.grid(row=0, column=1, padx=5, pady=5)
        self.show_pub_button.grid(row=0, column=2, padx=5, pady=5)

        # Signature display
        self.signature_text = tk.Text(self.sig_frame, height=4, width=85, font=("Consolas", 10), wrap=tk.NONE)
        self.signature_text.grid(row=1, column=0, columnspan=3, pady=5)
        self.signature_text.configure(state='disabled')

        # Logout and Theme toggle buttons
        btn_frame2 = tk.Frame(self.enc_frame)
        btn_frame2.pack(pady=10, fill="x")
        self.logout_button = tk.Button(btn_frame2, text="Logout", font=font_button, width=12, command=self.logout)
        self.theme_button = tk.Button(btn_frame2, text="Toggle Dark Mode", font=font_button, width=15, command=self.toggle_theme)

        self.logout_button.pack(side="left", padx=10)
        self.theme_button.pack(side="right", padx=10)

    def apply_theme(self):
        if self.dark_mode:
            bg_color = "#2E2E2E"
            fg_color = "#F5F5F5"
            entry_bg = "#3E3E3E"
            button_bg = "#4E4E4E"
            button_fg = "#E0E0E0"
        else:
            bg_color = "#F0F0F0"
            fg_color = "#000000"
            entry_bg = "#FFFFFF"
            button_bg = "#E0E0E0"
            button_fg = "#000000"

        self.master.configure(bg=bg_color)
        self.login_frame.configure(bg=bg_color)
        self.enc_frame.configure(bg=bg_color)

        # Login widgets
        for widget in self.login_frame.winfo_children():
            if isinstance(widget, tk.Label):
                widget.configure(bg=bg_color, fg=fg_color)
            elif isinstance(widget, tk.Entry):
                widget.configure(bg=entry_bg, fg=fg_color, insertbackground=fg_color)
            elif isinstance(widget, tk.Button):
                widget.configure(bg=button_bg, fg=button_fg, activebackground=button_bg)

        # Encryption frame widgets
        for widget in self.enc_frame.winfo_children():
            if isinstance(widget, (tk.Label, tk.LabelFrame)):
                widget.configure(bg=bg_color, fg=fg_color)
            elif isinstance(widget, tk.Frame):
                widget.configure(bg=bg_color)
                for child in widget.winfo_children():
                    if isinstance(child, tk.Button):
                        child.configure(bg=button_bg, fg=button_fg, activebackground=button_bg)
            elif isinstance(widget, scrolledtext.ScrolledText) or isinstance(widget, tk.Text):
                widget.configure(bg=entry_bg, fg=fg_color, insertbackground=fg_color)

        # Key and Signature frames children
        for frame in [self.key_frame, self.sig_frame]:
            for child in frame.winfo_children():
                if isinstance(child, tk.Button):
                    child.configure(bg=button_bg, fg=button_fg, activebackground=button_bg)
                elif isinstance(child, tk.Text):
                    child.configure(bg=entry_bg, fg=fg_color, insertbackground=fg_color)

    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        self.apply_theme()

    # --- Login/Register ---

    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        if not username or not password:
            messagebox.showwarning("Input Error", "Please enter username and password.")
            return
        if self.user_db.verify_user(username, password):
            self.logged_in_user = username
            messagebox.showinfo("Login Successful", f"Welcome, {username}!")
            self.login_frame.pack_forget()
            self.enc_frame.pack(padx=15, pady=15)
        else:
            messagebox.showerror("Login Failed", "Invalid username or password.")

    def register(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        if not username or not password:
            messagebox.showwarning("Input Error", "Please enter username and password.")
            return
        if self.user_db.add_user(username, password):
            messagebox.showinfo("Registration Successful", "User registered! Please login now.")
        else:
            messagebox.showerror("Registration Failed", "Username already exists.")

    def logout(self):
        self.logged_in_user = None
        self.key_int = None
        self.text_area.delete("1.0", tk.END)
        self.signature_text.configure(state='normal')
        self.signature_text.delete("1.0", tk.END)
        self.signature_text.configure(state='disabled')
        self.enc_frame.pack_forget()
        self.login_frame.pack(padx=15, pady=15)

    # --- File operations ---

    def load_file(self):
        filename = filedialog.askopenfilename(title="Select text file to load",
                                              filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if filename:
            try:
                with open(filename, "r", encoding='utf-8') as f:
                    text = f.read()
                self.text_area.delete("1.0", tk.END)
                self.text_area.insert(tk.END, text)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file:\n{e}")

    def encrypt_and_save(self):
        if self.key_int is None:
            messagebox.showwarning("Key Missing", "Please generate or load a key first.")
            return
        plaintext = self.text_area.get("1.0", tk.END).rstrip('\n')
        if not plaintext:
            messagebox.showwarning("Input Missing", "Please enter or load text to encrypt.")
            return

        try:
            ciphertext = encrypt(plaintext.encode('utf-8'), self.key_int)
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))
            return

        filename = filedialog.asksaveasfilename(title="Save Encrypted File",
                                                defaultextension=".bin",
                                                filetypes=[("Binary Files", "*.bin"), ("All Files", "*.*")])
        if filename:
            try:
                with open(filename, "wb") as f:
                    f.write(ciphertext)
                messagebox.showinfo("Success", "File encrypted and saved.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file:\n{e}")

    def load_and_decrypt(self):
        if self.key_int is None:
            messagebox.showwarning("Key Missing", "Please generate or load a key first.")
            return
        filename = filedialog.askopenfilename(title="Select encrypted file",
                                              filetypes=[("Binary Files", "*.bin"), ("All Files", "*.*")])
        if filename:
            try:
                with open(filename, "rb") as f:
                    ciphertext = f.read()
                plaintext_bytes = decrypt(ciphertext, self.key_int)
                plaintext = plaintext_bytes.decode('utf-8')
                self.text_area.delete("1.0", tk.END)
                self.text_area.insert(tk.END, plaintext)
                messagebox.showinfo("Success", "File decrypted and loaded.")
            except Exception as e:
                messagebox.showerror("Decryption Error", f"Failed to decrypt or load file:\n{e}")

    # --- Key Management ---

    def generate_key(self):
        # Generate random 64-bit integer key
        self.key_int = random.getrandbits(64)
        messagebox.showinfo("Key Generated", f"New key generated:\n{self.key_int:#018x}")

    def save_key_to_file(self):
        if self.key_int is None:
            messagebox.showwarning("Key Missing", "No key to save. Generate or load a key first.")
            return
        filename = filedialog.asksaveasfilename(title="Save Key File",
                                                defaultextension=".key",
                                                filetypes=[("Key Files", "*.key"), ("All Files", "*.*")])
        if filename:
            try:
                with open(filename, "w") as f:
                    f.write(f"{self.key_int}\n")
                messagebox.showinfo("Success", "Key saved successfully.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save key:\n{e}")

    def load_key_from_file(self):
        filename = filedialog.askopenfilename(title="Select Key File",
                                              filetypes=[("Key Files", "*.key"), ("All Files", "*.*")])
        if filename:
            try:
                with open(filename, "r") as f:
                    line = f.readline().strip()
                    key = int(line)
                    self.key_int = key
                messagebox.showinfo("Success", "Key loaded successfully.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load key:\n{e}")

    # --- RSA Signature ---

    def sign_text(self):
        text = self.text_area.get("1.0", tk.END).rstrip('\n')
        if not text:
            messagebox.showwarning("Input Missing", "Please enter or load text to sign.")
            return
        signature = sign_message(self.rsa_priv, text.encode('utf-8'))
        sig_b64 = base64.b64encode(signature).decode('utf-8')
        self.signature_text.configure(state='normal')
        self.signature_text.delete("1.0", tk.END)
        self.signature_text.insert(tk.END, sig_b64)
        self.signature_text.configure(state='disabled')
        messagebox.showinfo("Signed", "Text has been signed. Signature displayed.")

    def verify_text_signature(self):
        text = self.text_area.get("1.0", tk.END).rstrip('\n')
        sig_b64 = self.signature_text.get("1.0", tk.END).strip()
        if not text or not sig_b64:
            messagebox.showwarning("Missing Data", "Please enter/load text and signature to verify.")
            return
        try:
            signature = base64.b64decode(sig_b64)
        except Exception:
            messagebox.showerror("Invalid Signature", "Signature is not valid Base64.")
            return

        verified = verify_signature(self.rsa_pub, text.encode('utf-8'), signature)
        if verified:
            messagebox.showinfo("Verification Success", "Signature is valid.")
        else:
            messagebox.showerror("Verification Failed", "Signature is NOT valid.")

    def show_public_key(self):
        pub_pem = self.rsa_pub.export_key().decode('utf-8')
        win = tk.Toplevel(self.master)
        win.title("RSA Public Key")
        text = scrolledtext.ScrolledText(win, width=70, height=20, font=("Consolas", 10))
        text.pack(padx=10, pady=10)
        text.insert(tk.END, pub_pem)
        text.configure(state='disabled')

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()