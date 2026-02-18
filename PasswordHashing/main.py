import json
import os
import bcrypt
from cryptography.fernet import Fernet
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox

# ---------- CONFIG ----------
USER_DB = "users.json"
VAULT_DIR = "vaults"
os.makedirs(VAULT_DIR, exist_ok=True)

# ---------- FILE HANDLING ----------

def load_users():
    if not os.path.exists(USER_DB) or os.path.getsize(USER_DB) == 0:
        return {}
    with open(USER_DB, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}

def save_users(users):
    with open(USER_DB, "w") as f:
        json.dump(users, f, indent=4)

# ---------- ENCRYPTION HELPERS ----------
def get_user_key(username):
    key_file = os.path.join(VAULT_DIR, f"{username}_key.key")
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(key_file, "wb") as f:
            f.write(key)
        return key

def encrypt_data(username, data):
    fernet = Fernet(get_user_key(username))
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(username, data):
    fernet = Fernet(get_user_key(username))
    return fernet.decrypt(data.encode()).decode()

# ---------- PASSWORD STRENGTH ----------
def check_strength(password):
    msg = []
    if len(password) < 8:
        msg.append("❌ Minimum 8 characters")
    if not any(c.isupper() for c in password):
        msg.append("❌ Add uppercase letter")
    if not any(c.islower() for c in password):
        msg.append("❌ Add lowercase letter")
    if not any(c.isdigit() for c in password):
        msg.append("❌ Add number")
    if not any(c in "!@#$%^&*()-_=+[]{};:,.<>?" for c in password):
        msg.append("❌ Add special character")
    if msg:
        return "\n".join(msg), DANGER
    return "✅ Strong Password", SUCCESS

def update_strength_label(event=None):
    pwd = entry_password.get()
    text, color = check_strength(pwd)
    lbl_strength.config(text=text, bootstyle=color)

# ---------- USER MANAGEMENT ----------
def register_user():
    username = entry_username.get().strip()
    password = entry_password.get().strip()

    if not username or not password:
        messagebox.showwarning("⚠️ Input Error", "Please fill both fields.")
        return

    users = load_users()
    if username in users:
        messagebox.showerror("Error", "Username already exists.")
        return

    errors, color = check_strength(password)
    if color == DANGER:
        messagebox.showwarning("Weak Password", errors)
        return

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    users[username] = hashed.decode()
    save_users(users)

    with open(os.path.join(VAULT_DIR, f"{username}.json"), "w") as f:
        json.dump([], f)

    messagebox.showinfo("✅ Success", f"User '{username}' registered successfully!")
    entry_username.delete(0, END)
    entry_password.delete(0, END)
    lbl_strength.config(text="")

def login_user():
    username = entry_username.get().strip()
    password = entry_password.get().strip()

    users = load_users()
    if username not in users:
        messagebox.showerror("Error", "User not found! Please register first.")
        return

    if bcrypt.checkpw(password.encode(), users[username].encode()):
        open_dashboard(username)
    else:
        messagebox.showerror("Error", "Incorrect password!")

def show_users():
    users = load_users()
    if not users:
        messagebox.showinfo("Registered Users", "No registered users yet.")
    else:
        msg = "\n".join(users.keys())
        messagebox.showinfo("Registered Users", msg)

def toggle_password():
    if entry_password.cget("show") == "":
        entry_password.config(show="*")
        btn_toggle.config(text="👁️ Show")
    else:
        entry_password.config(show="")
        btn_toggle.config(text="🙈 Hide")
        
def restart_app():
    """Clear the dashboard and return to the login screen."""
    for widget in app.winfo_children():
        widget.destroy()
    show_login_page()


# ---------- DASHBOARD ----------
def open_dashboard(username):
    for widget in app.winfo_children():
        widget.destroy()

    ttk.Label(app, text=f"🔐 Welcome, {username}", font=("Helvetica", 16, "bold")).pack(pady=10)
    ttk.Button(app, text="Logout", bootstyle=SECONDARY, command=lambda: restart_app()).pack(anchor="ne", padx=10, pady=5)

    vault_file = os.path.join(VAULT_DIR, f"{username}.json")

    def load_vault():
        if not os.path.exists(vault_file):
            return []
        with open(vault_file, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return []

    def save_vault(data):
        with open(vault_file, "w") as f:
            json.dump(data, f, indent=4)

    def add_entry():
        site = entry_site.get().strip()
        user = entry_user.get().strip()
        pwd = entry_pwd.get().strip()

        if not site or not user or not pwd:
            messagebox.showwarning("Input Error", "All fields are required.")
            return

        encrypted_pwd = encrypt_data(username, pwd)
        vault = load_vault()
        vault.append({"site": site, "username": user, "password": encrypted_pwd})
        save_vault(vault)
        update_table()

        entry_site.delete(0, END)
        entry_user.delete(0, END)
        entry_pwd.delete(0, END)

    def delete_selected():
        selected_item = table.focus()
        if not selected_item:
            messagebox.showwarning("No Selection", "Please select an entry to delete.")
            return

        item_data = table.item(selected_item)["values"]
        site_to_delete = item_data[0]
        username_to_delete = item_data[1]

        confirm = messagebox.askyesno("Confirm Delete", f"Delete entry for '{site_to_delete}'?")
        if not confirm:
            return

        vault = load_vault()
        new_vault = [v for v in vault if not (v["site"] == site_to_delete and v["username"] == username_to_delete)]
        save_vault(new_vault)
        update_table()
        messagebox.showinfo("Deleted", f"Entry for '{site_to_delete}' has been removed.")

    def update_table():
        for row in table.get_children():
            table.delete(row)
        for v in load_vault():
            try:
                decrypted_pwd = decrypt_data(username, v["password"])
            except Exception:
                decrypted_pwd = "[Error Decrypting]"
            table.insert("", END, values=(v["site"], v["username"], decrypted_pwd))

    frame = ttk.Frame(app)
    frame.pack(pady=10)

    ttk.Label(frame, text="Website:").grid(row=0, column=0, padx=5, pady=5)
    entry_site = ttk.Entry(frame, width=20)
    entry_site.grid(row=0, column=1, padx=5)

    ttk.Label(frame, text="Username:").grid(row=1, column=0, padx=5, pady=5)
    entry_user = ttk.Entry(frame, width=20)
    entry_user.grid(row=1, column=1, padx=5)

    ttk.Label(frame, text="Password:").grid(row=2, column=0, padx=5, pady=5)
    entry_pwd = ttk.Entry(frame, width=20, show="*")
    entry_pwd.grid(row=2, column=1, padx=5)

    ttk.Button(frame, text="Add Entry", bootstyle=SUCCESS, command=add_entry).grid(row=3, column=0, columnspan=2, pady=10)

    # Table
    table = ttk.Treeview(app, columns=("Site", "Username", "Password"), show="headings", height=8)
    table.heading("Site", text="Website")
    table.heading("Username", text="Username")
    table.heading("Password", text="Password")
    table.pack(pady=10)

    # Delete button
    ttk.Button(app, text="🗑️ Delete Selected", bootstyle=DANGER, command=delete_selected).pack(pady=5)

    update_table()

# ---------- MAIN GUI ----------
app = ttk.Window(themename="superhero")
app.title("🧠 SecureVault: Password Hasher + Vault")
app.geometry("500x520")

def show_login_page():
    for widget in app.winfo_children():
        widget.destroy()

    ttk.Label(app, text="SecureVault Login", font=("Helvetica", 18, "bold")).pack(pady=20)

    frame = ttk.Frame(app)
    frame.pack(pady=10)

    global entry_username, entry_password, lbl_strength, btn_toggle

    ttk.Label(frame, text="Username:", font=("Arial", 12)).grid(row=0, column=0, padx=10, pady=10, sticky=W)
    entry_username = ttk.Entry(frame, width=25)
    entry_username.grid(row=0, column=1, pady=10, sticky=W)

    ttk.Label(frame, text="Password:", font=("Arial", 12)).grid(row=1, column=0, padx=10, pady=10, sticky=W)
    entry_password = ttk.Entry(frame, width=25, show="*")
    entry_password.grid(row=1, column=1, pady=10, sticky=W)

    # Toggle password visibility
    btn_toggle = ttk.Button(frame, text="👁️ Show", width=8, bootstyle=SECONDARY, command=toggle_password)
    btn_toggle.grid(row=1, column=2, padx=5)

    # Password strength label
    lbl_strength = ttk.Label(app, text="", font=("Arial", 10))
    lbl_strength.pack(pady=5)
    entry_password.bind("<KeyRelease>", update_strength_label)

    # Buttons
    btn_frame = ttk.Frame(app)
    btn_frame.pack(pady=20)
    ttk.Button(btn_frame, text="Register", bootstyle=SUCCESS, width=15, command=register_user).grid(row=0, column=0, padx=10)
    ttk.Button(btn_frame, text="Login", bootstyle=INFO, width=15, command=login_user).grid(row=0, column=1, padx=10)
    ttk.Button(app, text="Show Registered Users", bootstyle=WARNING, width=25, command=show_users).pack(pady=10)

# Call it when app starts
show_login_page()

app.mainloop()
