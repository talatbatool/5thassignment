import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# === Constants ===
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60

# === Session State Initialization ===
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# === Utility Functions ===
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# === Load Data ===
stored_data = load_data()

# === UI Layout ===
st.set_page_config(page_title="Secure Data App", page_icon="🔐", layout="centered")
st.markdown("# 🔐 Secure Multi-User Data System")

menu = ["🏠 Home", "📝 Register", "🔑 Login", "📦 Store Data", "🔎 Retrieve Data"]
choice = st.sidebar.radio("Navigate", menu)

# === Home ===
if choice == "🏠 Home":
    st.markdown("Welcome to your **Secure Encrypted Data Manager** 🛡️")
    st.info("Register or log in to store and retrieve encrypted data safely.")

# === Register ===
elif choice == "📝 Register":
    st.subheader("👤 Create New Account")
    with st.form("register_form", clear_on_submit=True):
        username = st.text_input("🆔 Choose Username")
        password = st.text_input("🔑 Choose Password", type="password")
        submitted = st.form_submit_button("Register")

        if submitted:
            if username and password:
                if username in stored_data:
                    st.warning("⚠️ Username already exists.")
                else:
                    stored_data[username] = {
                        "password": hash_password(password),
                        "data": []
                    }
                    save_data(stored_data)
                    st.success("✅ Registered successfully!")
            else:
                st.error("❌ Please fill in both fields.")

# === Login ===
elif choice == "🔑 Login":
    st.subheader("🔐 User Login")

    if time.time() < st.session_state.lockout_time:
        wait_time = int(st.session_state.lockout_time - time.time())
        st.error(f"⏳ Too many failed attempts. Try again in {wait_time} seconds.")
        st.stop()

    with st.form("login_form", clear_on_submit=True):
        username = st.text_input("🆔 Username")
        password = st.text_input("🔑 Password", type="password")
        submitted = st.form_submit_button("Login")

        if submitted:
            if username in stored_data and stored_data[username]["password"] == hash_password(password):
                st.session_state.authenticated_user = username
                st.session_state.failed_attempts = 0
                st.success(f"✅ Welcome back, {username}!")
            else:
                st.session_state.failed_attempts += 1
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Invalid credentials! Attempts left: {attempts_left}")

                if st.session_state.failed_attempts >= 3:
                    st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                    st.error("🔒 Locked out due to too many failed attempts.")
                    st.stop()

# === Store Data ===
elif choice == "📦 Store Data":
    if not st.session_state.authenticated_user:
        st.warning("🔒 Please log in to continue.")
    else:
        st.subheader("📄 Encrypt & Store Your Data")
        with st.form("store_data_form"):
            data = st.text_area("Enter data to encrypt")
            passkey = st.text_input("Encryption Key (passphrase)", type="password")
            submit_encrypt = st.form_submit_button("Encrypt & Save")

            if submit_encrypt:
                if data and passkey:
                    encrypted = encrypt_text(data, passkey)
                    stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                    save_data(stored_data)
                    st.success("✅ Data encrypted and stored!")
                else:
                    st.error("❌ Please fill in both fields.")

# === Retrieve Data ===
elif choice == "🔎 Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("🔒 Please log in to continue.")
    else:
        st.subheader("📥 Retrieve & Decrypt Data")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("ℹ️ No encrypted data found.")
        else:
            st.markdown("### 🧾 Encrypted Entries")
            for idx, item in enumerate(user_data, 1):
                st.code(item, language="text")

        st.markdown("---")
        with st.form("decrypt_form"):
            encrypted_input = st.text_area("Paste Encrypted Text")
            passkey = st.text_input("Enter Decryption Key", type="password")
            decrypt_submit = st.form_submit_button("🔓 Decrypt")

            if decrypt_submit:
                result = decrypt_text(encrypted_input, passkey)
                if result:
                    st.success(f"✅ Decrypted Text:\n\n{result}")
                else:
                    st.error("❌ Failed to decrypt. Invalid key or data.")
