
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
LOCKOUT_DURATION = 60  # seconds

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
        json.dump(data, f)

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

# === Load stored data ===
stored_data = load_data()

# === Layout Settings ===
st.set_page_config(page_title="SecureVault", page_icon="🔐", layout="centered")

st.markdown("<h1 style='text-align: center; color: #4CAF50;'>🔐 SecureVault</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center;'>Protect your personal data with military-grade encryption 🔒</p>", unsafe_allow_html=True)

# === Sidebar Navigation ===
menu = ["🏠 Home", "📝 Register", "🔑 Login", "📦 Store Data", "🔍 Retrieve Data"]
choice = st.sidebar.radio("📁 Navigate", menu)

# === Pages ===
if choice == "🏠 Home":
    st.header("Welcome to SecureVault!")
    st.success("✨ Create an account, encrypt your sensitive data, and keep it private forever.")
    st.image("https://cdn-icons-png.flaticon.com/512/3318/3318774.png", width=200)

elif choice == "📝 Register":
    st.header("🧾 Register New Account")
    st.write("Create a new account to securely store your encrypted data.")

    col1, col2 = st.columns(2)
    with col1:
        username = st.text_input("👤 Choose Username")
    with col2:
        password = st.text_input("🔐 Choose Password", type="password")

    if st.button("🚀 Register"):
        if username and password:
            if username in stored_data:
                st.warning("⚠️ Username already exists.")
            else:
                stored_data[username] = {"password": hash_password(password), "data": []}
                save_data(stored_data)
                st.success("✅ User registered successfully!")
        else:
            st.error("❗ Both fields are required.")

elif choice == "🔑 Login":
    st.header("🔐 Login to Your Vault")

    # Lockout Timer
    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"⏳ Too many failed attempts. Try again in {remaining} seconds.")
        st.stop()

    username = st.text_input("👤 Username")
    password = st.text_input("🔒 Password", type="password")

    if st.button("🔓 Login"):
        if username in stored_data and stored_data[username]["password"] == hash_password(password):
            st.session_state.authenticated_user = username
            st.session_state.failed_attempts = 0
            st.success(f"✅ Welcome, {username}!")
        else:
            st.session_state.failed_attempts += 1
            remaining = 3 - st.session_state.failed_attempts
            st.error(f"❌ Invalid credentials! Attempts left: {remaining}")

            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.stop()

elif choice == "📦 Store Data":
    st.header("🔒 Store Encrypted Data")
    if not st.session_state.authenticated_user:
        st.warning("🔐 You must be logged in to store data.")
    else:
        data = st.text_area("✍️ Enter the data you want to encrypt")
        passkey = st.text_input("🔑 Encryption Key (Passphrase)", type="password")

        if st.button("💾 Encrypt & Store"):
            if data and passkey:
                encrypted = encrypt_text(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_data(stored_data)
                st.success("✅ Data encrypted and stored successfully!")
                st.code(encrypted, language="text")
            else:
                st.error("⚠️ All fields are required.")

elif choice == "🔍 Retrieve Data":
    st.header("🔍 Retrieve Your Data")
    if not st.session_state.authenticated_user:
        st.warning("🔐 You must be logged in to retrieve your data.")
    else:
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])
        if not user_data:
            st.info("ℹ️ No encrypted entries found.")
        else:
            st.write(f"📂 You have {len(user_data)} encrypted entr{'y' if len(user_data)==1 else 'ies'}:")

            with st.expander("🔐 View All Encrypted Entries"):
                for i, item in enumerate(user_data, 1):
                    st.code(item, language="text")

            encrypted_input = st.text_area("📥 Paste the Encrypted Text")
            passkey = st.text_input("🔑 Enter your Passkey", type="password")

            if st.button("🔓 Decrypt"):
                result = decrypt_text(encrypted_input, passkey)
                if result:
                    st.success("✅ Decrypted Text:")
                    st.code(result, language="text")
                else:
                    st.error("❌ Incorrect passkey or invalid data.")
