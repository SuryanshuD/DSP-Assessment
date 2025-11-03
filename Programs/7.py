import streamlit as st
import hashlib
import base64

# ---------- Hash Functions ----------
def hash_text(text, algo):
    return hashlib.new(algo, text.encode()).hexdigest()

def hash_file(file, algo):
    file.seek(0)  # Reset pointer
    return hashlib.new(algo, file.read()).hexdigest()

# ---------- Simple Obfuscator ----------
def obfuscate_code(code):
    encoded = base64.b64encode(code.encode()).decode()
    return f'import base64\nexec(base64.b64decode("{encoded}").decode())'

# ---------- Streamlit App ----------
st.title("🔐 Hash & Code Obfuscator")

choice = st.sidebar.radio("Select Mode", ["Hash Generator", "Code Obfuscator"])

# ---------------- Hash Generator ----------------
if choice == "Hash Generator":
    input_type = st.radio("Input type", ["Text", "File"])

    if input_type == "Text":
        txt = st.text_area("Enter text")
        if st.button("Generate Hash") and txt:
            st.write("**MD5:**", hash_text(txt, "md5"))
            st.write("**SHA-1:**", hash_text(txt, "sha1"))
            st.write("**SHA-256:**", hash_text(txt, "sha256"))
            st.write("**SHA-512:**", hash_text(txt, "sha512"))

    else:  # File mode
        f = st.file_uploader("Upload file")
        if f and st.button("Generate File Hash"):
            st.write("**MD5:**", hash_file(f, "md5"))
            st.write("**SHA-1:**", hash_file(f, "sha1"))
            st.write("**SHA-256:**", hash_file(f, "sha256"))
            st.write("**SHA-512:**", hash_file(f, "sha512"))

# ---------------- Code Obfuscator ----------------
else:
    code = st.text_area("Paste Python code")
    if st.button("Obfuscate") and code.strip():
        st.subheader("🔎 Original Code")
        st.code(code, language="python")

        st.subheader("🕵️ Obfuscated Code")
        st.code(obfuscate_code(code), language="python")

        st.info("⚠️ Note: This is **basic Base64 encoding**, not secure code protection.")
