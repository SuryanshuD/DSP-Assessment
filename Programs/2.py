import hashlib, time

# --- Input ---
password = input("Enter a password: ")

# --- Hash the password ---
hash_val = hashlib.sha256(password.encode()).hexdigest()
print("\n🔐 Hashed password:", hash_val)

# --- Password strength check ---
if len(password) < 4:
    strength = "Weak ❌"
elif any(c.isdigit() for c in password) and any(c.isupper() for c in password):
    strength = "Strong 💪"
else:
    strength = "Medium ⚠️"
print("Password Strength:", strength)

# --- Dictionary / Brute-force simulation ---
dictionary = ["1234", "admin", "test", "password", "Secret", password]
print("\n🚀 Starting dictionary attack...\n")

for word in dictionary:
    time.sleep(0.3)  # simulate delay / progress
    print("Trying:", word)
    if hashlib.sha256(word.encode()).hexdigest() == hash_val:
        print(f"\n✅ Password cracked! → '{word}'")
        break
else:
    print("\n❌ Password not found in dictionary")

print("\n📊 Attack simulation complete.")