import hashlib, time, random

# Get user input
data = input("Enter data to protect: ")
key = int(input("Enter a secret key (number): "))

# Confidentiality: Encrypt & Decrypt
enc = ''.join(chr(ord(c) ^ key) for c in data)
dec = ''.join(chr(ord(c) ^ key) for c in enc)
print("\n🔒 Confidentiality ->", enc, "→", dec)

# Integrity: Check tampering
h1 = hashlib.sha256(data.encode()).hexdigest()
tampered = data + "!"  # simulate change
h2 = hashlib.sha256(tampered.encode()).hexdigest()
print("🧩 Integrity ->", "Safe ✅" if h1 == h2 else "Tampered ❌")

# Availability: Simulate load
print("🌐 Availability -> System under load...")
time.sleep(random.uniform(0.5, 1.5))
print("✅ System recovered and data accessible!")