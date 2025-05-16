import hashlib
from utils import encrypt_aes, decrypt_aes, sha256_hash

def get_key_from_password(password: str) -> bytes:
    return hashlib.sha256(password.encode()).digest()

def main():
    print("Encryption and Hashing Tool")
    print("1. SHA-256 Hash Text")
    print("2. SHA-256 Hash File")
    print("3. AES Encrypt Text")
    print("4. AES Decrypt Text")

    choice = input("Select an option: ")

    if choice == "1":
        data = input("Enter text to hash: ").encode()
        print("SHA-256 Hash:", sha256_hash(data))

    elif choice == "2":
        path = input("Enter file path: ")
        with open(path, "rb") as f:
            data = f.read()
        print("SHA-256 File Hash:", sha256_hash(data))

    elif choice == "3":
        text = input("Enter text to encrypt: ").encode()
        password = input("Enter password: ")
        key = get_key_from_password(password)
        ciphertext = encrypt_aes(key, text)
        print("Encrypted (base64):", ciphertext)

    elif choice == "4":
        ciphertext = input("Enter base64-encoded ciphertext: ")
        password = input("Enter password: ")
        key = get_key_from_password(password)
        try:
            plaintext = decrypt_aes(key, ciphertext)
            print("Decrypted text:", plaintext)
        except Exception as e:
            print("Decryption failed:", str(e))

    else:
        print("Invalid option.")

if __name__ == "__main__":
    main()
