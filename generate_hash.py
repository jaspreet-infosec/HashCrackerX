import hashlib

# Function to generate MD5 hash
def generate_md5_hash(password):
    return hashlib.md5(password.encode()).hexdigest()

# Function to generate SHA-256 hash
def generate_sha256_hash(password):
    return hashlib.sha256(password.encode()).hexdigest()

if __name__ == "__main__":
    password = input("Enter the password to hash: ")

    md5_hash = generate_md5_hash(password)
    sha256_hash = generate_sha256_hash(password)

    print(f"MD5 Hash of '{password}': {md5_hash}")
    print(f"SHA-256 Hash of '{password}': {sha256_hash}")
