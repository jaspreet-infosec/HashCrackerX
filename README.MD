
# 🔐 BruteForce Hash Cracker

A simple Python toolset to simulate brute-force attacks on hashed passwords using multi-threading. Includes functionality to generate MD5 and SHA-256 hashes and crack them using a wordlist.

## 📂 Project Structure

- `generate_hash.py`: Generate MD5 and SHA-256 hashes for a given password.
- `bruteforce.py`: Perform a brute-force attack on a hash using a wordlist and multithreading.
- `requirements.txt`: Lists Python dependencies for the project.

## ⚙️ Features

- Supports MD5 and SHA-256 hashing algorithms
- Multithreaded brute-force attack for faster cracking
- Custom wordlist support
- Clean and beginner-friendly Python implementation

## 🚀 Getting Started

### 🔧 Requirements

- Python 3.x

### 📥 Installation

1. Clone the repository or download the files:
   ```bash
   git clone https://github.com/yourusername/bruteforce-hash-cracker.git
   cd bruteforce-hash-cracker
```

2. Install the required packages:
    ```bash
    pip install -r requirements.txt
    ```
    
    
3. Make sure you have a wordlist file ready (e.g., `wordlist.txt`).
    

### ▶️ Usage

#### 1. Generate Hashes

```bash
python generate_hash.py
```

You will be prompted to enter a password. The script will output both MD5 and SHA-256 hashes.

#### 2. Run Brute Force Attack

```bash
python bruteforce.py
```

You will be prompted to:

- Choose the hash type (MD5 or SHA-256)
    
- Enter the target hash
    
- Provide the path to your wordlist
    

The script will attempt to crack the hash using multiple threads.

## 🧪 Example

```
Enter the password to hash: hello123
MD5 Hash of 'hello123': 3615f80c9d293ed7402687d1a61f2ea1
SHA-256 Hash of 'hello123': 9b2e2b3e7f56fc813b1304c4ef09b1de...
```

Use the resulting hash in `bruteforce.py` to try and crack it.

## 🙋‍♂️ Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

## 📜 License

This project is licensed under the [MIT License](https://chatgpt.com/c/LICENSE).

### 👨‍💻 Developed by [JAS PREET](https://github.com/jaspreet-infosec)

---

> ⚠️ **Disclaimer:** This tool is intended for educational purposes only. Do not use it for illegal or unethical activities.
