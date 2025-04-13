import hashlib
import threading
from queue import Queue


# Hashing functions
def hash_password_md5(password):
    return hashlib.md5(password.encode()).hexdigest()


def hash_password_sha256(password):
    return hashlib.sha256(password.encode()).hexdigest()


# Worker function for brute force attack
def worker(queue, target_hash, hash_function):
    while not queue.empty():
        word = queue.get()
        hashed_word = hash_function(word)

        if hashed_word == target_hash:
            print(f"[+] Password found: {word}")
            return
        queue.task_done()


# Function to run brute force attack with multi-threading
def brute_force(target_hash, hash_function, wordlist_path, num_threads=5):
    queue = Queue()

    # Load the wordlist
    with open(wordlist_path, 'r') as file:
        for line in file:
            word = line.strip()
            queue.put(word)

    # Launch threads to perform brute force
    for _ in range(num_threads):
        t = threading.Thread(target=worker, args=(queue, target_hash, hash_function))
        t.daemon = True
        t.start()

    queue.join()


if __name__ == "__main__":
    # Example usage
    print("Brute Force Attack Simulator")
    print("[1] MD5")
    print("[2] SHA-256")

    choice = input("Select hashing algorithm (1/2): ")
    if choice == "1":
        hash_function = hash_password_md5
    elif choice == "2":
        hash_function = hash_password_sha256
    else:
        print("Invalid choice!")
        exit()

    target_hash = input("Enter the target hash: ")
    wordlist_path = input("Enter path to wordlist file (e.g., wordlist.txt): ")

    brute_force(target_hash, hash_function, wordlist_path)
