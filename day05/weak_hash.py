# weak_hash.py
import hashlib

def get_md5_hash(data_string):
    # Using MD5, which is cryptographically weak for many security-sensitive purposes like password hashing.
    # Our Semgrep rule should flag this line.
    return hashlib.md5(data_string.encode()).hexdigest()

def get_sha1_hash(data_string):
    # SHA1 is also considered weak for many applications, though stronger than MD5.
    # We might write another rule for this later.
    return hashlib.sha1(data_string.encode()).hexdigest()

def get_sha256_hash(data_string):
    # Using SHA256, a stronger alternative for many use cases.
    return hashlib.sha256(data_string.encode()).hexdigest()

if __name__ == "__main__":
    password_to_hash = "mySuperSecretPa$$w0rd"

    hashed_with_md5 = get_md5_hash(password_to_hash)
    print(f"Password hashed with MD5: {hashed_with_md5}")

    hashed_with_sha1 = get_sha1_hash(password_to_hash)
    print(f"Password hashed with SHA1: {hashed_with_sha1}")

    hashed_with_sha256 = get_sha256_hash(password_to_hash)
    print(f"Password hashed with SHA256: {hashed_with_sha256}")

    # Another direct use of md5
    salt = "random_salt"
    token_md5 = hashlib.md5((password_to_hash + salt).encode()).hexdigest()
    print(f"Token with MD5: {token_md5}")

    print("\nRun Semgrep to find MD5 usage:")
    print("semgrep --config detect_md5.yml weak_hash.py")
