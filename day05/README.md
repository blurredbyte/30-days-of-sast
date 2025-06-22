# Day 05: Writing Your First Semgrep Rule

**Summary:** Today, we'll get hands-on with Semgrep by writing our first custom rule. We'll learn the basic structure of a Semgrep rule and apply it to find a specific pattern in Python code – for example, identifying the use of the `md5` hashing algorithm, which is considered weak for many security purposes.

**Today's Focus:** Creating a simple Semgrep rule to detect `hashlib.md5()`.

## Try it yourself

1.  **Create `weak_hash.py`** with the content below.
2.  **Create `detect_md5.yml`** (our Semgrep rule) with the content below.
3.  **Run Semgrep with your custom rule:**
    ```shell
    semgrep --config detect_md5.yml weak_hash.py
    ```
    You should see output similar to:
    ```
    weak_hash.py
    =================================
    custom-detect-md5:
      MD5 is a weak hashing algorithm and should not be used for security purposes like password hashing. Consider using SHA-256 or bcrypt.
      Target: weak_hash.py:8
          7| def get_md5_hash(data_string):
          8|     return hashlib.md5(data_string.encode()).hexdigest()
          9|

    Found 1 rule hit.
    ```

## Code Explanation

### `weak_hash.py` (Example Python Code)

```python
# weak_hash.py
import hashlib

def get_md5_hash(data_string):
    # Using MD5, which is cryptographically weak for many purposes
    return hashlib.md5(data_string.encode()).hexdigest()

def get_sha256_hash(data_string):
    # Using SHA256, a stronger alternative
    return hashlib.sha256(data_string.encode()).hexdigest()

password = "mysecretpassword"
hashed_password_md5 = get_md5_hash(password)
hashed_password_sha256 = get_sha256_hash(password)

print(f"MD5 Hash: {hashed_password_md5}")
print(f"SHA256 Hash: {hashed_password_sha256}")
```
*   This script demonstrates two hashing functions: one using `md5` (weak) and one using `sha256` (stronger). Our goal is to detect the `md5` usage.

### `detect_md5.yml` (Semgrep Rule)

```yaml
# detect_md5.yml
rules:
  - id: custom-detect-md5
    patterns:
      - pattern: hashlib.md5(...)
    message: "MD5 is a weak hashing algorithm and should not be used for security purposes like password hashing. Consider using SHA-256 or bcrypt."
    languages: [python]
    severity: WARNING
```

*   **`rules:`**: The top-level key for a list of rules.
*   **`- id: custom-detect-md5`**: Each rule needs a unique identifier.
*   **`patterns:`**: Defines the code patterns Semgrep should search for.
    *   **`- pattern: hashlib.md5(...)`**: This is the core of our rule.
        *   `hashlib.md5`: Matches the literal call to `hashlib.md5`.
        *   `(...)`: This is Semgrep's ellipsis operator. It means "match any arguments inside the parentheses." This makes the rule flexible enough to match `hashlib.md5()` with or without arguments, or with different arguments.
*   **`message: "MD5 is a weak hashing algorithm..."`**: The message displayed when the rule matches. This should explain the issue and suggest fixes.
*   **`languages: [python]`**: Specifies that this rule should only run on Python files.
*   **`severity: WARNING`**: Assigns a severity level to the finding (e.g., `INFO`, `WARNING`, `ERROR`).

This simple rule demonstrates the power of Semgrep's pattern matching. We can easily target specific function calls or code structures.

---
[Back to Main README](../README.md)
