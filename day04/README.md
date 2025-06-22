# Day 04: Introduction to Semgrep - A Modern SAST Tool

**Summary:** Today, we introduce Semgrep, a fast, open-source, and lightweight static analysis tool. It's designed to find bugs and enforce code standards using intuitive rule syntax. We'll cover what makes Semgrep different and how to run it for the first time.

**Today's Focus:** Running Semgrep with its pre-built ruleset on a Python example.

## Try it yourself

1.  **Install Semgrep:**
    ```shell
    # For macOS
    brew install semgrep

    # For other systems (requires Python 3.7+)
    python3 -m pip install semgrep
    ```
2.  **Create `insecure_deserialization.py`** with the content below.
3.  **Run Semgrep with the default ruleset:**
    Semgrep comes with a community-maintained ruleset (`r/python`) that covers many common security issues.
    ```shell
    semgrep --config "p/python" insecure_deserialization.py
    ```
    Or, to be more specific with a security-focused ruleset like `r/python.security`:
    ```shell
    semgrep --config "p/python.security" insecure_deserialization.py
    ```
    You might see output similar to:
    ```
    insecure_deserialization.py
    =================================
    semgrep.rules.python.security.insecure-pickle-usage:
      Detected use of `pickle.load` or `pickle.loads`. Deserializing untrusted data with `pickle` can lead to arbitrary code execution.
      Consider using a safer serialization format like JSON if the data is not from a trusted source.
      For more information, see: https://docs.python.org/3/library/pickle.html#security-considerations
      Target: insecure_deserialization.py:8
          7|
          8|    data = pickle.load(f) # Vulnerable: loading data from an untrusted file
          9|

    Found 1 rule hit.
    ```

## Code Explanation

The `insecure_deserialization.py` file contains an example of insecure deserialization using Python's `pickle` module.

```python
# insecure_deserialization.py
import pickle
import os

# Imagine this data comes from an untrusted source, like a file upload or network request
MALICIOUS_PICKLE_DATA = b"\x80\x04\x95\x28\x00\x00\x00\x00\x00\x00\x00\x8c\x08os\x94\x8c\x06system\x94\x93\x94\x8c\x0fwhoami\x94\x85\x94R\x94."
# This pickle data, when loaded, executes os.system('whoami')

# Simulate writing malicious data to a file
with open("data.pkl", "wb") as f:
    f.write(MALICIOUS_PICKLE_DATA)

# Vulnerable code: loading data from the file without validation
def load_data_from_file(filename):
    with open(filename, "rb") as f:
        data = pickle.load(f) # Vulnerable: loading data from an untrusted file
    return data

if __name__ == "__main__":
    print("Attempting to load data from data.pkl...")
    try:
        loaded_object = load_data_from_file("data.pkl")
        print("Loaded object:", loaded_object)
    except Exception as e:
        print("Error during deserialization:", e)
    finally:
        if os.path.exists("data.pkl"):
            os.remove("data.pkl")
```

*   **`import pickle`**: Imports Python's `pickle` module, used for serializing and deserializing Python object structures.
*   **`MALICIOUS_PICKLE_DATA`**: This is a byte string representing a pickled object. This specific payload is crafted to execute `os.system('whoami')` when deserialized by `pickle.load()` or `pickle.loads()`.
*   **`pickle.load(f)`**: This function reads a pickled object representation from the open file object `f` and reconstructs the object.
*   **Vulnerability (Insecure Deserialization)**: If the data being deserialized (from `data.pkl` in this case) is attacker-controlled, the attacker can craft a payload that executes arbitrary code on the system when `pickle.load()` is called. This is a very dangerous vulnerability.

Semgrep, using its rules, can identify the use of `pickle.load()` and flag it as a potential security risk because `pickle` is known to be unsafe when dealing with untrusted data. This demonstrates how Semgrep can quickly find common vulnerabilities out-of-the-box.

---
[Back to Main README](../README.md)
