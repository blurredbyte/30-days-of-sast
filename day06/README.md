# Day 06: Semgrep Patterns - Beyond Basic Matching

**Summary:** We'll explore more advanced Semgrep pattern features like metavariables, `pattern-either`, `pattern-inside`, and `pattern-not-inside`. These allow for more precise and context-aware rule writing, reducing false positives and negatives.

**Today's Focus:** Using metavariables and `pattern-inside` to find insecure `subprocess` calls in Python that don't use `shell=False` when a variable is part of the command.

## Try it yourself

1.  **Create `unsafe_subprocess.py`** with the content below.
2.  **Create `detect_unsafe_subprocess.yml`** with the content below.
3.  **Run Semgrep with your custom rule:**
    ```shell
    semgrep --config detect_unsafe_subprocess.yml unsafe_subprocess.py
    ```
    Expected output should flag the `subprocess.call("echo " + user_input, shell=True)` line.

## Code Explanation

### `unsafe_subprocess.py`

```python
# unsafe_subprocess.py
import subprocess

def safe_command_execution():
    # This is safe, command is a list of arguments, shell=False by default
    subprocess.run(["ls", "-l"])

def unsafe_command_execution_variable(user_input):
    # This is potentially unsafe if shell=True is used with unescaped user input
    # Our rule should catch this if shell=True is explicitly set or implied with a string command
    command_string = "echo " + user_input
    subprocess.run(command_string, shell=True, check=True) # Vulnerable: shell=True with variable input

def also_unsafe_command_str(user_input):
    # If the first argument to subprocess.run, .call, .check_output etc. is a string,
    # and shell=True (or shell is not explicitly False, which defaults to True for string commands in some contexts)
    # then it's risky.
    subprocess.call("grep " + user_input + " /some/file") # Implicit shell=True if string, depending on Python version/OS

def safer_command_with_variable(user_input):
    # Safer: command is a list, shell=False by default
    subprocess.run(["echo", user_input])

user_command = "some_file.txt; id" # Malicious input
unsafe_command_execution_variable(user_command)
also_unsafe_command_str(user_command)
safer_command_with_variable("test")
```

### `detect_unsafe_subprocess.yml`

```yaml
# detect_unsafe_subprocess.yml
rules:
  - id: python-subprocess-shell-true-with-variable
    languages: [python]
    severity: ERROR
    message: |
      Detected subprocess call with shell=True and a command constructed from variables.
      This is highly dangerous and can lead to command injection if the variable content
      is influenced by external input. Use a list of arguments for the command
      and avoid shell=True.
    patterns:
      - pattern-either:
        - pattern: subprocess.$FUNC($CMD_VAR, ..., shell=True, ...)
        - pattern: subprocess.$FUNC(..., cmd=$CMD_VAR, ..., shell=True, ...)
        # Pattern for when command is a string and shell=True is implicit or explicit
        - pattern: |
            subprocess.$FUNC("..." + $VAR + "...", ..., shell=True, ...)
        - pattern: |
            $X = "..." + $VAR + "..."
            ...
            subprocess.$FUNC($X, ..., shell=True, ...)
      - metavariable-regex:
          metavariable: $CMD_VAR
          regex: ^[a-zA-Z_][a-zA-Z0-9_]*$ # Ensure $CMD_VAR is a variable, not a literal string
      - focus-metavariable: $FUNC # Highlights the function call
    # Ensure $CMD_VAR is not a literal string by checking it's not quoted.
    # This is a bit tricky with just pattern syntax, a `metavariable-regex` on $CMD_VAR helps.
    # More robust checks might involve `pattern-not-بادpattern: subprocess.$FUNC("...", ..., shell=True, ...)`
    # or type information if available. The current regex ensures $CMD_VAR is an identifier.
```

*   **`pattern-either`**: Matches if any of the sub-patterns match.
*   **`subprocess.$FUNC($CMD_VAR, ..., shell=True, ...)`**:
    *   `$FUNC`: A metavariable that matches any function name (e.g., `run`, `call`, `check_output`).
    *   `$CMD_VAR`: A metavariable for the command argument.
    *   `shell=True`: Specifically looks for cases where `shell=True` is used.
*   **`$X = "..." + $VAR + "..." \n ... \n subprocess.$FUNC($X, ..., shell=True, ...)`**: This uses Semgrep's "statement block" or "sequence" matching. It looks for an assignment of a concatenated string (including a variable `$VAR`) to `$X`, followed by a `subprocess` call using `$X` with `shell=True`. The `...` on its own line matches any number of statements in between.
*   **`metavariable-regex`**: This allows you to apply a regex to the content captured by a metavariable. Here, it ensures `$CMD_VAR` is a typical variable name and not a string literal like `"ls -l"`. This helps reduce false positives where `shell=True` might be used with a hardcoded, safe command.
*   **`focus-metavariable: $FUNC`**: This tells Semgrep to highlight the part of the code matched by `$FUNC` in its output.

This rule is more complex and demonstrates how to combine Semgrep features to create targeted and context-aware checks for vulnerabilities like command injection.

---
[Back to Main README](../README.md)
