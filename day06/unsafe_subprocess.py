# unsafe_subprocess.py
import subprocess

def safe_command_execution_list():
    # This is safe: command is a list of arguments, shell=False by default.
    print("Running safe command (list): ls -l")
    subprocess.run(["ls", "-l"])

def safe_command_execution_string_literal_shell_false():
    # This is also safe: command is a string literal, but shell=False is explicit.
    print("Running safe command (string literal, shell=False): echo 'Hello World'")
    subprocess.run("echo 'Hello World'", shell=False, check=True) # shell=False makes it safer

def unsafe_command_execution_variable_shell_true(user_input):
    # VULNERABLE: shell=True with command string built from user input.
    # This is what our Semgrep rule should primarily target.
    print(f"Running unsafe command (variable, shell=True): echo {user_input}")
    command_string = "echo User input: " + user_input # Command string includes user input
    try:
        # The Semgrep rule should flag this line.
        subprocess.run(command_string, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Command failed (as expected with malicious input): {e}")
    except FileNotFoundError:
        print(f"Command not found (if echo isn't available via shell in some minimal envs)")


def unsafe_command_string_implicit_shell_true(user_input):
    # POTENTIALLY VULNERABLE: Command is a string, shell behavior can be platform-dependent
    # or default to True if not specified. Semgrep might also flag this.
    # For `subprocess.call`, `subprocess.check_call`, `subprocess.check_output`,
    # if the first arg is a string, `shell` defaults to `False`, but this was not always the case
    # and some developers might mistakenly assume it's True or use it in risky ways.
    # The most dangerous pattern is explicitly shell=True with variable input.
    print(f"Running potentially unsafe command (string, implicit shell): grep {user_input} some_file.txt")
    # subprocess.call("grep " + user_input + " /dev/null") # Example
    # Let's make it more explicit for the rule:
    try:
        subprocess.call("grep " + user_input + " /dev/null", shell=True) # Explicit to ensure rule match
    except Exception as e:
        print(f"Error with grep: {e}")


def safer_command_with_variable_no_shell_true(user_input):
    # SAFER: command is a list of arguments, shell=False by default.
    # User input is treated as a single argument.
    print(f"Running safer command (list with variable): echo {user_input}")
    subprocess.run(["echo", user_input], check=True)


if __name__ == "__main__":
    harmless_input = "example_text"
    malicious_input = "text; id" # Classic command injection payload

    print("--- Testing safe command (list) ---")
    safe_command_execution_list()

    print("\n--- Testing safe command (string literal, shell=False) ---")
    safe_command_execution_string_literal_shell_false()

    print("\n--- Testing UNSAFE command with shell=True and variable input ---")
    print(f"Using malicious input: '{malicious_input}'")
    unsafe_command_execution_variable_shell_true(malicious_input)
    print(f"Using harmless input: '{harmless_input}'")
    unsafe_command_execution_variable_shell_true(harmless_input)


    print("\n--- Testing potentially unsafe command (string, shell=True explicit for demo) ---")
    print(f"Using malicious input: '{malicious_input}'")
    unsafe_command_string_implicit_shell_true(malicious_input) # This will try to grep for "text;" and then run "id" if shell=True

    print("\n--- Testing SAFER command with variable input (shell=False by default) ---")
    print(f"Using malicious input: '{malicious_input}'")
    safer_command_with_variable_no_shell_true(malicious_input) # 'text; id' will be echoed literally
    print(f"Using harmless input: '{harmless_input}'")
    safer_command_with_variable_no_shell_true(harmless_input)

    print("\nRun Semgrep with: semgrep --config detect_unsafe_subprocess.yml unsafe_subprocess.py")
