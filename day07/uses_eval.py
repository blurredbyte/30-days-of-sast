# uses_eval.py
import ast # Needed for the suggested fix by one of the rules

def unsafe_evaluation(code_string):
    # This is dangerous if code_string comes from an untrusted source.
    # Semgrep rule `python-eval-to-ast-literal-eval` should offer to fix this.
    print(f"Input to unsafe_evaluation: {code_string}")
    result = eval(code_string)
    print(f"Eval result: {result}")
    return result

def another_unsafe_evaluation(dynamic_expr):
    # Another instance for Semgrep to find and fix.
    print(f"Input to another_unsafe_evaluation: {dynamic_expr}")
    # This line should be flagged and potentially autofixed.
    value = eval(dynamic_expr)
    print(f"Value from eval: {value}")
    return value

def complex_usage_of_eval(user_input_config):
    # This might be a case where ast.literal_eval is a perfect fit,
    # or where the second rule (commenting out) might be preferred
    # by a user if the input isn't guaranteed to be a literal.
    print(f"Input to complex_usage_of_eval: {user_input_config}")
    config_dict = eval(user_input_config) # Target for autofix
    if isinstance(config_dict, dict):
        print(f"Configured option 'host': {config_dict.get('host')}")
    return config_dict

if __name__ == "__main__":
    print("--- Demonstrating uses of eval() for Semgrep autofix ---")

    print("\nScenario 1: Simple arithmetic string")
    unsafe_evaluation("1 + 1") # Expected fix: ast.literal_eval("1 + 1") -> error, not a literal
                                # Or, if the rule is smart, it might see this isn't a literal.
                                # The basic rule will just substitute.

    print("\nScenario 2: String representing a list")
    another_unsafe_evaluation("'hello ' * 3") # eval() -> "hello hello hello "
                                          # ast.literal_eval() would error here.

    print("\nScenario 3: String representing a dictionary (suitable for ast.literal_eval)")
    complex_usage_of_eval("{'host': 'localhost', 'port': 8080, 'debug': True}")
    # Expected fix for complex_usage_of_eval: ast.literal_eval(...)

    print("\nScenario 4: Malicious input (demonstrates danger of eval)")
    # DANGER: The following line can execute arbitrary code.
    # Only uncomment if you understand the risk and are in a safe environment.
    # unsafe_evaluation("__import__('os').system('echo vulnerable_code_executed_via_eval')")

    print("\n--- After running Semgrep with --autofix, inspect this file for changes. ---")
    print("Commands to run:")
    print("1. See findings: semgrep --config fix_eval.yml uses_eval.py")
    print("2. Apply fixes:  semgrep --config fix_eval.yml uses_eval.py --autofix")

# Note on ast.literal_eval:
# ast.literal_eval safely evaluates an expression node or a string containing a Python literal or container display.
# The string or node provided may only consist of the following Python literal structures:
# strings, bytes, numbers, tuples, lists, dicts, sets, booleans, and None.
# It will raise an error for expressions like "1+1" or function calls.
# This makes it much safer than eval() when you expect simple literal data.
