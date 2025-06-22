# Day 07: Semgrep Autofix - Automated Code Remediation

**Summary:** Semgrep isn't just for finding issues; it can also automatically fix them! Today, we'll learn how to add `fix` or `autofix` suggestions to Semgrep rules, enabling one-click or automated code remediation for certain classes of vulnerabilities or style issues.

**Today's Focus:** Creating a Semgrep rule that detects `eval()` in Python and suggests replacing it with a safer alternative like `ast.literal_eval()`, or simply removing it if appropriate, using the `fix` key.

## Try it yourself

1.  **Create `uses_eval.py`** with the content below.
2.  **Create `fix_eval.yml`** (our Semgrep rule with autofix) with the content below.
3.  **Run Semgrep to see the finding and the suggested fix:**
    ```shell
    semgrep --config fix_eval.yml uses_eval.py
    ```
4.  **Apply the autofix (use with caution, always review changes):**
    ```shell
    semgrep --config fix_eval.yml uses_eval.py --autofix
    ```
    Then, inspect `uses_eval.py` to see the changes.

## Code Explanation

### `uses_eval.py` (Example Python Code)

```python
# uses_eval.py
import ast

def unsafe_evaluation(code_string):
    # This is dangerous if code_string comes from an untrusted source
    result = eval(code_string)
    print(f"Eval result: {result}")
    return result

def potentially_safer_evaluation(data_string):
    # This is safer for literal structures if that's what's expected
    # but our rule will initially just suggest removing eval or using ast.literal_eval
    try:
        # Let's assume this was intended for simple literals
        # result = eval(data_string) # We want to fix this line
        # The fix might suggest:
        # result = ast.literal_eval(data_string)
        # For the demo, we'll have a direct eval call to fix
        dangerous_result = eval(data_string)
        print(f"Dangerous eval result: {dangerous_result}")
    except Exception as e:
        print(f"Error: {e}")


# Example calls
unsafe_evaluation("1 + 1")
# unsafe_evaluation("__import__('os').system('echo vulnerable')") # Don't run this without understanding

potentially_safer_evaluation("{'key': 'value', 'num': 123}")
potentially_safer_evaluation("__import__('os').system('echo still_vulnerable_if_eval_is_used')")

```

### `fix_eval.yml` (Semgrep Rule with Autofix)

```yaml
# fix_eval.yml
rules:
  - id: python-eval-to-ast-literal-eval
    languages: [python]
    severity: ERROR
    message: |
      Use of `eval()` is dangerous as it can execute arbitrary code if the input
      is not strictly controlled. If you are evaluating simple Python literals
      (strings, numbers, tuples, lists, dicts, booleans, None),
      use `ast.literal_eval()` instead. Otherwise, re-evaluate the need for `eval()`.
    patterns:
      - pattern: eval($ARG)
    fix: ast.literal_eval($ARG) # Suggests replacing eval(ARG) with ast.literal_eval(ARG)
    metadata:
      category: security
      cwe: "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')"

  - id: python-remove-eval-if-no-safe-alternative-comment
    languages: [python]
    severity: WARNING
    message: |
      `eval()` is dangerous. If `ast.literal_eval()` is not suitable, consider
      refactoring the code to avoid dynamic code execution. This rule provides a
      comment placeholder for manual review if autofix is applied.
    patterns:
      - pattern: eval($ARG)
    # This fix is more of a placeholder to guide manual review or a more complex transformation.
    # It comments out the eval call and adds a TODO.
    fix: |
      # TODO: [SECURITY] eval() removed for safety. Review and implement a secure alternative.
      # Original: eval($ARG)
      # result_or_None = None # Placeholder if the result was assigned
    # To make this rule apply *after* the first one (if it wasn't taken),
    # you might need more complex logic or run rules sequentially.
    # For simplicity here, it will also match. A real setup might have these as separate rules
    # or use `pattern-not-inside` if `ast.literal_eval` is already considered.
    # This rule is more for demonstrating a different kind of fix.
    metadata:
      category: security
      notes: "This is a secondary rule to show a different fix strategy."

```

*   **`pattern: eval($ARG)`**:
    *   This pattern matches any call to `eval()` and captures its argument into the metavariable `$ARG`.
*   **`fix: ast.literal_eval($ARG)` (for the first rule)**:
    *   The `fix` key specifies the replacement string.
    *   Semgrep will replace the matched code `eval($ARG)` with `ast.literal_eval($ARG)`, preserving the original argument. This is a common and safer alternative if the input is expected to be a Python literal.
*   **`fix: | \n # TODO: ... \n # Original: eval($ARG) ...` (for the second rule)**:
    *   This demonstrates a multi-line fix. It comments out the original `eval` call and adds a `TODO` comment, prompting a developer to manually review and implement a safer alternative. This is useful when a direct code replacement isn't always appropriate or safe.

When Semgrep runs with `--autofix`, it applies these transformations directly to the source code file. It's crucial to review auto-applied fixes, as the context might require a more nuanced solution than the rule can provide.

---
[Back to Main README](../README.md)
