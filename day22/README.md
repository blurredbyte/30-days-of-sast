# Day 22: Advanced Taint Analysis: Custom Rules

## Summary

Building on our understanding of taint analysis from Day 21, today we'll explore how to write **custom taint analysis rules**. While SAST tools come with many predefined rules, real-world applications often have unique data flows, custom validation libraries, or internal frameworks that require tailored rules for effective vulnerability detection.

Writing custom taint rules allows you to:
-   Define application-specific sources (e.g., data from a custom messaging queue).
-   Identify sinks relevant to your application's sensitive operations.
-   Specify custom sanitizer functions or validation routines that are trusted within your codebase.
-   Reduce false positives by creating more precise rules.
-   Detect vulnerabilities in proprietary code or less common libraries.

We'll focus on the conceptual structure of custom taint rules for tools like Semgrep and CodeQL.

## CLI/Terminal Commands

The commands to run custom rules are generally the same as running the SAST tool, but you point it to your custom rule file(s).

**Semgrep:**
```bash
# Run Semgrep with your custom taint rule YAML file
semgrep --config day22/custom_taint_semgrep.yml your_project_directory/
# Or, if your_project_directory contains the code to be scanned:
semgrep --config day22/custom_taint_semgrep.yml .
```

**CodeQL:**
1.  Place your custom `.ql` query file in a CodeQL query pack or a designated directory.
2.  Create a CodeQL database for your project (if not already done):
    ```bash
    codeql database create my-custom-db --language=java --source-root /path/to/your/custom_taint_example_java_project/
    ```
3.  Run your custom query:
    ```bash
    codeql database analyze my-custom-db --format=sarif-latest --output=custom_results.sarif /path/to/your/custom_taint_query.ql
    # Example using the provided file name:
    # codeql database analyze my-custom-db --format=sarif-latest --output=custom_results.sarif day22/CustomTaint.ql
    ```

## Code Explanation

We'll use a Java example where a custom data type (`UserInputString`) is considered a source, and passing it to a specific logging method (`Log.sensitiveData`) without validation is considered a sink.

**`custom_taint_example/src/main/java/com/example/CustomTaint.java`:**
A Java class demonstrating a scenario where custom taint rules would be useful. It defines a `UserInputString` wrapper and a `Log` class with a sensitive logging method.

**`custom_taint_semgrep.yml`:**
A Semgrep rule to detect if `UserInputString` flows into `Log.sensitiveData` without being validated by `Validator.isValid()`.

**`CustomTaint.ql` (Conceptual CodeQL):**
A conceptual CodeQL query to find the same custom taint flow.

## Try it yourself

1.  Review the `custom_taint_example/src/main/java/com/example/CustomTaint.java` code.
2.  Examine `custom_taint_semgrep.yml` to see how sources, sinks, and sanitizers are defined for this custom scenario.
3.  If you have Semgrep, place `custom_taint_semgrep.yml` and the `custom_taint_example` directory appropriately and try running the scan.
    ```bash
    # From the 'day22' directory, assuming 'custom_taint_example' is inside it:
    semgrep --config custom_taint_semgrep.yml custom_taint_example/
    ```
4.  (Optional) If you are familiar with CodeQL, review `CustomTaint.ql` and try to adapt it to run against the Java code. This would require setting up a CodeQL database for the `custom_taint_example` project.
5.  Modify `CustomTaint.java` to see how changes (e.g., adding validation) affect the SAST tool's findings based on the custom rule.

This exercise highlights the flexibility and power of custom taint rules in adapting SAST tools to the specific security needs of your projects.
