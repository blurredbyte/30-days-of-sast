# Day 21: Introduction to Taint Analysis

## Summary

Today, we introduce a powerful concept in SAST: **Taint Analysis** (also known as taint tracking or information flow analysis). Taint analysis is a technique used to determine if data from untrusted sources (called "sources") can propagate through the application and reach sensitive operations (called "sinks") without proper sanitization or validation.

**Key Concepts:**
-   **Sources:** Points in the code where external, potentially untrusted data enters the application. Common sources include:
    -   HTTP request parameters, headers, bodies
    -   User input from forms
    -   Data read from files, databases, or network sockets
-   **Sinks:** Sensitive functions or operations in the code that, if executed with tainted data, could lead to vulnerabilities. Common sinks include:
    -   SQL query execution functions (potential SQLi)
    -   Functions that render HTML (potential XSS)
    -   File system operations (potential Path Traversal)
    -   Command execution functions (potential Command Injection)
    -   Deserialization routines
-   **Tainted Data:** Data that originates from a source and is considered untrusted.
-   **Propagation:** The process by which tainted data flows through the application, from variable assignments to function calls, etc.
-   **Sanitizers/Validators:** Functions or code constructs that check, clean, or transform tainted data, making it safe to use with sinks. If data passes through a sanitizer, it may no longer be considered tainted for certain sinks.
-   **Taint Flow:** A path from a source to a sink where tainted data is propagated. A taint flow without proper sanitization often indicates a potential vulnerability.

SAST tools that support taint analysis build a model of the code's data flow to track how data from sources can influence sinks.

## CLI/Terminal Commands (Conceptual)

Taint analysis is a feature within SAST tools. The commands would be the same as running the tool, but you'd be looking for results specifically identified through taint analysis.

**Semgrep (using taint mode):**
Semgrep's taint analysis is powerful. Rules are written to define sources, sinks, and sanitizers.

```bash
# Example: Run Semgrep with a ruleset that includes taint analysis rules
# (The '--taint-mode' might be implicit in well-defined taint rules or require specific flags)
semgrep --config "p/python.lang.security.injection.sql-injection-db-cursor-execute" .
# Or for a custom taint rule:
semgrep --config your_custom_taint_rule.yml .
```

**CodeQL:**
CodeQL is inherently built around data flow analysis, which is a superset of taint analysis. Queries are written in QL to model sources, sinks, and data flow paths.

```bash
# 1. Create database (if not already done)
codeql database create my-app-db --language=python --source-root /path/to/your/project
# 2. Analyze with a query that performs taint tracking (e.g., for SQLi)
codeql database analyze my-app-db --format=sarif-latest --output=results.sarif python/ql/src/Security/CWE-089/SqlInjection.ql
```

## Code Explanation

We'll use a simple Python example to illustrate a taint flow leading to a potential SQL injection.

**`taint_example.py`:**
A Python script that takes user input (source) and uses it directly in an SQL query (sink).

**`taint_rule.yml` (Conceptual Semgrep Taint Rule):**
A simplified Semgrep rule to demonstrate how one might define sources and sinks for the `taint_example.py`.

## Try it yourself

1.  Review the `taint_example.py` code.
2.  Examine the `taint_rule.yml` to understand how sources and sinks are conceptually defined for a tool like Semgrep.
3.  If you have Semgrep installed, you can try to run it with the rule.
    *   Note: The provided `taint_rule.yml` is highly conceptual. Real Semgrep taint rules involve more specific `pattern-sources`, `pattern-sinks`, and potentially `pattern-sanitizers` within the rule structure. See Semgrep's documentation on taint analysis for accurate syntax.
4.  Consider how you would sanitize the input in `taint_example.py` to prevent the SQL injection. (e.g., using parameterized queries). If a sanitizer was applied, the taint flow would be "cleaned," and a SAST tool should not report a vulnerability.

This day provides a foundational understanding of taint analysis, a technique that underpins many sophisticated SAST findings.
