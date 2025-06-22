# Day 20: SAST for Node.js (Express)

## Summary

Today, we delve into Static Application Security Testing (SAST) for Node.js applications, with a particular focus on those built with the Express.js framework. Node.js applications can be susceptible to a variety of vulnerabilities, and SAST tools are crucial for identifying these early in the development lifecycle.

Common vulnerabilities in Node.js/Express applications:
- **Cross-Site Scripting (XSS):** Similar to other web frameworks, if user input is rendered without proper sanitization or escaping in templates (e.g., EJS, Pug, Handlebars).
- **NoSQL Injection:** If user input is used to construct database queries for NoSQL databases like MongoDB without proper validation or sanitization.
- **Command Injection:** When user input is passed to functions like `child_process.exec()` or similar, allowing attackers to execute arbitrary system commands.
- **Path Traversal / Directory Traversal:** If user input is used to construct file paths that are then accessed by the application, potentially allowing access to arbitrary files.
- **Insecure Use of Middleware:** Misconfigured or outdated middleware can introduce vulnerabilities (e.g., `body-parser` issues in the past, or insecure session management).
- **Prototype Pollution:** A JavaScript-specific vulnerability that can occur when manipulating object prototypes, potentially leading to DoS or RCE.

## CLI/Terminal Commands

Using `njsscan` (Node.js Static Analysis Scan):

```bash
# Install njsscan (requires Python and pip)
pip install njsscan

# Navigate to your Node.js project directory
cd /path/to/your/nodejs_project

# Run njsscan
njsscan .
```

Using Semgrep with generic JavaScript/Node.js rules:

```bash
# Ensure you have Semgrep installed: pip install semgrep
# Navigate to your Node.js project directory
cd /path/to/your/nodejs_project

# Run Semgrep with a relevant ruleset (e.g., Node.js specific, or general JS)
semgrep --config "p/javascript" . # General JavaScript rules
semgrep --config "p/nodejs" .   # Node.js specific rules (if available in registry)
# Example for a specific rule like command injection:
semgrep --lang js -e 'child_process.exec($CMD)' --config "r/javascript.lang.security.audit.dangerous-exec.dangerous-exec" .
```

## Code Explanation

We'll create a simple Express application with a route that is vulnerable to Command Injection. The application will take a filename as a query parameter and use it in a `ls` command.

**`express_example.js`:**
An Express application that uses `child_process.exec` with unsanitized user input.

## Try it yourself

1.  Set up the example Express application:
    ```bash
    # Create a project directory
    mkdir node_sast_demo && cd node_sast_demo

    # Initialize npm project and install Express
    npm init -y
    npm install express

    # Create express_example.js with the provided code
    # ...
    ```
2.  Run the application: `node express_example.js`
3.  Test the vulnerable endpoint: `http://localhost:3000/list-files?filename=test.txt;whoami`
    You should see the output of `ls test.txt` followed by the output of `whoami`.
4.  Run a SAST tool like `njsscan` or Semgrep against `express_example.js`.
5.  Analyze the results to see if the command injection vulnerability is detected.
6.  Fix the vulnerability:
    *   Avoid using `exec` with user input if possible.
    *   If necessary, use `child_process.execFile` which is safer as it doesn't spawn a shell by default.
    *   Sanitize the input strictly (e.g., allow only alphanumeric characters if expecting a simple filename).

This example demonstrates a clear command injection flaw that SAST tools are generally good at finding.
