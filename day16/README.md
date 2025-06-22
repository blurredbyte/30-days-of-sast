# Day 16: SAST for JavaScript - Common Pitfalls (e.g., `eval`, `innerHTML`)

**Summary:** We'll focus on SAST for JavaScript, highlighting common vulnerabilities like those arising from `eval()`, `innerHTML` assignments (potential XSS), insecure `postMessage` usage, and prototype pollution. We'll use Semgrep for quick pattern matching and discuss how CodeQL can find deeper flaws.

**Today's Focus:** Writing Semgrep rules to detect `eval()` and direct `innerHTML` assignments from potentially unsafe sources in JavaScript.

## Try it yourself

### 1. Create `vulnerable.js`

```javascript
// vulnerable.js

// eval usage
function executeCode(str) {
    console.log("About to eval:", str);
    eval(str); // Vulnerable to code injection if str is user-controlled
}

executeCode("console.log('Eval executed direct string')");
// let userInputEval = "console.error('Eval from variable executed!'); require('fs').unlinkSync('/tmp/oops')";
// executeCode(userInputEval); // Example of dangerous input

// innerHTML usage
function setContent(elementId, htmlContent) {
    const el = document.getElementById(elementId);
    if (el) {
        // Vulnerable to XSS if htmlContent is user-controlled and not sanitized
        el.innerHTML = htmlContent;
        console.log(`Set innerHTML for ${elementId}`);
    }
}

// Simulate DOM for Node.js environment or browser
if (typeof window === 'undefined') {
    global.window = { document: { getElementById: (id) => ({ id: id, innerHTML: ''}) } };
    global.document = window.document;
}

setContent("div1", "<strong>Hello World!</strong>"); // Safe content
// let userInputHTML = "<img src=x onerror=alert('XSS_innerHTML')>";
// setContent("div2", userInputHTML); // Example of dangerous input

// postMessage usage - overly broad target origin
function sendMessage(message) {
    // Vulnerable if the target window/origin isn't specific enough or if message is sensitive
    // and target can be framed/controlled by attacker.
    window.parent.postMessage(message, "*"); // Using "*" is dangerous
    console.log("Sent message:", message);
}
// sendMessage({ action: "update", value: "some sensitivedata" });

// Prototype pollution (simplified example source)
function merge(target, source) {
    for (let key in source) {
        if (source.hasOwnProperty(key)) {
            // Vulnerable if source contains __proto__ or constructor
            // and target is a plain object.
            target[key] = source[key];
        }
    }
    return target;
}
let objA = { a: 1 };
// let maliciousSource = JSON.parse('{"__proto__": {"isAdmin": true}}');
// merge({}, maliciousSource); // isAdmin is now true on Object.prototype for some engines/setups
// console.log({}.isAdmin);
```

### 2. Create Semgrep Rules (`javascript_common_pitfalls.yml`)

```yaml
# javascript_common_pitfalls.yml
rules:
  - id: javascript-eval-usage
    patterns:
      - pattern: eval(...)
    message: "Use of eval() is dangerous and can lead to code injection if the argument is user-controlled. Avoid eval if possible, or use safer alternatives like JSON.parse() for data or new Function() in very controlled environments."
    languages: [javascript, typescript]
    severity: ERROR
    metadata:
      cwe: "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')"
      owasp: "A03:2021-Injection"

  - id: javascript-innerhtml-assignment
    patterns:
      - pattern: $ELEMENT.innerHTML = $CONTENT
      # Optional: Add pattern-not-inside to exclude if $CONTENT is a string literal
      # - pattern-not: $ELEMENT.innerHTML = "..."
    message: "Direct assignment to innerHTML can lead to Cross-Site Scripting (XSS) if the content ($CONTENT) is derived from user input and not properly sanitized. Use textContent for plain text, or ensure HTML is sanitized before assignment."
    languages: [javascript, typescript]
    severity: WARNING
    metadata:
      cwe: "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
      owasp: "A03:2021-Injection" # XSS is a form of injection

  - id: javascript-postmessage-wildcard-origin
    patterns:
      - pattern: $WIN.postMessage($MSG, "*")
    message: "Using a wildcard '*' as the targetOrigin in postMessage allows any site to receive the message. This can lead to information disclosure if the message is sensitive and the target window can be controlled by an attacker (e.g., through framing). Specify a precise targetOrigin."
    languages: [javascript, typescript]
    severity: WARNING
    metadata:
      cwe: "CWE-345: Insufficient Verification of Data Authenticity" # Related to origin validation
      owasp: "A08:2021-Software and Data Integrity Failures"
```

### 3. Run Semgrep

```shell
semgrep --config javascript_common_pitfalls.yml vulnerable.js
```
This should flag `eval()`, `el.innerHTML = ...`, and `window.parent.postMessage(message, "*")`.

## Discussion

*   **`eval()`:** Semgrep easily spots `eval()` calls. CodeQL could perform taint tracking to see if user-controlled input reaches `eval()`, making the finding more precise.
*   **`innerHTML`:** Semgrep flags all assignments. A more advanced Semgrep rule could try to check if the source is a variable (more risky) vs. a literal string. CodeQL excels here by tracking if user input (e.g., from `document.location.hash`, form fields, or AJAX responses) flows into an `innerHTML` sink without sanitization (e.g., via DOMPurify).
*   **`postMessage`:** The Semgrep rule looks for the literal `"*"` target origin. CodeQL can analyze if the message content is sensitive and if the target origin is indeed too broad or dynamically set in an insecure way.
*   **Prototype Pollution:** This is a more complex vulnerability. Detecting it often requires analyzing how objects are merged or properties are assigned, especially with keys like `__proto__`, `constructor`, or `prototype`. Semgrep can find basic patterns of unsafe merges, but CodeQL's data flow and class analysis are better suited for tracking the pollution from source to a gadget that exploits it. (A Semgrep rule for this would be more complex than the examples above).

**CodeQL for JavaScript:**
To analyze JavaScript with CodeQL:
1.  **Create Database:**
    ```shell
    codeql database create js-database --language=javascript --source-root=/path/to/js-project --search-path=/path/to/ql-packs
    ```
2.  **Run Queries:** Use standard JavaScript security queries (e.g., from `github/codeql-javascript:codeql-suites/javascript-security-extended.qls`) or write custom ones.
    ```ql
    // Conceptual CodeQL for XSS via innerHTML
    import javascript
    import semmle.javascript.security.dataflow.XssThroughDom::Configuration

    from XssThroughDom::Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
    where cfg.hasFlowPath(source, sink)
    select sink.getNode(), source, sink, "XSS vulnerability: unsanitized data from $@ flows to DOM via innerHTML $@",
      source.getNode(), "user input",
      sink.getNode(), "innerHTML assignment"
    ```

SAST for JavaScript requires attention to both client-side (browser) and server-side (Node.js) contexts. Frameworks like React, Angular, Vue also introduce their own security considerations and specific sinks (e.g., `dangerouslySetInnerHTML` in React).

---
[Back to Main README](../README.md)
