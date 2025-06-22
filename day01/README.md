# Day 01: Introduction to SAST - The What, Why, and How

**Summary:** This lesson introduces the fundamental concepts of Static Application Security Testing (SAST). We'll explore what SAST is, why it's crucial for software security, and how it generally works. We'll also touch upon its benefits and limitations.

**Today's Focus:** Understanding the landscape of SAST.

## Try it yourself

No specific commands for today as it's an introductory session. However, you can start thinking about the codebases you work with and where SAST might fit in.

Consider a simple piece of JavaScript code that uses `eval`.

```javascript
// example.js
function executeUserInput(input) {
  eval(input); // Potentially dangerous if input is not sanitized
}

executeUserInput("console.log('Hello from eval!')");
// What if input was malicious? e.g., "require('fs').unlinkSync('/critical/file')"
```

## Code Explanation

The `example.js` file contains a function `executeUserInput` that takes one argument, `input`, and executes it using `eval()`.

*   **`eval(input)`**: This JavaScript function executes a string as if it were JavaScript code.
*   **Vulnerability**: If `input` comes from an untrusted source (e.g., user input from a web form), a malicious user could provide a string that, when executed, performs harmful actions. This is known as a Code Injection vulnerability.

SAST tools are designed to detect such potentially dangerous patterns in code without actually running it.

---
[Back to Main README](../README.md)
