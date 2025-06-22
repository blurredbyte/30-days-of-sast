// vulnerable.js - Examples of common JavaScript pitfalls

// --- 1. eval usage ---
function executeCodeUnsafely(dynamicString) {
    console.log("Attempting to eval:", dynamicString);
    try {
        eval(dynamicString); // SINK: eval() is dangerous if dynamicString is user-controlled.
                             // Semgrep rule: javascript-eval-usage
    } catch (e) {
        console.error("Eval error:", e.message);
    }
}

console.log("--- eval() Demo ---");
executeCodeUnsafely("console.log('Eval executed a hardcoded safe string.')");

// Simulate user input (e.g., from URL parameter, localStorage, postMessage)
let userInputForEval = "console.warn('Eval executed from a variable.');";
// let userInputForEval = "const fs = require('fs'); fs.writeFileSync('/tmp/pwned_by_eval.txt', 'oops'); console.log('File written by eval!')"; // Malicious (Node.js context)
// let userInputForEval = "alert('Eval XSS');"; // Malicious (Browser context)
executeCodeUnsafely(userInputForEval); // SOURCE: userInputForEval -> SINK: eval()


// --- 2. innerHTML assignment (XSS) ---
function displayHtmlContent(elementId, htmlPayload) {
    // Simulate DOM in Node.js for this script to run without a browser
    if (typeof document === 'undefined') {
        global.document = {
            getElementById: function(id) {
                if (!this._elements) this._elements = {};
                if (!this._elements[id]) this._elements[id] = { id: id, innerHTML: '', textContent: '' };
                return this._elements[id];
            }
        };
    }

    const targetElement = document.getElementById(elementId);
    if (targetElement) {
        // SINK: Assignment to innerHTML is an XSS risk if htmlPayload is untrusted.
        // Semgrep rule: javascript-innerhtml-assignment
        targetElement.innerHTML = htmlPayload;
        console.log(`Element ${elementId} updated with HTML (potentially unsafe).`);
    } else {
        console.log(`Element ${elementId} not found.`);
    }
}

console.log("\n--- innerHTML Demo ---");
displayHtmlContent("userGreeting", "<strong>Welcome!</strong> This is safe."); // Literal, safe HTML

let userInputForHTML = "<img src='invalid-image' onerror='alert(\"XSS via innerHTML from variable!\")'>"; // Malicious XSS payload
// SOURCE: userInputForHTML -> SINK: targetElement.innerHTML
displayHtmlContent("userDetails", userInputForHTML);


// --- 3. postMessage with wildcard targetOrigin ---
function broadcastMessage(messageData) {
    // Simulate window.parent for Node.js
    if (typeof window === 'undefined') {
        global.window = { parent: { postMessage: (msg, origin) => console.log(`Mock parent received: ${JSON.stringify(msg)} with origin: ${origin}`) }};
    }

    // SINK: Using "*" as targetOrigin is dangerous if messageData is sensitive.
    // Semgrep rule: javascript-postmessage-wildcard-origin
    window.parent.postMessage(messageData, "*");
    console.log("Message broadcasted with wildcard targetOrigin.");
}

console.log("\n--- postMessage Demo ---");
broadcastMessage({ userAction: "logout", timestamp: Date.now() });


// --- 4. Prototype pollution (simplified example) ---
// For a full prototype pollution, you usually need a recursive merge or specific assignment patterns.
function unsafeMerge(target, source) {
  for (const key in source) {
    // A very naive check, real prototype pollution often bypasses hasOwnProperty or targets Object.create(null) differently.
    // if (source.hasOwnProperty(key)) {
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
        console.warn(`Potentially unsafe key in source for merge: ${key}`);
        // In a real exploit, this might not be enough to stop it.
      }
      // SINK: Direct assignment can lead to prototype pollution if key is __proto__
      // and target is a plain JS object, and source is attacker-controlled.
      target[key] = source[key];
    // }
  }
  return target;
}

console.log("\n--- Prototype Pollution Demo (Simplified) ---");
let cleanObject = {};
let maliciousPayload = JSON.parse('{"__proto__": {"isPolluted": true}}');

console.log("Before pollution, cleanObject.isPolluted:", cleanObject.isPolluted); // undefined
unsafeMerge(cleanObject, maliciousPayload);
console.log("After pollution, cleanObject.isPolluted:", cleanObject.isPolluted); // true, if pollution occurred on cleanObject itself
console.log("Checking prototype: ({}).isPolluted:", ({}).isPolluted); // true, if Object.prototype was polluted.

// Reset to avoid affecting other tests if Object.prototype was polluted (in some environments)
if (({}).isPolluted) {
    console.log("Attempting to clean Object.prototype.isPolluted");
    delete Object.prototype.isPolluted;
    console.log("After cleanup, ({}).isPolluted:", ({}).isPolluted);
}


console.log("\n--- End of Demos ---");
console.log("Run: semgrep --config javascript_common_pitfalls.yml vulnerable.js");

// CodeQL queries for these would involve:
// - Taint tracking for eval: User input (e.g., `RemoteFlowSource`) to `eval` sink.
// - Taint tracking for XSS: User input to `innerHTML` sink (e.g., `DomHtmlXssSink`).
// - Specific checks for `postMessage` arguments.
// - Advanced data flow analysis for prototype pollution (tracking assignment to `__proto__` or specific library vulnerabilities).
