# Day 29: Case Study: Finding a Real-World Vulnerability with SAST

## Summary

Today, we'll walk through a hypothetical (but realistic) case study of how SAST tools can be used to find a significant vulnerability in a web application. This example will focus on identifying an Insecure Direct Object Reference (IDOR) vulnerability, a common and often critical issue.

**Scenario:**
A web application allows users to view their invoices. Invoices are accessed via a URL like `https://example.com/invoices?id=12345`. The backend system is written in Java.

**Vulnerability:** Insecure Direct Object Reference (IDOR)
An IDOR vulnerability occurs when an application provides direct access to objects based on user-supplied input. If the application doesn't verify that the user is authorized to access the specific object, attackers can manipulate the input (e.g., the `id` parameter) to access other users' data.

## Code Explanation

We'll look at a simplified Java servlet code snippet that handles invoice retrieval.

**`vulnerable_code_snippet.java`:**
A snippet from a Java servlet or controller that fetches an invoice based on an ID from the request parameters without proper authorization checks.

**`finding_rule.yml` (Conceptual Semgrep Rule):**
A conceptual Semgrep rule that could help identify this type of IDOR pattern. Real-world IDOR detection often requires more sophisticated taint tracking (data from user input reaching a database query without an authorization check on the result).

## The Investigation and Discovery Process with SAST

1.  **Initial Scan & Rule Triggering:**
    -   A SAST tool (e.g., Semgrep with custom rules, or CodeQL with its standard queries) is run against the codebase.
    -   A rule designed to detect patterns where user input is used in database queries or to retrieve sensitive objects might get triggered. Let's say our `finding_rule.yml` (or a similar one) flags the line where `request.getParameter("id")` is used to fetch an `Invoice` object.

2.  **Analyzing the Finding:**
    -   **Source:** The SAST tool highlights that the `invoiceId` comes directly from `request.getParameter("id")`. This is an untrusted user input (the source of taint).
    -   **Sink:** The `invoiceId` is used in `invoiceService.getInvoiceById(invoiceId)`. This method likely queries the database for an invoice with the given ID (the sink for the tainted data).
    -   **Missing Sanitization/Validation (Authorization Check):** The security analyst or developer reviewing the finding would then look at the surrounding code:
        -   Is there any check to ensure that the `currentUser` (obtained from the session) is actually the owner of the `invoiceId` being requested?
        -   In our `vulnerable_code_snippet.java`, this check is missing. The code directly fetches and displays any invoice whose ID is provided.

3.  **Understanding the Impact:**
    -   If an attacker changes the `id` parameter in the URL (e.g., `?id=100` to `?id=101`), they could potentially view invoices belonging to other users.
    -   This could lead to a serious data breach, exposing sensitive financial information.

4.  **Confirming the Vulnerability (Manual or with other tools):**
    -   A developer might manually test this by logging in as User A, accessing their invoice URL, then changing the ID to one they know belongs to User B.
    -   DAST tools could also potentially find this by systematically changing ID parameters, although they wouldn't know the *why* from the code perspective.

5.  **Remediation:**
    -   The fix involves adding an authorization check. After retrieving the invoice, the application must verify that the logged-in user is authorized to view it.
    ```java
    // ... (inside the servlet/controller)
    String invoiceIdParam = request.getParameter("id");
    long invoiceId = Long.parseLong(invoiceIdParam);
    User currentUser = (User) request.getSession().getAttribute("currentUser");

    Invoice invoice = invoiceService.getInvoiceById(invoiceId);

    if (invoice != null && invoice.getUserId().equals(currentUser.getId())) { // <-- FIX: Authorization check
        // Display invoice
        response.getWriter().write("Invoice Details: " + invoice.getDetails());
    } else {
        // Log unauthorized access attempt
        response.sendError(HttpServletResponse.SC_FORBIDDEN, "You are not authorized to view this invoice.");
    }
    // ...
    ```

## How the SAST Rule Helped

-   **Pattern Recognition:** The SAST rule (even a simple one) flagged a risky pattern: user input flowing into a data retrieval mechanism.
-   **Guided Investigation:** While the initial SAST alert might be generic (e.g., "User input used in database query"), it directs the developer/analyst to the precise location in the code.
-   **Contextual Analysis (Human):** The human then applies security knowledge to understand *why* this pattern is dangerous in this specific context (lack of authorization for the retrieved object).
-   **More Advanced SAST (Taint Analysis):** A more sophisticated SAST tool with good taint analysis capabilities could provide a more precise alert, such as: "User-controlled 'id' parameter from HTTP request reaches database query in 'getInvoiceById' and the result is used without an authorization check against the current session user."

## Try it yourself

1.  Review `vulnerable_code_snippet.java`. Imagine you are a developer or security analyst.
2.  Look at the conceptual `finding_rule.yml`. How would it match the vulnerable code?
3.  Think about what a SAST tool would report. What information would be most helpful?
4.  Consider the proposed remediation. How does it fix the IDOR vulnerability?
5.  If you have Semgrep, try to adapt the `finding_rule.yml` to be more concrete and run it against the Java snippet (you might need to wrap the snippet in a class/method structure for Semgrep to parse it correctly as Java).

This case study illustrates that SAST is a powerful tool for identifying potential vulnerabilities by highlighting risky code patterns. While tools automate detection, human analysis is often crucial for confirming vulnerabilities and understanding the full context, especially for complex issues like authorization flaws.
