# Day 25: False Positives and False Negatives in SAST

## Summary

When using SAST tools, you'll inevitably encounter **false positives** and **false negatives**. Understanding what these are, why they occur, and how to manage them is crucial for the effective use of SAST and for maintaining developer trust in the tools.

-   **False Positive (FP):**
    -   **Definition:** A reported vulnerability that is not actually a vulnerability. The tool flags safe code as dangerous.
    -   **Impact:** Wastes developers' time investigating non-issues, can lead to "alert fatigue," and may erode confidence in the SAST tool.
    -   **Common Causes:**
        -   Overly broad or generic rules.
        -   Tool's inability to understand complex context, custom sanitizers, or mitigating controls.
        -   Analysis limitations (e.g., not understanding specific framework protections).

-   **False Negative (FN):**
    -   **Definition:** A real vulnerability that the SAST tool fails to detect.
    -   **Impact:** Creates a false sense of security. Critical vulnerabilities might be missed and make their way into production.
    -   **Common Causes:**
        -   Missing rules for a specific vulnerability type or pattern.
        -   Tool's inability to trace complex data flows or understand new/uncommon coding patterns.
        -   Analysis depth limitations (e.g., not performing inter-procedural or inter-file analysis sufficiently).
        -   Misconfiguration of the tool or scan.
        -   Code that is too dynamic for static analysis to fully comprehend.

The goal is to find a balance: minimizing both FPs (to keep results actionable) and FNs (to maximize security).

## Code Explanation

We'll provide two Python examples:
1.  `example_fp.py`: Code that might be flagged by a very generic SAST rule as having an issue (e.g., SQL injection) even though it's constructed safely or in a way that's clearly not exploitable in its specific context.
2.  `example_fn.py`: Code that contains a subtle vulnerability that a simpler SAST rule might miss, leading to a false negative.

These examples are illustrative; actual tool behavior depends on their specific rules and analysis capabilities.

**`example_fp.py`:**
This code might construct an SQL query string in a way that a naive pattern-matching rule flags, even if the variable part is hardcoded or comes from a trusted, controlled source.

**`example_fn.py`:**
This code might have an indirect data flow or use a less common method to introduce a vulnerability (e.g., second-order SQL injection or a vulnerability hidden by complex logic) that basic SAST rules might not catch.

## Managing False Positives

1.  **Rule Tuning/Customization:**
    -   Modify existing rules or write more precise custom rules (as discussed on Day 22).
    -   Adjust rule severity levels.
2.  **Ignoring Specific Alerts:**
    -   Most tools allow you to mark specific findings as "false positive," "won't fix," or "intentional" with justifications. This helps baseline the current state.
    -   Use code comments (e.g., `# nosemgrep`, `# sonarignore`) to suppress warnings for specific lines if the tool supports it.
3.  **Improving Code Clarity:**
    -   Sometimes, refactoring code to be more explicit about safety can help SAST tools understand it better.
4.  **Using Sanitizer/Validation Annotations:**
    -   For tools that support it, annotate custom sanitizer functions so the tool recognizes them.
5.  **Feedback Loop:**
    -   Report persistent FPs to the SAST tool vendor or community to help improve rules.

## Managing False Negatives

1.  **Augment with Other Tools:**
    -   Use multiple SAST tools, as they have different strengths.
    -   Combine SAST with DAST (Dynamic Application Security Testing) and IAST (Interactive Application Security Testing).
2.  **Custom Rule Development:**
    -   If you identify a pattern that your SAST tool misses, write a custom rule for it.
3.  **Manual Code Review:**
    -   SAST is a tool, not a replacement for human expertise. Critical modules should still undergo manual code review.
4.  **Threat Modeling:**
    -   Understand potential threats to your application to guide what you look for, both with tools and manually.
5.  **Security Champions & Training:**
    -   Educate developers on secure coding practices to prevent vulnerabilities in the first place.
6.  **Stay Updated:**
    -   Keep your SAST tool and its rule sets updated to cover the latest vulnerability patterns.
7.  **Testing and Red Teaming:**
    -   Penetration testing and red team exercises can uncover vulnerabilities that automated tools miss.

## Try it yourself

1.  Review `example_fp.py` and `example_fn.py`.
2.  Consider how a SAST tool might interpret these examples.
    -   For `example_fp.py`: Think about a naive rule (e.g., any string concatenation in `cursor.execute()`) that would flag it.
    -   For `example_fn.py`: Think about why a simple rule might not see the connection between the input and the sink.
3.  Run a SAST tool (like Semgrep with generic rules, or another tool you have) against these files.
    -   Do you get the expected false positive or false negative? (This will heavily depend on the tool and its rules.)
    -   If you get a false positive, try to use the tool's mechanism to ignore it or refine a rule (if possible).
    -   If you suspect a false negative, try to write a custom rule (as learned on Day 22) to detect it.

Understanding and managing FPs and FNs is an ongoing process that requires a combination of tool configuration, custom rule development, and integration with broader security practices.
