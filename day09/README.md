# Day 09: Introduction to CodeQL - Querying Code for Vulnerabilities

**Summary:** We shift gears to CodeQL, a powerful semantic code analysis engine. CodeQL lets you query code as if it were data. We'll cover its basic concepts: how it builds a database from code and how QL (Query Language) is used to find patterns.

**Today's Focus:** Understanding CodeQL's philosophy and looking at a conceptual example of a QL query.

## Try it yourself

No specific CodeQL installation or commands for today. The goal is conceptual understanding.

Consider this simple Python code with a potential SQL injection:
```python
# vulnerable_sqli.py
import sqlite3

def get_user_data(conn, user_id):
    # Vulnerable SQL query
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor = conn.execute(query)
    return cursor.fetchone()

# Setup (mock)
# conn = sqlite3.connect(':memory:')
# conn.execute("CREATE TABLE users (id TEXT, name TEXT)")
# conn.execute("INSERT INTO users VALUES ('1', 'Alice')")
# print(get_user_data(conn, "1' OR '1'='1")) # Example of an attack
```

A conceptual CodeQL query to find this might look something like this (this is simplified QL-like pseudocode):

```ql
// Conceptual QL-like pseudocode for finding SQL injection
import python

from StringConcatenation concat, FunctionCall exec, VariableAccess userInput
where
  // The user input flows into a string concatenation
  userInput.getName().regexpMatch(".*id") and // Input variable name contains "id"
  concat.getAnOperand() = userInput.getARead() and
  // The result of concatenation flows into an SQL execution function
  exec.getArgument(0) = concat and
  exec.getFunction().getName().regexpMatch("execute|query")
select exec, "Potential SQL injection: User input flows into SQL query."
```

## CodeQL Concepts

1.  **Code as Data:** CodeQL first builds a relational database from your source code. This database represents the code's structure (AST), control flow, data flow, and more.
    *   For Python, it would understand modules, functions, classes, variables, calls, assignments, etc.
    *   For C, it would understand pointers, memory allocation, preprocessor directives, etc.

2.  **QL (Query Language):** QL is an object-oriented query language specifically designed for querying these code databases.
    *   It allows you to define custom logic to find specific patterns, vulnerabilities, or code smells.
    *   Queries can range from simple (e.g., "find all calls to function X") to very complex (e.g., "find all paths where user input can reach a specific sensitive function without proper sanitization" - taint tracking).

3.  **Key Abstractions in QL (Example for Python):**
    *   `Module`: Represents a Python file.
    *   `Function`: Represents a function definition.
    *   `Call`: Represents a function call.
    *   `Expr`: Represents an expression.
    *   `Name`: Represents a variable name.
    *   `StringLiteral`: Represents a string literal.
    *   **DataFlow / TaintTracking:** Powerful features to track the flow of data through the program. For example, tracking if data from an HTTP request (`source`) reaches an SQL query execution (`sink`) without passing through a sanitizer.

**Why CodeQL?**
*   **Deep Semantic Analysis:** Goes beyond regex or simple AST matching. It understands the code's meaning.
*   **Powerful Query Language:** Allows for expressing complex vulnerability patterns.
*   **Extensibility:** Users can write their own queries for custom checks.
*   **Community and Standard Libraries:** A large set of existing queries for common vulnerabilities (e.g., OWASP Top 10) are available.

In the coming days, we'll learn how to install CodeQL, create databases, and write and run actual QL queries.

---
[Back to Main README](../README.md)
