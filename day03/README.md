# Day 03: Advanced `grep` Fu - Regex for Security

**Summary:** Building on yesterday's lesson, we'll explore how to use regular expressions (regex) with `grep` (and `egrep` or `grep -E`) to perform more sophisticated pattern matching for security vulnerabilities. This allows for more flexible and accurate searches than simple string matching.

**Today's Focus:** Using `grep` with regex to find SQL injection vulnerabilities in PHP.

## Try it yourself

1.  **Create `db_query.php`** with the content below.
2.  **Basic search for `$_GET` and `query` (noisy)**:
    ```shell
    grep "\$_GET" db_query.php
    grep "query" db_query.php
    ```
3.  **More targeted regex search for SQLi vulnerability**:
    This regex looks for lines where `$_GET` or `$_POST` is used in constructing an SQL query that involves `mysql_query` or `$conn->query`.
    ```shell
    grep -E -n --color=auto "(\\$(_GET|_POST)\\[.*\\]).*(mysql_query|->query)" db_query.php
    ```
    *   `-E`: Enables extended regular expressions.
    *   `(\\$(_GET|_POST)\\[.*\\])`: Matches `$_GET[...]` or `$_POST[...]`.
        *   `\\$`: Escapes the `$` symbol.
        *   `(_GET|_POST)`: Matches either `_GET` or `_POST`.
        *   `\\[.*\\]`: Matches anything inside square brackets `[]`.
    *   `.*`: Matches any characters between the user input and the query execution.
    *   `(mysql_query|->query)`: Matches either `mysql_query` or `->query` (common in MySQLi or PDO).

## Code Explanation

The `db_query.php` file demonstrates a classic SQL injection vulnerability.

```php
// db_query.php
<?php
// Assume $conn is a valid database connection (e.g., MySQLi or PDO)
// For demonstration, we'll mock it.
class MockDBConnection {
    public function query($sql) {
        echo "Executing query: " . htmlspecialchars($sql) . "\n";
        // In a real app, this would execute the query against the database.
        // If $sql contains malicious input, it could be harmful.
    }
}
$conn = new MockDBConnection();

// Vulnerable code
$userId = $_GET['id']; // User input directly from URL parameter

// Constructing SQL query directly with user input
$sql = "SELECT * FROM users WHERE id = " . $userId; // SQL Injection vulnerability

$conn->query($sql);

// Example of a safer, parameterized query (conceptual)
// $stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
// $stmt->bind_param("i", $userId);
// $stmt->execute();

echo "Processing complete.\n";
?>
```

*   **`$userId = $_GET['id'];`**: Retrieves the value of the `id` parameter from the URL. This is user-controlled input.
*   **`$sql = "SELECT * FROM users WHERE id = " . $userId;`**: The user input `$userId` is directly concatenated into the SQL query string.
*   **Vulnerability (SQL Injection)**: If a malicious user provides input like `1 OR 1=1`, the query becomes `SELECT * FROM users WHERE id = 1 OR 1=1`, potentially returning all users. More dangerous inputs could modify or delete data.
*   **`$conn->query($sql);`**: Executes the constructed SQL query.

The `grep -E` command with the regex helps identify lines where user input from `$_GET` or `$_POST` is likely used in forming an SQL query, a common pattern for SQL injection vulnerabilities. While not foolproof (it can have false positives/negatives), it's much more powerful than simple string matching for this kind of flaw.

---
[Back to Main README](../README.md)
