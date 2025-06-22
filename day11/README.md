# Day 11: Writing Basic CodeQL Queries

**Summary:** Now that we have a CodeQL database, we can start querying it. We'll learn the basic structure of a QL query (`import`, `from`, `where`, `select`) and write a few simple queries to explore the Java code from Day 10.

**Today's Focus:** Writing and running simple QL queries to find all method calls or all string literals in our Java example.

## Prerequisites

*   CodeQL CLI installed and configured (Day 10).
*   A CodeQL database created for the `my-java-app` project (e.g., `my-java-db` from Day 10).
*   Standard QL libraries for Java downloaded (e.g., in `/path/to/your/ql-packs/codeql-java` or your CodeQL repo clone).

## Try it yourself

### 1. Create Query Files

Create a directory to store your custom queries, e.g., `my-codeql-queries`.

**Query 1: Find all method calls (`FindAllMethodCalls.ql`)**
Create `my-codeql-queries/FindAllMethodCalls.ql`:
```ql
/**
 * @name Find all method calls
 * @kind points-to // or table, problem
 * @description Finds all method call expressions in the Java codebase.
 * @id java/example/find-all-method-calls
 */
import java

// 'from' declares variables and their types
// 'MethodCall' is a QL class representing a call to a method.
// 'mc' is a variable of type MethodCall.
from MethodCall mc
// 'where' specifies conditions (optional for just selecting all)
// No 'where' clause means select all instances of MethodCall.
// 'select' determines what the query outputs
select mc, "This is a method call to: " + mc.getMethod().getName()
```

**Query 2: Find all string literals (`FindAllStringLiterals.ql`)**
Create `my-codeql-queries/FindAllStringLiterals.ql`:
```ql
/**
 * @name Find all string literals
 * @kind table // This query is best viewed as a table
 * @description Finds all string literal expressions in the Java codebase.
 * @id java/example/find-all-string-literals
 */
import java

// 'StringLiteral' is a QL class from the Java QL library.
// 'sl' is a variable of type StringLiteral.
from StringLiteral sl
select sl, sl.getValue() // Select the literal itself and its string value
```

### 2. Run the Queries

Use the `codeql query run` command. You'll need:
*   Path to your CodeQL database.
*   Path to your QL query file.
*   The `--search-path` used during database creation (or path to your QL packs / CodeQL repo clone).

```shell
# Ensure you have the database created from Day 10 (e.g., my-java-db)
# and your QL pack/library path (e.g., /path/to/your/ql-packs or /path/to/codeql-repo)

# Run Query 1: FindAllMethodCalls.ql
codeql query run \
  --database=../day10/my-java-db \
  --search-path=/path/to/your/ql-packs \
  my-codeql-queries/FindAllMethodCalls.ql

# Run Query 2: FindAllStringLiterals.ql
codeql query run \
  --database=../day10/my-java-db \
  --search-path=/path/to/your/ql-packs \
  my-codeql-queries/FindAllStringLiterals.ql

# To output results in a more structured format (e.g., SARIF for IDEs, or CSV):
# codeql query run --database=../day10/my-java-db --search-path=/path/to/your/ql-packs \
#   --output=results.sarif my-codeql-queries/FindAllMethodCalls.ql
# codeql query run --database=../day10/my-java-db --search-path=/path/to/your/ql-packs \
#   --output=results.csv my-codeql-queries/FindAllStringLiterals.ql
```
*Replace `/path/to/your/ql-packs` with the actual path to your downloaded QL packs or your full `codeql` repository clone.*
*The `../day10/my-java-db` assumes you are running these commands from the `day11` directory.*

You will see results printed to the console, or written to the specified output file. For example, `FindAllMethodCalls.ql` will list calls like `System.out.println(...)`, `args.length > 0`, `name.equals("admin")`, etc.

## QL Query Structure Explained

*   **Query Metadata (Header Comment):**
    *   `@name`: Human-readable name for the query.
    *   `@kind`: Type of query, influencing how results are displayed.
        *   `points-to`: Highlights specific locations in code (good for alerts).
        *   `table`: Results are best viewed as a table.
        *   `problem`: Similar to `points-to`, used for security alerts.
        *   `path-problem`: For taint tracking, shows a path from source to sink.
    *   `@description`: Explains what the query does.
    *   `@id`: A unique identifier for the query (e.g., `language/pack/query-name`).
    *   `@tags`: Optional tags like `security`, `correctness`.
*   **`import java`**: Imports the standard QL library for Java. This makes Java-specific classes like `MethodCall`, `StringLiteral`, `Class`, `Method`, etc., available. Other languages have their own imports (e.g., `import python`, `import javascript`).
*   **`from ...`**: Declares variables and their QL types. For example, `from MethodCall mc` declares a variable `mc` that will range over all method calls found in the database.
*   **`where ...` (Optional):** Defines conditions that must be true for a result to be selected. If omitted, all instances of the types in the `from` clause are considered.
*   **`select ...`**: Specifies what information the query should output for each match. It can include the QL entities themselves (which link back to source code), strings, or values derived from these entities. The number of columns in the `select` often depends on the `@kind`.

These basic queries demonstrate how to start exploring a codebase with CodeQL. By changing the QL classes in `from` and adding `where` clauses, you can begin to search for more specific patterns.

---
[Back to Main README](../README.md)
