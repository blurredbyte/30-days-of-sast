# Day 14: Exploring Common CodeQL Query Packs

**Summary:** CodeQL comes with a rich set of standard libraries and query packs for various languages, covering many common vulnerability types (OWASP Top 10, CWEs) and coding best practices. We'll explore how to find and use these pre-built queries.

**Today's Focus:** Locating and running standard CodeQL security queries (e.g., for Java) against our existing database.

## Prerequisites

*   CodeQL CLI, Java database (`my-java-db`), QL libraries (from previous days).
*   The QL packs (e.g., `github/codeql-java` or the full `github/codeql` repository clone) must be accessible to the CodeQL CLI, typically configured via `--search-path` or by having them in a standard location CodeQL checks.

## Standard Query Packs

CodeQL queries are organized into "QL packs". A QL pack is a directory with a `qlpack.yml` file at its root.
*   **Standard Libraries (`codeql/<language>-ql` or `github/codeql-<language>`):** These form the foundation, providing the QL classes and predicates for analyzing a specific language (e.g., `codeql/java-ql` contains the libraries for Java). They are located in `ql/java/ql/src` if you cloned the `github/codeql` repo, or within the downloaded pack directory.
*   **Standard Query Packs (`codeql/<language>-queries` or `github/codeql-<language>` subdirectories):** These contain pre-written queries for finding vulnerabilities, bugs, and anti-patterns. For example, `codeql/java-queries` (found in `ql/java/ql/src/Security`, `ql/java/ql/src/Performance`, etc. in the full repo, or as part of the `github/codeql-java` pack).

Key query suites often found:
*   `codeql/<language>-security-extended.qls` or `codeql-suites/<language>-security-extended.qls`
*   `codeql/<language>-security-and-quality.qls` or `codeql-suites/<language>-security-and-quality.qls`

A `.qls` file is a "query suite" file, which defines a set of queries to run.

## Try it yourself

### 1. Locate Standard Query Suites

If you cloned the `github/codeql` repository (e.g., to `/path/to/codeql-repo`):
The Java security queries are typically in:
*   `/path/to/codeql-repo/java/ql/src/Security/`
*   `/path/to/codeql-repo/java/ql/src/experimental/Security/`
*   And suite files like `/path/to/codeql-repo/java/ql/suites/security-extended.qls`

If you used `codeql pack download github/codeql-java --output /path/to/your/ql-packs/codeql-java`:
The queries and suites will be within the `/path/to/your/ql-packs/codeql-java` directory structure, often mirrored from the main repository. For example, a suite might be at `/path/to/your/ql-packs/codeql-java/codeql-suites/java-security-extended.qls`.

### 2. Run a Standard Security Query Suite

We'll use the `codeql database analyze` command, which is designed to run suites of queries and produce structured output (like SARIF).

```shell
# Ensure my-java-db exists from Day 10
# Adjust --search-path to where your CodeQL packs are (e.g., /path/to/your/ql-packs or /path/to/codeql-repo if you cloned the whole thing)
# Adjust the path to the .qls file based on your CodeQL distribution.

# Example using a common security suite for Java:
# The exact path to the .qls file can vary slightly based on how you obtained CodeQL queries (pack download vs. full repo clone).
# If you used `codeql pack download`, the suite might be directly referenceable by its pack name.

# Option 1: Referencing a standard suite from a downloaded pack (modern way)
# This assumes `github/codeql-java` pack is available through the search path.
codeql database analyze ../day10/my-java-db \
  github/codeql-java:codeql-suites/java-security-extended.qls \
  --search-path=/path/to/your/ql-packs \
  --format=sarif-latest \
  --output=java-security-extended-results.sarif

# Option 2: Providing a direct path to a .qls file (if Option 1 doesn't resolve)
# (You'll need to find the exact path to java-security-extended.qls within your ql-packs or codeql repo clone)
# codeql database analyze ../day10/my-java-db \
#   /path/to/your/ql-packs/codeql-java/codeql-suites/java-security-extended.qls \
#   --search-path=/path/to/your/ql-packs \
#   --format=sarif-latest \
#   --output=java-security-extended-results.sarif


# The command might take a few minutes.
# It will run many security queries against your `my-java-db`.
```

*   **`codeql database analyze <database>`**: Command to analyze a database.
*   **`<query_suite_or_pack_and_path>`**: Specifies the queries to run.
    *   `github/codeql-java:codeql-suites/java-security-extended.qls`: This format specifies a QL pack (`github/codeql-java`) and a path to a resource (the `.qls` file) within that pack. This is the preferred way if using downloaded packs.
    *   You can also provide a direct file path to a `.ql` or `.qls` file.
*   **`--search-path=/path/to/your/ql-packs`**: (or `/path/to/codeql-repo`) Tells CodeQL where to find the QL packs and libraries.
*   **`--format=sarif-latest`**: Specifies the output format. SARIF is a standard format for static analysis results and can be uploaded to GitHub or viewed in IDEs.
*   **`--output=java-security-extended-results.sarif`**: The file where results will be saved.

### 3. Inspect the Results

*   Open the `java-security-extended-results.sarif` file in a text editor or a SARIF viewer (like the VS Code extension for SARIF).
*   You might see findings from various queries. For our simple `Example.java`, it might find:
    *   The path traversal issue from `PathTraversal.ql` (if that query or a similar one is part of the suite).
    *   Perhaps issues related to "Hard-coded credentials" if it picked up string literals that look like passwords (unlikely in our current example).
    *   "Log injection" if `System.out.println` is considered a logging sink and input is from an external source (our `args[0]` example).
    *   Many queries might produce no results on such a small, simple example.

## Exploring Available Queries

*   **VS Code Extension:** The CodeQL extension for VS Code is excellent for browsing queries within downloaded packs or a CodeQL repo clone. You can see query source code, metadata, and often documentation.
*   **GitHub Repository (`github/codeql`):** Browse the `ql/<language>/ql/src` directory. Subdirectories like `Security`, `Performance`, `Likely Bugs` often contain many `.ql` files.
*   **`codeql resolve queries <query_suite.qls>`:** This command can show you which `.ql` files are included in a given query suite.
    ```shell
    codeql resolve queries --search-path=/path/to/your/ql-packs github/codeql-java:codeql-suites/java-security-extended.qls
    ```

Running standard query packs is a great way to get broad security coverage quickly. You can then supplement these with your custom queries for project-specific concerns or more nuanced checks.

---
[Back to Main README](../README.md)
