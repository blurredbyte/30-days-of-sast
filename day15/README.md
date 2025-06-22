# Day 15: Customizing and Contributing to CodeQL Queries

**Summary:** While standard CodeQL queries are powerful, you'll often need to customize them or write new ones. We'll discuss strategies for extending existing queries (e.g., adding new sources/sinks/sanitizers) and how to structure your custom queries for maintainability. We'll also touch upon contributing back to the CodeQL community.

**Today's Focus:** Modifying the `PathTraversal.ql` query from Day 13 to include a new, custom source or sink.

## Prerequisites

*   Day 13 setup: CodeQL CLI, Java database (`my-java-db`), QL libraries.
*   `PathTraversal.ql` from Day 13.
*   `my-java-app` from Day 10. Let's modify it slightly.

## Try it yourself

### 1. Modify `Example.java`

Add a new method that reads from a properties file and uses that value in a file operation. This will be our new custom source.

In `day10/my-java-app/Example.java`, add:
```java
// Add to Example.java
import java.util.Properties;
import java.io.FileInputStream;
import java.io.IOException;

// ... (inside Example class)
public String getPathFromConfig(String configFileName) {
    Properties props = new Properties();
    try (FileInputStream fis = new FileInputStream(configFileName)) {
        props.load(fis);
        // Our new custom source: data read from a properties file
        return props.getProperty("userFilePath");
    } catch (IOException e) {
        System.err.println("Error reading config: " + e.getMessage());
        return null;
    }
}

// Modify main method to use this:
public static void main(String[] args) {
    // ... (existing main code) ...

    Example ex = new Example(); // instance already created
    // Create a dummy config file for the test
    try {
        Properties tempProps = new Properties();
        tempProps.setProperty("userFilePath", "dummy_config_path.txt"); // This value will be "tainted"
        try (java.io.FileOutputStream fos = new java.io.FileOutputStream("temp_config.properties")) {
            tempProps.store(fos, "Temporary config for testing");
        }
    } catch (IOException e) { /* ignore for demo */ }

    String configPath = ex.getPathFromConfig("temp_config.properties");
    if (configPath != null) {
        System.out.println("Path from config: " + configPath);
        ex.readFile(configPath); // Data from config flows to readFile
    }
}
```
**Important:** After modifying `Example.java`, **you must rebuild the CodeQL database**:
```shell
# Remove old database first (optional, but good practice)
# rm -rf ../day10/my-java-db

codeql database create ../day10/my-java-db \
  --language=java \
  --source-root=../day10/my-java-app \
  --search-path=/path/to/your/ql-packs \
  --overwrite # Overwrite if it exists
```
*Replace `/path/to/your/ql-packs` as usual.*

### 2. Create `CustomPathTraversal.ql`

Copy `day13/my-codeql-queries/PathTraversal.ql` to `day15/my-codeql-queries/CustomPathTraversal.ql`.
Now, modify `CustomPathTraversal.ql` to add our new source:

```ql
/**
 * @name Potential Path Traversal from Command Line or Config File
 * @description Finds potential path traversal vulnerabilities where user input
 *              from command line arguments OR a config file flows into file system operations.
 * @kind path-problem
 * @id java/example/custom-path-traversal
 * @problem.severity warning
 * @precision medium
 * @tags security external/cwe/cwe-022
 */
import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.PathTraversal
import DataFlow::PathGraph

// Define a new QL class to represent our custom source (reading from Properties)
class PropertiesValueSource extends DataFlow::Node {
  PropertiesValueSource() {
    // `this` refers to a DataFlow::Node
    // We are looking for calls to `props.getProperty(...)`
    exists(MethodAccess ma, Method getPropMethod |
      ma.getMethod() = getPropMethod and
      getPropMethod.getDeclaringType().hasQualifiedName("java.util", "Properties") and
      getPropMethod.hasName("getProperty") and
      this.asExpr() = ma // The node is the MethodAccess itself (the call)
    )
  }
}

class CustomPathTraversalConfig extends TaintTracking::Configuration {
  CustomPathTraversalConfig() { this = "CustomPathTraversalConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof FlowSources::CommandLineArgs or // Original source
    source instanceof PropertiesValueSource           // Our new custom source
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(Expr fileAccessExpr | PathManipulation.isFileSystemAccess(fileAccessExpr) and
      sink.asExpr() = fileAccessExpr)
  }
}

from CustomPathTraversalConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Untrusted data from ($@) flows to a file system access operation ($@).",
  source.getNode(), source.getNode().getLocation().toStringWithFile(),
  sink.getNode(), sink.getNode().getLocation().toStringWithFile()
```

### 3. Run the Customized Query

```shell
codeql query run \
  --database=../day10/my-java-db \
  --search-path=/path/to/your/ql-packs \
  my-codeql-queries/CustomPathTraversal.ql \
  --output=custom-path-results.sarif
```
This query should now find two paths:
1.  The original path from the command-line argument.
2.  The new path from `props.getProperty("userFilePath")` to `ex.readFile(configPath)`.

## Customizing CodeQL Queries

1.  **Identify the Target Query:** Start with a standard query that's close to what you need. If none exists, you'll write one from scratch, but often you can adapt.
2.  **Understand its Logic:** Read the QL source. Pay attention to its `isSource`, `isSink`, `isSanitizer` predicates if it's a taint tracking query. Use the VS Code extension to explore QL classes and predicates.
3.  **Define New Elements (Sources, Sinks, Sanitizers, etc.):**
    *   **Create QL Classes:** If you need to model a specific type of code element not well-represented by existing QL classes, define your own.
        *   `class MyCustomSource extends DataFlow::Node { ... }`
        *   The characteristic predicate (constructor `MyCustomSource() { ... }`) defines what AST/data flow nodes belong to this class.
    *   **Write Predicates:** Encapsulate logic for identifying these new elements.
4.  **Modify the Configuration:**
    *   Copy the original query file to your custom query pack/directory.
    *   In your `TaintTracking::Configuration` (or other relevant config class):
        *   Update `isSource`, `isSink`, or `isSanitizer` to include your new QL classes or predicates.
        *   Example: `override predicate isSource(DataFlow::Node source) { super.isSource(source) or source instanceof MyCustomSource }` (if extending a config that already has sources).
5.  **Test Thoroughly:** Run your modified query on various code samples (both vulnerable and non-vulnerable) to ensure it's accurate and doesn't introduce too many false positives/negatives.

## Structuring Custom Queries

*   **Use QL Packs:** Organize your custom queries into your own QL pack. Create a `qlpack.yml` file. This helps manage dependencies and makes your queries usable by others.
    ```yaml
    # my-custom-pack/qlpack.yml
    name: my-org/my-custom-queries
    version: 0.1.0
    library: false # True if it's a library pack, false if it's a query pack
    dependencies:
      codeql/java-all: "*" # Or specific version range
      # other packs your queries depend on
    extractor: java
    ```
*   **Clear Naming:** Use descriptive names for files, queries (`@name`, `@id`), classes, and predicates.
*   **Documentation:** Add QLDoc comments (like `/** ... */`) to explain what your queries, classes, and predicates do.
*   **Modularity:** Use predicates and classes to keep queries clean and reusable.

## Contributing to CodeQL

*   **GitHub:** The CodeQL queries are open source on GitHub (`github/codeql`).
*   **Process:** Contributions typically involve:
    1.  Forking the `github/codeql` repository.
    2.  Making your changes or additions (new queries, improvements to existing ones).
    3.  Adding tests for your queries.
    4.  Submitting a Pull Request.
*   **Guidelines:** Follow the contribution guidelines in the CodeQL repository regarding coding style, testing, and documentation.
*   **Community:** Engage with the CodeQL community on GitHub discussions or other forums.

Customizing queries allows you to tailor CodeQL to your specific codebase, frameworks, and security requirements, significantly enhancing its effectiveness.

---
[Back to Main README](../README.md)
