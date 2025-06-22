# Day 13: Taint Tracking with CodeQL

**Summary:** Taint tracking is a powerful CodeQL feature for finding vulnerabilities like SQL injection, XSS, command injection, etc. It involves identifying "sources" of untrusted data, "sinks" where this data could cause harm, and "sanitizers" that make the data safe. We'll write a basic taint tracking query.

**Today's Focus:** Writing a QL query to find potential Path Traversal vulnerabilities in our Java example by tracking data flow from a command-line argument (source) to a file access operation (sink).

## Prerequisites

*   Day 12 setup: CodeQL CLI, Java database (`my-java-db`), QL libraries.
*   `my-java-app` from Day 10, specifically the `readFile` method and its usage in `main`.

## Try it yourself

### 1. Create Taint Tracking Query File (`PathTraversal.ql`)

Create `my-codeql-queries/PathTraversal.ql`:

```ql
/**
 * @name Potential Path Traversal
 * @description Finds potential path traversal vulnerabilities where user input
 *              from command line arguments flows into file access operations.
 * @kind path-problem
 * @id java/example/path-traversal
 * @problem.severity warning
 * @precision high
 * @tags security external/cwe/cwe-022
 */
import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.PathTraversal

// Define a configuration for taint tracking
class PathTraversalConfig extends TaintTracking::Configuration {
  PathTraversalConfig() { this = "PathTraversalConfig" }

  // Define sources of tainted data
  override predicate isSource(DataFlow::Node source) {
    // Source: command-line arguments to main method
    exists(Method m, Parameter p |
      m.hasName("main") and
      m.isStatic() and // main method is static
      p = m.getParameter(0) and // String[] args
      source.asParameter() = p.getVariable().getAnAccess().getArrayElement() // Treat each element of args array as a source
    )
    // Alternative: Use RemoteFlowSource for web app inputs, etc.
    // For this example, args[0] is our source via Example.java's main.
    // More precisely, we can use a standard RemoteFlowSource if we model args as remote.
    // Or, more simply for this CLI example:
    // source instanceof RemoteFlowSource and source.toString().matches("%args%")
  }

  // Define sinks where tainted data is dangerous
  override predicate isSink(DataFlow::Node sink) {
    // Sink: argument to 'new File(path)' or similar file system operations
    // Using the predefined FileSystemAccess sink from the standard library for simplicity
    exists(Expr arg | PathManipulation.isFileSystemAccess(arg) and sink.asExpr() = arg)
  }

  // Optional: Define sanitizers (not used in this basic example)
  // override predicate isSanitizer(DataFlow::Node node) { ... }
}

// Run the taint tracking query
from PathTraversalConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Untrusted data from command line argument $@ flows to a file system access operation $@",
  source.getNode(), source.getNode().toString(),
  sink.getNode(), sink.getNode().toString()

```
*Note: The source definition for command-line arguments can be tricky. The provided one is an attempt. A simpler, broader source for `args[0]` in `Example.main` would be `source.asParameter() = mainMethod.getParameter(0).getVariable().getAnAccess().getArrayElement()` where `mainMethod` is specifically `Example.main`. The standard library often provides `RemoteFlowSource` which can model various inputs.*

A more direct way to model the source for our specific `Example.java`:
```ql
// ... imports ...
class PathTraversalConfig extends TaintTracking::Configuration {
  PathTraversalConfig() { this = "PathTraversalConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(MethodAccess ma, Method mainMethod |
      mainMethod.getDeclaringType().hasQualifiedName("com.example.sast", "Example") and
      mainMethod.hasName("main") and
      // Source is the first argument to 'performAction' or 'readFile' if called from main
      // and that argument originates from args[0]
      // This requires looking at data flow *into* these calls.
      // For a simpler direct source:
      // The expression `args[0]` in the main method.
      exists(Parameter p | p = mainMethod.getParameter(0) and source.asExpr() = p.getAnAccess().(ArrayAccess).getArrayElement(0))
    )
  }
  // ... isSink remains the same ...
}
// ... from ... where ... select ...
```
The library `semmle.code.java.dataflow.FlowSources` already defines `CommandLineArgs` as a source. We can use that.

Refined `PathTraversal.ql` using `FlowSources.CommandLineArgs`:
```ql
/**
 * @name Potential Path Traversal from Command Line
 * @description Finds potential path traversal vulnerabilities where user input
 *              from command line arguments flows into file system operations.
 * @kind path-problem
 * @id java/example/command-line-path-traversal
 * @problem.severity warning
 * @precision high
 * @tags security external/cwe/cwe-022
 */
import java
import semmle.code.java.dataflow.FlowSources // For CommandLineArgs
import semmle.code.java.security.PathTraversal // For PathManipulation.isFileSystemAccess

// Define a configuration for taint tracking
class CmdLinePathTraversalConfig extends TaintTracking::Configuration {
  CmdLinePathTraversalConfig() { this = "CmdLinePathTraversalConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof FlowSources::CommandLineArgs // Data from command line arguments
  }

  override predicate isSink(DataFlow::Node sink) {
    // Argument to a method that constructs a path or accesses the file system
    exists(Expr arg | PathManipulation.isFileSystemAccess(arg) and sink.asExpr() = arg)
  }
}

// Run the taint tracking query
from CmdLinePathTraversalConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Untrusted data from command line argument ($@) flows to a file system access operation ($@).",
  source.getNode(), source.getNode().getLocation().toString(),
  sink.getNode(), sink.getNode().getLocation().toString()

```

### 2. Run the Query

```shell
# Ensure my-java-db exists from Day 10
# Adjust --search-path to your QL packs or CodeQL repo clone

codeql query run \
  --database=../day10/my-java-db \
  --search-path=/path/to/your/ql-packs \
  my-codeql-queries/PathTraversal.ql
```
This query should find a path from `args[0]` in `Example.main` to the `fileName` parameter of `ex.readFile(name + "_report.txt")` which is then used in `new File(fileName)`.

## CodeQL Taint Tracking Explained

*   **Core Idea:** Track the flow of data from potentially untrusted "sources" to sensitive "sinks." If data flows without proper "sanitization," it's a vulnerability.
*   **`import semmle.code.java.dataflow.FlowSources`**: Provides standard definitions for various sources of untrusted input (e.g., command line, network, file).
*   **`import semmle.code.java.security.PathTraversal`**: Provides helpers like `PathManipulation.isFileSystemAccess` for identifying sinks related to file system access. Many other security libraries exist (e.g., for SQLi, XSS).
*   **`TaintTracking::Configuration`**: A special class you extend to define your taint tracking analysis.
    *   **`isSource(DataFlow::Node source)`**: A predicate you override to define what counts as a source of tainted data. `DataFlow::Node` represents an element in the program that can have a value (e.g., a parameter, an expression).
    *   **`isSink(DataFlow::Node sink)`**: A predicate you override to define what counts as a sink.
    *   **`isSanitizer(DataFlow::Node node)` (Optional):** A predicate to define nodes that, if data flows through them, render it safe for a particular sink.
*   **`DataFlow::PathNode`**: Represents a node along a data flow path.
*   **`cfg.hasFlowPath(source, sink)`**: This is the magic call. It uses the CodeQL engine's data flow analysis capabilities to find if there's a path from any `source` node (defined by `isSource`) to any `sink` node (defined by `isSink`), respecting any sanitizers.
*   **`@kind path-problem`**: This tells CodeQL that the query results represent a path from a source to a sink. IDEs and GitHub will display these paths.
*   **`select sink.getNode(), source, sink, "Message with $@", source.getNode(), "source description", sink.getNode(), "sink description"`**:
    *   The `select` statement for `path-problem` queries has a specific structure.
    *   `sink.getNode()`: The primary location of the problem (the sink).
    *   `source`: The source `PathNode`.
    *   `sink`: The sink `PathNode`.
    *   The string message: Can use placeholders like `$@` which will be filled with information about the nodes (e.g., their string representation or location). The subsequent arguments fill these placeholders.

**In our `PathTraversal.ql`:**
*   **Source:** `FlowSources::CommandLineArgs` - any data coming from command line arguments. In `Example.java`, this is `args` in `main`.
*   **Sink:** `PathManipulation.isFileSystemAccess(arg)` - expressions used in file system operations like `new File(path)`, `Files.newInputStream(path)`, etc. In `Example.java`, this is the argument to `new File(fileName)` in the `readFile` method.

The query should detect that `args[0]` (source) flows into `name`, which then flows into `fileName` (via `name + "_report.txt"`), which is then used in `new File(fileName)` (sink).

Taint tracking is one of CodeQL's most powerful features for security analysis. The standard libraries provide many pre-defined sources, sinks, and configurations for common vulnerability patterns.

---
[Back to Main README](../README.md)
