/**
 * @name Potential Path Traversal from Command Line Argument
 * @description This query identifies potential path traversal vulnerabilities where
 *              data originating from command line arguments is used in file system
 *              access operations without proper sanitization.
 * @kind path-problem // Indicates that the query traces a path from a source to a sink.
 * @id java/examples/security/command-line-path-traversal
 * @problem.severity warning
 * @precision medium // Precision can be low, medium, high. Adjust based on expected false positives.
 * @tags security external/cwe/cwe-022 external/cwe/cwe-023 external/cwe/cwe-036 external/cwe/cwe-073
 *       path-traversal command-line-input
 */

import java
// Import standard CodeQL libraries for data flow and security analysis.
import semmle.code.java.dataflow.FlowSources // Defines common sources of untrusted data.
import semmle.code.java.security.PathTraversal // Defines path traversal sinks and sanitizers.
import DataFlow::PathGraph // Required for path-problem queries to select paths.

/**
 * Defines the configuration for our taint tracking analysis.
 * We extend `TaintTracking::Configuration` to specify our sources and sinks.
 */
class CommandLineToPathTraversalConfig extends TaintTracking::Configuration {
  CommandLineToPathTraversalConfig() {
    // A unique name for this configuration.
    this = "CommandLineToPathTraversalConfig"
  }

  /**
   * Overrides `isSource` to define what we consider as sources of tainted data.
   * In this case, we use a predefined source type from the standard library:
   * `FlowSources::CommandLineArgs` represents data coming from command line arguments.
   */
  override predicate isSource(DataFlow::Node source) {
    source instanceof FlowSources::CommandLineArgs
  }

  /**
   * Overrides `isSink` to define where tainted data could cause harm.
   * We use `PathManipulation.isFileSystemAccess(expr)` from the standard PathTraversal library.
   * This predicate identifies expressions that are used as arguments to file system operations
   * (e.g., arguments to `new File(path)`, `Files.newInputStream(Paths.get(path))`, etc.).
   */
  override predicate isSink(DataFlow::Node sink) {
    exists(Expr gefährlicheExpr |
      PathManipulation.isFileSystemAccess(gefährlicheExpr) and
      sink.asExpr() = gefährlicheExpr
    )
  }

  /**
   * Optional: Override `isSanitizer` to define nodes that sanitize tainted data.
   * For this basic example, we are not defining any custom sanitizers.
   * The `PathTraversal` library itself might define some default sanitizers.
   * Example:
   * override predicate isSanitizer(DataFlow::Node node) {
   *   node.getType().hasName("String") and
   *   exists(MethodAccess ma | ma.getMethod().hasName("getCanonicalPath") |
   *     node.asExpr() = ma // If the node is the result of getCanonicalPath
   *   )
   * }
   */
}

// The main part of the query.
from
  CommandLineToPathTraversalConfig config, // An instance of our configuration.
  DataFlow::PathNode sourceNode, // A node on the path identified as a source.
  DataFlow::PathNode sinkNode    // A node on the path identified as a sink.
where
  // `config.hasFlowPath(sourceNode, sinkNode)` is true if the analysis finds a path
  // from a `sourceNode` to a `sinkNode` according to our `config`.
  config.hasFlowPath(sourceNode, sinkNode)
select
  // For `path-problem` queries, the `select` statement has a specific structure:
  // 1. The element to highlight in the code for the alert (usually the sink).
  // 2. The source `PathNode`.
  // 3. The sink `PathNode`.
  // 4. A message string describing the problem. Placeholders `$@` are filled by subsequent arguments.
  // 5. Subsequent arguments provide data for the placeholders in the message.
  sinkNode.getNode(), sourceNode, sinkNode,
  "Potential path traversal: Untrusted data from command line argument ($@) " +
  "is used to construct a file path ($@) without proper sanitization.",
  sourceNode.getNode(), sourceNode.getNode().getLocation().toStringWithFile(), // Placeholder 1: Source node and its location
  sinkNode.getNode(), sinkNode.getNode().getLocation().toStringWithFile()     // Placeholder 2: Sink node and its location

// How this applies to `day10/my-java-app/Example.java`:
// 1. `FlowSources::CommandLineArgs` will identify `args` in `main(String[] args)` as a source.
//    Specifically, an element like `args[0]` when accessed.
// 2. In `main`, `name = args[0]` taints `name`.
// 3. `ex.readFile(name + "_report.txt")` passes the tainted `name` (concatenated) to `readFile`.
// 4. Inside `readFile(String fileName)`, `fileName` is now tainted.
// 5. `new File(fileName)` is a file system access. `PathManipulation.isFileSystemAccess(fileName)`
//    will identify `fileName` (as used in `new File(fileName)`) as a sink.
// 6. CodeQL's data flow analysis connects `args[0]` to `fileName` in `new File(fileName)`.
//
// To run (assuming database `my-java-db` from day10 and ql packs in `~/codeql-packs`):
// codeql query run --database=../day10/my-java-db --search-path=~/codeql-packs my-codeql-queries/PathTraversal.ql
//
// To view results nicely, especially path queries, use the CodeQL extension in VS Code,
// or output to SARIF and view in GitHub (if GHAS enabled) or other SARIF viewers.
// codeql query run --database=../day10/my-java-db --search-path=~/codeql-packs --output=paths.sarif my-codeql-queries/PathTraversal.ql
