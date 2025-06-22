/**
 * @name Potential Path Traversal from Command Line or Config File
 * @description Finds potential path traversal vulnerabilities where user input
 *              originating from command line arguments OR from a value read from
 *              a properties file flows into file system operations.
 *              This query demonstrates customizing a taint tracking configuration
 *              by adding a new source type.
 * @kind path-problem
 * @id java/examples/security/custom-path-traversal
 * @problem.severity warning
 * @precision medium
 * @tags security external/cwe/cwe-022 path-traversal custom-source
 */

import java
import semmle.code.java.dataflow.FlowSources // For standard CommandLineArgs
import semmle.code.java.security.PathTraversal // For standard path traversal sinks
import DataFlow::PathGraph // Required for path-problem queries

/**
 * Defines a QL class `PropertiesValueSource` that represents data flow nodes
 * originating from the return value of `java.util.Properties.getProperty()`.
 * This will be our custom taint source.
 */
class PropertiesValueSource extends DataFlow::Node {
  PropertiesValueSource() {
    // `this` refers to a DataFlow::Node.
    // We are looking for method calls to `getProperty` on an object of type `java.util.Properties`.
    // The DataFlow::Node is the result of this call.
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().getASourceSupertype*().hasQualifiedName("java.util", "Properties") and
      ma.getMethod().hasName("getProperty") and
      this.asExpr() = ma // The node `this` is the expression representing the method call itself.
    )
  }
}

/**
 * Our custom taint tracking configuration.
 * It includes the standard command line arguments source and our new `PropertiesValueSource`.
 */
class CustomPathTraversalConfig extends TaintTracking::Configuration {
  CustomPathTraversalConfig() {
    this = "CustomPathTraversalConfig" // Unique name for the configuration
  }

  /**
   * Defines sources of tainted data.
   * It includes command line arguments and values read from Properties.getProperty().
   */
  override predicate isSource(DataFlow::Node source) {
    source instanceof FlowSources::CommandLineArgs or // Standard source
    source instanceof PropertiesValueSource           // Our custom source
  }

  /**
   * Defines sinks where tainted data can cause harm.
   * We use the standard `PathManipulation.isFileSystemAccess` to identify file system sinks.
   */
  override predicate isSink(DataFlow::Node sink) {
    exists(Expr fileSystemAccessExpr |
      PathManipulation.isFileSystemAccess(fileSystemAccessExpr) and
      sink.asExpr() = fileSystemAccessExpr
    )
  }

  /**
   * Optional: isSanitizer can be overridden here if needed.
   * For example, if we knew a specific method that validates and cleans paths.
   * override predicate isSanitizer(DataFlow::Node node) { ... }
   */
}

// Main query: Find paths from sources to sinks using our custom configuration.
from
  CustomPathTraversalConfig config, // An instance of our configuration
  DataFlow::PathNode sourceNode,    // The source node of a detected path
  DataFlow::PathNode sinkNode       // The sink node of a detected path
where
  config.hasFlowPath(sourceNode, sinkNode) // Check if a tainted path exists
select
  // Standard select clause for path-problem queries:
  sinkNode.getNode(), sourceNode, sinkNode,
  "Potential path traversal: Data from source ($@) flows to a file system access ($@) without validated sanitization.",
  sourceNode.getNode(), sourceNode.getNode().getLocation().toStringWithFile(), // For the first $@
  sinkNode.getNode(), sinkNode.getNode().getLocation().toStringWithFile()     // For the second $@

// To run this query:
// 1. Ensure `day10/my-java-app/Example.java` has been updated with `getPathFromConfig`
//    and the main method calls it, then rebuild the database for `day10/my-java-db`.
//    Example rebuild command (run from `day15` or similar):
//    codeql database create ../day10/my-java-db --language=java --source-root=../day10/my-java-app --search-path=/path/to/your/ql-packs --overwrite
//
// 2. Run the query:
//    codeql query run --database=../day10/my-java-db --search-path=/path/to/your/ql-packs my-codeql-queries/CustomPathTraversal.ql
//
// Expected behavior:
// - It should find the original path from command-line arguments (args[0] -> name -> readFile).
// - It should also find the new path:
//   props.getProperty("userFilePath") [source] -> configPath -> ex.readFile(configPath) [sink: new File(fileName) inside readFile]
//
// Note: The `PropertiesValueSource` models the *call* to `getProperty` as the source.
// CodeQL's data flow will then track the return value of this call.
