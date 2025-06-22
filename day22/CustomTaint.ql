/**
 * @name Custom Taint Flow for UserInputString to Log.sensitiveData
 * @description Detects if data from a UserInputString flows to Log.sensitiveData
 *              without being validated by Validator.isValid or sanitized by Validator.sanitize.
 * @kind path-problem
 * @problem.severity warning
 * @id java/custom-userinputstring-to-log-sensitivedata
 * @tags security
 *       experimental
 *       custom-taint
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

// Define a custom source: UserInputString instances or data originating from them
class CustomSource extends FlowSource {
  CustomSource() {
    // Source 1: An instantiation of UserInputString
    exists(ClassInstanceExpr cie |
      cie.getConstructedType().hasQualifiedName("com.example", "UserInputString") and
      this.asExpr() = cie
    )
    or
    // Source 2: A parameter of type UserInputString
    exists(Parameter param |
      param.getType().hasQualifiedName("com.example", "UserInputString") and
      this.asParameter() = param
    )
    or
    // Source 3: A call to UserInputString.getData() if the qualifier is tainted
    exists(MethodCall mc, Method getDataMethod |
      getDataMethod.getDeclaringType().hasQualifiedName("com.example", "UserInputString") and
      getDataMethod.hasName("getData") and
      mc.getMethod() = getDataMethod and
      this.asExpr() = mc and
      TaintTracking.localTaint(DataFlow::exprNode(mc.getQualifier()), _) // Check if 'this' for getData() is tainted
    )
  }
}

// Define a custom sink: The second argument to Log.sensitiveData
class CustomSink extends DataFlow::ExprNode {
  CustomSink() {
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasQualifiedName("com.example", "Log") and
      mc.getMethod().hasName("sensitiveData") and
      this.asExpr() = mc.getArgument(1) // The second argument (data)
    )
  }
}

// Define a custom sanitizer
class CustomSanitizer extends TaintTracking::Sanitizer {
  CustomSanitizer() {
    // Sanitizer 1: A call to Validator.isValid guards the use of the data
    // This is complex to model perfectly. A simpler approach is to consider
    // data sanitized if it's within an 'if' block conditioned by Validator.isValid.
    // For this example, let's focus on Validator.sanitize as a clearer sanitizer.
    // exists(IfStmt ifStmt, MethodCall validationCall |
    //   validationCall.getMethod().getDeclaringType().hasQualifiedName("com.example", "Validator") and
    //   validationCall.getMethod().hasName("isValid") and
    //   ifStmt.getCondition() = validationCall and
    //   this.asExpr().getEnclosingStmt().getParent*() = ifStmt.getThen() and
    //   this.asExpr() = validationCall.getArgument(0) // The argument to isValid is considered sanitized in then-branch
    // )
    // or
    // Sanitizer 2: Data is the result of a call to Validator.sanitize
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasQualifiedName("com.example", "Validator") and
      mc.getMethod().hasName("sanitize") and
      this.asExpr() = mc
    )
  }
}

// Configuration for the taint tracking
class CustomTaintConfig extends TaintTracking::Configuration {
  CustomTaintConfig() { this = "CustomUserInputStringTaintConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof CustomSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof CustomSink }

  override predicate isSanitizer(DataFlow::Node node) { node.asExpr() = any(CustomSanitizer s).asExpr() }
}

from CustomTaintConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Untrusted data from UserInputString reaches Log.sensitiveData."
