/**
 * @name Find System.out.println calls
 * @description This query identifies all method calls to `System.out.println()`
 *              in a Java codebase. It demonstrates the use of predicates to encapsulate
 *              checking logic, making the main query body cleaner.
 * @kind points-to  // Results will point to specific locations in the code.
 * @id java/examples/preds/find-system-out-println-calls
 * @tags examples predicates methods java
 */

import java

/**
 * A predicate that holds if the given method call `mc` is a call to a method named "println"
 * and the qualifier of the call (the part before `.println`) is `System.out`.
 */
predicate isSystemOutPrintlnCall(MethodCall mc) {
  // Check if the method being called is named "println"
  mc.getMethod().hasName("println")
  and
  // Check if the qualifier of the method call is `System.out`.
  // `getQualifier()` returns the expression on which the method is called.
  // For `System.out.println()`, `mc.getQualifier()` refers to `System.out`.
  // `System.out` is a field access (`out`) on a type access (`System`).
  exists(FieldAccess fa | fa = mc.getQualifier() |
    fa.getField().hasName("out") // The field being accessed is named "out"
    and
    // The qualifier of the field access `fa.getQualifier()` should be the type `System`.
    // `getType()` on a `TypeNameAccess` gives the `Type` itself.
    fa.getQualifier().(TypeNameAccess).getType().hasQualifiedName("java.lang", "System")
  )
}

/**
 * An alternative predicate to check if a `Method` entity `m` is specifically
 * the `println` method belonging to `java.io.PrintStream` (which is the type of `System.out`).
 * This is a more abstract check on the method itself, not the call site.
 */
predicate isAPrintlnMethodOfPrintStream(Method m) {
  m.hasName("println") and
  m.getDeclaringType().getASourceSupertype*().hasQualifiedName("java.io", "PrintStream")
  // getASourceSupertype*() includes the type itself and all its supertypes.
}

// Main query logic
from MethodCall mc // For every method call `mc` in the database
where
  // Use our custom predicate to filter for calls to System.out.println
  isSystemOutPrintlnCall(mc)
  // Alternatively, if we wanted to find calls to any println method of a PrintStream:
  // isAPrintlnMethodOfPrintStream(mc.getMethod())
select mc, "This is a call to System.out.println with argument: " + mc.getArgument(0).toString()
// We select the method call `mc` itself (which links to the source code)
// and a message that includes the first argument to println.

// To run this query (assuming database `my-java-db` from day10 and ql packs in `~/codeql-packs`):
// codeql query run --database=../day10/my-java-db --search-path=~/codeql-packs my-codeql-queries/FindPrintlnCalls.ql

// Notes on robustness:
// - `isSystemOutPrintlnCall` is quite specific to the `System.out.println` pattern.
// - If `System.out` were assigned to another variable `PrintStream myOut = System.out;`
//   and then `myOut.println()` was called, `isSystemOutPrintlnCall` would not find it directly
//   without further data flow analysis (which CodeQL excels at, for later days!).
// - `isAPrintlnMethodOfPrintStream` is broader and would identify `myOut.println()` if `myOut` is of type `PrintStream`.
//   However, it wouldn't confirm that `myOut` is *specifically* `System.out`.
// For security queries, precisely tracking data flow from sources to sinks is key. These structural
// queries are foundational steps.
