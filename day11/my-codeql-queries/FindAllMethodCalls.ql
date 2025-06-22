/**
 * @name Find all method calls
 * @description This query finds all explicit method calls in the Java codebase.
 *              It demonstrates basic QL syntax: import, from, select.
 * @kind table  // Results are best viewed as a table. 'points-to' could also be used to link to code.
 * @id java/examples/basic/find-all-method-calls
 * @tags examples basic exploration
 */

import java // Import the standard Java library for CodeQL

// 'from' declares variables that range over elements in the CodeQL database.
// 'MethodCall' is a QL class representing a call to a method.
// 'mc' is a variable that will, in turn, refer to each method call in the database.
from MethodCall mc
// There is no 'where' clause, so we are selecting all method calls.
// 'select' determines what the query outputs for each 'mc' found.
// We select the method call itself and a descriptive string.
// The first selected element (mc) will be linked to its location in the source code by IDEs.
select mc, // The method call element
       mc.getMethod().getDeclaringType().getFullName() + "." + mc.getMethod().getName() + "()", // Formatted method name
       mc.getLocation().getStartLine(), // Start line of the call
       mc.getLocation().getStartColumn() // Start column of the call
       // mc.getArgument(int index) // Can be used to get arguments
       // mc.getQualifier() // Can be used to get the object or class on which the method is called
// Example output for a call like `System.out.println("Hello")`:
// | mc                      | Method Name        | Line | Column |
// | ----------------------- | ------------------ | ---- | ------ |
// | System.out.println(...) | java.io.PrintStream.println | 10   | 8      |

// To run this query (assuming database `my-java-db` from day10 and ql packs in `~/codeql-packs`):
// codeql query run --database=../day10/my-java-db --search-path=~/codeql-packs my-codeql-queries/FindAllMethodCalls.ql
// Or, to output to CSV:
// codeql query run --database=../day10/my-java-db --search-path=~/codeql-packs --output=method_calls.csv my-codeql-queries/FindAllMethodCalls.ql
