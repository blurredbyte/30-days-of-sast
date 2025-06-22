/**
 * @name Find all string literals
 * @description This query finds all string literals (e.g., "hello") in the Java codebase.
 *              It's useful for identifying hardcoded secrets (though needs refinement for that),
 *              or just exploring string usage.
 * @kind table // Results are best viewed as a table.
 * @id java/examples/basic/find-all-string-literals
 * @tags examples basic exploration strings
 */

import java // Import the standard Java library for CodeQL

// 'StringLiteral' is a QL class representing a string literal in the source code.
// 'sl' is a variable that will iterate over all string literals.
from StringLiteral sl
// No 'where' clause means we select all string literals.
// 'select' determines the output.
// We select the string literal element, its actual string value, and its location.
select sl, // The StringLiteral element itself (links to code location)
       sl.getValue(), // The actual content of the string
       sl.getLocation().getStartLine(), // Start line
       sl.getLocation().getStartColumn() // Start column

// Example output for code like `String greeting = "Hello, World!";`:
// | sl              | Value          | Line | Column |
// | --------------- | -------------- | ---- | ------ |
// | "Hello, World!" | Hello, World!  | 5    | 25     |

// To run this query (assuming database `my-java-db` from day10 and ql packs in `~/codeql-packs`):
// codeql query run --database=../day10/my-java-db --search-path=~/codeql-packs my-codeql-queries/FindAllStringLiterals.ql
// Or, to output to CSV:
// codeql query run --database=../day10/my-java-db --search-path=~/codeql-packs --output=string_literals.csv my-codeql-queries/FindAllStringLiterals.ql
