# Day 12: Understanding CodeQL Predicates and Classes

**Summary:** To write more powerful CodeQL queries, we need to understand predicates (custom logic/functions) and classes (custom types). Predicates help encapsulate complex conditions, and classes allow us to model specific code elements relevant to our analysis.

**Today's Focus:** Refactoring Day 11's queries to use predicates and introducing simple custom QL class concepts. We'll find method calls to `System.out.println`.

## Prerequisites

*   Day 11 setup: CodeQL CLI, Java database (`my-java-db`), QL libraries.
*   `my-java-app` from Day 10.

## Try it yourself

### 1. Create Query File with Predicates (`FindPrintlnCalls.ql`)

Create `my-codeql-queries/FindPrintlnCalls.ql` (you can reuse the `my-codeql-queries` directory):

```ql
/**
 * @name Find System.out.println calls
 * @description Finds all method calls to System.out.println() using predicates.
 * @kind points-to
 * @id java/example/find-println-calls
 * @tags examples predicates classes
 */
import java

// Predicate to check if a MethodCall 'mc' is a call to "println"
predicate isPrintlnCall(MethodCall mc) {
  mc.getMethod().hasName("println") and
  mc.getQualifier().toString().matches("System.out") // Check the qualifier is System.out
  // More robust check for qualifier:
  // exists(FieldAccess fa | fa = mc.getQualifier() and
  //   fa.getField().hasName("out") and
  //   fa.getQualifier().(TypeNameAccess).getType().hasQualifiedName("java.lang", "System")
  // )
}

// Another way: Predicate to check if a Method 'm' is the "println" method of "System.out"
predicate isSystemOutPrintlnMethod(Method m) {
  m.hasName("println") and
  m.getDeclaringType().hasQualifiedName("java.io", "PrintStream") and
  // Further check that this PrintStream is indeed System.out (can be complex)
  // For simplicity, the check on MethodCall's qualifier is often easier for direct calls.
  // This predicate is more about identifying the target method itself.
  exists(FieldAccess fa |
    fa.getField().hasName("out") and
    fa.getQualifier().(TypeNameAccess).getType().hasQualifiedName("java.lang", "System") and
    m.getDeclaringType() = fa.getType() // Check if method's type matches field's type
  )
}


from MethodCall mc // Variable 'mc' of type MethodCall
where
  // Call the predicate to filter method calls
  isPrintlnCall(mc)
  // Alternatively, if isSystemOutPrintlnMethod was fully robust for specific System.out:
  // isSystemOutPrintlnMethod(mc.getMethod())
select mc, "Call to System.out.println: " + mc.getArgument(0).toString()
```

### 2. Run the Query

```shell
# Ensure my-java-db exists from Day 10
# Adjust --search-path to your QL packs or CodeQL repo clone

codeql query run \
  --database=../day10/my-java-db \
  --search-path=/path/to/your/ql-packs \
  my-codeql-queries/FindPrintlnCalls.ql
```
This query should identify all calls to `System.out.println` in `Example.java`.

## CodeQL Predicates and Classes Explained

### Predicates

*   **Definition:** A predicate is like a function or a reusable condition in QL. It groups logic that can be called multiple times.
*   **Syntax:**
    ```ql
    // Predicate without arguments that evaluates to true or false
    predicate name() {
      // conditions
      this.isSomething() and this.isSomethingElse() // 'this' refers to the variable it's called on
    }

    // Predicate with arguments
    predicate name(Type1 arg1, Type2 arg2, ...) {
      // conditions involving arg1, arg2, etc.
      arg1.getProperty() = arg2.getAnotherProperty()
    }
    ```
*   **Usage:** Predicates are used in `where` clauses or within other predicates to make queries more readable and modular.
*   **`isPrintlnCall(MethodCall mc)` Example:**
    *   Takes a `MethodCall` object `mc` as input.
    *   `mc.getMethod().hasName("println")`: Checks if the called method's name is "println".
    *   `mc.getQualifier().toString().matches("System.out")`: Checks if the object or class on which the method is called (the qualifier) converts to the string "System.out". This is a simpler but potentially less robust way. The commented-out section shows a more precise way by checking the field `out` of class `System`.

### QL Classes (Introduction)

*   **Concept:** QL is object-oriented. You can define your own classes that extend existing QL classes (like `MethodCall`, `Class`, `Expr`). This allows you to create more specific types for your analysis.
*   **Purpose:**
    *   To group related entities that share common characteristics relevant to your query.
    *   To associate specific predicates (member predicates) with these entities.
*   **Simple Example (Conceptual - we'll build on this later):**
    Imagine you want to define a "LoggerCall" class that represents calls to various logging methods (`log.info`, `logger.debug`, etc.).

    ```ql
    // Conceptual LoggerCall class
    class LoggerCall extends MethodCall {
      LoggerCall() { // Characteristic predicate (constructor)
        // 'this' refers to an instance of MethodCall
        (
          this.getMethod().hasName("info") or
          this.getMethod().hasName("debug") or
          this.getMethod().hasName("error")
        ) and
        // And the method is declared in a class whose name contains "Logger"
        this.getMethod().getDeclaringType().getName().matches("%Logger%")
      }

      // Member predicate to get the log message
      Expr getLogMessage() {
        result = this.getArgument(0) // Assuming message is the first argument
      }
    }

    // Then you could query:
    // from LoggerCall lc
    // select lc, lc.getLogMessage()
    ```

**Benefits of Predicates and Classes:**

*   **Modularity:** Break down complex queries into smaller, manageable pieces.
*   **Readability:** Make queries easier to understand by giving names to complex conditions or specialized types.
*   **Reusability:** Define a predicate or class once and use it in multiple queries.

In the `FindPrintlnCalls.ql` query, `isPrintlnCall` is a predicate that encapsulates the logic for identifying a specific type of method call. This makes the `from-where-select` part of the query cleaner. We'll explore custom QL classes more deeply when we get to taint tracking.

---
[Back to Main README](../README.md)
