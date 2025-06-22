# Day 18: SAST for Java - Spotting Vulnerabilities in Spring Boot

**Summary:** We'll look at SAST for Java applications, particularly those built with the Spring Boot framework. Common vulnerabilities include SQL Injection (especially with native queries or string concatenation in JPQL/HQL), XSS, Insecure Deserialization, SSRF, and misconfigurations in Spring Security.

**Today's Focus:** Writing CodeQL queries to detect potential SQL Injection in Spring Data JPA when using concatenated strings in `@Query` annotations, and identifying potential XSS from model attributes rendered in Thymeleaf templates without proper escaping (conceptual).

## Prerequisites

*   CodeQL CLI, Java database (`my-java-db` from Day 10, or create a new one for the Spring Boot example), QL libraries.

## Try it yourself

### 1. Create a Simple Spring Boot Application (`spring-sast-demo`)

It's best to use a small, self-contained Spring Boot project.
**`pom.xml` (Maven project file):**
```xml
<!-- spring-sast-demo/pom.xml -->
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example.sast</groupId>
    <artifactId>spring-sast-demo</artifactId>
    <version>0.0.1-SNAPSHOT</version>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.7.5</version> <!-- Or a more recent stable version -->
        <relativePath/>
    </parent>
    <properties>
        <java.version>11</java.version>
    </properties>
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-thymeleaf</artifactId>
        </dependency>
        <dependency>
            <groupId>com.h2database</groupId>
            <artifactId>h2</artifactId>
            <scope>runtime</scope>
        </dependency>
    </dependencies>
    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>
</project>
```

**`src/main/java/com/example/sast/DemoApplication.java`:**
```java
// spring-sast-demo/src/main/java/com/example/sast/DemoApplication.java
package com.example.sast;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
// Other imports for entities, repositories, controllers
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.GeneratedValue;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import java.util.List;

@SpringBootApplication
public class DemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }
}

// --- Entity ---
@Entity
class Product {
    @Id @GeneratedValue
    private Long id;
    private String name;
    private String category;
    // getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getCategory() { return category; }
    public void setCategory(String category) { this.category = category; }
}

// --- Repository ---
interface ProductRepository extends JpaRepository<Product, Long> {
    // Vulnerable: String concatenation in @Query (JPQL/HQL)
    @Query("SELECT p FROM Product p WHERE p.category = ?1 AND p.name LIKE CONCAT('%', ?2, '%')") // This is actually safe with positional params
    List<Product> findByCategoryAndNameLikeSafePositional(String category, String namePart);

    // Let's create a clearly vulnerable example with string concatenation for an ORDER BY clause
    // Note: Spring Data JPA typically doesn't allow dynamic ORDER BY like this directly in @Query.
    // This is a bit contrived for @Query, raw JDBC/JPA Criteria API would be more common for such dynamic parts.
    // However, if someone were to build the query string *before* passing to a nativeQuery, it's a risk.
    // For a more realistic @Query vulnerability, consider nativeQuery=true with concatenation.
    @Query(value = "SELECT * FROM product p WHERE p.category = :category ORDER BY :orderByField", nativeQuery = true)
    List<Product> findByCategoryOrderByFieldNativeSafe(@Param("category") String category, @Param("orderByField") String orderByField);

    // Truly VULNERABLE example (conceptual, as Spring Data might prevent this exact syntax for JPQL)
    // This is to illustrate what a CodeQL query might look for: string literals being concatenated
    // into a query string.
    // @Query("SELECT p FROM Product p WHERE p.category = '" + "some_static_category" + "' AND p.name LIKE :namePart") // This is safe concatenation of literals
    // A query would need to find concatenation with *variable* data.
    // For native queries, it's more direct:
    // Assume queryPart is a variable:
    // @Query(value = "SELECT * FROM product p WHERE " + queryPart, nativeQuery = true)
}


// --- Controller ---
@Controller
class ProductController {
    private final ProductRepository productRepository;
    public ProductController(ProductRepository productRepository) {
        this.productRepository = productRepository;
    }

    @GetMapping("/products/search")
    @ResponseBody
    public List<Product> searchProducts(
            @RequestParam String category,
            @RequestParam(required = false, defaultValue = "id") String sort // User controls sort field
    ) {
        // VULNERABLE if sort parameter was used to build a query string via concatenation
        // String queryStr = "SELECT * FROM product WHERE category = '" + category + "' ORDER BY " + sort;
        // For the @Query example, let's assume a method that would take sort
        // This is still safe because :orderByField is a named parameter
        return productRepository.findByCategoryOrderByFieldNativeSafe(category, sort);
    }

    @GetMapping("/product/view")
    public String viewProduct(@RequestParam String name, Model model) {
        // Potential XSS if 'productName' is rendered unescaped in Thymeleaf
        // and originates from 'name' request parameter.
        model.addAttribute("productName", name); // Source: request param 'name'
        model.addAttribute("productDescription", "<script>alert('XSS in description from server')</script>"); // Server-defined, but still risky if unescaped
        return "product_view"; // Assumes product_view.html template
    }
}
```

**`src/main/resources/templates/product_view.html` (Thymeleaf template):**
```html
<!-- spring-sast-demo/src/main/resources/templates/product_view.html -->
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head><title>Product View</title></head>
<body>
    <!-- Safe by default with th:text -->
    <h1>Product: <span th:text="${productName}">Default Name</span></h1>

    <!-- VULNERABLE: th:utext (unescaped text) renders HTML directly -->
    <!-- If productName or productDescription contains malicious script, it will execute -->
    <p>Name (unescaped): <span th:utext="${productName}">Default Name</span></p> <!-- Sink for XSS -->
    <p>Description (unescaped): <div th:utext="${productDescription}">Default Description</div></p> <!-- Sink for XSS -->

    <!-- Safer alternatives -->
    <p>Name (escaped, using data-* attribute then JS): <span id="pname" th:data-productname="${productName}"></span></p>
    <script th:inline="javascript">
      /*<![CDATA[*/
      // var productName = /*[[${productName}]]*/ 'default'; // Inlined JS, Thymeleaf escapes by default
      // document.getElementById('pname').textContent = productName; // Setting as text content is safe

      // If you must use th:data, retrieve and set text content
      var pNameElement = document.getElementById('pname');
      if (pNameElement) {
        pNameElement.textContent = pNameElement.getAttribute('data-productname');
      }
      /*]]>*/
    </script>
</body>
</html>
```

### 2. Create CodeQL Database for the Spring Boot App

```shell
# Navigate to the directory containing the spring-sast-demo project
# cd /path/to/your/projects/

# If an old database exists for this path, you might want to remove it first.
# rm -rf spring-sast-db

codeql database create spring-sast-db \
  --language=java \
  --source-root=spring-sast-demo \
  --command="mvn clean package -DskipTests" \
  --search-path=/path/to/your/ql-packs \
  --overwrite
```
*Replace `/path/to/your/ql-packs` as usual. The `--command` tells CodeQL how to build the Maven project.*

### 3. Create CodeQL Query File (`SpringSqlAndXss.ql`)

```ql
/**
 * @name Potential SQL Injection and XSS in Spring Boot
 * @description Finds potential SQL injection in Spring Data JPA native queries
 *              with string concatenation, and potential XSS vulnerabilities
 *              in Thymeleaf templates using th:utext with request data.
 * @kind path-problem
 * @id java/spring/example/sqli-xss
 * @problem.severity warning
 * @precision medium
 * @tags security spring sql-injection xss
 */
import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.SqlInjection
import semmle.code.java.security.Xss // For XSS sinks related to web frameworks
import semmle.code.java.frameworks.spring.SpringController
import semmle.code.java.frameworks.spring.SpringDataJPA
import semmle.code.java.frameworks.thymeleaf.Thymeleaf // For Thymeleaf XSS
import DataFlow::PathGraph


// --- SQL Injection Configuration for Spring Data JPA Native Queries ---
class SpringJpaNativeSqlConcatenationConfig extends SqlInjection::Configuration {
  SpringJpaNativeSqlConcatenationConfig() { this = "SpringJpaNativeSqlConcatenationConfig" }

  override predicate isSource(DataFlow::Node source) {
    // Source: Parameters of Spring controller methods
    exists(SpringControllerMethod scm | source.asParameter() = scm.getARequestParameter())
  }

  override predicate isSink(DataFlow::Node sink) {
    // Sink: Argument to a native SQL query execution that involves string concatenation
    exists(SpringDataJpaQueryMethod qm, StringConcat sc |
      qm.isNativeQuery() and
      // The query string itself is a concatenation
      sc = qm.getQueryValueElement().(StringLiteral).getEnclosingElement+() and // crude way to check if query string involves concat.
      sink.asExpr() = sc.getAnOperand() and // Sink is an operand of the concatenation
      // Ensure this concatenation is part of the query string for the native query
      sc = qm.getQueryAnnotation().getValueArgument("value") // This is not quite right, need to link sc to the query string
      // A better sink would be:
      // sink.asExpr() = qm.getQueryValueElement() and // The whole query string
      // qm.getQueryValueElement().(StringLiteral).getValue().matches("%ConcatenationContext%") // Heuristic
      // For a precise sink, one would model how Spring executes these.
      // For now, let's use a simpler sink: any argument to a native query method
      // if the query string itself looks like it's built via concatenation.
      // This is hard to model perfectly without seeing the concatenation flow into the query annotation value.
      // Let's simplify and use the standard SQL injection sink and see if it picks up anything with a source.
      // The standard SqlInjection sink should cover many cases if data flows there.
      // For this example, we'll focus on just identifying the pattern of concatenation in @Query(nativeQuery=true)
      // This part of the query is more illustrative of the *intent* than a perfectly working query for this specific scenario.
      // A real query would be more complex.
      // For today, we'll simplify the SQLi part or rely on standard queries to show the concept.
      // Let's assume a simpler sink for illustration:
      // The method call to a repository method that has a native query with concatenation.
      exists(MethodAccess ma | ma.getMethod() = qm and sink.asExpr() = ma.getAnArgument()) and
      qm.getQueryValueElement().(StringLiteral).isConcatenated() // Fictional predicate
    )
    // More realistically, use the standard SQL injection sink:
    // SqlInjection::isSink(sink)
    // And ensure the flow path goes through a concatenated native query string.
    // This requires a custom Sanitizer or flow step to model how Spring uses @Query.
    // For now:
    SqlInjection::isSink(sink) and
    exists(SpringDataJpaQueryMethod qm |
        qm.isNativeQuery() and
        // Crude check that the query string itself might be dynamic (not just literals)
        // This requires a data flow step for the query string itself.
        // This query is becoming too complex for a daily example if fully fleshed out.
        // Let's assume a simpler structural check for vulnerable @Query annotations for now.
        // (See alternative simpler query below for just finding risky @Query)
        sink.getNode().getEnclosingCallable() = qm // Sink is inside a JPA query method
    )
  }
}

// --- XSS Configuration for Thymeleaf th:utext ---
class ThymeleafUnescapedTextXssConfig extends Xss::Configuration {
  ThymeleafUnescapedTextXssConfig() { this = "ThymeleafUnescapedTextXssConfig" }

  override predicate isSource(DataFlow::Node source) {
    // Source: Parameters of Spring controller methods, or model attributes set from them.
    exists(SpringControllerMethod scm |
      source.asParameter() = scm.getARequestParameter()
      // Or, data flowing from request param to a model attribute
      // This is a more complex flow to model here, usually covered by the main XSS lib.
    )
    // Standard remote flow sources are good here.
    // source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    // Sink: Data used with th:utext in Thymeleaf, identified by Thymeleaf specific sinks.
    sink instanceof Thymeleaf::UnescapedTextSink // Predefined sink from Thymeleaf QL library
  }
}


// --- Main Query ---
// This attempts to combine both, which can be messy. Better to have separate queries.
// For demonstration:
from DataFlow::PathNode source, DataFlow::PathNode sink
where
  // SQLi Path
  (exists(SpringJpaNativeSqlConcatenationConfig sqlCfg | sqlCfg.hasFlowPath(source, sink))) or
  // XSS Path
  (exists(ThymeleafUnescapedTextXssConfig xssCfg | xssCfg.hasFlowPath(source, sink)))
select sink.getNode(), source, sink, "Potential vulnerability: Data from source ($@) flows to a sensitive sink ($@).",
  source.getNode(), source.getNode().getLocation().toStringWithFile(),
  sink.getNode(), sink.getNode().getLocation().toStringWithFile()

// --- Simpler Standalone Query for Risky @Query (Structural, not taint tracking) ---
/*
import java
import semmle.code.java.frameworks.spring.SpringDataJPA

from SpringDataJpaQueryMethod qm, Annotation ann, StringLiteral queryValue
where
  ann = qm.getAnnotation() and
  ann.getType().hasQualifiedName("org.springframework.data.jpa.repository", "Query") and
  (
    // Check for nativeQuery=true
    exists(AnnotationElement nativeQueryEl |
      nativeQueryEl = ann.getElement("nativeQuery") and
      nativeQueryEl.getValue().(BooleanLiteral).getValue() = "true"
    )
    or
    // Or if it's just a JPQL query (less direct risk but still if complex)
    not exists(ann.getElement("nativeQuery"))
  ) and
  queryValue = ann.getElement("value").getValue().(StringLiteral) and
  // Heuristic: query string contains typical concatenation or placeholder patterns
  // that are NOT Spring EL or named/indexed parameters if not careful.
  // This is hard to get right without seeing actual concatenation.
  // A better structural check would look for `+` ops in the annotation value.
  (
    queryValue.getValue().matches("%+%") // Contains a plus, indicating potential concatenation
    // queryValue.isConcatenation() // Fictional, but what we'd want for a StringLiteral
  ) and
  // Exclude if it looks like it's using SpEL for dynamic parts (which can also be risky if not careful)
  not queryValue.getValue().matches("%#\\{.*\\}%")
select qm, "Spring Data JPA @Query uses a potentially concatenated string. Review for SQL injection: " + queryValue.getValue()
*/
```
*The SQLi part of the CodeQL query is complex to get right for string concatenation within the `@Query` annotation value itself without deep modeling of how Spring processes annotations. The provided query is a conceptual starting point. Standard CodeQL Java security queries are generally more robust for common SQLi patterns.*

### 4. Run the Query

```shell
codeql query run \
  --database=spring-sast-db \
  --search-path=/path/to/your/ql-packs \
  my-codeql-queries/SpringSqlAndXss.ql \
  --output=spring-results.sarif
```
*This query, especially the SQLi part, is illustrative. The XSS part using `Thymeleaf::UnescapedTextSink` is more likely to work as expected if the data flow is correctly identified from a `RemoteFlowSource` (which `SpringControllerMethod` parameters are).*

You would then inspect `spring-results.sarif`.

## Discussion

*   **SQL Injection in Spring Data JPA:**
    *   **Named/Positional Parameters:** Using `?1`, `:paramName` in `@Query` is generally safe as Spring/JPA handles parameterization.
    *   **Native Queries (`nativeQuery = true`):** If the query string itself is built by concatenating user input *before* being passed to the `@Query` annotation or if `String` SpEL expressions in `@Query` are used insecurely, SQLi can occur. The example `findByCategoryOrderByFieldNativeSafe` is safe because `orderByField` is a parameter. A vulnerable pattern would be: `String unsafeQuery = "SELECT * FROM tbl WHERE val = '" + userInput + "'"; // then use this string`.
    *   **CodeQL:** The `SqlInjection` library in `semmle.code.java.security` is powerful. It identifies sources (e.g., web request parameters via `RemoteFlowSource`) and sinks (e.g., JDBC `Statement.execute()`). Custom queries might be needed for very framework-specific ways of constructing queries if they bypass standard JDBC paths.
*   **XSS in Spring MVC + Thymeleaf:**
    *   **Thymeleaf Autoescaping:** Thymeleaf (like Jinja2) autoescapes by default when using `th:text`, `th:value`, etc., or `[[${...}]]`.
    *   **`th:utext` (Unescaped Text):** This explicitly renders content as raw HTML. If data passed to `th:utext` comes from user input (e.g., via a `@RequestParam` to a `Model` attribute), it's an XSS sink.
    *   **CodeQL:** The `semmle.code.java.security.Xss` and `semmle.code.java.frameworks.thymeleaf.Thymeleaf` libraries help. `RemoteFlowSource` can model user input, and `Thymeleaf::UnescapedTextSink` models the `th:utext` sink.
*   **Other Spring Vulnerabilities:**
    *   **Insecure Deserialization:** If Java deserialization is used with untrusted data (e.g., from HTTP requests, files).
    *   **SSRF (Server-Side Request Forgery):** If URLs for HTTP requests made by the server are user-controlled.
    *   **Spring Expression Language (SpEL) Injection:** If SpEL expressions are built from user input.
    *   **Open Redirects, CSRF (if not using Spring Security's protection properly).**

CodeQL's standard Java queries (`java-security-extended.qls`) cover many of these common Spring vulnerabilities. Custom queries are useful for project-specific logic or newer/less common framework features.

---
[Back to Main README](../README.md)
