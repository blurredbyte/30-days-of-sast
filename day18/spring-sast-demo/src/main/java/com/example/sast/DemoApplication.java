package com.example.sast;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.servlet.http.HttpServletRequest; // For RemoteFlowSource example
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


@SpringBootApplication
public class DemoApplication {
    private static final Logger log = LoggerFactory.getLogger(DemoApplication.class);
    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
        log.info("Spring SAST Demo Application Started.");
    }
}

// --- Entity ---
@Entity
class Product {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String name;
    private String category;
    private String description;

    // Constructors
    public Product() {}
    public Product(String name, String category, String description) {
        this.name = name;
        this.category = category;
        this.description = description;
    }

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getCategory() { return category; }
    public void setCategory(String category) { this.category = category; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
}

// --- Repository ---
interface ProductRepository extends JpaRepository<Product, Long> {

    // Example 1: Safe query using named parameters (JPQL)
    @Query("SELECT p FROM Product p WHERE p.category = :category AND p.name LIKE CONCAT('%', :namePart, '%')")
    List<Product> findByCategoryAndNameLikeSafe(@Param("category") String category, @Param("namePart") String namePart);

    // Example 2: Potentially risky native query if query string is built with concatenation
    // This specific example uses named parameters, so it's safe as written.
    // A CodeQL query would look for cases where the query string itself is from an unsafe source.
    @Query(value = "SELECT * FROM product WHERE category = :category ORDER BY :orderByField :direction", nativeQuery = true)
    List<Product> findByCategoryOrderByFieldNative(
            @Param("category") String category,
            @Param("orderByField") String orderByField,
            @Param("direction") String direction);

    // Example 3: A method that might be used with a dynamically constructed query string (conceptual)
    // This is just a standard JPA method name, but if a service layer built a query string
    // and passed it to a more generic executor, that would be the risk.
    List<Product> findByNameContainingIgnoreCase(String nameFragment);


    // VULNERABLE Example: Native query where part of the SQL structure (not just values) comes from a parameter.
    // Spring Data JPA does not directly support dynamic table names or column names via @Param in this way.
    // This is a common misconception. To achieve this, developers might resort to string concatenation
    // *before* the query string is passed to @Query or when using EntityManager.
    // This is a placeholder to discuss the vulnerability type.
    // @Query(value = "SELECT * FROM product p WHERE p.category = :category ORDER BY :orderByField", nativeQuery = true)
    // List<Product> findByCategoryOrderByDynamicField(@Param("category") String category, @Param("orderByField") String orderByField);
    // If orderByField was "name; DROP TABLE product;", and if Spring directly substituted it (it doesn't), it would be SQLi.
    // The actual risk is when building the query string in Java code using concatenation:
    // String query = "SELECT * FROM product ORDER BY " + userInputSortField; (This is the pattern to find)
}


// --- Controller ---
@Controller
class ProductController {
    private static final Logger log = LoggerFactory.getLogger(ProductController.class);
    private final ProductRepository productRepository;

    public ProductController(ProductRepository productRepository) {
        this.productRepository = productRepository;
        // Initialize with some data
        if (productRepository.count() == 0) {
            productRepository.save(new Product("Laptop Pro", "Electronics", "High-end laptop for professionals."));
            productRepository.save(new Product("Wireless Mouse", "Electronics", "Ergonomic wireless mouse."));
            productRepository.save(new Product("Organic Coffee", "Groceries", "Fair-trade organic coffee beans."));
        }
    }

    @GetMapping("/")
    public String home(Model model) {
        model.addAttribute("products", productRepository.findAll());
        return "home";
    }

    // SQL Injection example (conceptual - if repository method was vulnerable)
    @GetMapping("/products/search_vulnerable_sqli")
    @ResponseBody
    public List<Product> searchProductsSqli(
            @RequestParam String category, // Source for SQLi
            @RequestParam(defaultValue = "name") String sortField, // Source for SQLi (if used in string concat)
            @RequestParam(defaultValue = "ASC") String sortDir // Source for SQLi (if used in string concat)
    ) {
        log.info("Searching products in category: {} sorted by {} {}", category, sortField, sortDir);
        // VULNERABLE PATTERN (if ProductRepository built query string by concatenation):
        // String query = "SELECT * FROM product WHERE category = '" + category + "' ORDER BY " + sortField + " " + sortDir;
        // This would be caught by a CodeQL query looking for string concatenation flowing into a query execution sink.
        // The current ProductRepository.findByCategoryOrderByFieldNative is safe due to named params.
        // To make this endpoint actually demonstrate the vulnerability with the current repo,
        // we'd need a custom method in the repo that *does* use concatenation.
        // For now, we rely on the conceptual vulnerability pattern.
        // Let's simulate a call that *would* be vulnerable if the repo method was:
        // return productRepository.executeDynamicQuery("SELECT * FROM product WHERE category = '"+category+"'");

        // This is safe with current repo method:
        return productRepository.findByCategoryOrderByFieldNative(category, sortField, sortDir.toUpperCase());
    }

    // XSS Example
    @GetMapping("/product/view_vulnerable_xss")
    public String viewProductXss(
            @RequestParam Long id,
            @RequestParam(required = false) String referrerName, // Source for XSS
            Model model,
            HttpServletRequest request // For RemoteFlowSource
    ) {
        Optional<Product> productOpt = productRepository.findById(id);
        if (productOpt.isPresent()) {
            Product product = productOpt.get();
            model.addAttribute("product", product);

            // SOURCE: referrerName from @RequestParam
            // SINK: This data is added to the model and then rendered with th:utext in product_details_xss.html
            String userProvidedReferrer = request.getParameter("referrerName"); // Another way to get source
            if (userProvidedReferrer != null && !userProvidedReferrer.isEmpty()) {
                 model.addAttribute("referrerInfo", "Thank you for visiting from " + userProvidedReferrer + "!");
            } else {
                model.addAttribute("referrerInfo", "Welcome!");
            }
            // This example also shows a hardcoded script for product.description to test th:utext
            // The actual XSS vulnerability we'd be looking for with CodeQL is userProvidedReferrer -> model -> th:utext.
            return "product_details_xss";
        }
        return "redirect:/";
    }

     @GetMapping("/product/view_safe_xss")
    public String viewProductSafeXss(
            @RequestParam Long id,
            @RequestParam(required = false) String referrerName,
            Model model
    ) {
        Optional<Product> productOpt = productRepository.findById(id);
        if (productOpt.isPresent()) {
            Product product = productOpt.get();
            model.addAttribute("product", product);
            if (referrerName != null && !referrerName.isEmpty()) {
                 model.addAttribute("referrerInfo", "Thank you for visiting from " + referrerName + "!");
            } else {
                model.addAttribute("referrerInfo", "Welcome!");
            }
            // product_details_safe.html will use th:text for user-provided content
            return "product_details_safe";
        }
        return "redirect:/";
    }
}
