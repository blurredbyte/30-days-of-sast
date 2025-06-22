<?php
// db_query.php

// Assume $conn is a valid database connection (e.g., MySQLi or PDO)
// For demonstration, we'll mock it.
class MockDBConnection {
    public function query($sql) {
        echo "Executing query: " . htmlspecialchars($sql) . "\n";
        // In a real app, this would execute the query against the database.
        // If $sql contains malicious input, it could be harmful.
    }

    // Mock prepare and bind_param for the "safer" example
    public function prepare($sql) {
        echo "Preparing statement: " . htmlspecialchars($sql) . "\n";
        return new MockStatement();
    }
}

class MockStatement {
    public function bind_param($types, ...$vars) {
        echo "Binding params: types=" . htmlspecialchars($types) . ", vars=" . htmlspecialchars(implode(", ", $vars)) . "\n";
    }
    public function execute() {
        echo "Executing prepared statement.\n";
    }
}

$conn = new MockDBConnection();

// --- Vulnerable Code ---
// Simulating input from a GET request, e.g., db_query.php?id=123
$_GET['id'] = isset($_GET['id']) ? $_GET['id'] : '1'; // Default to '1' if not set for CLI execution

$userInputUnsafe = $_GET['id'];

// Constructing SQL query directly with user input - VULNERABLE TO SQL INJECTION
$sqlUnsafe = "SELECT data FROM products WHERE id = " . $userInputUnsafe;
echo "Vulnerable query construction:\n";
$conn->query($sqlUnsafe); // Example: if id = '1 OR 1=1', query becomes 'SELECT data FROM products WHERE id = 1 OR 1=1'

echo "\n---\n\n";

// --- Potentially Vulnerable Code (depending on context and sanitization, but pattern is risky) ---
$_POST['username'] = isset($_POST['username']) ? $_POST['username'] : 'admin'; // Default for CLI
$username = $_POST['username'];
$password = "some_password"; // Passwords should be hashed, this is just for SQLi demo

// Another way to concatenate, still vulnerable
$sqlLogin = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
echo "Another vulnerable query construction (login):\n";
$conn->query($sqlLogin); // Example: if username = 'admin'--
                        // query becomes SELECT * FROM users WHERE username = 'admin'--' AND password = '...'
                        // The '--' comments out the rest of the query.

echo "\n---\n\n";


// --- Example of a Safer, Parameterized Query (Conceptual) ---
echo "Safer query construction (parameterized):\n";
$safeUserId = isset($_GET['safe_id']) ? $_GET['safe_id'] : 2; // Default for CLI

// Using prepared statements with placeholders
$stmt = $conn->prepare("SELECT data FROM products WHERE id = ?");
if ($stmt) {
    $stmt->bind_param("i", $safeUserId); // "i" means $safeUserId is an integer
    $stmt->execute();
}

echo "\nProcessing complete.\n";

// To test the vulnerable parts from CLI:
// php db_query.php id="1 OR 1=1"
// php db_query.php id="1; DROP TABLE users;" (this would be very bad on a real system)
?>
