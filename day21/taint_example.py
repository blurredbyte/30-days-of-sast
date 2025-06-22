import sqlite3

def get_user_data_vulnerable(username):
    """
    Fetches user data from the database. This version is vulnerable to SQL injection.
    """
    # SOURCE: 'username' parameter comes from an external source (e.g., web request)
    # SINK: sqlite3.Cursor.execute() when used with string formatting for queries
    # TAINT FLOW: 'username' flows directly into the SQL query string.

    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    # This is the vulnerable part
    query = f"SELECT * FROM users WHERE username = '{username}'"
    print(f"Executing query: {query}")

    try:
        cursor.execute(query) # Untrusted data 'username' reaches the SQL execution sink
        results = cursor.fetchall()
        for row in results:
            print(row)
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
    finally:
        conn.close()

def get_user_data_safe(username):
    """
    Fetches user data using parameterized queries, preventing SQL injection.
    """
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    # SANITIZER (implicitly, by using parameterized queries):
    # The database driver handles proper escaping of 'username'.
    # The taint from 'username' does not lead to an injection.
    query = "SELECT * FROM users WHERE username = ?"
    print(f"Executing query: {query} with parameter: {username}")

    try:
        cursor.execute(query, (username,)) # 'username' is passed as a parameter
        results = cursor.fetchall()
        for row in results:
            print(row)
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
    finally:
        conn.close()

def setup_database():
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT)")
    cursor.execute("INSERT INTO users (username, email) VALUES ('alice', 'alice@example.com')")
    cursor.execute("INSERT INTO users (username, email) VALUES ('bob', 'bob@example.com')")
    conn.commit()
    conn.close()

if __name__ == "__main__":
    setup_database()

    print("--- Demonstrating VULNERABLE SQL Injection ---")
    # Malicious input: ' OR '1'='1
    # This would make the query: SELECT * FROM users WHERE username = '' OR '1'='1'
    malicious_username = "' OR '1'='1"
    get_user_data_vulnerable(malicious_username)

    print("\n--- Demonstrating SAFE query (parameterized) ---")
    # The same malicious input will be treated as a literal string
    get_user_data_safe(malicious_username)

    print("\n--- VULNERABLE: Getting Alice's data (benign input) ---")
    get_user_data_vulnerable("alice")

    print("\n--- SAFE: Getting Alice's data (benign input) ---")
    get_user_data_safe("alice")
