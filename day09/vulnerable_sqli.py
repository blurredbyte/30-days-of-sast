# vulnerable_sqli.py
import sqlite3
import sys

# This is a simplified example to illustrate the concept for CodeQL.
# In a real application, database interactions would be more structured.

def create_schema(conn):
    """Creates a simple users table."""
    try:
        conn.execute("CREATE TABLE users (id TEXT PRIMARY KEY, name TEXT, email TEXT)")
        conn.execute("INSERT INTO users (id, name, email) VALUES ('1', 'Alice Wonder', 'alice@example.com')")
        conn.execute("INSERT INTO users (id, name, email) VALUES ('2', 'Bob The Builder', 'bob@example.com')")
        conn.execute("INSERT INTO users (id, name, email) VALUES ('3', 'Charlie Chaplin', 'charlie@example.com')")
        conn.commit()
        print("Database schema created and populated.")
    except sqlite3.Error as e:
        print(f"Schema creation error: {e}")


def get_user_data_vulnerable(conn, user_id_input):
    """
    Fetches user data from the database using the provided user_id.
    This function is vulnerable to SQL injection.
    """
    # VULNERABLE: User input is directly concatenated into the SQL query string.
    # A CodeQL query would aim to identify this pattern:
    # Source: user_id_input (potentially from an external source like HTTP request)
    # Sink: The first argument to conn.execute()
    # Path: Direct string concatenation involving user_input that forms the query.
    query = "SELECT id, name, email FROM users WHERE id = '" + user_id_input + "'"
    print(f"Executing vulnerable query: {query}")

    try:
        cursor = conn.execute(query)
        user_data = cursor.fetchone()
        if user_data:
            return {"id": user_data[0], "name": user_data[1], "email": user_data[2]}
        else:
            return None
    except sqlite3.Error as e:
        print(f"Database query error: {e}")
        return None

def get_user_data_safe(conn, user_id_input):
    """
    Fetches user data safely using parameterized queries.
    """
    query = "SELECT id, name, email FROM users WHERE id = ?" # Parameterized query
    print(f"Executing safe query with parameter: {user_id_input}")
    try:
        cursor = conn.execute(query, (user_id_input,)) # Pass parameters as a tuple
        user_data = cursor.fetchone()
        if user_data:
            return {"id": user_data[0], "name": user_data[1], "email": user_data[2]}
        else:
            return None
    except sqlite3.Error as e:
        print(f"Database query error: {e}")
        return None


if __name__ == "__main__":
    db_connection = sqlite3.connect(':memory:') # Use an in-memory database for this demo
    create_schema(db_connection)

    print("\n--- Demonstrating Vulnerable SQL Injection ---")
    # Scenario 1: Legitimate input
    user_id_legit = "1"
    print(f"Fetching data for user ID: {user_id_legit}")
    data = get_user_data_vulnerable(db_connection, user_id_legit)
    print(f"Data found: {data}")

    # Scenario 2: Malicious input (SQL Injection attack)
    # This input closes the string for 'id' and adds an OR condition that is always true,
    # potentially bypassing intended logic or dumping more data.
    user_id_malicious = "2' OR '1'='1"
    print(f"\nFetching data with malicious user ID: {user_id_malicious}")
    data_vulnerable = get_user_data_vulnerable(db_connection, user_id_malicious)
    print(f"Data found (vulnerable): {data_vulnerable}")
    # If the query were more complex or allowed multiple statements, more damage could be done.

    print("\n--- Demonstrating Safe Query (Parameterized) ---")
    # Scenario 3: Legitimate input with safe function
    print(f"Fetching data for user ID: {user_id_legit} (safe)")
    data_safe_legit = get_user_data_safe(db_connection, user_id_legit)
    print(f"Data found: {data_safe_legit}")

    # Scenario 4: Malicious input with safe function
    # The malicious string will be treated as a literal value for the ID,
    # likely finding no matching user, thus preventing the injection.
    print(f"\nFetching data with malicious user ID: {user_id_malicious} (safe)")
    data_safe_malicious = get_user_data_safe(db_connection, user_id_malicious)
    print(f"Data found (safe): {data_safe_malicious if data_safe_malicious else 'No user found, injection averted'}")


    db_connection.close()

    # Conceptual CodeQL elements:
    # - Identify function calls like `conn.execute(...)` as SQL execution sinks.
    # - Identify parameters to functions (like `user_id_input`) as potential sources of tainted data.
    # - Track data flow from sources to sinks.
    # - Identify patterns like string concatenation (`+`) involving tainted data that forms the query string.
    # - Standard CodeQL libraries for Python would provide classes for these (e.g., SqlExecution, StringConcatenation).
    # - A query would use these classes to define the vulnerable pattern.
    #
    # Example (very simplified QL logic):
    # from DataFlow::Node source, DataFlow::Node sink
    # where source.isParameter("user_id_input") and sink.isSqlArgumentTo("execute")
    # and source.flowsTo(sink) via string concatenation
    # select sink, "Potential SQLi"
