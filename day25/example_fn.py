import sqlite3
import os

# This example demonstrates a scenario where a vulnerability might be missed (False Negative)
# due to indirect data flow or reliance on environmental factors not typically checked by all SAST rules.

DATABASE_NAME = "fn_example.db"

def initialize_db():
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, name TEXT, description TEXT)")
    cursor.execute("INSERT OR IGNORE INTO items (name, description) VALUES ('widget', 'A standard widget')")
    cursor.execute("INSERT OR IGNORE INTO items (name, description) VALUES ('gadget', 'A shiny new gadget')")
    conn.commit()
    conn.close()

def get_item_description_by_name(item_name):
    """
    Retrieves an item's description. This function itself looks safe
    as it uses parameterized queries.
    """
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    # This query is safe (parameterized)
    query = "SELECT description FROM items WHERE name = ?"
    # print(f"Executing FN example query (safe part): {query} with param: {item_name}")

    try:
        cursor.execute(query, (item_name,))
        result = cursor.fetchone()
        return result[0] if result else "Item not found"
    except sqlite3.Error as e:
        print(f"Database error in FN example: {e}")
        return "Error retrieving item"
    finally:
        conn.close()

def process_request_indirect_config(user_input_item_name):
    """
    This function uses an environment variable to decide on sorting.
    A SAST tool might not trace the flow from an environment variable
    into an SQL query if its taint sources don't include os.environ by default,
    or if it doesn't handle this specific pattern of string formatting for ORDER BY.
    This could lead to a False Negative for SQL Injection via ORDER BY.
    """
    # Environment variable controls sorting - this is the indirect part
    # A SAST tool might not consider os.environ.get() a primary taint source by default for all rules.
    sort_column = os.environ.get("ITEM_SORT_COLUMN", "name") # Default to 'name'

    # Basic check, but not a robust sanitizer against all SQLi in ORDER BY
    if sort_column not in ["name", "description", "id"]:
        print(f"Invalid sort column: {sort_column}. Defaulting to 'name'.")
        sort_column = "name" # Fallback, but the check itself is basic

    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    # VULNERABILITY: SQL Injection in ORDER BY clause
    # The 'sort_column' comes from an environment variable and is directly interpolated.
    # An attacker controlling the environment variable could inject SQL.
    # Example: ITEM_SORT_COLUMN="name; --, description" (syntax varies by DB)
    # Or ITEM_SORT_COLUMN="name ASC, (SELECT CASE WHEN (substr(password,1,1)='a') THEN name ELSE id END FROM users LIMIT 1)"
    # (This is a complex blind SQLi example for illustration of impact)
    try:
        # The vulnerability lies here.
        # A SAST tool might miss this if:
        # 1. It doesn't track os.environ.get() as a source for SQLi.
        # 2. It doesn't recognize string formatting into ORDER BY as a sink.
        # 3. The path from source to sink is too convoluted for its analysis depth.
        query = f"SELECT name, description FROM items WHERE name LIKE ? ORDER BY {sort_column}"
        # print(f"Executing FN example query (unsafe part): {query}")

        # To make it runnable, let's search for part of the item_name
        cursor.execute(query, (f"%{user_input_item_name}%",))
        items = cursor.fetchall()

        if not items:
            return "No items found."
        return "\n".join([f"- {name}: {desc}" for name, desc in items])

    except sqlite3.Error as e:
        print(f"Database error in FN (unsafe part): {e}")
        return "Error processing request."
    finally:
        conn.close()

if __name__ == "__main__":
    initialize_db()

    print("--- Example for Potential False Negative ---")
    print("Simulating a scenario where an environment variable might cause an issue.")

    # Scenario 1: Environment variable is not set or is benign
    print("\n[SCENARIO 1: Benign sort column (default or valid)]")
    # Ensure ITEM_SORT_COLUMN is not set or is 'name'/'description' for this test
    if "ITEM_SORT_COLUMN" in os.environ:
        del os.environ["ITEM_SORT_COLUMN"] # Or set to "name"
    # os.environ["ITEM_SORT_COLUMN"] = "description"
    results = process_request_indirect_config("widget")
    print(f"Results for 'widget':\n{results}")

    # Scenario 2: Malicious environment variable (conceptual)
    # To test this, you'd run the script with the env var set:
    # ITEM_SORT_COLUMN="name --" python example_fn.py
    # or ITEM_SORT_COLUMN="name UNION SELECT username, password FROM users --" (if users table existed)
    # The Python script itself can't easily simulate an attacker controlling its launch environment
    # for this specific os.environ example within the same run.

    print("\n[SCENARIO 2: Malicious sort column (conceptual)]")
    print("To test the vulnerability, run this script with a malicious ITEM_SORT_COLUMN env var:")
    print("  Linux/macOS: ITEM_SORT_COLUMN=\"name --\" python day25/example_fn.py")
    print("  Windows (cmd): set ITEM_SORT_COLUMN=name -- && python day25/example_fn.py")
    print("  Windows (PowerShell): $env:ITEM_SORT_COLUMN='name --'; python day25/example_fn.py")
    print("A SAST tool might miss this if it doesn't consider os.environ a taint source for SQLi or if the ORDER BY sink is not well-defined.")

    # Example of setting it temporarily for a sub-test (might not reflect true env attack)
    print("\n[SCENARIO 3: Simulating malicious env var internally for one call (for demo)]")
    original_sort_col = os.environ.get("ITEM_SORT_COLUMN")
    os.environ["ITEM_SORT_COLUMN"] = "id; --" # A simple injection attempt
    results_malicious_env = process_request_indirect_config("gadget")
    print(f"Results for 'gadget' with malicious (simulated) env var:\n{results_malicious_env}")

    # Restore original environment variable, if it existed
    if original_sort_col is None:
        if "ITEM_SORT_COLUMN" in os.environ: # if it was set by this script
             del os.environ["ITEM_SORT_COLUMN"]
    else:
        os.environ["ITEM_SORT_COLUMN"] = original_sort_col

    # Cleanup
    if os.path.exists(DATABASE_NAME):
        os.remove(DATABASE_NAME)

    # A SAST tool might not flag `query = f"SELECT ... ORDER BY {sort_column}"` if:
    # - It doesn't trace taint from `os.environ.get()`. Many tools focus on web request parameters.
    # - The rule for SQL injection is too specific (e.g., only looks for injections in WHERE clauses).
    # - The connection between the source (os.environ) and the sink (ORDER BY clause)
    #   is considered too indirect or involves configurations (environment variables)
    #   that the static analyzer doesn't model by default.
    # This would be a False Negative.
