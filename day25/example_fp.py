import sqlite3

# This module is responsible for fetching application configuration.
# The table name is determined internally by the application logic, not by direct user input.

DB_CONFIG_TABLE_NAME = "app_config" # Hardcoded, trusted table name

def get_config_value(key_name: str):
    """
    Retrieves a configuration value for a given key.
    The table name is fixed and trusted. The key_name is also expected
    to be from a controlled set or validated before calling this.

    A naive SAST rule might flag the f-string usage in cursor.execute()
    as a potential SQL injection, considering it a false positive if 'key_name'
    is also validated or from a trusted source, and especially since the table name is hardcoded.
    """
    if not key_name or not isinstance(key_name, str) or not key_name.isalnum():
        # Basic validation, though a real app might have stricter checks or use an allow-list.
        print(f"Invalid key_name: {key_name}")
        return None

    conn = None
    try:
        conn = sqlite3.connect(':memory:') # Example database
        cursor = conn.cursor()

        # Pre-populate for the example to run
        cursor.execute(f"CREATE TABLE IF NOT EXISTS {DB_CONFIG_TABLE_NAME} (key TEXT PRIMARY KEY, value TEXT)")
        cursor.execute(f"INSERT OR IGNORE INTO {DB_CONFIG_TABLE_NAME} (key, value) VALUES ('feature_x_enabled', 'true')")
        cursor.execute(f"INSERT OR IGNORE INTO {DB_CONFIG_TABLE_NAME} (key, value) VALUES ('api_version', 'v2')")
        conn.commit()

        # The query construction:
        # DB_CONFIG_TABLE_NAME is a hardcoded constant.
        # key_name is a parameter. A very sensitive SAST tool might still flag this
        # if it doesn't see strong enough sanitization for key_name or if its
        # rules are very broad about f-strings in SQL.
        # However, if key_name is strictly controlled/validated, this could be a false positive.
        query = f"SELECT value FROM {DB_CONFIG_TABLE_NAME} WHERE key = '{key_name}'"
        # print(f"Executing FP example query: {query}")

        cursor.execute(query) # Naive rule might flag this line
        result = cursor.fetchone()

        if result:
            return result[0]
        return None
    except sqlite3.Error as e:
        print(f"Database error in FP example: {e}")
        return None
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    print("--- Example for Potential False Positive ---")

    # Case 1: Valid key
    value = get_config_value("feature_x_enabled")
    print(f"Config for 'feature_x_enabled': {value}") # Expected: true

    # Case 2: Another valid key
    value_api = get_config_value("api_version")
    print(f"Config for 'api_version': {value_api}") # Expected: v2

    # Case 3: Non-existent key
    value_non = get_config_value("non_existent_key")
    print(f"Config for 'non_existent_key': {value_non}") # Expected: None

    # Case 4: Potentially "malicious" key, but basic validation catches it
    # If a SAST tool flags the query construction with "feature_x_enabled" as SQLi,
    # it's likely a False Positive because DB_CONFIG_TABLE_NAME is constant and
    # key_name (if validated properly) is safe.
    # The vulnerability really depends on how controllable 'key_name' is *before* this function.
    # A generic f-string rule might not consider the `isalnum` check sufficient.
    value_malicious = get_config_value("test_key'; DROP TABLE users; --")
    print(f"Config for 'test_key'; DROP TABLE users; --': {value_malicious}") # Expected: None (due to validation)

    # What a SAST tool might see:
    # cursor.execute(f"SELECT value FROM {DB_CONFIG_TABLE_NAME} WHERE key = '{key_name}'")
    # If a rule just says "f-string in execute is bad", this is a finding.
    # If the rule says "f-string in execute is bad IF any interpolated var is user-controlled AND not sanitized",
    # then it depends on whether the tool can trace `key_name` to an external source and recognize `isalnum`
    # or other prior validation as sufficient. If `key_name` is from a safe, internal source, it's an FP.
    # If `isalnum` is considered insufficient for all cases, it might be a True Positive, highlighting weak sanitization.
    # The "false positive" nature often depends on context outside the immediate line of code.
    print("\nConsider if a SAST tool flags the query construction. If 'key_name' is always validated or from a trusted source, it could be an FP.")
