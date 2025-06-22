package com.example;

// Imagine this class represents data coming directly from a user without validation yet.
class UserInputString {
    private final String data;

    public UserInputString(String data) {
        this.data = data;
    }

    public String getData() {
        return data;
    }

    @Override
    public String toString() {
        return data; // For simplicity, but could be risky if not handled carefully.
    }
}

class Validator {
    // Our custom validation/sanitization method.
    public static boolean isValid(UserInputString input) {
        if (input == null || input.getData() == null) {
            return false;
        }
        // Example validation: disallow common script tags (very basic)
        return !input.getData().contains("<script>");
    }

    public static String sanitize(UserInputString input) {
        if (input == null || input.getData() == null) {
            return "";
        }
        return input.getData().replace("<", "&lt;").replace(">", "&gt;");
    }
}

class Log {
    // This method is considered a sink if it receives unvalidated UserInputString.
    public static void sensitiveData(String id, String data) {
        System.out.println("SENSITIVE_LOG (" + id + "): " + data);
    }

    public static void safeData(String id, String data) {
        System.out.println("SAFE_LOG (" + id + "): " + data);
    }
}

public class CustomTaint {

    public void processUserInput(UserInputString userInput, UserInputString safeInput, String normalString) {
        // Vulnerable: UserInputString directly to sensitiveData sink
        Log.sensitiveData("user_raw", userInput.getData()); // Sink reached by tainted data

        // Potentially vulnerable depending on rule (if only UserInputString object is tainted)
        String extractedData = userInput.getData();
        Log.sensitiveData("user_extracted", extractedData); // Sink reached by data from tainted object

        // Safe: UserInputString is validated before reaching the sink
        if (Validator.isValid(userInput)) {
            Log.sensitiveData("user_validated", userInput.getData()); // Sanitizer used
        } else {
            Log.safeData("user_invalid", "Input was invalid");
        }

        // Safe: UserInputString is sanitized
        String sanitizedData = Validator.sanitize(userInput);
        Log.sensitiveData("user_sanitized", sanitizedData); // Sanitizer used

        // Safe: Input is not of the tainted type UserInputString
        Log.sensitiveData("system_data", normalString); // Not a UserInputString, should not be flagged by our custom rule

        // Safe: Input is validated (even if it was safe to begin with)
        if (Validator.isValid(safeInput)) {
             Log.sensitiveData("safe_input_validated", safeInput.getData());
        }
    }

    public static void main(String[] args) {
        CustomTaint ct = new CustomTaint();

        UserInputString taintedInput = new UserInputString("<script>alert('xss')</script>");
        UserInputString benignInput = new UserInputString("HelloUser");
        String systemString = "SystemData";

        System.out.println("--- Test Case 1: Tainted Input ---");
        ct.processUserInput(taintedInput, benignInput, systemString);
        /* Expected Semgrep/CodeQL findings for taintedInput:
         * - Log.sensitiveData("user_raw", userInput.getData()) -> VULNERABLE
         * - Log.sensitiveData("user_extracted", extractedData) -> VULNERABLE (if rule tracks data extraction)
         * No findings for validated, sanitized, or system_data calls.
         */

        System.out.println("\n--- Test Case 2: Benign Input ---");
        UserInputString anotherBenignInput = new UserInputString("AnotherHello");
        ct.processUserInput(benignInput, anotherBenignInput, systemString);
        /* Expected Semgrep/CodeQL findings for benignInput (if rule is strict on type, not content):
         * - Log.sensitiveData("user_raw", userInput.getData()) -> VULNERABLE (because type is UserInputString and not validated)
         * - Log.sensitiveData("user_extracted", extractedData) -> VULNERABLE
         * No findings for validated, sanitized, or system_data calls.
         * A sophisticated rule might only flag if the content is also dangerous, but
         * type-based tainting is common for custom wrappers.
         */
    }
}
