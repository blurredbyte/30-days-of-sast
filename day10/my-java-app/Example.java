// my-java-app/Example.java
// A simple Java class for CodeQL database creation demo.
package com.example.sast; // Added a package declaration

import java.io.File; // For potential future use with readFile
import java.nio.file.Paths; // For potential future use with readFile

public class Example {

    public static void main(String[] args) {
        String name = "World";
        if (args.length > 0) {
            // Source: Command line argument args[0]
            name = args[0];
        }
        // Simple string concatenation, could be a sink if name is tainted and used in a sensitive context later.
        System.out.println("Hello, " + name + "!");

        // A slightly more complex example for later queries
        performAction(name); // name (potentially from args[0]) flows into performAction

        Example ex = new Example();
        ex.readFile(name + "_report.txt"); // name flows into readFile after concatenation
    }

    public static void performAction(String input) {
        // This method receives the 'input' which could be tainted.
        if (input.equals("admin")) {
            System.out.println("Performing admin action for: " + input);
            // In a real app, this might be a sensitive operation.
            // A query could check if 'input' comes from an untrusted source.
        } else {
            System.out.println("Performing user action for: " + input);
        }
    }

    // A function that might be a sink for a vulnerability (e.g., path traversal)
    public void readFile(String fileName) {
        // Sink: fileName parameter of readFile.
        // If fileName is constructed from user input without sanitization, it's a path traversal risk.
        System.out.println("Attempting to read file: " + fileName);

        // A more realistic file operation:
        try {
            File f = new File(fileName);
            // Normalize path to prevent some traversal, but not all if not careful
            String canonicalPath = f.getCanonicalPath();
            System.out.println("Canonical path: " + canonicalPath);

            // Check if it's within an expected directory (very basic check)
            if (!canonicalPath.startsWith(System.getProperty("user.dir"))) {
                 // System.err.println("Warning: Path may be outside current directory!");
                 // For a demo, let's not make it too noisy for now.
            }

            // Actual file reading logic would go here...
            // e.g., Files.readString(Paths.get(fileName));
        } catch (java.io.IOException e) {
            System.err.println("File operation error: " + e.getMessage());
        }
    }

    public String processUserInput(String data) {
        // Another method that processes data, could be a source or part of a flow.
        String processedData = data.trim().toLowerCase();
        return "processed_" + processedData;
    }
}

// To compile this (if not using a build tool that CodeQL can hook into automatically):
// Make sure you are in the `my-java-app` directory or its parent.
// If in `my-java-app`:
// javac com/example/sast/Example.java
// If in parent of `my-java-app`:
// javac my-java-app/com/example/sast/Example.java

// CodeQL database creation command (run from parent of my-java-app):
// Assuming CodeQL CLI is set up and QL packs are downloaded to ~/codeql-packs/
// Adjust --search-path and --source-root as per your setup.

// If your project doesn't have an explicit build command (like for this single file):
// codeql database create my-java-db --language=java --source-root=my-java-app --search-path=~/codeql-packs

// If it were a Maven project (and my-java-app was the root of it with a pom.xml):
// codeql database create my-java-db --language=java --source-root=my-java-app --command="mvn clean package -DskipTests" --search-path=~/codeql-packs

// If it were a Gradle project:
// codeql database create my-java-db --language=java --source-root=my-java-app --command="gradlew clean build -x test" --search-path=~/codeql-packs
