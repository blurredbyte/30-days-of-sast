# Day 10: Setting Up CodeQL and Creating a Database

**Summary:** We'll walk through installing the CodeQL CLI and using it to create a CodeQL database for a sample project. A CodeQL database is a relational representation of a codebase, which queries can then be run against.

**Today's Focus:** Installing CodeQL CLI, downloading standard QL libraries, and creating a database for a small Java project.

## Prerequisites

1.  **Java Development Kit (JDK):** CodeQL needs a JDK to build Java projects. Version 8, 11, or 17 are commonly used. Make sure `java` and `javac` are in your PATH.
    *   Check with `java -version`.
2.  **Python (for some CodeQL scripts, optional for basic use):** Python 3 is generally useful.

## Try it yourself

### 1. Install CodeQL CLI

*   Go to the [CodeQL CLI releases page on GitHub](https://github.com/github/codeql-cli-binaries/releases).
*   Download the `codeql-PLATFORM.zip` file appropriate for your operating system (e.g., `codeql-linux64.zip`, `codeql-osx64.zip`, `codeql-win64.zip`).
*   Extract the archive to a directory, e.g., `/opt/codeql-home/` or `C:\codeql-home\`.
*   Add the directory containing the `codeql` executable (e.g., `/opt/codeql-home/codeql`) to your system's `PATH` environment variable.
*   Verify installation:
    ```shell
    codeql --version
    ```

### 2. Download Standard CodeQL Libraries (Queries)

The CodeQL CLI needs the standard QL libraries, which contain the definitions for analyzing various languages and common queries.
```shell
# Create a directory to store QL packs
mkdir -p /path/to/your/ql-packs # e.g., ~/codeql-packs or C:\codeql-packs

# Use CodeQL to download the core query packs for desired languages
# This command downloads the standard libraries for Java. Add other languages as needed (e.g., python, javascript, csharp, cpp, go, ruby).
codeql pack download github/codeql-java --output /path/to/your/ql-packs/codeql-java
# For other languages, e.g., Python:
# codeql pack download github/codeql-python --output /path/to/your/ql-packs/codeql-python
# ...and so on for javascript, go, csharp, cpp, ruby.

# You can also clone the entire CodeQL repository which contains these libraries:
# git clone https://github.com/github/codeql.git /path/to/codeql-repo
# The standard libraries would then be in /path/to/codeql-repo/ql/java/ql/src etc.
# However, `pack download` is the more modern way for specific language packs.
```
*Note: For `codeql pack download`, you might need to be authenticated with GitHub if you hit rate limits. See CodeQL docs for authentication.*

### 3. Create a Sample Java Project

*   Create a directory for a simple Java project, e.g., `my-java-app`.
*   Inside `my-java-app`, create `Example.java`:

```java
// my-java-app/Example.java
public class Example {
    public static void main(String[] args) {
        String name = "World";
        if (args.length > 0) {
            name = args[0]; // User input from command line argument
        }
        System.out.println("Hello, " + name + "!"); // Simple string concatenation

        // A slightly more complex example for later queries
        performAction(name);
    }

    public static void performAction(String input) {
        if (input.equals("admin")) {
            System.out.println("Performing admin action.");
            // In a real app, this might be a sensitive operation
        } else {
            System.out.println("Performing user action for: " + input);
        }
    }

    // A function that might be a sink for a vulnerability (e.g., path traversal)
    public void readFile(String fileName) {
        System.out.println("Attempting to read file: " + fileName);
        // In a real scenario: new File(fileName).exists(), etc.
    }
}
```

### 4. Create a CodeQL Database

Navigate to the directory *outside* your Java project (e.g., if `my-java-app` is in `~/projects`, `cd ~/projects`).
Run the following command:

```shell
# Replace /path/to/your/ql-packs/codeql-java with the actual path from step 2
# Replace my-java-app with the path to your Java project
# Replace my-java-db with the desired name for your database directory

codeql database create my-java-db \
  --language=java \
  --source-root=my-java-app \
  --search-path=/path/to/your/ql-packs/codeql-java
  # If you cloned the full codeql repo, --search-path might be /path/to/codeql-repo

# For Java projects using Maven or Gradle, CodeQL often infers the build automatically.
# If not, you might need to specify a build command:
# codeql database create my-java-db --language=java --source-root=my-java-app \
#   --command="mvn clean package -DskipTests" \
#   --search-path=/path/to/your/ql-packs/codeql-java

# If successful, you'll see output indicating database creation progress and completion.
# A new directory `my-java-db` will be created containing the CodeQL database.
```

*   **`codeql database create my-java-db`**: Command to create a database named `my-java-db`.
*   **`--language=java`**: Specifies the language of the codebase.
*   **`--source-root=my-java-app`**: Path to the root of the source code.
*   **`--search-path=/path/to/your/ql-packs/codeql-java`**: Tells CodeQL where to find the QL libraries for Java. If you downloaded multiple language packs, you can point to the parent directory (e.g., `/path/to/your/ql-packs`). CodeQL will find the appropriate language pack.
*   **`--command` (Optional but often needed for compiled languages):** If your project has a specific build process (e.g., Maven, Gradle, make), you provide the build command here. CodeQL "watches" the build process to understand how files are compiled and linked. For simple, single Java files, it might auto-detect.

After these steps, you'll have a CodeQL database (`my-java-db`) ready for querying in the next lesson!

## Troubleshooting
*   **Build Errors:** Most issues arise from CodeQL not being able to build the project. Ensure the JDK is correctly set up and that the `--command` (if used) successfully builds your project standalone.
*   **Extractor Errors:** If CodeQL fails to "extract" information, check language support and JDK compatibility.
*   **PATH issues:** Ensure the Codeql CLI binary path and JDK bin path are correctly set in your environment variables.

---
[Back to Main README](../README.md)
