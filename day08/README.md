# Day 08: Integrating Semgrep into CI/CD Pipelines

**Summary:** Static analysis is most effective when automated. Today, we'll discuss strategies for integrating Semgrep into Continuous Integration/Continuous Deployment (CI/CD) pipelines (like GitHub Actions, GitLab CI, Jenkins). This ensures code is scanned automatically on commits or pull requests.

**Today's Focus:** Creating a basic GitHub Actions workflow file that runs Semgrep.

## Try it yourself

1.  **Ensure your project has some Python code and Semgrep rules**, for example, from `day05` or `day07`.
    *   `weak_hash.py` and `detect_md5.yml` (from Day 05)
    *   `uses_eval.py` and `fix_eval.yml` (from Day 07)
2.  **Create a GitHub Actions workflow file:** `.github/workflows/semgrep_scan.yml` with the content below.
3.  **Commit and push this workflow file to a GitHub repository.**
4.  **Observe the "Actions" tab in your GitHub repository.** Semgrep should run on new pushes or pull requests.

## Workflow Explanation (`.github/workflows/semgrep_scan.yml`)

```yaml
# .github/workflows/semgrep_scan.yml
name: Semgrep SAST Scan

on:
  push:
    branches: [ "main", "master", "develop" ] # Branches to scan on push
  pull_request:
    branches: [ "main", "master", "develop" ] # Target branches for PRs
  workflow_dispatch: # Allows manual triggering

jobs:
  semgrep:
    name: Run Semgrep
    runs-on: ubuntu-latest # Use the latest Ubuntu runner

    container:
      # Use the official Semgrep Docker image
      # Check for the latest stable version: https://hub.docker.com/r/returntocorp/semgrep
      image: returntocorp/semgrep:v1.60.0 # Specify a version

    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Run Semgrep SAST Scan
        run: |
          # Example: Run Semgrep with a specific configuration file from the repo
          # This assumes you have your rules in a file like .semgrep.yml or a specific path
          # For this demo, let's assume we use rules from day05 and day07
          # You'd typically have a primary Semgrep config file for your project.
          echo "Running Semgrep with custom rules..."
          # semgrep --config path/to/your/semgrep-rules.yml --error .

          # Example using rules from previous days (adjust paths as needed if they are in subdirs)
          # If your code and rules are in the root:
          # semgrep --config day05/detect_md5.yml --config day07/fix_eval.yml day05/weak_hash.py day07/uses_eval.py --error

          # A more realistic CI setup might use a general config or auto-discovery:
          # Scan all Python files with a recommended Python ruleset and any .semgrep.yml files
          semgrep ci --config "p/python" --config "auto" --error
          # The `semgrep ci` command is optimized for CI environments.
          # It automatically finds relevant files and rules.
          # `--config "p/python"` loads a broad set of Python rules.
          # `--config "auto"` will load rules from any `.semgrep.yml` or `.semgrepignore` files in the repo.
          # `--error` will make the job fail if Semgrep finds any issues (useful for blocking PRs).

        # Optional: Upload SARIF results for GitHub Advanced Security Code Scanning
        # Only available on public repos or private repos with GHAS enabled.
      # - name: Upload SARIF file
      #   if: always() # Run this step even if Semgrep finds issues and fails
      #   uses: github/codeql-action/upload-sarif@v2
      #   with:
      #     sarif_file: semgrep.sarif # Default output file for `semgrep ci`
```

*   **`name: Semgrep SAST Scan`**: The name of the workflow.
*   **`on:`**: Defines the events that trigger the workflow.
    *   `push`: Runs on pushes to specified branches.
    *   `pull_request`: Runs on pull requests targeting specified branches.
    *   `workflow_dispatch`: Allows manual triggering from the Actions tab.
*   **`jobs:`**: Contains one or more jobs.
    *   **`semgrep:`**: Name of the job.
    *   **`runs-on: ubuntu-latest`**: Specifies the runner environment.
    *   **`container: image: returntocorp/semgrep:vX.Y.Z`**: Runs the job steps inside the official Semgrep Docker container. This is recommended as it provides Semgrep without needing to install it on the runner. *Always specify a version tag for stability.*
    *   **`steps:`**: A sequence of tasks.
        *   **`actions/checkout@v3`**: Checks out your repository code.
        *   **`Run Semgrep SAST Scan`**:
            *   `semgrep ci`: This is the recommended command for CI. It intelligently scans the repository.
            *   `--config "p/python"`: Loads the community Python ruleset. You can add more language-specific rulesets like `p/javascript`, `p/java`, etc.
            *   `--config "auto"`: Automatically loads rules from `.semgrep.yml` files found in the repository. This is great for your custom rules.
            *   `--error`: Exits with a non-zero status code if any issues are found, which will typically fail the CI job (good for blocking merges on PRs).
            *   The output is usually `semgrep.sarif` by default when using `semgrep ci`.
        *   **`Upload SARIF file` (Optional)**:
            *   If you have GitHub Advanced Security, you can upload the `semgrep.sarif` results to integrate with GitHub's code scanning alerts.

**To make this practical for the 30-day structure:**
You would typically have a central Semgrep configuration file at the root of your repository (e.g., `.semgrep.yml` or `semgrep-rules.yml`) that includes rules relevant to your entire project, or references rule files from the daily directories.

For example, your root `.semgrep.yml` might look like:
```yaml
# .semgrep.yml (in the root of the 30-day project)
rules:
  # Include rules from specific days
  - id: include-day05-rules
    rules:
      - rules_path: day05/detect_md5.yml
  - id: include-day07-rules
    rules:
      - rules_path: day07/fix_eval.yml
  # Add other project-wide rules or registry rules directly
  - id: example-registry-rule
    rules:
      - semgrep.dev.example.rule # Placeholder for a real registry rule
```
Then in the GitHub Action, `semgrep ci --config "auto"` would pick this up.

---
[Back to Main README](../README.md)
