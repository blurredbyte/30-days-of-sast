# Day 23: SAST in CI/CD Pipelines

## Summary

Integrating Static Application Security Testing (SAST) into your Continuous Integration/Continuous Deployment (CI/CD) pipeline is a crucial step towards building secure software. Automating SAST scans ensures that code is consistently checked for vulnerabilities with every commit or pull request, providing rapid feedback to developers and preventing security issues from reaching production.

**Benefits of SAST in CI/CD:**
-   **Early Detection:** Find and fix vulnerabilities early in the development lifecycle, reducing remediation costs.
-   **Developer Feedback:** Provide immediate feedback to developers within their workflow, promoting security awareness.
-   **Automation:** Ensure consistent application of security checks without manual intervention.
-   **Gatekeeping:** Optionally fail builds or block deployments if critical vulnerabilities are found.
-   **Compliance:** Help meet regulatory and compliance requirements that mandate security testing.

**Key Considerations for Integration:**
-   **Speed:** SAST scans can be time-consuming. Choose tools and configure them for incremental scans or focus on critical rules to avoid significantly slowing down the pipeline.
-   **Accuracy:** Minimize false positives to maintain developer trust. Tune rules and use baseline files if supported.
-   **Actionable Results:** Ensure findings are clear, provide context, and suggest remediation. Integrate with issue trackers.
-   **Workflow Integration:** Trigger scans on pull requests, merges to main branches, or nightly builds.
-   **Baseline Scans:** For existing projects, establish a baseline of current findings and focus on new issues introduced by changes.

## CLI/Terminal Commands (Conceptual within CI/CD)

The actual commands are executed by your CI/CD system (e.g., GitHub Actions, Jenkins, GitLab CI). You define these commands in your CI configuration file.

**Example: GitHub Action for Semgrep**
(This is a conceptual snippet for `github_action_example.yml`)

```yaml
# In .github/workflows/semgrep_scan.yml
name: Semgrep SAST Scan

on:
  push:
    branches: [ main, master, develop ]
  pull_request:
    branches: [ main, master, develop ]

jobs:
  semgrep:
    name: Scan
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Run Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          # publishToken: ${{ secrets.SEMGREP_APP_TOKEN }} # For Semgrep App dashboard integration
          # config: "p/default" # Default rules, or your custom ruleset like "your-org.my-ruleset"
          # generateSarif: true # To upload results to GitHub Security tab
          failOnSeverity: ERROR # Optionally fail the build on ERROR severity findings
```

**Example: GitHub Action for CodeQL**
(This is a conceptual snippet for `github_action_example.yml`)

```yaml
# In .github/workflows/codeql_analysis.yml
name: "CodeQL Analysis"

on:
  push:
    branches: [ main, master, develop ]
  pull_request:
    branches: [ main, master, develop ]
  schedule:
    - cron: '0 0 * * 0' # Weekly scan

jobs:
  analyze:
    name: Analyze
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
      security-events: write

    strategy:
      fail-fast: false
      matrix:
        language: [ 'java', 'python', 'javascript' ] # Add languages relevant to your repo

    steps:
    - name: Checkout repository
      uses: actions/checkout@v3

    - name: Initialize CodeQL
      uses: github/codeql-action/init@v2
      with:
        languages: ${{ matrix.language }}
        # queries: +security-extended, +security-and-quality # Or path to custom queries

    - name: Autobuild (if applicable)
      uses: github/codeql-action/autobuild@v2

    - name: Perform CodeQL Analysis
      uses: github/codeql-action/analyze@v2
      with:
        category: "/language:${{matrix.language}}"
```

## Code Explanation

For this day, the "code" is the CI/CD configuration file itself. We'll provide an example of a GitHub Actions workflow file.

**`github_action_example.yml`:**
A YAML file defining a GitHub Actions workflow that runs a SAST tool (e.g., Semgrep or CodeQL). This file would typically reside in the `.github/workflows/` directory of your repository.

*Note: The repository already contains a `.github/workflows/semgrep_scan.yml` which is a good practical example.*

## Try it yourself

1.  **Explore Existing CI/CD:** If your project already has a CI/CD pipeline, investigate how SAST could be added.
2.  **Set up a Demo with GitHub Actions:**
    *   Create a new public repository on GitHub.
    *   Add some sample code (e.g., from previous days' examples like `day20/express_example.js` or `day21/taint_example.py`).
    *   Create a `.github/workflows/` directory.
    *   Add a workflow file (e.g., `semgrep_ci.yml`) based on the `github_action_example.yml` content or the existing `semgrep_scan.yml` in this series' repo.
        *   For Semgrep, you can use public rules like `semgrep --config "p/default" .` or point to a specific ruleset.
        *   For CodeQL, follow the setup provided by the `github/codeql-action`.
    *   Commit and push the changes.
    *   Go to the "Actions" tab in your GitHub repository to see the workflow run.
    *   If vulnerabilities are found and you've configured SARIF output (common for CodeQL and an option for Semgrep), check the "Security" tab under "Code scanning alerts."
3.  **Experiment:**
    *   Introduce a known vulnerability into your sample code and see if the CI/CD SAST job detects it.
    *   Configure the job to fail if critical issues are found.
    *   Explore options for sending notifications or creating issues from findings.

Integrating SAST into CI/CD is a practical step that turns SAST from an occasional audit activity into a continuous security practice.
