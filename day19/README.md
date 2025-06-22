# Day 19: SAST for Ruby on Rails

## Summary

Today's focus is on applying SAST to Ruby on Rails applications. Rails has built-in protections against many common web vulnerabilities, but misconfigurations, outdated versions, or unsafe coding practices can still lead to security issues. We'll cover some common Rails vulnerabilities and how SAST tools can help identify them.

Common vulnerabilities in Ruby on Rails applications:
- **SQL Injection (SQLi):** While ActiveRecord (Rails' ORM) provides strong protection, raw SQL queries or improperly constructed query conditions can still be vulnerable.
- **Cross-Site Scripting (XSS):** Rails automatically escapes content in ERB templates by default, but using `raw` or `html_safe` with user input can introduce XSS.
- **Mass Assignment:** Older Rails versions were susceptible. Strong Parameters, introduced in Rails 4, largely mitigate this by requiring explicit permission for attributes to be updated through forms.
- **Cross-Site Request Forgery (CSRF):** Rails has built-in CSRF protection (`protect_from_forgery`), but it can be accidentally disabled.
- **Insecure Direct Object References (IDOR):** Exposing internal object IDs that can be manipulated by attackers to access unauthorized data.
- **Command Injection:** If user input is passed to system commands.

## CLI/Terminal Commands

Using `Brakeman` (a popular static analysis tool specifically for Ruby on Rails):

```bash
# Install Brakeman
gem install brakeman

# Navigate to your Rails project directory
cd /path/to/your/rails_example

# Run Brakeman
brakeman
```

Using Semgrep with a generic Ruby rule (example for command injection):

```bash
# Ensure you have Semgrep installed: pip install semgrep
# Navigate to your Rails project directory
cd /path/to/your/rails_example

# Run Semgrep with a rule (e.g., for command injection)
semgrep --config "p/ruby.lang.security.audit.command-injection.command-injection-Kernel" .
# Or a more general ruleset
semgrep --config "p/ruby" .
```

## Code Explanation

We'll create a minimal Rails application with a controller action that is vulnerable to XSS because it explicitly uses `html_safe` on user input.

**`app/controllers/users_controller.rb`:**
A controller with an action that takes a `name` parameter and renders it unsafely.

**`app/views/users/show.html.erb`:**
An ERB template that displays the `name` using `html_safe`.

## Try it yourself

1.  Set up a minimal Rails application (you can use the example files in `rails_example` as a guide, but you'll need a full Rails app structure).
    ```bash
    rails new rails_sast_demo --minimal
    cd rails_sast_demo
    # Then create the controller and view as per the example
    rails generate controller Users show
    # Edit app/controllers/users_controller.rb and app/views/users/show.html.erb
    # Add a route to config/routes.rb: get 'users/show', to: 'users#show'
    ```
2.  Run a SAST tool like Brakeman or Semgrep against the code.
3.  Analyze the results to see if the XSS vulnerability is detected.
4.  Fix the vulnerability by removing `html_safe` or ensuring the input is properly sanitized if it *must* contain HTML. In most cases, relying on Rails' default escaping is best.

For the `rails_example` folder, we'll only provide the vulnerable controller and view, not a full Rails app structure, for brevity. Users will need to integrate these into a working Rails app to test with tools like Brakeman.
