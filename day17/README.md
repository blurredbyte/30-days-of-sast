# Day 17: SAST for Python - Django and Flask Security

**Summary:** We'll explore SAST for Python web frameworks, focusing on Django and Flask. Common issues include SQL injection, Cross-Site Scripting (XSS), Server-Side Template Injection (SSTI), insecure direct object references (IDOR), and command injection.

**Today's Focus:** Writing Semgrep rules for detecting potential SQL injection in Django ORM and unsafe `markupsafe.Markup` usage in Flask/Jinja2 templates (potential XSS).

## Try it yourself

### 1. Create `app_django.py` (Conceptual Django Snippets)

```python
# app_django.py (Illustrative Django snippets)
from django.db import models
from django.db import connection # For raw SQL example
from django.http import HttpResponse

# Assume a User model exists
class User(models.Model):
    username = models.CharField(max_length=100)
    email = models.CharField(max_length=100)
    # ... other fields

def get_user_data_vulnerable_raw_sql(request):
    user_id = request.GET.get("id")
    # Vulnerable to SQL Injection if user_id is not sanitized
    query = "SELECT * FROM users_user WHERE id = '%s';" % user_id # Classic %-formatting risk
    with connection.cursor() as cursor:
        cursor.execute(query) # Semgrep should flag this
        row = cursor.fetchone()
    return HttpResponse(str(row))

def get_user_data_vulnerable_extra(request):
    user_id_field = request.GET.get("field") # e.g., "username"
    user_id_value = request.GET.get("value") # e.g., "admin"
    # Vulnerable if field and value are not controlled.
    # User.objects.extra(where=["%s='%s'" % (user_id_field, user_id_value)]) # Risky .extra() usage
    # For simplicity, let's use a direct filter construction that might be flagged
    # by a rule looking for string formatting in ORM calls.
    # This specific ORM construct might not be flagged by simple rules,
    # but illustrates the intent. A real rule would be more complex.
    # users = User.objects.filter(**{f"{user_id_field}__exact": user_id_value}) # Safer
    # Let's imagine a less safe construction for demonstration:
    from django.db.models import Q
    # This is contrived, but for demo of string formatting near ORM:
    # query_string = "%s = '%s'" % (user_id_field, user_id_value)
    # users = User.objects.filter(Q(query_string)) # This wouldn't work directly,
                                                 # but Q objects can take strings in some contexts.
                                                 # The .raw() or .extra() are better examples.
    # Focus on .raw() as it's clearer
    users = User.objects.raw("SELECT * FROM users_user WHERE %s = '%s'" % (user_id_field, user_id_value))
    return HttpResponse(str(list(users)))


def get_user_data_safe(request):
    user_id = request.GET.get("id")
    # Safe: Django ORM handles sanitization for simple lookups
    users = User.objects.filter(id=user_id)
    return HttpResponse(str(list(users)))

# Dummy request object for local execution if needed
class DummyRequest:
    def __init__(self, get_params):
        self.GET = get_params

if __name__ == '__main__':
    # This is conceptual and won't run as a full Django app.
    # Illustrates the functions for Semgrep to scan.
    print("Django examples loaded. Run Semgrep against this file.")
    # req = DummyRequest({'id': '1'})
    # print(get_user_data_safe(req))
    # req_vuln = DummyRequest({'id': "1' OR '1'='1"})
    # print(get_user_data_vulnerable_raw_sql(req_vuln)) # Needs DB setup to run
```

### 2. Create `app_flask.py` (Conceptual Flask Snippets)

```python
# app_flask.py (Illustrative Flask snippets)
from flask import Flask, request, render_template_string, Markup

app = Flask(__name__)

@app.route('/greet')
def greet():
    name = request.args.get('name', 'Guest')
    # Potential XSS if name is not escaped and comes directly into template
    # that uses Markup inappropriately.
    # By default, Jinja2 autoescapes. Markup() explicitly bypasses this.

    # Vulnerable scenario: User input directly wrapped in Markup
    # Semgrep should flag this direct usage of Markup with request data.
    html_output = Markup(f"<h1>Hello {name}!</h1>") # name is from request.args

    # Safer: Let Jinja2 handle escaping (default behavior)
    # html_output_safe = f"<h1>Hello {name}!</h1>"
    # return render_template_string(html_output_safe)

    return render_template_string(html_output)


@app.route('/greet_safe')
def greet_safe():
    name = request.args.get('name', 'Guest')
    # Jinja2 autoescapes by default.
    # So, if name is "<script>alert(1)</script>", it will be rendered as text.
    template_string = "<h1>Hello {{ user_name }}!</h1>"
    return render_template_string(template_string, user_name=name)

# Example of SSTI if not careful (not the focus of today's Markup rule but related)
@app.route('/ssti_example')
def ssti_example():
    template_code = request.args.get('template', 'Hello World')
    # Extremely vulnerable to SSTI if template_code is user-controlled
    # return render_template_string(template_code)
    return render_template_string(f"Your template output: {template_code}")


if __name__ == '__main__':
    # This is conceptual. To run, you'd use `flask run`.
    # For Semgrep, it just needs to parse the file.
    print("Flask examples loaded. Run Semgrep against this file.")
    # Example URLs for testing (if app were running):
    # /greet?name=<script>alert('XSS')</script>  (Should trigger alert due to Markup)
    # /greet_safe?name=<script>alert('XSS')</script> (Should display the script tags as text)
```

### 3. Create Semgrep Rules (`python_web_framework_security.yml`)

```yaml
# python_web_framework_security.yml
rules:
  - id: python-django-raw-sql-formatting
    patterns:
      - pattern-either:
          - pattern: |
              $CURSOR.execute("... %s ..." % ($VAR, ...))
          - pattern: |
              $CURSOR.execute("... {} ...".format($VAR, ...))
          - pattern: |
              $QUERY = "... %s ..." % ($VAR, ...)
              ...
              $CURSOR.execute($QUERY)
          - pattern: |
              $QUERY = "... {} ...".format($VAR, ...)
              ...
              $CURSOR.execute($QUERY)
      - pattern-inside: |
          with connection.cursor() as $CURSOR:
            ...
      - pattern-not: $CURSOR.execute(..., [...]) # Exclude parameterized queries
      - pattern-not: $CURSOR.execute(..., {...}) # Exclude parameterized queries (dict)
    message: "Django raw SQL query using string formatting (%, .format()) with variables. This is highly vulnerable to SQL injection. Use parameterized queries instead (e.g., cursor.execute(query, [param1, param2]))."
    languages: [python]
    severity: ERROR
    metadata:
      cwe: "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
      owasp: "A03:2021-Injection"
      framework: django

  - id: python-django-orm-raw-method-string-formatting
    patterns:
      - pattern-either:
        - pattern: $MODEL.objects.raw("... %s ..." % ($VAR, ...), ...)
        - pattern: $MODEL.objects.raw("... {} ...".format($VAR, ...), ...)
        # .extra() is also risky but its syntax is more varied.
        # - pattern: $MODEL.objects.extra(where=["... %s ..." % ($VAR, ...)], ...)
    message: "Django ORM `.raw()` method used with string formatting (%, .format()) and variables. This can lead to SQL injection. Ensure parameters are passed correctly to `.raw()` or use the ORM's safe filtering methods."
    languages: [python]
    severity: ERROR
    metadata:
      cwe: "CWE-89"
      owasp: "A03:2021-Injection"
      framework: django

  - id: python-flask-markupsafe-markup-from-request
    patterns:
      - pattern: flask.Markup($ARG)
      - pattern-inside: |
          def $VIEW_FUNC(..., $REQUEST_VAR, ...): # Or @$APP.route(...) ... def $VIEW_FUNC():
            ...
            $ARG = $REQUEST_VAR.$METHOD(...) # e.g. request.args.get(...)
            ...
      - metavariable-pattern:
          metavariable: $REQUEST_VAR
          pattern-either:
            - pattern: request # flask.request
            - pattern: $X # Could be any variable name if request is assigned
      - metavariable-regex:
          metavariable: $METHOD
          regex: (args|form|values|cookies|data|json|files|get|getlist|__getitem__)
    message: "Flask's `Markup()` used with data directly from a request object (`request.args`, `request.form`, etc.). This explicitly bypasses Jinja2's auto-escaping and can lead to XSS if the request data contains malicious HTML/JS. Ensure data is properly sanitized before wrapping in Markup(), or avoid Markup() and let Jinja2 escape by default."
    languages: [python]
    severity: WARNING # Could be ERROR if source is confirmed as user-controlled without sanitization.
    metadata:
      cwe: "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
      owasp: "A03:2021-Injection" # XSS
      framework: flask
```

### 4. Run Semgrep

```shell
semgrep --config python_web_framework_security.yml app_django.py app_flask.py
```
This should flag:
*   In `app_django.py`: The `cursor.execute(query)` and `User.objects.raw(...)` lines due to `%` formatting.
*   In `app_flask.py`: The `Markup(f"<h1>Hello {name}!</h1>")` line because `name` comes from `request.args`.

## Discussion

*   **SQL Injection (Django):**
    *   **Raw SQL:** The rule `python-django-raw-sql-formatting` looks for string formatting (`%s`, `.format()`) inside `cursor.execute()`. Django's ORM is generally safe, but `raw()` and `extra()` methods, or direct cursor usage, can reintroduce SQLi if not handled carefully. Parameterized queries (`cursor.execute("SELECT ... WHERE id=%s", [user_id])`) are the fix.
    *   **ORM:** Most Django ORM methods (e.g., `filter()`, `get()`, `exclude()`) are SQLi-proof for value-based injections. However, if column names or SQL keywords are constructed from user input (e.g., `User.objects.filter(**{user_controlled_field: value})`), it can be risky. CodeQL is better for tracking such complex data flows.
*   **XSS (Flask/Jinja2):**
    *   Jinja2 (Flask's default templating engine) autoescapes by default, which prevents most XSS.
    *   `markupsafe.Markup()` or `flask.Markup()` explicitly tells Jinja2 that a string is safe and should not be escaped. If user-controlled data is wrapped in `Markup()`, XSS becomes possible.
    *   The Semgrep rule `python-flask-markupsafe-markup-from-request` tries to find `Markup()` calls where the argument comes from `request` data. This requires some `pattern-inside` and metavariable logic.
*   **Server-Side Template Injection (SSTI):** If template strings themselves are constructed from user input (e.g., `render_template_string(user_input)`), SSTI can occur. This is a different vulnerability than XSS via `Markup`. A specific rule would target such patterns.
*   **CodeQL for Python Web Apps:** CodeQL has robust taint tracking for Python. It can find:
    *   SQLi: `SqlInjectionConfig` tracks data from web requests (`RemoteFlowSource`) to SQL execution sinks.
    *   XSS: `XssInjectionConfig` tracks data to template rendering sinks or direct HTML responses.
    *   SSTI, Command Injection, etc. have their own configurations.

SAST for web frameworks often involves understanding framework-specific APIs, security mechanisms (like autoescaping, CSRF protection), and common ways these are misused or bypassed.

---
[Back to Main README](../README.md)
