# app_flask.py (Illustrative Flask snippets for SAST demonstration)
# Note: This file is not a runnable Flask app as-is but contains code patterns
# for SAST tools like Semgrep to analyze.

from flask import Flask, request, render_template_string, Markup, jsonify
import jinja2 # For more explicit control if needed, though Flask handles it.

app = Flask(__name__)

# --- Routes for XSS via Markup ---

@app.route('/greet_vulnerable_markup')
def greet_vulnerable_markup():
    # SOURCE: User input from request arguments
    user_name = request.args.get('name', 'Guest')

    # SINK: User input directly wrapped in Markup, then rendered.
    # This bypasses Jinja2's default auto-escaping, leading to XSS if user_name contains HTML/JS.
    # Semgrep rule: python-flask-markupsafe-markup-from-request
    # Example vulnerable URL: /greet_vulnerable_markup?name=<script>alert('XSS via Markup')</script>
    greeting_html = Markup(f"<h2>Hello {user_name}!</h2><p>Welcome to our vulnerable page.</p>")

    # The template itself is simple, the vulnerability is in how `greeting_html` is constructed.
    return render_template_string("<div>{{ content_from_server | safe }}</div>", content_from_server=greeting_html)
    # Using |safe filter in template is equivalent to wrapping in Markup in Python code, if content_from_server was not already Markup.

@app.route('/greet_safer_markup')
def greet_safer_markup():
    user_name = request.args.get('name', 'Guest') # Source

    # SAFER (Conceptual): Sanitize or ensure 'user_name' is safe before wrapping in Markup.
    # For this demo, we'll assume it's been "sanitized" (e.g., only allowing alphanumerics, or HTML escaped).
    # In a real app, use a library like Bleach.
    import re
    sanitized_name = re.sub(r'[^\w\s]', '', user_name) # Example very basic sanitizer

    # Although still using Markup, the input is claimed to be sanitized.
    # A SAST tool might still flag Markup usage as a point to review for sanitizer effectiveness.
    greeting_html = Markup(f"<h2>Hello {sanitized_name}!</h2><p>Welcome to our safer page.</p>")
    return render_template_string("<div>{{ content | safe }}</div>", content=greeting_html)


@app.route('/greet_safe_jinja_autoescape')
def greet_safe_jinja_autoescape():
    user_name = request.args.get('name', 'Guest') # Source

    # SAFE: Jinja2 autoescapes by default.
    # If user_name is "<script>alert(1)</script>", Jinja2 will render the tags as plain text.
    # No Markup() call means auto-escaping is active for `user_name_in_template`.
    template = "<div><h2>Hello {{ user_name_in_template }}!</h2><p>Jinja2 auto-escaped this.</p></div>"
    return render_template_string(template, user_name_in_template=user_name)


# --- Routes for Server-Side Template Injection (SSTI) ---
# Not the primary focus of today's Semgrep rule, but important for Flask.

@app.route('/ssti_vulnerable_render')
def ssti_vulnerable_render():
    # SOURCE: User input used directly as part of the template string.
    template_content = request.args.get('template_str', '<em>Hello World from default template string!</em>')

    # VULNERABLE TO SSTI: Rendering a string that is fully or partially user-controlled.
    # Example: /ssti_vulnerable_render?template_str={{config}} will leak server config.
    # Example: /ssti_vulnerable_render?template_str={{ cycler.__init__.__globals__.os.popen('id').read() }} (RCE)
    try:
        rendered_template = render_template_string(f"<p>Your custom content: {template_content}</p>")
    except jinja2.exceptions.TemplateSyntaxError as e:
        rendered_template = f"Template Error: {e}"
    return rendered_template


@app.route('/ssti_safer_approach')
def ssti_safer_approach():
    user_message = request.args.get('message', 'Default message.') # Source

    # SAFER: User input is passed as data to a fixed template, not used to construct the template itself.
    # Jinja2 will auto-escape user_message if it's directly rendered.
    fixed_template = "<p>Message from user: {{ usr_msg }}</p>"
    return render_template_string(fixed_template, usr_msg=user_message)


if __name__ == '__main__':
    # This block allows the file to be parsed by SAST tools without running a server.
    print("Flask SAST examples loaded.")
    print("To test with Semgrep, run:")
    print("semgrep --config python_web_framework_security.yml app_flask.py")

    # For actual execution, you would typically run:
    # export FLASK_APP=app_flask.py
    # flask run
    #
    # Then access URLs like:
    # http://127.0.0.1:5000/greet_vulnerable_markup?name=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E
    # http://127.0.0.1:5000/greet_safe_jinja_autoescape?name=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E
    # http://127.0.0.1:5000/ssti_vulnerable_render?template_str=%7B%7Bconfig%7D%7D
    pass
