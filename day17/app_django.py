# app_django.py (Illustrative Django snippets for SAST demonstration)
# Note: This file is not a runnable Django app but contains code patterns
# that SAST tools can analyze. Assume necessary Django setup and models exist.

from django.db import models, connection
from django.http import HttpResponse, HttpRequest

# --- Models (Conceptual) ---
# Assume this model is defined in a models.py and migrated.
class UsersUser(models.Model): # Django typically appends appname_
    username = models.CharField(max_length=100)
    email = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)
    # created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        # This helps if you run this outside a full Django project context
        # for some ORM operations, but raw SQL won't care.
        app_label = 'users'
        db_table = 'users_user' # Explicit table name

# --- Views (Conceptual) ---

def get_user_data_vulnerable_raw_sql_percent_format(request: HttpRequest):
    user_id = request.GET.get("id", "0") # Source: request.GET
    # VULNERABLE: Classic SQL Injection with %-formatting
    # Semgrep rule: python-django-raw-sql-formatting
    query = "SELECT * FROM users_user WHERE id = '%s';" % user_id # Sink: query construction

    results = []
    with connection.cursor() as cursor:
        cursor.execute(query) # Sink: execution of tainted query
        for row in cursor.fetchall():
            results.append(dict(zip([col[0] for col in cursor.description], row)))
    return HttpResponse(str(results))


def get_user_data_vulnerable_raw_sql_fstring(request: HttpRequest):
    username_param = request.GET.get("username", "") # Source
    # VULNERABLE: SQL Injection with f-string formatting
    # Semgrep rule: python-django-raw-sql-formatting (if adapted for f-strings, or a new one)
    # The provided rule might not catch f-strings as it focuses on % and .format()
    # Let's use .format() to match the existing rule.
    query = "SELECT * FROM users_user WHERE username = '{}';".format(username_param) # Sink

    results = []
    with connection.cursor() as cursor:
        cursor.execute(query) # Sink
        for row in cursor.fetchall():
            results.append(dict(zip([col[0] for col in cursor.description], row)))
    return HttpResponse(str(results))


def get_user_data_vulnerable_orm_raw_method(request: HttpRequest):
    user_status_str = request.GET.get("status", "1") # Source: e.g., "1" or "0" or "1; DROP TABLE users_user"
    # VULNERABLE: ORM's .raw() method with string formatting
    # Semgrep rule: python-django-orm-raw-method-string-formatting
    # Note: Django's .raw() expects params argument for safety. Here we bypass it.
    query = "SELECT * FROM users_user WHERE is_active = %s" % user_status_str # Sink

    try:
        users = UsersUser.objects.raw(query) # Sink: execution of tainted query via ORM raw
        user_list = [{"id": u.id, "username": u.username} for u in users]
    except Exception as e: # Catch potential DB errors if injection breaks syntax
        user_list = [{"error": str(e)}]
    return HttpResponse(str(user_list))


def get_user_data_safe_orm_filter(request: HttpRequest):
    user_id_from_req = request.GET.get("id") # Source
    # SAFE: Django ORM handles sanitization for simple lookups like filter()
    # No direct string concatenation into SQL query structure.
    users = UsersUser.objects.filter(id=user_id_from_req) # ORM handles this safely
    user_list = [{"id": u.id, "username": u.username} for u in users]
    return HttpResponse(str(user_list))

def get_user_data_safe_raw_sql_parameterized(request: HttpRequest):
    user_id_param = request.GET.get("id") # Source
    query = "SELECT * FROM users_user WHERE id = %s;" # Query with placeholder

    results = []
    with connection.cursor() as cursor:
        # SAFE: Parameterized query. DB driver handles escaping.
        cursor.execute(query, [user_id_param]) # Parameters passed separately
        for row in cursor.fetchall():
            results.append(dict(zip([col[0] for col in cursor.description], row)))
    return HttpResponse(str(results))


# --- Dummy request for local testing/SAST tool parsing aid ---
class DummyHttpRequest:
    def __init__(self, get_params=None):
        self.GET = get_params if get_params is not None else {}
        self.POST = {}
        self.COOKIES = {}
        self.META = {}
        self.method = 'GET'

if __name__ == '__main__':
    # This block is for making the file self-contained for SAST tools
    # and basic conceptual checks. It does not run a Django server.
    print("Django SAST examples loaded.")
    print("To test with Semgrep, run:")
    print("semgrep --config python_web_framework_security.yml app_django.py")

    # Example of how a view might be called (conceptually)
    # For actual execution, Django's routing and DB setup would be needed.
    # req = DummyHttpRequest({'id': '1'})
    # print("\nSimulating safe ORM filter:")
    # print(get_user_data_safe_orm_filter(req).content)

    # req_raw_safe = DummyHttpRequest({'id': '2'})
    # print("\nSimulating safe raw SQL (parameterized):")
    # print(get_user_data_safe_raw_sql_parameterized(req_raw_safe).content)

    # req_vuln_percent = DummyHttpRequest({'id': "3' OR '1'='1"}) # Malicious input
    # print("\nSimulating vulnerable raw SQL (%-format) - EXPECTS DB for full test:")
    # print(get_user_data_vulnerable_raw_sql_percent_format(req_vuln_percent).content)

    # req_vuln_format = DummyHttpRequest({'username': "admin' OR '1'='1"}) # Malicious input
    # print("\nSimulating vulnerable raw SQL (.format) - EXPECTS DB for full test:")
    # print(get_user_data_vulnerable_raw_sql_fstring(req_vuln_format).content)

    # req_vuln_orm_raw = DummyHttpRequest({'status': "1 OR 1=1"}) # Malicious input
    # print("\nSimulating vulnerable ORM raw() - EXPECTS DB for full test:")
    # print(get_user_data_vulnerable_orm_raw_method(req_vuln_orm_raw).content)
    pass
