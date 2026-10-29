"""
tests/mock_target.py - Local Vulnerable & False-Positive Target for AegisScan
Run via: python tests/mock_target.py
"""
from flask import Flask, request, render_template_string
import html

app = Flask(__name__)

INDEX_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>AegisScan Target Testbed</title>
    <style>
        body { font-family: sans-serif; margin: 40px; background: #0f172a; color: #f8fafc; }
        a { color: #38bdf8; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .card { background: #1e293b; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .tag-vuln { color: #ef4444; font-weight: bold; }
        .tag-safe { color: #22c55e; font-weight: bold; }
    </style>
</head>
<body>
    <h1>AegisScan Test Lab</h1>
    <p>This server provides test endpoints to demonstrate True Positives (exploits) and False Positive discrimination.</p>

    <div class="card">
        <h3><span class="tag-vuln">[Vulnerable]</span> SQL Injection Endpoint</h3>
        <p><a href="/vulnerable_sqli?id=1">/vulnerable_sqli?id=1</a></p>
    </div>

    <div class="card">
        <h3><span class="tag-vuln">[Vulnerable]</span> Reflected XSS Endpoint</h3>
        <p><a href="/vulnerable_xss?name=guest">/vulnerable_xss?name=guest</a></p>
    </div>

    <div class="card">
        <h3><span class="tag-safe">[Safe - Benign Reflection]</span> Search Page</h3>
        <p><a href="/search?q=test">/search?q=test</a></p>
    </div>

    <div class="card">
        <h3><span class="tag-safe">[Safe - Generic 500 Error]</span> Item Details Page</h3>
        <p><a href="/item?id=101">/item?id=101</a></p>
    </div>
</body>
</html>
"""

@app.route("/", methods=["GET"])
def index():
    return render_template_string(INDEX_HTML)

# 1. Benign Echo: Properly sanitized reflection (Should NOT be flagged as XSS)
@app.route("/search", methods=["GET"])
def search():
    query = request.args.get("q", "")
    safe_query = html.escape(query)
    template = f"""
    <html>
        <body>
            <h1>Search Results</h1>
            <p>You searched for: {safe_query}</p>
        </body>
    </html>
    """
    return render_template_string(template)

# 2. Generic Internal Server Error (Should NOT be flagged as SQLi)
@app.route("/item", methods=["GET"])
def item():
    val = request.args.get("id", "")
    if "'" in val or "--" in val:
        # Returns 500 with a generic custom error message; NO database leak
        return "Internal Application Error: Invalid character syntax detected by application filter.", 500
    return f"Displaying details for item: {html.escape(val)}"

# 3. Truly Vulnerable SQLi: Emulates real database syntax failure
@app.route("/vulnerable_sqli", methods=["GET"])
def vuln_sqli():
    val = request.args.get("id", "1")
    if "'" in val or "--" in val or "OR" in val.upper() or "UNION" in val.upper():
        return (
            f"<div>Database error: You have an error in your SQL syntax; "
            f"check the manual that corresponds to your MySQL server version for the right syntax to use near '{val}' at line 1</div>",
            500
        )
    return f"<div>User Record Found: ID={html.escape(val)}, Username=admin, Role=Security Analyst</div>"

# 4. Truly Vulnerable XSS: Injected input reflected raw without HTML escaping
@app.route("/vulnerable_xss", methods=["GET"])
def vuln_xss():
    name = request.args.get("name", "guest")
    # Vulnerable raw reflection
    return f"<html><body><h1>Welcome {name}!</h1><p>Active user profile page.</p></body></html>"

if __name__ == "__main__":
    print("[*] AegisScan Mock Server running at http://127.0.0.1:5000 ...")
    app.run(host="127.0.0.1", port=5000, debug=False)
