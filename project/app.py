from flask import Flask, request, render_template, redirect, url_for, session, flash, jsonify, Response
import sqlite3
from datetime import datetime
app = Flask(__name__)

app.secret_key = "supersecretkey"
DATABASE = "./proxy_data.db"

def query_db(query, args=(), one=False):
    """Helper function to interact with the database."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(query, args)
    rv = cursor.fetchall()
    conn.commit()
    conn.close()
    return (rv[0] if rv else None) if one else rv

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    """Admin login page."""
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        # Check if the email and password match an admin in the database
        query = "SELECT * FROM admin WHERE email = ? AND password = ?"
        result = query_db(query, (email, password), one=True)

        if result:
            # Store the email in session to keep track of logged-in user
            session["admin_logged_in"] = True
            session["admin_email"] = email
            return redirect(url_for("index"))
        else:
            flash("Invalid credentials. Please try again.", "danger")
            return redirect(url_for("admin_login"))

    return render_template("login.html")

@app.route("/")
def index():
    """Render the main admin interface."""
    if "admin_logged_in" not in session or not session["admin_logged_in"]:
        return redirect(url_for("admin_login"))
    return render_template("index.html")

@app.route("/admin/logout")
def admin_logout():
    """Log out the admin."""
    session.pop("admin_logged_in", None)
    session.pop("admin_email", None)
    return redirect(url_for("admin_login"))

@app.route("/blacklist", methods=["GET", "POST"])
def blacklist():
    """Manage the blacklist."""
    if request.method == "POST":
        domain = request.form["domain"]
        query_db("INSERT OR IGNORE INTO blacklist (domain) VALUES (?)", (domain,))
        return redirect(url_for("blacklist"))

    blacklist = query_db("SELECT domain FROM blacklist")
    return render_template("blacklist.html", blacklist=blacklist)

@app.route("/blacklist/delete/<domain>", methods=["POST"])
def delete_blacklist(domain):
    """Delete a domain from the blacklist."""
    query_db("DELETE FROM blacklist WHERE domain = ?", (domain,))
    return redirect(url_for("blacklist"))

@app.route("/whitelist", methods=["GET", "POST"])
def whitelist():
    """Manage the whitelist."""
    if request.method == "POST":
        domain = request.form["domain"]
        query_db("INSERT OR IGNORE INTO whitelist (domain) VALUES (?)", (domain,))
        return redirect(url_for("whitelist"))

    whitelist = query_db("SELECT domain FROM whitelist")
    return render_template("whitelist.html", whitelist=whitelist)

@app.route("/whitelist/delete/<domain>", methods=["POST"])
def delete_whitelist(domain):
    """Delete a domain from the whitelist."""
    query_db("DELETE FROM whitelist WHERE domain = ?", (domain,))
    return redirect(url_for("whitelist"))

@app.route("/logs", methods=["GET"])

def logs():
    """View and filter logs based on query parameters."""
    keyword = request.args.get("keyword", "")
    start_time = request.args.get("start_time", "")
    end_time = request.args.get("end_time", "")

    query = "SELECT timestamp, message FROM logs WHERE 1=1"
    params = []

    if keyword:
        query += " AND message LIKE ?"
        params.append(f"%{keyword}%")
    
    # Ensure start_time and end_time are properly formatted
    if start_time:
        try:
            # Convert start_time to match database format
            start_time = datetime.strptime(start_time, "%Y-%m-%dT%H:%M").strftime("%Y-%m-%d %H:%M:%S")
            query += " AND timestamp >= ?"
            params.append(start_time)
        except ValueError as e:
            print(f"Start time formatting error: {e}")
    if end_time:
        try:
            # Convert end_time to match database format
            end_time = datetime.strptime(end_time, "%Y-%m-%dT%H:%M").strftime("%Y-%m-%d %H:%M:%S")
            query += " AND timestamp <= ?"
            params.append(end_time)
        except ValueError as e:
            print(f"End time formatting error: {e}")

    print("SQL Query:", query)
    print("Parameters:", params)

    logs = query_db(query, params)
    return render_template(
        "logs.html",
        logs=logs,
        keyword=keyword,
        start_time=start_time,
        end_time=end_time
    )

@app.route("/logs/export", methods=["GET"])
def export_logs():
    """Export logs to a CSV file."""
    keyword = request.args.get("keyword", "")
    start_time = request.args.get("start_time", "")
    end_time = request.args.get("end_time", "")

    query = "SELECT timestamp, message FROM logs WHERE 1=1"
    params = []

    if keyword:
        query += " AND message LIKE ?"
        params.append(f"%{keyword}%")
    if start_time:
        try:
            start_time = datetime.strptime(start_time, "%Y-%m-%dT%H:%M").strftime("%Y-%m-%d %H:%M:%S")
            query += " AND timestamp >= ?"
            params.append(start_time)
        except ValueError as e:
            print(f"Start time formatting error: {e}")
    if end_time:
        try:
            end_time = datetime.strptime(end_time, "%Y-%m-%dT%H:%M").strftime("%Y-%m-%d %H:%M:%S")
            query += " AND timestamp <= ?"
            params.append(end_time)
        except ValueError as e:
            print(f"End time formatting error: {e}")

    logs = query_db(query, params)

    # Create CSV response
    def generate_csv():
        yield "Timestamp,Message\n"
        for log in logs:
            yield f"{log[0]},{log[1]}\n"

    return Response(
        generate_csv(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=logs.csv"}
    )


@app.route("/cache", methods=["GET", "POST"])
def cache():
    """View and manage cache entries."""
    if request.method == "POST": #Did not use this if functionality
        # Add a new cache entry
        url = request.form["url"]
        data = request.form["data"]
        expiry = request.form["expiry"]
        query_db("INSERT OR REPLACE INTO cache (url, data, expiry) VALUES (?, ?, ?)", (url, data, expiry))
        return redirect(url_for("cache"))
    # View all cache entries
    cache_entries = query_db("SELECT url, data, expiry FROM cache")
    return render_template("cache.html", cache=cache_entries)

@app.route("/cache/clear", methods=["POST"])
def clear_cache(): #Did not use this function
    """Clear cache entries."""
    url = request.form.get("url", None) 
    if url:
        query_db("DELETE FROM cache WHERE url = ?", (url,))
    else:
        query_db("DELETE FROM cache")  # Clear all cache entries
    return redirect(url_for("cache"))

@app.route("/active_connections")
def active_connections_view():
    """View the number of active connections."""
    result = query_db("SELECT active_connections FROM settings WHERE id = 1", one=True)
    if result is None or result[0] is None:
        active_connections = 0  # Default to 0 if no value is present
    else:
        active_connections = result[0]
    return jsonify({"active_connections": active_connections})


if __name__ == "__main__":
    app.run(debug=True)
