import sqlite3

# Initialize the database
def initialize_db():
    conn = sqlite3.connect("proxy_data.db")
    cursor = conn.cursor()

    # Create the settings table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        active_connections INTEGER
    )
    """)

    # Create the admin table with email as unique and auto-incremented id
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS admin (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    """)

    email = "admin@example.com"
    password = "adminpassword"  

    try:
        cursor.execute("INSERT INTO admin (email, password) VALUES (?, ?)", (email, password))
        conn.commit()
        print("Admin account created successfully.")
    except sqlite3.IntegrityError:
        print("Admin account already exists.")

    # Check if the settings table is empty and insert the initial value
    cursor.execute("SELECT * FROM settings")
    if cursor.fetchone() is None:
        cursor.execute("INSERT INTO settings (active_connections) VALUES (0)")

    # Create other tables
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS cache (
        url TEXT PRIMARY KEY,
        data BLOB,
        expiry TIMESTAMP
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        message TEXT
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS blacklist (
        domain TEXT PRIMARY KEY
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS whitelist (
        domain TEXT PRIMARY KEY
    )
    """)

    # Commit the changes and close the connection
    conn.commit()
    conn.close()

if __name__ == "__main__":
    initialize_db()
