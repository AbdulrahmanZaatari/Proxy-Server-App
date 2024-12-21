# Proxy Server and Admin Panel

## Overview
This project includes two main components:

1. **Proxy Server**: A Python-based proxy server that manages and filters requests using a blacklist and whitelist. It includes caching capabilities to enhance performance and logging mechanisms for monitoring.
2. **Admin Panel**: A web-based interface built with Flask for managing the proxy server settings, including blacklists, whitelists, logs, and cache.

---

## Features

### Proxy Server
- **HTTP/HTTPS Proxy**:
  - Handles both HTTP and HTTPS requests.
  - Modifies request headers as needed.
- **Caching**:
  - Stores responses in memory and SQLite database to reduce redundant requests.
  - Periodically cleans up expired cache entries.
- **Blacklist/Whitelist Management**:
  - Filters requests based on domains specified in the blacklist and whitelist.
  - Dynamically reloads these lists at regular intervals.
- **Connection Management**:
  - Tracks active connections and updates the count in the database.
- **Logging**:
  - Logs all incoming requests, responses, and errors to a file and database.

### Admin Panel
- **Authentication**:
  - Secure admin login/logout functionality.
- **Manage Blacklist and Whitelist**:
  - Add, view, and delete domains from the blacklist and whitelist.
- **Logs Viewer**:
  - Filter logs by keyword or date range.
  - Export logs to a CSV file.
- **Cache Management**:
  - View all cached entries.
  - Add or clear cache entries.
- **Active Connections**:
  - View the number of active connections in real time.

---

## Setup and Installation

### Requirements
- Python 3.7+
- SQLite3
- Flask

### Installation Steps

1. **Clone the repository**:
   ```bash
   git clone <repository_url>
   cd <repository_directory>
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Initialize the SQLite Database**:
   - Ensure the `proxy_data.db` file exists in the project root.
   - Use the following schema to set up the database:
     ```sql
     CREATE TABLE admin (email TEXT PRIMARY KEY, password TEXT);
     CREATE TABLE blacklist (domain TEXT PRIMARY KEY);
     CREATE TABLE whitelist (domain TEXT PRIMARY KEY);
     CREATE TABLE logs (timestamp DATETIME, message TEXT);
     CREATE TABLE cache (url TEXT PRIMARY KEY, data TEXT, expiry DATETIME);
     CREATE TABLE settings (id INTEGER PRIMARY KEY, active_connections INTEGER);
     ```

4. **Run the Proxy Server**:
   ```bash
   python proxy_server.py
   ```

5. **Run the Admin Panel**:
   ```bash
   python app.py
   ```

---

## Usage

### Proxy Server
- Start the proxy server on `127.0.0.1:9090`.
- Update your system or browser's proxy settings to route traffic through `127.0.0.1:9090`.

### Admin Panel
- Access the admin panel at `http://127.0.0.1:5000/admin/login`.
- Use the admin credentials stored in the database to log in.

---

## Directory Structure
- `app.py`: Flask-based admin panel for managing proxy settings.
- `proxy_server.py`: Core proxy server implementation.
- `proxy_data.db`: SQLite database for storing configurations, logs, and cache.
- `templates/`: HTML templates for the admin panel.
- `static/`: Static assets like CSS and JavaScript for the admin panel.

---

## Security Considerations
- Use a strong `secret_key` in `app.py` for session management.
- Ensure proper validation and sanitization of inputs to prevent SQL injection.
- Deploy behind a firewall or use SSL/TLS for secure communication.

---

## License
This project is open-source and available under the [MIT License](LICENSE).

---

## Contact
For questions or contributions, please contact the repository maintainer.

