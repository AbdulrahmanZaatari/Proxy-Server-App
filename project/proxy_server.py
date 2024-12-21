import socket
import threading
import select
import datetime, time
from urllib.parse import urlparse
import sqlite3
from datetime import datetime, timedelta
import logging

active_connections = 0

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

connection_lock = threading.Lock()

cache_lock = threading.Lock()

stop_event = threading.Event()

# Constants for the proxy server
PROXY_HOST = '127.0.0.1'  # Proxy server's host
PROXY_PORT = 9090         # Proxy server's port

# Cache dictionary for in-memory caching (will complement database caching)
cache = {}

# Blacklist and Whitelist Initialization
# These should be dynamically loaded from the database to reflect changes made in the admin interface.
def load_blacklist():
    try:
        conn = sqlite3.connect("proxy_data.db")
        cursor = conn.cursor()
        cursor.execute("SELECT domain FROM blacklist")
        result = {row[0] for row in cursor.fetchall()}
    except sqlite3.Error as e:
        logging.error(f"Error loading blacklist: {e}")
        result = set()  # Return an empty set in case of failure
    finally:
        conn.close()
    return result


def load_whitelist():
    try:
        conn = sqlite3.connect("proxy_data.db")
        cursor = conn.cursor()
        cursor.execute("SELECT domain FROM whitelist")
        result = {row[0] for row in cursor.fetchall()}
    except sqlite3.Error as e:
        logging.error(f"Error loading whitelist: {e}")
        result = set()  # Return an empty set in case of failure
    finally:
        conn.close()
    return result 


refresh_lock = threading.Lock()

def refresh_lists():
    global blacklist, whitelist
    while not stop_event.is_set():
        with refresh_lock:
            blacklist = load_blacklist()
            whitelist = load_whitelist()
        logging.info("Refreshed blacklist and whitelist.")
        time.sleep(60)  # Refresh every 60 seconds
#initialize
blacklist = load_blacklist()
whitelist = load_whitelist()

def handle_client(client_socket):
    """
    Handle incoming client requests, parse and modify them, and forward to the target server.
    """
    try:
        # Increment active connections in memory and database
        with connection_lock:
            active_connections = get_active_connections_from_db() + 1  # Fetch from DB, increment in memory
            update_active_connections_in_db(active_connections)  # Update in the database
        log_message(f"New connection. Active connections: {active_connections}")

        # Retrieve the client's IP and port
        client_address = client_socket.getpeername()
        log_message(f"Client connected: {client_address[0]}:{client_address[1]}")

        # Receive the client's request
        request = client_socket.recv(4096).decode()
        if not request:
            log_message("Empty request received; closing connection.")
            return

        # Parse the request (method, URL, host, port)
        try:
            method, url, host, port = parse_request(request)
            log_message(f"Request parsed: Method={method}, URL={url}, Host={host}, Port={port}")
        except ValueError as e:
            log_message(f"Error parsing request: {e}")
            reject_request(client_socket)
            return

        # Check if the host is allowed based on whitelist/blacklist
        if not is_allowed(url, host):
            log_message(f"Blocked request to {host} due to whitelist/blacklist restrictions.")
            reject_request(client_socket)
            return

        # Handle HTTPS tunneling (CONNECT method)
        if method == "CONNECT":
            log_message(f"Handling HTTPS CONNECT request for {host}:{port}")
            handle_https_tunneling(client_socket, host, port)
        else:
            # Handle HTTP requests
            log_message(f"Handling HTTP request for {host}:{port}")
            modified_request = modify_headers(request, host)
            handle_http_request(client_socket, modified_request, host, port)

    except Exception as e:
        log_message(f"Error handling client: {e}")
        logging.error(f"Error handling client: {e}", exc_info=True)  # Log stack trace for debugging

    finally:
        # Decrement active connections in memory and database
        with connection_lock:
            active_connections = get_active_connections_from_db() - 1  # Fetch from DB, decrement in memory
            update_active_connections_in_db(active_connections)  # Update in the database
        log_message(f"Connection closed. Active connections: {active_connections}")

        # close the client socket and log the disconnection
        try:
            if client_socket.fileno() != -1:  # Ensure socket is still valid
                client_socket.close()
                log_message(f"Client disconnected: {client_address[0]}:{client_address[1]}")
        except Exception as e:
            log_message(f"Error while closing client connection: {e}")
        cleanup_cache()  # Clean up expired cache entries

def get_active_connections_from_db():
    """Retrieve the current active connections from the database."""
    conn = sqlite3.connect("proxy_data.db")
    cursor = conn.cursor()
    cursor.execute("SELECT active_connections FROM settings WHERE id = 1")
    active_connections = cursor.fetchone()[0]  # Assuming only one row exists
    conn.close()
    return active_connections

def update_active_connections_in_db(active_connections):
    """Update the active connections in the database."""
    conn = sqlite3.connect("proxy_data.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE settings SET active_connections = ? WHERE id = 1", (active_connections,))
    conn.commit()
    conn.close()

def parse_request(request):
    """
    Parse the client's HTTP request to extract the method, URL, host, and port.
    """
    try:
        # Parse the request line (e.g., "GET http://example.com/path HTTP/1.1")
        request_line = request.split("\r\n")[0]
        method, url, http_version = request_line.split()

        # Parse the URL to extract components
        if method == "CONNECT":
            # CONNECT requests only contain the host:port in the URL
            host, port = url.split(":")
            port = int(port)
        else:
            parsed_url = urlparse(url)
            host = parsed_url.hostname
            port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)

        # Log parsing details
        logging.info(f"Parsed Request: Method={method}, URL={url}, Host={host}, Port={port}")
        return method, url, host, port
    except Exception as e:
        logging.error(f"Error parsing request: {e}")
        raise ValueError("Invalid request format.") from e

def is_allowed(url, host):
    """
    Check if the request URL or host is allowed based on blacklist/whitelist.
    """
    try:
        # Check if the host is in the black and white list at the same time
        if host in blacklist and host in whitelist:
            log_message(f"Request blocked: {host} is in both blacklist and whitelist")
            return False

        # Check if the host is in the blacklist
        elif host in blacklist:
            log_message(f"Request blocked: {host} is blacklisted")
            return False

        # If whitelist is active, ensure the host is in the whitelist
        elif whitelist and host not in whitelist:
            log_message(f"Request blocked: {host} is not in the whitelist")
            return False

        # Allow the request if it is not blacklisted and is whitelisted
        log_message(f"Request allowed: {host}")
        return True
    except Exception as e:
        log_message(f"Error checking allow list for host {host}: {e}")
        return False

def reject_request(client_socket):
    """
    Send a custom HTTP response to the client rejecting the request.
    """
    try:
        response = (
            "HTTP/1.1 403 Forbidden\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 50\r\n"
            "\r\n"
            "<html><body><h1>403 Forbidden</h1></body></html>"
        )
        client_socket.sendall(response.encode())
        log_message("Sent 403 Forbidden response to client")
    except Exception as e:
        log_message(f"Error sending 403 Forbidden response: {e}")
    finally:
        try:
            client_socket.close()
            log_message("Client connection closed after rejection.")
        except Exception as e:
            log_message(f"Error closing client socket after rejection: {e}")

def handle_https_tunneling(client_socket, host, port):
    """
    Handle HTTPS tunneling by forwarding encrypted traffic between client and target server.
    """
    try:
        # Establish a connection to the target server
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as target_socket:
            target_socket.connect((host, port))
            log_message(f"Established secure tunnel to target server: {host}:{port}")

            # Send HTTP 200 response to client to confirm the tunnel is ready
            client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            log_message("Sent 200 Connection Established to client")

            # Forward data between client and server
            forward_data(client_socket, target_socket)
            log_message(f"Encrypted traffic relayed between client and target server: {host}:{port}")

    except Exception as e:
        log_message(f"Error handling HTTPS tunneling to {host}:{port} - {e}")
        print(f"Error handling HTTPS tunneling: {e}")

def forward_data(client_socket, target_socket):
    """
    Forward data between client and target server.
    """
    sockets = [client_socket, target_socket]
    try:
        while True:
            # Wait for data on either socket
            ready_sockets, _, _ = select.select(sockets, [], [])
            for sock in ready_sockets:
                try:
                    data = sock.recv(4096)
                    if not data:
                        # Log which socket closed the connection
                        if sock is client_socket:
                            log_message("Client closed the connection.")
                        else:
                            log_message("Target server closed the connection.")
                        return  # Exit the function when one side closes the connection

                    # Forward the data to the other socket
                    if sock is client_socket:
                        target_socket.sendall(data)
                    else:
                        client_socket.sendall(data)

                except socket.timeout:
                    log_message("Socket timeout occurred during data forwarding.")
                    return
                except socket.error as e:
                    log_message(f"Socket error during forwarding: {e}")
                    return
    except Exception as e:
        log_message(f"Unexpected error during data forwarding: {e}")
    finally:
        # Close sockets if they're still open
        try:
            if client_socket.fileno() != -1:
                client_socket.close()
                log_message("Client socket closed.")
        except Exception as e:
            log_message(f"Error closing client socket: {e}")

        try:
            if target_socket.fileno() != -1:
                target_socket.close()
                log_message("Target socket closed.")
        except Exception as e:
            log_message(f"Error closing target socket: {e}")

def modify_headers(request, host):
    """
    Modify headers in the client's HTTP request.
    - Remove the Proxy-Connection header.
    """
    try:
        lines = request.split("\r\n")
        modified_headers = []

        for line in lines:
            if line.startswith("Proxy-Connection:"):
                # Skip Proxy-Connection header
                continue
            else:
                # Keep other headers as-is
                modified_headers.append(line)

        # Log modified headers
        logging.debug("Modified Headers:\n" + "\n".join(modified_headers))
        return "\r\n".join(modified_headers)
    except Exception as e:
        logging.error(f"Error modifying headers: {e}")
        raise ValueError("Invalid header format.") from e


def handle_http_request(client_socket, request, host, port):
    """
    Handle HTTP requests by forwarding them to the target server and caching the response.
    """
    try:
        # Construct the full URL
        url = f"http://{host}{urlparse(request.split(' ')[1]).path}"

        # Check if the response is cached
        cached_data = get_cached_response(url)
        if cached_data:
            log_message(f"Cache hit: {url}")
            client_socket.sendall(cached_data)  # Send cached data to the client
            return

        # Establish connection to the target server
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as target_socket:
            target_socket.settimeout(30)  # Timeout for server connection
            target_socket.connect((host, port))
            log_message(f"Connected to target server: {host}:{port}")

            # Send the client's request to the target server
            target_socket.sendall(request.encode())
            log_message(f"Forwarded request to target server: {host}:{port}")

            # Read the response from the server
            response_data = b""
            headers = None

            while True:
                try:
                    chunk = target_socket.recv(4096)
                    if not chunk:  # End of the server's response
                        break
                    response_data += chunk

                    # Extract headers if not already done
                    if headers is None and b"\r\n\r\n" in response_data:
                        headers, body = response_data.split(b"\r\n\r\n", 1)
                        headers = headers.decode()
                        log_message(f"Received headers: {headers.strip()}")

                        # Cache the initial part of the response
                        full_response = headers.encode() + b"\r\n\r\n" + body
                        cache_response(url, full_response, headers)

                        # Send the headers and body to the client immediately
                        client_socket.sendall(full_response)
                        response_data = body  # Retain only the body for further chunks
                    else:
                        # Send subsequent chunks to the client
                        client_socket.sendall(chunk)
                except socket.timeout:
                    log_message(f"Timeout during receive from {host}:{port}")
                    break

            # Cache the complete response after receiving all chunks
            if headers:
                full_response = headers.encode() + b"\r\n\r\n" + response_data
                cache_response(url, full_response, headers)
                log_message(f"Response fully cached for {url}")
            else:
                log_message(f"No valid headers received from {url}, skipping cache.")

    except socket.timeout:
        log_message(f"Timeout while connecting to {host}:{port}")
        if client_socket.fileno() != -1:
            client_socket.sendall(b"HTTP/1.1 504 Gateway Timeout\r\n\r\n")
    except Exception as e:
        log_message(f"Error handling HTTP request to {host}:{port}: {e}")
        logging.error(f"Error details: {e}", exc_info=True)
        if client_socket.fileno() != -1:
            client_socket.sendall(b"HTTP/1.1 500 Internal Server Error\r\n\r\n")
    finally:
        try:
            if client_socket.fileno() != -1:  # Ensure client socket is still valid
                client_socket.close()
                log_message(f"Client disconnected.")
        except Exception as e:
            log_message(f"Error while closing client connection: {e}")

def get_cached_response(url):
    with cache_lock:
        if url in cache:
            entry = cache[url]
            if entry["expiry"] > time.time():
                log_message(f"Cache hit for URL: {url}")
                return entry["data"]
            else:
                log_message(f"Cache expired for URL: {url}")
                del cache[url]
    return None

def cache_response(url, response_data, headers):
    with cache_lock:
        expiry = time.time() + 60  # Default expiry time (60 seconds)
        
        # Update in-memory cache
        cache[url] = {
            "data": response_data,
            "expiry": expiry
        }
        
        # Log cache addition
        log_message(f"Cached response for {url}. Expires at: {expiry}")
        
        # Store the cache entry in the SQLite database
        try:
            conn = sqlite3.connect("proxy_data.db")
            cursor = conn.cursor()
            # Insert or replace the entry into the cache table
            cursor.execute("""
                INSERT OR REPLACE INTO cache (url, data, expiry)
                VALUES (?, ?, ?)
            """, (url, response_data, datetime.fromtimestamp(expiry)))
            conn.commit()
            log_message(f"Cache entry added to database for {url}")
        except sqlite3.Error as e:
            log_message(f"Error saving cache entry to database: {e}")
        finally:
            conn.close()

def cleanup_cache():
    with cache_lock:
        current_time = time.time()
        expired_urls = [url for url, entry in cache.items() if entry["expiry"] <= current_time]
        
        # Remove expired entries from in-memory cache
        for url in expired_urls:
            del cache[url]
            log_message(f"Cache entry expired and removed: {url}")
        
        # Remove expired entries from the SQLite database
        try:
            conn = sqlite3.connect("proxy_data.db")
            cursor = conn.cursor()
            cursor.execute("DELETE FROM cache WHERE expiry <= ?", (datetime.fromtimestamp(current_time),))
            conn.commit()
            #log_message("Expired cache entries removed from database.")
        except sqlite3.Error as e:
            log_message(f"Error cleaning up cache entries in database: {e}")
        finally:
            conn.close()

def log_message(message):
    """
    Log a message to a file with a timestamp and optionally print to the console.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_file_path = "proxy_server.log"

    try:
        with open(log_file_path, "a") as log_file:
            log_file.write(f"[{timestamp}] {message}\n")
        # Print to console for debugging or runtime awareness
        print(f"[{timestamp}] {message}")
    except Exception as e:
        print(f"Error writing to log file: {e}")


def schedule_cleanup():
    """
    Periodically clean up expired entries in the cache every hour
    """
    try:
        while not stop_event.is_set():
            time.sleep(0.5) 
            cleanup_cache()
    except Exception as e:
        log_message(f"Error in scheduled cache cleanup: {e}")
    finally:
        log_message("Scheduled cache cleanup stopped.")

def monitor_proxy():
    """
    Periodically monitor and log the state of the proxy server.
    """
    while not stop_event.is_set():
        try:
            with connection_lock:
                current_active_connections = active_connections
            cache_size = len(cache)  # Number of cached items

            # Log metrics
            log_message(f"Monitoring: Active connections: {current_active_connections}, Cache size: {cache_size}")
            time.sleep(10)  # Adjust interval as needed
        except Exception as e:
            log_message(f"Error in monitor_proxy: {e}")



stop_event = threading.Event() 


def main():
    server_socket = None
    cache_lock = threading.Lock()  # Ensure thread-safe access to cache
    try:
        # Start the blacklist/whitelist refresh thread
        refresh_thread = threading.Thread(target=refresh_lists, daemon=True)
        refresh_thread.start()
        log_message("Blacklist/Whitelist refresh thread started.")

        # Start the cache cleanup thread
        cleanup_thread = threading.Thread(target=schedule_cleanup, daemon=True)
        cleanup_thread.start()
        log_message("Cache cleanup thread started.")

        # Start a thread to display active connections in real-time
        monitor_thread = threading.Thread(target=monitor_proxy, daemon=True)
        monitor_thread.start()
        log_message("Proxy monitoring thread started.")


        # Create and bind the server socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((PROXY_HOST, PROXY_PORT))
        server_socket.listen(5)
        server_socket.settimeout(1.0)  # Set a timeout to allow graceful shutdown
        print(f"Proxy server running on {PROXY_HOST}:{PROXY_PORT}")
        log_message(f"Proxy server running on {PROXY_HOST}:{PROXY_PORT}")

        # Main loop to accept incoming connections
        while not stop_event.is_set():
            try:
                client_socket, addr = server_socket.accept()
                log_message(f"Accepted connection from {addr}")
                client_thread = threading.Thread(target=handle_client, args=(client_socket,))
                client_thread.start()
            except socket.timeout:
                pass
            except Exception as e:
                log_message(f"Error accepting connection: {e}")

    except KeyboardInterrupt:
        print("Server stopped by user.")
        log_message("Server stopped by user.")
        stop_event.set()
    except Exception as e:
        print(f"Error starting server: {e}")
        log_message(f"Error starting server: {e}")
    finally:
        # Clean up server resources
        if server_socket:
            server_socket.close()
            log_message("Server socket closed.")
        # Signal all threads to stop
        stop_event.set()
        log_message("Proxy server shutdown complete.")
        print("Proxy server shutdown complete.")


if __name__ == "__main__":
    main()
