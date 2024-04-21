import socket
import multiprocessing
import ssl
import logging
import argparse
import signal
import hashlib
import secrets
import zlib
import asyncio

SERVER_CERT = 'server.crt'  # Server's certificate file
SERVER_KEY = 'server.key'    # Server's private key file
LOG_FILE = 'vpn.log'         # Log file

# Define a dictionary to store user credentials
USER_DATABASE = {
    'user1': {
        'password_hash': 'df91b379ff9cafac86e8c8f5ed07a86e',  # Hashed password for 'password1'
        'salt': '5a9f1bb891608d1cb0f4ccfa1c2514d6'           # Salt used for 'password1'
    },
    'user2': {
        'password_hash': 'b21a02e99f51af1a86f15e71d1b7d028',  # Hashed password for 'password2'
        'salt': '6ef7a3282e84a6fa0b4a5a452b1e7d05'           # Salt used for 'password2'
    },
    # Add more users as needed
}

class VPNServer:
    def __init__(self, host, port, max_connections):
        self.host = host
        self.port = port
        self.max_connections = max_connections
        self.server_socket = None
        self.logger = logging.getLogger('VPNServer')
        self.logger.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler = logging.FileHandler(LOG_FILE)
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        self.shutdown_requested = multiprocessing.Event()  # Use multiprocessing Event
        self.connections = multiprocessing.Manager().list()  # Shared list among processes

    def handle_client(self, client_socket):
        try:
            # Perform authentication
            if not self.authenticate_client(client_socket):
                return

            while not self.shutdown_requested.is_set():
                data = client_socket.recv(4096)
                if not data:
                    break
                # Compress data before sending
                compressed_data = zlib.compress(data)
                client_socket.send(compressed_data)
        except Exception as e:
            self.logger.error(f"Error handling client: {e}")
        finally:
            client_socket.close()
            self.connections.remove(client_socket)

    def authenticate_client(self, client_socket):
        client_socket.send(b"Username: ")
        username = client_socket.recv(1024).decode().strip()

        # Certificate-based authentication
        cert = client_socket.getpeercert()
        if cert and 'commonName' in cert:
            if cert['commonName'] in USER_DATABASE:
                self.logger.info(f"Authenticated user: {cert['commonName']}")
                return True

        # Username/password authentication
        client_socket.send(b"Password: ")
        password = client_socket.recv(1024).decode().strip()

        if username in USER_DATABASE:
            stored_password_hash = USER_DATABASE[username]['password_hash']
            salt = USER_DATABASE[username]['salt']
            input_password_hash = hashlib.md5((password + salt).encode()).hexdigest()

            if input_password_hash == stored_password_hash:
                self.logger.info(f"Authenticated user: {username}")
                return True

        self.logger.warning(f"Authentication failed for user: {username}")
        client_socket.send(b"Authentication failed. Disconnecting.\n")
        client_socket.close()
        return False

    async def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(self.max_connections)
        self.logger.info(f'[*] Listening on {self.host}:{self.port}')

        loop = asyncio.get_event_loop()
        while not self.shutdown_requested.is_set():
            client_socket, client_addr = await loop.sock_accept(self.server_socket)
            self.logger.info(f'[*] Accepted connection from {client_addr[0]}:{client_addr[1]}')

            # Wrap the client socket with SSL/TLS
            ssl_socket = ssl.wrap_socket(client_socket, server_side=True, certfile=SERVER_CERT, keyfile=SERVER_KEY, ssl_version=ssl.PROTOCOL_TLS)

            # Limiting the number of connections
            if len(self.connections) >= self.max_connections:
                self.logger.warning("Maximum number of connections reached. Rejecting new connection.")
                ssl_socket.close()
                continue

            self.connections.append(ssl_socket)
            loop.create_task(self.handle_client(ssl_socket))

    def stop(self):
        if self.server_socket:
            self.server_socket.close()
            self.logger.info("Server stopped.")

    # IDP method to detect suspicious activities
    def detect_intrusion(self, client_socket):
        # Implement your IDP logic here
        return False  # Return True if intrusion is detected, False otherwise

def parse_args():
    parser = argparse.ArgumentParser(description='VPN Server')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Host IP address to bind')
    parser.add_argument('--port', type=int, default=12345, help='Port to listen on')
    parser.add_argument('--max-connections', type=int, default=5, help='Maximum number of connections')
    return parser.parse_args()

def sigint_handler(signal, frame):
    print("SIGINT received. Exiting...")
    vpn_server.stop()
    exit(0)

def main():
    signal.signal(signal.SIGINT, sigint_handler)

    args = parse_args()
    vpn_server = VPNServer(args.host, args.port, args.max_connections)
    asyncio.run(vpn_server.start())

if __name__ == "__main__":
    main()
