import socket
import threading
from typing import Dict, Tuple

try:
    from src.message_format import build_chat_message
    from src.protocol import MessageReader, ProtocolDecodeError, default_protocol
    from src.utils import log_message
except ImportError:
    from message_format import build_chat_message
    from protocol import MessageReader, ProtocolDecodeError, default_protocol
    from utils import log_message

HOST = "127.0.0.1"
PORT = 9000

clients: Dict[socket.socket, str] = {}
clients_lock = threading.Lock()


def remove_client(connection: socket.socket) -> None:
    with clients_lock:
        username = clients.pop(connection, None)
    if username:
        log_message(f"Client disconnected: {username}")


def broadcast(message: str, sender_name: str, sender_connection: socket.socket) -> None:
    packet = build_chat_message(sender_name, message)
    with clients_lock:
        targets = list(clients.items())

    for connection, _ in targets:
        if connection is sender_connection:
            continue
        try:
            connection.sendall(packet)
        except OSError:
            remove_client(connection)


def handle_client(connection: socket.socket, address: Tuple[str, int]) -> None:
    username = None
    reader = MessageReader(default_protocol)
    should_disconnect = False
    try:
        connection.settimeout(1.0)
        while True:
            try:
                raw = connection.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                break

            if not raw:
                break

            for frame in reader.feed(raw):
                try:
                    payload = reader.decode(frame)
                except ProtocolDecodeError:
                    log_message(f"Invalid message from {address}: {frame!r}")
                    continue

                message_type = payload.get("type")

                if message_type == "login":
                    with clients_lock:
                        username = payload.get("username") or f"user_{len(clients) + 1}"
                        clients[connection] = username
                    log_message(f"New client connected: {username} from {address}")
                    welcome = default_protocol.encode({
                        "type": "system",
                        "sender": "server",
                        "message": f"Welcome, {username}! You are now connected."
                    })
                    connection.sendall(welcome)
                    continue

                if message_type == "chat":
                    sender = payload.get("sender") or username or "anonymous"
                    message = payload.get("message", "")
                    log_message(f"Message from {sender}: {message}")
                    broadcast(message, sender, connection)
                    continue

                if message_type == "leave":
                    should_disconnect = True
                    break

            if should_disconnect:
                break
    finally:
        remove_client(connection)
        connection.close()


def start_server() -> None:
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    log_message(f"Server started on {HOST}:{PORT}")

    try:
        while True:
            connection, address = server_socket.accept()
            thread = threading.Thread(target=handle_client, args=(connection, address), daemon=True)
            thread.start()
    except KeyboardInterrupt:
        log_message("Server shutting down...")
    finally:
        server_socket.close()


if __name__ == "__main__":
    start_server()
