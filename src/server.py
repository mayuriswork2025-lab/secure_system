import socket
import threading
from typing import Dict, Tuple

try:
    from src.protocol import MessageReader, ProtocolDecodeError, default_protocol
    from src.utils import log_message
except ImportError:
    from protocol import MessageReader, ProtocolDecodeError, default_protocol
    from utils import log_message

HOST = "127.0.0.1"
PORT = 9000
LISTEN_BACKLOG = 5
RECV_BUFFER_SIZE = 4096
SOCKET_TIMEOUT_SECONDS = 1.0

clients: Dict[socket.socket, str] = {}
clients_lock = threading.Lock()


def remove_client(connection: socket.socket) -> None:
    with clients_lock:
        username = clients.pop(connection, None)
    if username:
        log_message(f"Client disconnected: {username}")


def _find_connection_by_username(username: str) -> socket.socket | None:
    with clients_lock:
        for connection, name in clients.items():
            if name == username:
                return connection
    return None


def _handle_login(connection: socket.socket, address: Tuple[str, int], payload: dict) -> str:
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
    return username


def _handle_chat(username: str, payload: dict) -> None:
    sender = payload.get("sender") or username or "anonymous"
    target = payload.get("target")
    message = payload.get("message", "")

    log_message(f"Message from {sender} to {target}: {message}")

    target_connection = _find_connection_by_username(target) if target else None
    if target_connection is None:
        log_message(f"Chat delivery failed: {target} is not connected")
        return

    target_connection.sendall(default_protocol.encode(payload))


def _handle_dh_public(username: str, payload: dict) -> None:
    sender = payload.get("sender") or username or "anonymous"
    target = payload.get("target")

    log_message(f"DH public value from {sender} for {target}")

    target_connection = _find_connection_by_username(target) if target else None
    if target_connection is None:
        log_message(f"DH exchange failed: {target} is not connected")
        return

    target_connection.sendall(default_protocol.encode(payload))


def handle_client(connection: socket.socket, address: Tuple[str, int]) -> None:
    username = None
    # TCP is a byte stream, not a message stream: one recv() can return part
    # of a message, several messages, or both. MessageReader buffers raw
    # bytes and only hands back frames once a full delimiter-terminated
    # message has arrived.
    reader = MessageReader(default_protocol)
    should_disconnect = False
    try:
        connection.settimeout(SOCKET_TIMEOUT_SECONDS)
        while True:
            try:
                raw = connection.recv(RECV_BUFFER_SIZE)
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
                    username = _handle_login(connection, address, payload)
                elif message_type == "chat":
                    _handle_chat(username, payload)
                elif message_type == "dh_public":
                    _handle_dh_public(username, payload)
                elif message_type == "leave":
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
    server_socket.listen(LISTEN_BACKLOG)
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
