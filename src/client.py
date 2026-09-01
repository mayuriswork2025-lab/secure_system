import argparse
import socket
import sys
import threading

try:
    from src.message_format import build_chat_message, build_login_message
    from src.protocol import MessageReader, ProtocolDecodeError, default_protocol
except ImportError:
    from message_format import build_chat_message, build_login_message
    from protocol import MessageReader, ProtocolDecodeError, default_protocol


def receive_messages(sock: socket.socket) -> None:
    reader = MessageReader(default_protocol)
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break

            for frame in reader.feed(data):
                try:
                    payload = reader.decode(frame)
                except ProtocolDecodeError:
                    print(f"[invalid packet] {frame!r}")
                    print("> ", end="", flush=True)
                    continue

                message_type = payload.get("type")
                if message_type == "system":
                    print(f"[server] {payload.get('message', '')}")
                    print("", end="", flush=True)
                elif message_type == "chat":
                    sender = payload.get("sender", "unknown")
                    message = payload.get("message", "")
                    print(f"[{sender}] {message}")
                    print("> ", end="", flush=True)
        except OSError:
            break


def run_client(username: str, host: str, port: int, message: str | None = None) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, port))
        sock.sendall(build_login_message(username))

        receiver = threading.Thread(target=receive_messages, args=(sock,), daemon=True)
        receiver.start()

        if message is not None:
            sock.sendall(build_chat_message(username, message))
            print(f"[you] {message}")
            return

        print(f"Connected as {username}. Type messages and press Enter.")
        print("Type 'quit' to exit.")

        while True:
            text = input("> ")
            if text.strip().lower() == "quit":
                sock.sendall(default_protocol.encode({"type": "leave"}))
                break
            sock.sendall(build_chat_message(username, text))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Phase 1 plaintext chat client")
    parser.add_argument("--username", required=True, help="Client username")
    parser.add_argument("--host", default="127.0.0.1", help="Server host")
    parser.add_argument("--port", type=int, default=9000, help="Server port")
    parser.add_argument("--message", help="Optional message to send once and exit")
    args = parser.parse_args()

    try:
        run_client(args.username, args.host, args.port, args.message)
    except KeyboardInterrupt:
        print("\nConnection closed.")
        sys.exit(0)
