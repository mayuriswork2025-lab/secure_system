import argparse
import socket
import sys
import threading
import time
from typing import Dict

try:
    from src.dh import compute_public_key, compute_shared_secret, derive_session_key, generate_private_key
    from src.message_format import build_chat_message, build_dh_public_message, build_login_message
    from src.protocol import MessageReader, ProtocolDecodeError, default_protocol
except ImportError:
    from dh import compute_public_key, compute_shared_secret, derive_session_key, generate_private_key
    from message_format import build_chat_message, build_dh_public_message, build_login_message
    from protocol import MessageReader, ProtocolDecodeError, default_protocol

RECV_BUFFER_SIZE = 4096
DH_HANDSHAKE_TIMEOUT_SECONDS = 5.0


class DHSessionState:
    """Tracks in-progress and completed DH handshakes with other peers."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.pending_private_keys: Dict[str, int] = {}
        self.session_keys: Dict[str, bytes] = {}


class ChatClient:
    """Connects to the chat server, runs DH handshakes, and sends/receives messages."""

    def __init__(self, username: str, host: str, port: int) -> None:
        self.username = username
        self.host = host
        self.port = port
        self.state = DHSessionState()
        self.sock: socket.socket | None = None

    def run(self, message: str | None = None, target: str | None = None) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            self.sock = sock
            sock.connect((self.host, self.port))
            sock.sendall(build_login_message(self.username))

            receiver = threading.Thread(target=self.receive_messages, daemon=True)
            receiver.start()

            if message is not None:
                self.send_once(message, target)
            else:
                self.interactive_loop()

    def send_once(self, message: str, target: str | None) -> None:
        if not target:
            print("Error: --message requires --target <username> -- chat is peer-targeted.")
            return

        self.start_dh_handshake(target)
        if not self.wait_for_session_key(target, DH_HANDSHAKE_TIMEOUT_SECONDS):
            print(f"[dh] Timed out waiting for {target} to respond; message not sent.")
            return

        self.sock.sendall(build_chat_message(self.username, target, message))
        print(f"[you -> {target}] {message}")

    def interactive_loop(self) -> None:
        print(f"Connected as {self.username}. Type messages and press Enter.")
        print("Type '/dh <username>' to start a Diffie-Hellman key exchange with a peer.")
        print("Type '/msg <username> <text>' to send a message to a peer you've exchanged keys with.")
        print("Type 'quit' to exit.")

        while True:
            text = input("> ")
            stripped = text.strip()

            if stripped.lower() == "quit":
                self.sock.sendall(default_protocol.encode({"type": "leave"}))
                break

            if stripped.startswith("/dh "):
                peer = stripped[len("/dh "):].strip()
                if not peer:
                    print("[dh] Usage: /dh <username>")
                    continue
                self.start_dh_handshake(peer)
                continue

            if stripped.startswith("/msg "):
                rest = stripped[len("/msg "):].strip()
                peer, _, body = rest.partition(" ")
                if not peer or not body:
                    print("[msg] Usage: /msg <username> <text>")
                    continue
                self.send_chat(peer, body)
                continue

            print("Unrecognized input. Use '/dh <username>' or '/msg <username> <text>'.")

    def send_chat(self, peer: str, body: str) -> None:
        with self.state.lock:
            has_session = peer in self.state.session_keys
        if not has_session:
            print(f"[msg] No session with {peer} yet. Run '/dh {peer}' first.")
            return
        self.sock.sendall(build_chat_message(self.username, peer, body))
        print(f"[you -> {peer}] {body}")

    def receive_messages(self) -> None:
        # TCP is a byte stream, not a message stream: one recv() can return part
        # of a message, several messages, or both. MessageReader buffers raw
        # bytes and only hands back frames once a full delimiter-terminated
        # message has arrived.
        reader = MessageReader(default_protocol)
        while True:
            try:
                data = self.sock.recv(RECV_BUFFER_SIZE)
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
                    elif message_type == "dh_public":
                        self.handle_dh_public(payload)
                        print("> ", end="", flush=True)
            except OSError:
                break

    def start_dh_handshake(self, peer: str) -> None:
        private_key = generate_private_key()
        public_key = compute_public_key(private_key)
        with self.state.lock:
            self.state.pending_private_keys[peer] = private_key
        self.sock.sendall(build_dh_public_message(self.username, peer, public_key))
        print(f"[dh] Sent public value to {peer}: {public_key}")
        print(f"[dh] Waiting for {peer}'s response...")

    def handle_dh_public(self, payload: dict) -> None:
        sender = payload.get("sender", "unknown")
        peer_public_key = int(payload["public_key"])

        with self.state.lock:
            pending_private_key = self.state.pending_private_keys.pop(sender, None)

            if pending_private_key is not None:
                # We initiated this handshake; this is the peer's reply.
                shared_secret = compute_shared_secret(pending_private_key, peer_public_key)
                self.state.session_keys[sender] = derive_session_key(shared_secret)
            else:
                # The peer initiated; generate our keys, derive the secret, and reply.
                our_private_key = generate_private_key()
                our_public_key = compute_public_key(our_private_key)
                shared_secret = compute_shared_secret(our_private_key, peer_public_key)
                self.state.session_keys[sender] = derive_session_key(shared_secret)
                self.sock.sendall(build_dh_public_message(self.username, sender, our_public_key))

            session_key = self.state.session_keys[sender]
        print(f"[dh] Peer public value from {sender}: {peer_public_key}")
        print(f"[dh] Shared secret established with {sender}")
        print(f"[dh] Session key (hex): {session_key.hex()}")

    def wait_for_session_key(self, peer: str, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self.state.lock:
                if peer in self.state.session_keys:
                    return True
            time.sleep(0.05)
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secure chat client")
    parser.add_argument("--username", required=True, help="Client username")
    parser.add_argument("--host", default="127.0.0.1", help="Server host")
    parser.add_argument("--port", type=int, default=9000, help="Server port")
    parser.add_argument("--message", help="Optional message to send once and exit")
    parser.add_argument("--target", help="Peer username to DH-handshake with and send --message to")
    args = parser.parse_args()

    try:
        ChatClient(args.username, args.host, args.port).run(args.message, args.target)
    except KeyboardInterrupt:
        print("\nConnection closed.")
        sys.exit(0)
