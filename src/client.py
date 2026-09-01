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


def _handle_dh_public(sock: socket.socket, username: str, payload: dict, state: DHSessionState) -> None:
    sender = payload.get("sender", "unknown")
    peer_public_key = int(payload["public_key"])

    with state.lock:
        pending_private_key = state.pending_private_keys.pop(sender, None)

        if pending_private_key is not None:
            # We initiated this handshake; this is the peer's reply.
            shared_secret = compute_shared_secret(pending_private_key, peer_public_key)
            state.session_keys[sender] = derive_session_key(shared_secret)
        else:
            # The peer initiated; generate our keys, derive the secret, and reply.
            our_private_key = generate_private_key()
            our_public_key = compute_public_key(our_private_key)
            shared_secret = compute_shared_secret(our_private_key, peer_public_key)
            state.session_keys[sender] = derive_session_key(shared_secret)
            sock.sendall(build_dh_public_message(username, sender, our_public_key))

    session_key = state.session_keys[sender]
    print(f"[dh] Peer public value from {sender}: {peer_public_key}")
    print(f"[dh] Shared secret established with {sender}")
    print(f"[dh] Session key (hex): {session_key.hex()}")


def receive_messages(sock: socket.socket, username: str, state: DHSessionState) -> None:
    # TCP is a byte stream, not a message stream: one recv() can return part
    # of a message, several messages, or both. MessageReader buffers raw
    # bytes and only hands back frames once a full delimiter-terminated
    # message has arrived.
    reader = MessageReader(default_protocol)
    while True:
        try:
            data = sock.recv(RECV_BUFFER_SIZE)
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
                    _handle_dh_public(sock, username, payload, state)
                    print("> ", end="", flush=True)
        except OSError:
            break


def _start_dh_handshake(sock: socket.socket, username: str, peer: str, state: DHSessionState) -> None:
    private_key = generate_private_key()
    public_key = compute_public_key(private_key)
    with state.lock:
        state.pending_private_keys[peer] = private_key
    sock.sendall(build_dh_public_message(username, peer, public_key))
    print(f"[dh] Sent public value to {peer}: {public_key}")
    print(f"[dh] Waiting for {peer}'s response...")


def _wait_for_session_key(peer: str, state: DHSessionState, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with state.lock:
            if peer in state.session_keys:
                return True
        time.sleep(0.05)
    return False


def run_client(username: str, host: str, port: int, message: str | None = None, target: str | None = None) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, port))
        sock.sendall(build_login_message(username))

        state = DHSessionState()
        receiver = threading.Thread(target=receive_messages, args=(sock, username, state), daemon=True)
        receiver.start()

        if message is not None:
            if not target:
                print("Error: --message requires --target <username> -- chat is now peer-targeted.")
                return

            _start_dh_handshake(sock, username, target, state)
            if not _wait_for_session_key(target, state, DH_HANDSHAKE_TIMEOUT_SECONDS):
                print(f"[dh] Timed out waiting for {target} to respond; message not sent.")
                return

            sock.sendall(build_chat_message(username, target, message))
            print(f"[you -> {target}] {message}")
            return

        print(f"Connected as {username}. Type messages and press Enter.")
        print("Type '/dh <username>' to start a Diffie-Hellman key exchange with a peer.")
        print("Type '/msg <username> <text>' to send a message to a peer you've exchanged keys with.")
        print("Type 'quit' to exit.")

        while True:
            text = input("> ")
            stripped = text.strip()

            if stripped.lower() == "quit":
                sock.sendall(default_protocol.encode({"type": "leave"}))
                break

            if stripped.startswith("/dh "):
                peer = stripped[len("/dh "):].strip()
                if not peer:
                    print("[dh] Usage: /dh <username>")
                    continue
                _start_dh_handshake(sock, username, peer, state)
                continue

            if stripped.startswith("/msg "):
                rest = stripped[len("/msg "):].strip()
                peer, _, body = rest.partition(" ")
                if not peer or not body:
                    print("[msg] Usage: /msg <username> <text>")
                    continue
                with state.lock:
                    has_session = peer in state.session_keys
                if not has_session:
                    print(f"[msg] No session with {peer} yet. Run '/dh {peer}' first.")
                    continue
                sock.sendall(build_chat_message(username, peer, body))
                print(f"[you -> {peer}] {body}")
                continue

            print("Unrecognized input. Use '/dh <username>' or '/msg <username> <text>'.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secure chat client")
    parser.add_argument("--username", required=True, help="Client username")
    parser.add_argument("--host", default="127.0.0.1", help="Server host")
    parser.add_argument("--port", type=int, default=9000, help="Server port")
    parser.add_argument("--message", help="Optional message to send once and exit")
    parser.add_argument("--target", help="Peer username to DH-handshake with and send --message to")
    args = parser.parse_args()

    try:
        run_client(args.username, args.host, args.port, args.message, args.target)
    except KeyboardInterrupt:
        print("\nConnection closed.")
        sys.exit(0)
