try:
    from src.protocol import default_protocol
except ImportError:
    from protocol import default_protocol


def build_login_message(username: str) -> bytes:
    payload = {
        "type": "login",
        "username": username,
    }
    return default_protocol.encode(payload)


def build_chat_message(sender: str, message: str) -> bytes:
    payload = {
        "type": "chat",
        "sender": sender,
        "message": message,
    }
    return default_protocol.encode(payload)
