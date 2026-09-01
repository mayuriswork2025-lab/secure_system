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


def build_chat_message(sender: str, target: str, message: str) -> bytes:
    payload = {
        "type": "chat",
        "sender": sender,
        "target": target,
        "message": message,
    }
    return default_protocol.encode(payload)


def build_dh_public_message(sender: str, target: str, public_key: int) -> bytes:
    payload = {
        "type": "dh_public",
        "sender": sender,
        "target": target,
        "public_key": str(public_key),
    }
    return default_protocol.encode(payload)
