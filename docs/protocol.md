# Wire protocol

## Framing

Every message is a single JSON object followed by a `\n` delimiter, sent
over a persistent TCP connection between a client and the server. TCP does
not preserve message boundaries, so both sides buffer incoming bytes and
only parse a message once a full `\n`-terminated frame has arrived
(`src/protocol/reader.py`). The JSON encoding and the delimiter are both
owned by `src/protocol/json_protocol.py`; a different `WireProtocol`
implementation (e.g. a binary or encrypted format) could be swapped in
without changing anything else in `server.py` or `client.py`.

## Message types

| `type`      | Direction         | Fields                                   | Purpose |
|-------------|--------------------|-------------------------------------------|---------|
| `login`     | client -> server   | `username`                                | Registers the connection under a username. |
| `system`    | server -> client   | `sender`, `message`                       | Server-generated notices (e.g. welcome message). |
| `chat`      | client -> server -> one client | `sender`, `target`, `message` | Plaintext chat message, relayed by the server to `target` only (unicast). The client rejects sending one before a `/dh` handshake with `target` has produced a session key. |
| `leave`     | client -> server   | (none)                                     | Client is disconnecting; server closes the connection. |
| `dh_public` | client -> server -> one client | `sender`, `target`, `public_key` | Diffie-Hellman public value, relayed by the server to `target` only (unicast, not broadcast). |

## Diffie-Hellman key exchange

Goal: two clients (Alice and Bob) derive a shared secret without ever
putting that secret on the wire. Implemented in `src/dh.py`; the network
handshake lives in `client.py`'s `/dh <username>` command and
`_handle_dh_public`.

**Group parameters.** Both parties use the same publicly known (p, g):
RFC 3526's 2048-bit MODP Group 14, with generator `g = 2`. Publishing these
values is standard practice and does not weaken the exchange — DH's
security rests on the discrete-log problem being hard for this group, not
on the group being secret.

**Handshake (2 messages):**

```
Alice                          Server                          Bob
  |-- dh_public(target=bob) -----> |                              |
  |                                |-- dh_public(sender=alice) -->|
  |                                |                          [Bob generates
  |                                |                           his own keys,
  |                                |                           derives the
  |                                |                           shared secret]
  |                                |<-- dh_public(target=alice) --|
  |<-- dh_public(sender=bob) ------|                              |
[Alice derives the
 shared secret]
```

1. Alice runs `/dh bob`. Her client generates a private key `a` (a random
   integer) and computes her public value `A = g^a mod p`. It stores `a`
   locally (keyed by `bob`) and sends `{"type": "dh_public", "sender":
   "alice", "target": "bob", "public_key": A}` to the server.
2. The server looks up the connection currently registered as `bob` and
   forwards the message to that connection only — it never sees `a`, `b`,
   or the resulting shared secret, only the public value `A`.
3. Bob's client receives the message. Since he has no `alice` handshake in
   progress, he treats it as an incoming request: generates his own
   private key `b`, computes `B = g^b mod p`, computes the shared secret
   `s = A^b mod p`, and replies with his own `dh_public` message carrying
   `B`.
4. Alice's client receives Bob's reply, looks up her stored `a`, and
   computes `s = B^a mod p`.
5. Both sides now hold the same `s` (proven: `A^b = (g^a)^b = g^(ab) =
   (g^b)^a = B^a mod p`). Each side hashes `s` with SHA-256
   (`derive_session_key`) to get a fixed-size 256-bit session key, ready to
   use as an AES key in phase 3.

**What crosses the network:** only `A` and `B` (the public values). `a`,
`b`, and `s` never leave the process that generated them.

**Validation:** running `python src/dh.py` performs the same math locally
for two simulated parties and asserts the derived secrets match. Running
two `client.py` instances and typing `/dh <peer>` performs the same
exchange for real, over the socket connection, and prints the resulting
session key hex on both sides so they can be compared by eye.

## Known limitations (carried forward to later phases)

- No authentication of the public values: a man-in-the-middle relay (the
  server, or an attacker who compromises it) could substitute its own
  public value for Alice's or Bob's and complete two separate handshakes,
  reading everything in between. This is the classic DH MITM weakness and
  is exactly what phase 5's adversarial test is meant to demonstrate.
  Phases 3 and 4 (signatures, certificates) exist to close this gap.
- The relayed `dh_public` message is not itself authenticated or
  encrypted — the server (or anyone impersonating it) can read the public
  values in transit, though per the DH problem this alone doesn't reveal
  the shared secret.
