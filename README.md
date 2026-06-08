# QCP - QUIC Chat Protocol

QCP is a small, stateful application-layer chat protocol that runs over QUIC. It  
was built for the CS544 graduate Computer Networks term project. The QUIC/TLS  
transport is provided by `aioquic`; every  
other concern (framing, serialization, PDU processing, and the protocol state  
machine) is hand-written.

## What the protocol is

Each connection is a single bidirectional QUIC stream that carries a sequence of
**PDUs**. Every PDU is a fixed 8-byte header followed by a variable payload.

All multi-byte integers are big-endian; strings are UTF-8 with a length prefix.
`SEQ_NUM` is meaningful only for `CHAT_MSG` and `ACK` (each direction keeps its
own counter starting at 1); it is 0 for every other message type.

A deterministic finite automaton (DFA) is enforced on **both** endpoints.

### Message types


| Type           | Id  | Direction        | Payload                                               |
| -------------- | --- | ---------------- | ----------------------------------------------------- |
| `LOGIN_REQ`    | 1   | client -> server | username (1-byte len) + password (1-byte len)         |
| `LOGIN_OK`     | 2   | server -> client | none                                                  |
| `LOGIN_FAIL`   | 3   | server -> client | reason code (1): 1 bad user, 2 bad password, 3 locked |
| `CHAT_MSG`     | 4   | either           | text (2-byte len)                                     |
| `ACK`          | 5   | either           | none; `SEQ_NUM` mirrors the acknowledged chat         |
| `TYPING_START` | 6   | either           | none                                                  |
| `TYPING_STOP`  | 7   | either           | none                                                  |
| `DISCONNECT`   | 8   | either           | reason (1-byte len, optional)                         |
| `ERROR`        | 9   | either           | error code (1) + description (1-byte len)             |


### Error codes

`MALFORMED_PDU=1`, `UNSUPPORTED_VERSION=2`, `ILLEGAL_STATE=3`,
`PROTOCOL_VIOLATION=4`. Any of these is reported in an `ERROR` PDU and then the
connection is closed.

### Correctness rules (all enforced and tested)

- **Illegal state**: a PDU that is not a legal transition for the current state
(e.g. `CHAT_MSG` while authenticating, `LOGIN_REQ` while connected) -> `ERROR 3`.
- **Malformed PDU**: bad payload length, undefined message type, or invalid
UTF-8 -> `ERROR 1`.
- **Unsupported version**: any `VERSION` other than 1 -> `ERROR 2`.
- **Stale / duplicate ACK**: an `ACK` for a sequence never sent or already
acknowledged -> `ERROR 4`.
- **Login fail closes the connection** after `LOGIN_FAIL` is sent.
- **Bounded waits**: authentication (10s), disconnect (5s), and idle (60s)
timeouts guarantee the protocol cannot stall.

## Project layout

```
qcp/
  constants.py   enums + protocol constants (no magic numbers anywhere else)
  errors.py      exception types mapped 1:1 to ERROR codes
  codec.py       pure header + length-prefixed field encode/decode + framer
  pdu.py         PDU dataclasses with one build_X / parse_X per type
  state.py       state enum, event enum, transition table + validation
  session.py     per-connection protocol engine shared by both ends
  transport.py   async QUIC plumbing (timers, stream transport, base protocol)
  server.py      QUIC server: bind, accept, one session per connection
  client.py      QUIC client + command-line chat UI
tests/           pytest unit, DFA, integration, end-to-end, and fuzz tests
certs/           self-signed cert generator for QUIC TLS
```

The layers are kept strictly separate: `codec.py` and `pdu.py` contain no
networking or async code and their serialization functions are pure; `state.py`
is data plus small validation functions with no I/O; `session.py` holds no
global mutable state and receives every dependency by injection.

## Requirements

- Python 3.11+
- The dependencies pinned in `requirements.txt` (`aioquic`, `pytest`)
- `openssl` on `PATH` for certificate generation

## Install

```bash
make install        # creates .venv and installs requirements.txt
```

## Generate certificates

```bash
make certs          # writes certs/cert.pem and certs/key.pem (self-signed)
```

## Run the server

```bash
make run-server                      # localhost:4433 by default
# or directly, with flags:
.venv/bin/python -m qcp.server --host 0.0.0.0 --port 4433 \
    --cert certs/cert.pem --key certs/key.pem
```

Server flags: `--host` (default `localhost`), `--port` (default `4433`),
`--cert` (default `certs/cert.pem`), `--key` (default `certs/key.pem`).

## Run the client

```bash
make run-client SERVER=localhost PORT=4433
# or directly:
.venv/bin/python -m qcp.client <server-host> --port 4433 \
    --username bob --password builder
```

Client flags: positional `host` (required, the server address), `--port`
(default `4433`), `--username` (default `bob`), `--password` (default
`builder`). In the chat UI you type plain messages; commands are `/help`,
`/typing`, and `/quit`. Protocol message names are never exposed to the user.

Demo credentials: `bob` / `builder` and `admin` / `admin123`.

## Run the tests

```bash
make test           # runs the full pytest suite
```

The suite covers happy paths and explicit negative/DFA cases: chat before login
(`ERROR 3`), unsupported version (`ERROR 2`), payload-length mismatch and
undefined type (`ERROR 1`), stale and duplicate ACKs (`ERROR 4`), login failure
closing the connection, the login->chat->ACK round trip, the graceful disconnect
handshake, all three timeouts, account lockout, a real end-to-end exchange over
QUIC (`tests/test_e2e.py`, skipped automatically if certificates are absent),
and a fuzz test that throws thousands of random byte strings at the parser and
at a live session to confirm they always reject cleanly and never crash.

## Concurrency (extra credit)

The server is fully concurrent. `aioquic`'s `serve` runs on a single asyncio
event loop and creates an independent `QcpServerProtocol` (and therefore an
independent `Session` with its own DFA state and sequence counters) for every
QUIC connection. Many clients are handled at once cooperatively without threads;
all per-connection timers are scheduled with `loop.call_later`, so no client can
block another.

## Deliberate spec deviation

The `LOGIN_REQ` payload intentionally **omits the 4-byte feature bitmask** that
appears in the broader protocol design. It is out of scope for Part 3 and is
deliberately excluded here. `LOGIN_REQ` is exactly username and password, each
length-prefixed.

Account lockout (`LOGIN_FAIL` reason 3) is implemented as a simple in-memory
counter: five failed attempts for a username within 60 seconds lock the account.
The counter is per-server-process and is not persisted.