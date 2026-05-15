# Design Document

## Approach A — mTLS Streaming (Transport Layer)

### How it works

The idea here is simple: let TLS 1.3 do the heavy lifting. Both sides have X.509 certificates. When the sender connects, they go through a standard TLS handshake where both present their certs. If either cert is wrong, the handshake fails and nothing gets through.

Once the TLS tunnel is up, everything inside it is encrypted with AES-256-GCM automatically — I don't have to call any cipher functions myself. I just send chunked data through the TLS socket and the record layer handles encryption, MACs, all of it.

### Architecture

```
Sender                              Receiver
  |                                    |
  |--- TCP connect ------------------->|
  |<== TLS 1.3 handshake (ECDHE) ====>|
  |    (both show certs, both verify)  |
  |                                    |
  |--- META: filename, size, hash ---->|
  |<-- RESUME: offset to start from ---|
  |                                    |
  |--- DATA: chunk 0 (1MB) ---------->|
  |--- DATA: chunk 1 (1MB) ---------->|
  |--- ...                             |
  |--- DATA: chunk 4095 ------------->|
  |--- DONE: final hash, total size -->|
  |                                    |
  |<-- ACK: ok or error ---------------|
```

All the DATA frames travel inside the TLS tunnel, so they're encrypted on the wire.

### Key management

- Each side has an ECDSA P-384 key pair embedded in a self-signed X.509 cert
- Certs are exchanged out-of-band before the transfer (setup.py generates them)
- Each side pins the other's cert directly — no CA chain, no system trust store
- TLS 1.3 does ECDHE for session keys, so we get forward secrecy for free

### Algorithms

- TLS 1.3 with `TLS_AES_256_GCM_SHA384` cipher suite
- ECDHE on P-384 for key exchange
- ECDSA with SHA-384 for cert signatures
- SHA-256 for the whole-file integrity check (application layer)
- 1MB chunk size, length-prefixed framing

### What forward secrecy means here

TLS 1.3 forces ephemeral key exchange. The session keys are derived from a one-time ECDHE exchange and thrown away after. So even if someone steals the server's private key next year, they can't decrypt traffic they recorded today. Approach B doesn't have this because it uses a static pre-shared key.

---

## Approach B — Encrypted Envelope (Application Layer)

### How it works

This one doesn't use TLS at all. The TCP connection is plain. Instead, I handle all the crypto manually at the application layer:

1. Both sides authenticate with ECDSA challenge-response
2. Sender builds a manifest listing the SHA-256 hash of every chunk, signs it
3. Each chunk is encrypted individually with AES-256-GCM using the pre-shared key
4. Receiver decrypts each chunk, checks it against the manifest, then does a full-file SHA-256 at the end

The big difference from Approach A: the encrypted envelope is self-contained. You could save it to disk, pass it through an untrusted server, and decrypt it later. TLS can't do that — it needs both sides online at the same time.

### Architecture

```
Sender                              Receiver
  |                                    |
  |--- TCP connect (plain) ---------->|
  |                                    |
  |--- challenge + session_nonce ----->|
  |<-- challenge + signed response ----|
  |--- signed response --------------->|
  |    (both verified, mutual auth)    |
  |                                    |
  |--- Signed META: file info -------->|
  |--- Signed MANIFEST: chunk hashes ->|
  |<-- RESUME: offset ------------------|
  |                                    |
  |--- Encrypted chunk 0 ------------>|  decrypt, check hash vs manifest
  |--- Encrypted chunk 1 ------------>|
  |--- ...                             |
  |--- Encrypted chunk 4095 --------->|
  |--- Signed DONE ------------------->|
  |                                    |
  |<-- ACK ----------------------------|
```

### Key management

- 256-bit AES pre-shared key generated with `os.urandom(32)`, shared out-of-band
- ECDSA P-384 signing keys for both sides, public keys exchanged out-of-band
- No forward secrecy — if the PSK leaks, past transfers are exposed
- To mitigate this you'd rotate the PSK after each transfer, but I didn't implement that

### Nonce construction

This is important and it's where I caught an issue with Claude's suggestion. The nonce for AES-GCM is 12 bytes, constructed as:

```
nonce = session_random[0:4] || chunk_counter_big_endian[8]
```

The 4-byte random prefix changes every transfer. Without it, two transfers with the same PSK would encrypt chunk 0 with the same (key, nonce) pair, which completely breaks GCM — it leaks the XOR of the two plaintexts and lets an attacker forge tags. The session random doesn't need to be secret, just unique.

### Algorithms

- AES-256-GCM for per-chunk encryption (via `cryptography` library's AESGCM)
- 12-byte nonce: 4 random + 8 counter
- Chunk index used as AAD (additional authenticated data)
- ECDSA P-384 with SHA-384 for signing metadata, manifest, and DONE frame
- SHA-256 per-chunk (in manifest) and whole-file
- 1MB chunks, same framing as Approach A

### Signed manifest

Before sending any data, the sender computes SHA-256 of every chunk and puts them in a list. This list gets ECDSA-signed. The receiver verifies the signature first, then checks each decrypted chunk against the corresponding hash. This means tampering is caught in two places: the GCM tag catches ciphertext modification, and the manifest catches chunk substitution or reordering.

---

## Shared Components

Both approaches share:

- **SafeFileWriter** — writes to a `.tmp` file, verifies SHA-256, then does an atomic rename. If anything fails, the temp file is deleted. The final filename is never written until verification passes.
- **ResumeState** — saves progress to a `.resume_<filename>.json` file every 100 chunks. On reconnect, the receiver reads this, finds the partial temp file, and tells the sender where to pick up. On integrity failure, both the state file and temp file are deleted.
- **Framing** — all messages use `[4-byte type][8-byte length][payload]` format. No reliance on TCP FIN to know when the file ends.
- **Retry with backoff** — sender retries up to 5 times with exponential backoff (2, 4, 8, 16, 32 seconds).

---

## Threat Model

### Approach A

| Threat | CIAA | Defense |
|---|---|---|
| Passive eavesdropper | C | TLS 1.3 encrypts everything. Session keys from ECDHE never cross the wire. Forward secrecy means recorded traffic stays safe even if long-term keys leak later. |
| Active MITM modifies bytes | I | TLS record MAC catches any tampered record. Full-file SHA-256 as a second check. Temp file deleted on mismatch. |
| Attacker spoofs endpoint | A | Mutual TLS — both sides present certs, both verify against pinned fingerprints. Wrong cert = handshake fails, no data flows. |
| Replay attack | I/A | TLS 1.3 uses fresh random in every handshake. Replayed records use old session keys that don't match. |
| Connection drops at 80% | A | Temp file + resume state. Receiver waits for reconnection. Sender retries with backoff. Resumes from last saved chunk. |
| Untrusted broker | — | Not applicable. TLS needs a live session. Can't store-and-forward. |

### Approach B

| Threat | CIAA | Defense |
|---|---|---|
| Passive eavesdropper | C | Every chunk AES-256-GCM encrypted. PSK never on the wire. Ciphertext looks random without the key. |
| Active MITM modifies bytes | I | GCM auth tag catches tampered ciphertext. Manifest hash catches chunk substitution. SHA-256 full-file check at the end. |
| Attacker spoofs endpoint | A | ECDSA challenge-response — both sides sign random challenges with their private keys. Wrong key = verification fails, connection closed. |
| Replay attack | I/A | Fresh session_random per transfer used in nonce derivation. Replayed ciphertext has wrong nonce, decryption fails. |
| Connection drops at 80% | A | Same as A — temp file, resume state, backoff retry. Manifest lets receiver identify exactly which chunks are missing. |
| Untrusted broker | C/I | Encrypted envelope is self-contained. Broker sees only ciphertext and signatures. Compromise of the broker doesn't leak the file. |

---

## Why These Are Actually Different

Not just a cipher swap. The fundamental difference is where the security boundary sits:

1. **Approach A** — I never touch a cipher. TLS handles everything. My code reads plaintext, writes plaintext, and trusts the transport.
2. **Approach B** — I call AESGCM.encrypt() and AESGCM.decrypt() myself. I derive nonces, sign manifests, verify tags. The transport is plain TCP.

This leads to real tradeoffs. Approach A gets forward secrecy and simplicity but can't work through a broker. Approach B can transit untrusted storage but if the PSK leaks, everything's exposed.
