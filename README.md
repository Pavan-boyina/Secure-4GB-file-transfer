# Secure 4GB File Transfer

CMPE 272 — Security Engineering Final

Two different ways to securely send a 4GB file over a network you can't trust. Both satisfy CIAA (Confidentiality, Integrity, Authenticity, Availability). Written in Python using the `cryptography` library.

## Setup

You need Python 3.9+ and one dependency:

```
pip3 install cryptography
```

Then generate keys and a test file:

```
python3 setup.py --test-file
```

This creates key material in `keys-a/` and `keys-b/`, plus a 4GB random file called `test_4gb.bin`. Takes a couple minutes. If you just want to do a quick sanity check first, use `--tiny-test` for a 1MB file or `--small-test` for 64MB.

## Running Approach A (mTLS)

This one uses TLS 1.3 with mutual certificates. Open two terminals.

Terminal 1 (receiver):
```
python3 approach-a-tls-mtls/receiver.py --output-dir output_a
```

Terminal 2 (sender):
```
python3 approach-a-tls-mtls/sender.py test_4gb.bin
```

## Running Approach B (Encrypted Envelope)

This one encrypts each chunk individually with AES-256-GCM over plain TCP. Two terminals again.

Terminal 1 (receiver):
```
python3 approach-b-encrypted-envelope/receiver.py --output-dir output_b
```

Terminal 2 (sender):
```
python3 approach-b-encrypted-envelope/sender.py test_4gb.bin
```

## Verifying

After both transfers finish, check that all hashes match:

```
shasum -a 256 test_4gb.bin output_a/test_4gb.bin output_b/test_4gb.bin
```

All three should be identical.

## Testing Failure Cases

Wrong certificate (should reject):
```
python3 approach-a-tls-mtls/sender.py test_4gb.bin --sender-cert keys-a/receiver.crt --sender-key keys-a/receiver.key
```

Kill sender mid-transfer (should resume):
Start receiver and sender normally, Ctrl+C the sender partway through. Then restart the sender with the same command. It picks up from where it stopped, not from scratch.

Wrong PSK (should reject):
```
python3 -c "import os; open('keys-b/bad.psk','wb').write(os.urandom(32))"
python3 approach-b-encrypted-envelope/sender.py test_4gb.bin --psk keys-b/bad.psk
```

## How the Two Approaches Differ

| | Approach A | Approach B |
|---|---|---|
| Security sits at | Transport layer (TLS 1.3) | Application layer (AES-GCM over plain TCP) |
| Key exchange | ECDHE, online, ephemeral | Pre-shared key, offline, static |
| Forward secrecy | Yes | No |
| Authentication | Mutual X.509 certificates | ECDSA challenge-response |
| Works through a broker | No, needs a live TLS session | Yes, envelope is self-contained |
| Chunk size | 1 MB | 1 MB |

## Project Structure

```
secure-file-transfer/
├── README.md
├── DESIGN.md
├── AI_NOTES.md
├── setup.py
├── shared/
│   ├── utils.py        — framing, SafeFileWriter, ResumeState, constants
│   └── keygen.py       — key and cert generation for both approaches
├── approach-a-tls-mtls/
│   ├── sender.py
│   └── receiver.py
└── approach-b-encrypted-envelope/
    ├── sender.py
    └── receiver.py
```

Only external dependency is `cryptography`. No hand-rolled crypto.
