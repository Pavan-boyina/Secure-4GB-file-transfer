# AI Notes

## What I used

Claude (Anthropic) for pretty much everything — design decisions, code scaffolding, debugging, and reviewing crypto choices. I didn't use any other AI tools.

## What Claude wrote vs what I wrote

Claude generated most of the boilerplate. The TCP framing code (`send_frame`/`recv_frame`), the `SafeFileWriter` class, argparse CLI stuff, and the key generation utility — all Claude. I described what I wanted and it produced working code that I then reviewed and tested.

For the actual crypto parts:
- Approach A: Claude set up the `ssl.SSLContext` with TLS 1.3, configured cert pinning, and wrote the chunked send/receive loop. I verified the TLS settings were actually enforcing 1.3 and not falling back to 1.2.
- Approach B: Claude wrote the ECDSA challenge-response protocol, the AES-GCM encryption per chunk, and the signed manifest logic. This one I read more carefully because there's more room to get things wrong when you're doing crypto at the application layer.

The design doc and threat model tables — Claude drafted them, I went through each row and checked it actually matched what the code does.

## Where Claude got something wrong

The nonce construction for Approach B. First version Claude gave me used a simple incrementing counter as the 12-byte GCM nonce. Starts at 0, goes up by 1 for each chunk. Seems fine at first — no reuse within a single transfer.

The problem: if you use the same PSK for two different transfers (which is realistic — the PSK is long-lived), chunk 0 of transfer 1 and chunk 0 of transfer 2 get encrypted with the exact same (key, nonce) pair. That's catastrophic for GCM. An attacker who records both transfers can XOR the ciphertexts to get the XOR of the plaintexts, and can forge authentication tags.

I caught this because the assignment brief specifically warns about nonce reuse, so I was looking for it. I asked Claude to add a per-session random prefix. Final design: `nonce = random_4_bytes || counter_8_bytes`. The random part changes every transfer so the nonces are unique across sessions. It doesn't need to be secret, just unique.

This is the kind of thing where Claude's answer looks correct on first read but silently breaks a core security guarantee. If I'd just trusted it, the code would run fine but be cryptographically broken.

## What Claude did better than I expected

The threat model analysis. When I asked it to map each threat to specific mechanisms in both approaches, it immediately flagged that forward secrecy is a meaningful difference — Approach A has it from TLS 1.3's mandatory ECDHE, Approach B doesn't because PSK is static. It also pointed out that the "untrusted broker" row only really applies to Approach B since TLS requires a live session. I hadn't thought through those distinctions that clearly.

## What Claude did worse than I expected

Error handling in the receiver code. The initial version had the temp file cleanup and the commit logic in a way where I wasn't confident the temp file would always get deleted on failure. The `except` block would catch the error and try to clean up, but there were paths where `SafeFileWriter.finalize()` could partially execute before an exception. I had to trace through every branch manually to convince myself the fail-closed guarantee actually held. Took two rounds of back-and-forth to get it right.

Also, the resume feature initially didn't work — the receiver just always said "start from 0" regardless of how much it had already received. I had to push Claude to actually implement the state persistence (saving progress to a JSON file) and temp file reuse. The plumbing was there but it wasn't connected.

Bottom line: Claude is fast at producing code that looks right. But for anything security-critical, you have to read every line yourself. The assignment is right that "Claude said it would work" isn't evidence.
