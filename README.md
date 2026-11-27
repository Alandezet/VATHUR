# VATHUR

Encrypted group chat in **one HTML file**. No server, no install, no accounts.
Open `vathur.html` in a browser (from a file or any static host) and go.

Messages travel through a public [ntfy](https://ntfy.sh) relay, but the relay only ever sees opaque ciphertext.

## How it works

- **Room secret.** Creating a room generates a random 256-bit secret. The invite code *is* that secret. Share it over a channel you already trust (in person, Signal), never in the room.
- **Topic + keys.** HKDF-SHA256 derives the ntfy topic name and, for every 5-minute epoch, a fresh AES-256-GCM key from the room secret. Keys are never derived from the clock alone.
- **Signed envelopes.** Every message is signed with the sender's Ed25519 key over `topic | epoch | nonce | ciphertext | pubkey`. The topic, epoch and sender key are also bound into the AES-GCM associated data, so messages can't be moved between rooms or re-attributed.
- **Hidden metadata.** Username and timestamp are inside the encrypted body. Plaintext is padded to 128-byte blocks. The relay sees only a topic, a size bucket and a time.
- **Replay/stale protection.** Messages outside a ~16h window or stamped in the future are dropped, and duplicates are ignored.
- **Vault.** Your identity key, rooms and pins are stored in `localStorage` encrypted with AES-256-GCM under a key from your passphrase (PBKDF2-SHA256, 600k iterations). Export an encrypted backup from Settings.
- **Verification.** Tap a name to see the sender's fingerprint, compare it out-of-band, and mark them verified. Callsigns are pinned per room on first sight and flagged if the key changes.

## Threat model (honest version)

Protects against: the relay operator and network observers reading messages; outsiders without the invite code reading or posting; forged, tampered, replayed or cross-room messages.

Does **not** provide:
- **Forward secrecy.** Anyone who gets the room secret can decrypt everything captured, past and future. Rotate by making a new room if an invite leaks.
- **Per-member revocation.** Everyone with the code shares one secret. Removing someone means starting a new room.
- **Metadata privacy.** The relay sees your IP and message timing. Use a VPN/Tor and/or self-host ntfy (Settings → server) if that matters.
- **Protection from a compromised device or a modified copy of this file.** Verify the file hash below before trusting a copy someone sent you.
- **Hard guarantees on identity.** A new member's key is trusted on first sight until you verify the fingerprint.
- **Audited code.** It uses the browser's Web Crypto only, but this project has not had an independent review.

## Requirements

A recent Chrome, Firefox or Safari (Ed25519 in Web Crypto). Works on Android/iOS browsers too.

## Legacy

The original Flask/Termux prototype lives in [`legacy/`](legacy/). It has known cryptographic weaknesses (clock-derived message keys, unauthenticated server) and is kept for reference only. Do not use it for anything sensitive.
