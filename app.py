import os
import json
import hashlib
import base64
from datetime import datetime, timezone
from flask import Flask, render_template, request, jsonify
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
    load_der_private_key
)
import requests

app = Flask(__name__)

NTFY_SERVER = os.environ.get("NTFY_SERVER", "https://ntfy.sh")

# ── Key derivation ──────────────────────────────────────────────────────────

def floor_to_5min(dt: datetime) -> datetime:
    floored = dt.replace(second=0, microsecond=0, minute=(dt.minute // 5) * 5)
    return floored

def derive_msg_key(dt: datetime) -> bytes:
    """AES key from 5-min time window."""
    window = floor_to_5min(dt)
    return hashlib.sha256(window.strftime('%Y-%m-%dT%H:%M').encode()).digest()

def derive_ts_key(chan_seed: str) -> bytes:
    """Static AES key from channel date — used to encrypt the timestamp."""
    return hashlib.sha256(f"tskey:{chan_seed}".encode()).digest()

def derive_channel(chan_seed: str) -> str:
    digest = hashlib.sha256(f"channel:{chan_seed}".encode()).hexdigest()[:16]
    return f"vathur-{digest}"

def derive_keys_channel(chan_seed: str) -> str:
    """Separate ntfy channel for public key exchange."""
    digest = hashlib.sha256(f"keys:{chan_seed}".encode()).hexdigest()[:16]
    return f"vathur-keys-{digest}"

# ── Timestamp encryption ────────────────────────────────────────────────────

def encrypt_timestamp(ts: str, chan_seed: str) -> str:
    """Encrypt the timestamp string using the channel-derived static key."""
    key   = derive_ts_key(chan_seed)
    nonce = os.urandom(12)
    ct    = AESGCM(key).encrypt(nonce, ts.encode(), None)
    return base64.b64encode(nonce + ct).decode()

def decrypt_timestamp(blob: str, chan_seed: str) -> str:
    """Decrypt the timestamp blob."""
    key = derive_ts_key(chan_seed)
    raw = base64.b64decode(blob)
    nonce, ct = raw[:12], raw[12:]
    return AESGCM(key).decrypt(nonce, ct, None).decode()

# ── Message encryption ──────────────────────────────────────────────────────

def encrypt_message(plaintext: str, dt: datetime) -> str:
    key   = derive_msg_key(dt)
    nonce = os.urandom(12)
    ct    = AESGCM(key).encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ct).decode()

def decrypt_message(blob: str, dt: datetime) -> str:
    key = derive_msg_key(dt)
    raw = base64.b64decode(blob)
    nonce, ct = raw[:12], raw[12:]
    return AESGCM(key).decrypt(nonce, ct, None).decode()

# ── Identity: Ed25519 signing ───────────────────────────────────────────────

KEY_FILE = os.path.join(os.path.dirname(__file__), ".vathur_identity")

def load_or_create_keypair():
    """Load existing Ed25519 keypair or generate a new one."""
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            priv = load_der_private_key(f.read(), password=None)
    else:
        priv = Ed25519PrivateKey.generate()
        with open(KEY_FILE, "wb") as f:
            f.write(priv.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption()))
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv, pub

PRIVATE_KEY, PUBLIC_KEY = load_or_create_keypair()

def sign_message(message: str) -> str:
    sig = PRIVATE_KEY.sign(message.encode())
    return base64.b64encode(sig).decode()

def verify_signature(message: str, sig_b64: str, pub_b64: str) -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.serialization import load_der_public_key
        pub_raw = base64.b64decode(pub_b64)
        pub_key = Ed25519PublicKey.from_public_bytes(pub_raw)
        pub_key.verify(base64.b64decode(sig_b64), message.encode())
        return True
    except Exception:
        return False

# ── Routes ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/identity", methods=["GET"])
def identity():
    """Return this device's public key."""
    return jsonify({
        "ok": True,
        "public_key": base64.b64encode(PUBLIC_KEY).decode()
    })

@app.route("/publish_key", methods=["POST"])
def publish_key():
    """Publish this device's public key + username to the keys channel."""
    data     = request.json
    username = data.get("username", "").strip()
    chan_seed = data.get("channel_seed", "").strip()
    if not username or not chan_seed:
        return jsonify({"ok": False, "error": "Missing username or channel_seed"}), 400

    pub_b64      = base64.b64encode(PUBLIC_KEY).decode()
    keys_channel = derive_keys_channel(chan_seed)
    payload      = json.dumps({"u": username, "k": pub_b64})

    try:
        r = requests.post(
            f"{NTFY_SERVER}/{keys_channel}",
            data=payload.encode(),
            headers={"Content-Type": "text/plain"},
            timeout=10
        )
        if r.status_code not in (200, 201):
            return jsonify({"ok": False, "error": f"ntfy returned {r.status_code}"}), 500
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    return jsonify({"ok": True, "keys_channel": keys_channel})

@app.route("/fetch_keys", methods=["POST"])
def fetch_keys():
    """Fetch all known public keys from the keys channel."""
    data     = request.json
    chan_seed = data.get("channel_seed", "").strip()
    if not chan_seed:
        return jsonify({"ok": False, "error": "Missing channel_seed"}), 400

    keys_channel = derive_keys_channel(chan_seed)
    try:
        r = requests.get(
            f"{NTFY_SERVER}/{keys_channel}/json?poll=1&since=all",
            timeout=15
        )
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    known_keys = {}  # username -> latest public key
    for line in r.text.strip().splitlines():
        try:
            obj  = json.loads(line)
            body = json.loads(obj.get("message", "{}"))
            u, k = body.get("u"), body.get("k")
            if u and k:
                known_keys[u] = k  # last seen key wins
        except Exception:
            continue

    return jsonify({"ok": True, "keys": known_keys})

@app.route("/send", methods=["POST"])
def send():
    data      = request.json
    message   = data.get("message", "").strip()
    chan_seed  = data.get("channel_seed", "").strip()
    username  = data.get("username", "anonymous").strip()

    if not message or not chan_seed:
        return jsonify({"ok": False, "error": "Missing message or channel_seed"}), 400

    now     = datetime.now(timezone.utc)
    ts_str  = floor_to_5min(now).strftime("%Y-%m-%dT%H:%M")
    enc_ts  = encrypt_timestamp(ts_str, chan_seed)        # encrypted timestamp
    enc_msg = encrypt_message(message, now)               # encrypted message
    pub_b64 = base64.b64encode(PUBLIC_KEY).decode()
    sig     = sign_message(message)                       # signature over plaintext

    channel = derive_channel(chan_seed)
    # Format: VATHUR|<enc_timestamp>|<enc_message>|<username>|<pubkey>|<signature>
    payload = f"VATHUR|{enc_ts}|{enc_msg}|{username}|{pub_b64}|{sig}"

    try:
        r = requests.post(
            f"{NTFY_SERVER}/{channel}",
            data=payload.encode(),
            headers={"Content-Type": "text/plain"},
            timeout=10
        )
        if r.status_code not in (200, 201):
            return jsonify({"ok": False, "error": f"ntfy returned {r.status_code}"}), 500
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    return jsonify({"ok": True, "channel": channel, "window": ts_str})

@app.route("/receive", methods=["POST"])
def receive():
    data      = request.json
    chan_seed  = data.get("channel_seed", "").strip()

    if not chan_seed:
        return jsonify({"ok": False, "error": "Missing channel_seed"}), 400

    channel = derive_channel(chan_seed)
    try:
        r = requests.get(
            f"{NTFY_SERVER}/{channel}/json?poll=1&since=all",
            timeout=15
        )
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    messages = []
    for line in r.text.strip().splitlines():
        try:
            obj = json.loads(line)
        except Exception:
            continue
        body = obj.get("message", "")
        if not body.startswith("VATHUR|"):
            continue
        parts = body.split("|", 5)
        if len(parts) != 6:
            continue
        _, enc_ts, enc_msg, username, pub_b64, sig = parts
        try:
            ts_str    = decrypt_timestamp(enc_ts, chan_seed)
            dt        = datetime.strptime(ts_str, "%Y-%m-%dT%H:%M").replace(tzinfo=timezone.utc)
            plaintext = decrypt_message(enc_msg, dt)
            verified  = verify_signature(plaintext, sig, pub_b64)
            messages.append({
                "time":     ts_str,
                "text":     plaintext,
                "user":     username,
                "pub_key":  pub_b64,
                "verified": verified
            })
        except Exception:
            messages.append({
                "time":     "??:??",
                "text":     "[decryption failed]",
                "user":     "???",
                "pub_key":  "",
                "verified": False
            })

    return jsonify({"ok": True, "channel": channel, "messages": messages})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
