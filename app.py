import os
import hashlib
import base64
from datetime import datetime, timezone
from flask import Flask, render_template, request, jsonify
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import requests

app = Flask(__name__)

# ── Key derivation ──────────────────────────────────────────────────────────

def floor_to_5min(dt: datetime) -> datetime:
    """Round a datetime DOWN to the nearest 5-minute window."""
    floored = dt.replace(second=0, microsecond=0,
                         minute=(dt.minute // 5) * 5)
    return floored

def derive_key(dt: datetime) -> bytes:
    """Derive a 256-bit AES key from a datetime window alone."""
    window = floor_to_5min(dt)
    raw = window.strftime('%Y-%m-%dT%H:%M')
    return hashlib.sha256(raw.encode()).digest()  # 32 bytes = AES-256

def derive_channel(date_str: str) -> str:
    """
    Derive a stable ntfy channel name from a user-chosen date string.
    date_str format: 'YYYY-MM-DDTHH:MM'  e.g. '2008-01-21T20:05'
    """
    digest = hashlib.sha256(f"channel:{date_str}".encode()).hexdigest()[:16]
    return f"vathur-{digest}"

# ── Encryption / Decryption ─────────────────────────────────────────────────

def encrypt_message(plaintext: str, dt: datetime) -> str:
    """AES-256-GCM encrypt. Returns base64(nonce + ciphertext)."""
    key = derive_key(dt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ct).decode()

def decrypt_message(blob: str, dt: datetime) -> str:
    """AES-256-GCM decrypt. blob is base64(nonce + ciphertext)."""
    key = derive_key(dt)
    aesgcm = AESGCM(key)
    raw = base64.b64decode(blob)
    nonce, ct = raw[:12], raw[12:]
    return aesgcm.decrypt(nonce, ct, None).decode()

# ── Routes ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/send", methods=["POST"])
def send():
    data = request.json
    message   = data.get("message", "").strip()
    chan_seed  = data.get("channel_seed", "").strip()  # e.g. "2008-01-21T20:05"

    if not message or not chan_seed:
        return jsonify({"ok": False, "error": "Missing message or channel seed"}), 400

    now = datetime.now(timezone.utc)
    window = floor_to_5min(now)
    timestamp = window.strftime("%Y-%m-%dT%H:%M")   # unencrypted, sent with msg
    encrypted = encrypt_message(message, now)
    channel   = derive_channel(chan_seed)

    ntfy_server = os.environ.get("NTFY_SERVER", "https://ntfy.sh")
    payload = f"VATHUR|{timestamp}|{encrypted}"

    try:
        r = requests.post(
            f"{ntfy_server}/{channel}",
            data=payload.encode(),
            headers={"Content-Type": "text/plain"},
            timeout=10
        )
        if r.status_code not in (200, 201):
            return jsonify({"ok": False, "error": f"ntfy returned {r.status_code}"}), 500
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    return jsonify({"ok": True, "channel": channel, "window": timestamp})

@app.route("/receive", methods=["POST"])
def receive():
    """Fetch + decrypt messages from ntfy for a given channel seed."""
    data      = request.json
    chan_seed  = data.get("channel_seed", "").strip()
    since     = data.get("since", "1h")   # ntfy poll window

    if not chan_seed:
        return jsonify({"ok": False, "error": "Missing channel seed"}), 400

    channel     = derive_channel(chan_seed)
    ntfy_server = os.environ.get("NTFY_SERVER", "https://ntfy.sh")

    try:
        r = requests.get(
            f"{ntfy_server}/{channel}/json?poll=1&since={since}",
            timeout=15
        )
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    messages = []
    for line in r.text.strip().splitlines():
        import json
        try:
            obj = json.loads(line)
        except Exception:
            continue
        body = obj.get("message", "")
        if not body.startswith("VATHUR|"):
            continue
        parts = body.split("|", 2)
        if len(parts) != 3:
            continue
        _, timestamp, blob = parts
        try:
            dt = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M").replace(tzinfo=timezone.utc)
            plaintext = decrypt_message(blob, dt)
            messages.append({"time": timestamp, "text": plaintext})
        except Exception:
            messages.append({"time": timestamp, "text": "[decryption failed]"})

    return jsonify({"ok": True, "channel": channel, "messages": messages})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
