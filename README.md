# Cypherly — Setup & Deployment Guide

## Architecture

```
[User A Browser]                    [User B Browser]
     │                                    │
     │  ECDH key exchange (public keys)   │
     │◄──────────── Server ──────────────►│
     │                                    │
     │  AES-256-GCM encrypted messages    │
     └──────────────────────────────────►│
```

- The **server never sees plaintext**. It only relays encrypted blobs.
- Keys are generated **fresh on every session** (ephemeral).
- **Nothing is stored** — no messages, no logs, no IP logs.

---

## 1. Install Dependencies

```bash
cd your-project-folder
npm install
```

---

## 2. Run Locally (for testing)

```bash
npm start
# Server listens on 127.0.0.1:3000
```

Open http://localhost:3000 in your browser.

---

## 3. Deploy as a Tor Hidden Service (.onion)

### Step 1 — Install Tor

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install tor -y
```

**macOS (Homebrew):**
```bash
brew install tor
```

### Step 2 — Configure Tor

Edit the Tor config file:
```bash
sudo nano /etc/tor/torrc
```

Add these lines at the end:
```
HiddenServiceDir /var/lib/tor/secure-chat/
HiddenServicePort 80 127.0.0.1:3000
```

### Step 3 — Start Tor

```bash
sudo systemctl enable tor
sudo systemctl start tor
```

### Step 4 — Get your .onion address

```bash
sudo cat /var/lib/tor/secure-chat/hostname
# Outputs something like: abc123xyz...onion
```

**Share this `.onion` address** with your friends over a secure channel (Signal, etc.)

### Step 5 — Start your chat server

```bash
npm start
```

Your chat is now accessible at `http://youraddress.onion` via the Tor Browser.

---

## 4. Server Hardening (Linux VPS)

### Run as a non-root user
```bash
# Create a dedicated user
sudo useradd -r -s /bin/false Cypherly
sudo chown -R Cypherly:Cypherly /path/to/your/app

# Run as that user
sudo -u Cypherly node index.js
```

### Use systemd to auto-restart
Create `/etc/systemd/system/Cypherly.service`:
```ini
[Unit]
Description=Cypherly Server
After=network.target

[Service]
Type=simple
User=Cypherly
WorkingDirectory=/path/to/your/app
ExecStart=/usr/bin/node index.js
Restart=on-failure
RestartSec=5
# No logging to disk
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable Cypherly
sudo systemctl start Cypherly
```

### Firewall — block all external ports except Tor
```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh         # keep SSH access
# Do NOT open port 3000 — Tor proxies in internally
sudo ufw enable
```

---

## 5. Security Properties

| Property | Status | How |
|---|---|---|
| End-to-end encryption | ✅ | AES-256-GCM, keys never leave client |
| Forward secrecy | ✅ | Ephemeral ECDH P-384 keys per session |
| Server sees plaintext | ❌ Never | Server relays ciphertext only |
| Message logging | ❌ Never | No writes to disk anywhere |
| IP exposure (via Tor) | ❌ Hidden | .onion hides server IP |
| Client IP to server | ⚠️ Hidden via Tor Browser | Clients must use Tor Browser |
| Authentication | ⚠️ Manual | Compare key fingerprints out-of-band |

---

## 6. Important Notes for Users

1. **Both sides must use Tor Browser** to hide their IP from the server.
2. **Compare key fingerprints** with your friends via a separate secure channel (Signal/in-person) to prevent MITM attacks.
3. **Room IDs are not secret by themselves** — use a long, random room ID and share it over Signal.
4. **This is not anonymous messaging** if you reveal your identity in the chat content.

---

## 7. What this does NOT protect against

- A compromised **endpoint device** (keylogger, malware on your computer)
- **Traffic analysis** if not using Tor Browser on the client side
- **Social engineering** — fingerprint verification is manual
