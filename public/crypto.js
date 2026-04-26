/**
 * crypto.js — Client-side E2EE using Web Crypto API
 *
 * Key exchange:  ECDH P-384
 * Encryption:    AES-256-GCM  (256-bit key, 96-bit IV, 128-bit auth tag)
 * Fingerprint:   SHA-256 of exported public key (hex, shown to user)
 *
 * Flow:
 *   1. On join, generate an ECDH keypair
 *   2. Export public key → send to server (server relays to peers)
 *   3. On receiving a peer's public key → derive shared AES key via ECDH
 *   4. Encrypt messages with that shared AES key before sending
 *   5. Decrypt received messages with the matching shared AES key
 */

const Crypto = (() => {
  // Our keypair (set once per session)
  let myKeyPair = null;

  // Map<peerId, CryptoKey> — shared AES key per peer
  const sharedKeys = new Map();

  /** Generate our ephemeral ECDH keypair */
  async function generateKeyPair() {
    myKeyPair = await window.crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-384' },
      true,        // extractable (so we can export public key)
      ['deriveKey']
    );
    return myKeyPair;
  }

  /** Export public key as base64 string for transmission */
  async function exportPublicKey() {
    const raw = await window.crypto.subtle.exportKey('spki', myKeyPair.publicKey);
    return btoa(String.fromCharCode(...new Uint8Array(raw)));
  }

  /** Import a peer's base64 public key */
  async function importPublicKey(b64) {
    const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    return window.crypto.subtle.importKey(
      'spki',
      raw,
      { name: 'ECDH', namedCurve: 'P-384' },
      false,
      []
    );
  }

  /** Derive a shared AES-256-GCM key from our private key + peer's public key */
  async function deriveSharedKey(peerPublicKey) {
    return window.crypto.subtle.deriveKey(
      { name: 'ECDH', public: peerPublicKey },
      myKeyPair.privateKey,
      { name: 'AES-GCM', length: 256 },
      false,       // not extractable
      ['encrypt', 'decrypt']
    );
  }

  /** Add/update a peer: import their public key and derive shared secret */
  async function addPeer(peerId, publicKeyB64) {
    const peerPubKey = await importPublicKey(publicKeyB64);
    const sharedKey = await deriveSharedKey(peerPubKey);
    sharedKeys.set(peerId, sharedKey);
  }

  /** Remove a peer when they disconnect */
  function removePeer(peerId) {
    sharedKeys.delete(peerId);
  }

  /**
   * Encrypt a plaintext string for a specific peer.
   * Returns { iv: base64, ciphertext: base64 }
   */
  async function encrypt(plaintext, peerId) {
    const key = sharedKeys.get(peerId);
    if (!key) throw new Error(`No shared key for peer ${peerId}`);

    const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV
    const encoded = new TextEncoder().encode(plaintext);

    const ciphertextBuf = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      encoded
    );

    return {
      iv: btoa(String.fromCharCode(...iv)),
      ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertextBuf))),
    };
  }

  /**
   * Broadcast encrypt: encrypt for every connected peer.
   * Returns array of { recipientId, iv, ciphertext }
   */
  async function encryptForAll(plaintext) {
    const results = [];
    for (const peerId of sharedKeys.keys()) {
      const enc = await encrypt(plaintext, peerId);
      results.push({ recipientId: peerId, ...enc });
    }
    return results;
  }

  /**
   * Decrypt a message from a specific peer.
   * Returns plaintext string.
   */
  async function decrypt(iv, ciphertext, fromPeerId) {
    const key = sharedKeys.get(fromPeerId);
    if (!key) throw new Error(`No shared key for peer ${fromPeerId}`);

    const ivBytes = Uint8Array.from(atob(iv), c => c.charCodeAt(0));
    const ciphertextBytes = Uint8Array.from(atob(ciphertext), c => c.charCodeAt(0));

    const plainBuf = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: ivBytes },
      key,
      ciphertextBytes
    );

    return new TextDecoder().decode(plainBuf);
  }

  /** SHA-256 fingerprint of our public key (hex string) */
  async function getFingerprint() {
    const raw = await window.crypto.subtle.exportKey('spki', myKeyPair.publicKey);
    const hash = await window.crypto.subtle.digest('SHA-256', raw);
    return Array.from(new Uint8Array(hash))
      .map(b => b.toString(16).padStart(2, '0'))
      .join(':')
      .slice(0, 47); // first 8 groups for display
  }

  function hasPeer(peerId) {
    return sharedKeys.has(peerId);
  }

  function peerCount() {
    return sharedKeys.size;
  }

  return {
    generateKeyPair,
    exportPublicKey,
    addPeer,
    removePeer,
    encrypt,
    encryptForAll,
    decrypt,
    getFingerprint,
    hasPeer,
    peerCount,
  };
})();
