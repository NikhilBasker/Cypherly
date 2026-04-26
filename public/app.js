/**
 * app.js — No inline handlers, CSP-safe, Tor Browser compatible
 */
(async () => {
  let socket = null;
  let myName = 'Anonymous';
  let myRoom = '';
  let myPassword = '';
  let isHost = false;
  const peerNames = new Map();
  const sentMessages = new Map();
  const typingPeers = new Map();
  let typingTimer = null;
  let iAmTyping = false;
  let observer = null;

  // ── XHR (no fetch — more compatible with Tor Browser) ──────────────────────
  function xhr(method, url, body) {
    return new Promise((resolve, reject) => {
      const req = new XMLHttpRequest();
      req.open(method, url);
      req.setRequestHeader('Content-Type', 'application/json');
      req.timeout = 15000;
      req.onload = () => {
        try { resolve({ ok: req.status < 400, data: JSON.parse(req.responseText) }); }
        catch { reject(new Error('Bad JSON')); }
      };
      req.onerror = () => reject(new Error('Network error'));
      req.ontimeout = () => reject(new Error('Timeout'));
      req.send(body ? JSON.stringify(body) : null);
    });
  }

  // ── DOM refs ────────────────────────────────────────────────────────────────
  const $ = id => document.getElementById(id);

  // ── Wire up all buttons via addEventListener (CSP-safe) ────────────────────
  $('tab-create').addEventListener('click', () => switchTab('create'));
  $('tab-join').addEventListener('click',   () => switchTab('join'));
  $('create-btn').addEventListener('click', createRoom);
  $('join-btn').addEventListener('click',   joinWithToken);
  $('leave-btn').addEventListener('click',  leaveRoom);
  $('send-btn').addEventListener('click',   sendMessage);
  $('mobile-menu-btn').addEventListener('click', toggleSidebar);
  $('generate-invite-btn').addEventListener('click', generateInvite);
  $('copy-invite-btn').addEventListener('click', copyInvite);

  $('msg-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
  });

  $('msg-input').addEventListener('input', () => {
    if (!socket || Crypto.peerCount() === 0) return;
    if (!iAmTyping) { iAmTyping = true; socket.emit('typing', { isTyping: true }); }
    clearTimeout(typingTimer);
    typingTimer = setTimeout(() => {
      iAmTyping = false;
      socket.emit('typing', { isTyping: false });
    }, 2000);
  });

  $('messages').addEventListener('click', () => {
    document.querySelector('.sidebar').classList.remove('open');
  });

  // ── Tab switching ───────────────────────────────────────────────────────────
  function switchTab(tab) {
    $('panel-create').classList.toggle('hidden', tab !== 'create');
    $('panel-join').classList.toggle('hidden', tab !== 'join');
    $('tab-create').classList.toggle('active', tab === 'create');
    $('tab-join').classList.toggle('active', tab === 'join');
    hideError();
  }

  // ── Create room ─────────────────────────────────────────────────────────────
  async function createRoom() {
    const room     = $('create-room').value.trim();
    const password = $('create-password').value;
    const name     = $('create-name').value.trim() || 'Anonymous';
    if (!room)     { showError('Enter a room ID'); return; }
    if (!password) { showError('Enter a room password'); return; }

    setLoading('create-btn', true, 'Creating…');
    try {
      const { ok, data } = await xhr('POST', '/api/create-room', { room, password });
      if (!ok) { showError(data.error || 'Server error'); setLoading('create-btn', false, 'Create Room & Join'); return; }
      myPassword = password;
      isHost = true;
      await connectToRoom(room, name, data.token);
    } catch (e) {
      showError('Cannot reach server: ' + e.message);
      setLoading('create-btn', false, 'Create Room & Join');
    }
  }

  // ── Join with token ─────────────────────────────────────────────────────────
  async function joinWithToken() {
    const room  = $('join-room').value.trim();
    const token = $('join-token').value.trim();
    const name  = $('join-name').value.trim() || 'Anonymous';
    if (!room)  { showError('Enter the room ID'); return; }
    if (!token) { showError('Paste your invite token'); return; }
    setLoading('join-btn', true, 'Joining…');
    isHost = false;
    await connectToRoom(room, name, token);
  }

  // ── Core connect ────────────────────────────────────────────────────────────
  async function connectToRoom(room, name, token) {
    myName = name;
    myRoom = room;

    try { await Crypto.generateKeyPair(); }
    catch (e) {
      showError('Crypto init failed: ' + e.message);
      setLoading('create-btn', false, 'Create Room & Join');
      setLoading('join-btn', false, 'Join Room');
      return;
    }

    const publicKey   = await Crypto.exportPublicKey();
    const fingerprint = await Crypto.getFingerprint();
    $('key-fingerprint').textContent = fingerprint;

    socket = io({ transports: ['polling', 'websocket'], timeout: 20000 });

    socket.on('connect', () => socket.emit('join', { room, publicKey, token }));

    socket.on('auth-error', (msg) => {
      showError(msg);
      setLoading('create-btn', false, 'Create Room & Join');
      setLoading('join-btn', false, 'Join Room');
      if (socket) { socket.disconnect(); socket = null; }
    });

    socket.on('room-peers', async (peers) => {
      $('room-display').textContent = room;
      $('mobile-room-display').textContent = room;
      $('join-screen').classList.add('hidden');
      $('chat-screen').classList.remove('hidden');
      if (isHost) $('invite-section').classList.remove('hidden');

      setupObserver();
      addSystemMsg('🔐 Keys generated. You are in the room.');
      addSystemMsg('Fingerprint: ' + fingerprint);

      for (const [id, pk] of Object.entries(peers)) {
        await Crypto.addPeer(id, pk);
        updatePeersList();
        const enc = await Crypto.encrypt(JSON.stringify({ type: 'name', name: myName }), id);
        socket.emit('encrypted-message', { recipientId: id, ...enc });
      }
      addSystemMsg(Object.keys(peers).length > 0
        ? '✅ Connected to ' + Object.keys(peers).length + ' peer(s)'
        : '⏳ Waiting for peers to join…');
    });

    socket.on('peer-joined', async ({ id, publicKey: pk }) => {
      await Crypto.addPeer(id, pk);
      updatePeersList();
      addSystemMsg('✅ A peer joined — encrypted channel established');
      const enc = await Crypto.encrypt(JSON.stringify({ type: 'name', name: myName }), id);
      socket.emit('encrypted-message', { recipientId: id, ...enc });
      for (const [msgId, msg] of sentMessages)
        if (msg.status === 'sent') updateReceiptStatus(msgId, 'delivered');
    });

    socket.on('encrypted-message', async ({ from, iv, ciphertext }) => {
      if (!Crypto.hasPeer(from)) return;
      try {
        const plaintext = await Crypto.decrypt(iv, ciphertext, from);
        const data = JSON.parse(plaintext);
        if (data.type === 'name') {
          peerNames.set(from, data.name); updatePeersList();
        } else if (data.type === 'msg') {
          const el = addMessage(peerNames.get(from) || ('Peer-' + from.slice(0,6)), data.text, 'incoming', data.msgId);
          if (data.msgId) scheduleReadReceipt(el, data.msgId, from);
        } else if (data.type === 'receipt') {
          updateReceiptStatus(data.msgId, 'read');
        }
      } catch (_) {}
    });

    socket.on('typing', ({ from, isTyping }) => {
      const name = peerNames.get(from) || ('Peer-' + from.slice(0,6));
      if (isTyping) typingPeers.set(from, name); else typingPeers.delete(from);
      renderTypingBar();
    });

    socket.on('read-receipt', ({ msgId }) => updateReceiptStatus(msgId, 'read'));

    socket.on('peer-left', (id) => {
      const name = peerNames.get(id) || ('Peer-' + id.slice(0,6));
      Crypto.removePeer(id); peerNames.delete(id); typingPeers.delete(id);
      updatePeersList(); renderTypingBar();
      addSystemMsg('👋 ' + name + ' left');
    });

    socket.on('peer-count', (count) => {
      $('peer-count').textContent = count;
      $('mobile-peer-count').textContent = count;
    });

    socket.on('error',         (msg) => addSystemMsg('⚠️ ' + msg));
    socket.on('connect_error', (e)   => {
      showError('Connection failed: ' + e.message);
      setLoading('create-btn', false, 'Create Room & Join');
      setLoading('join-btn',   false, 'Join Room');
    });
  }

  // ── Typing bar ──────────────────────────────────────────────────────────────
  function renderTypingBar() {
    const bar = $('typing-bar');
    if (typingPeers.size === 0) { bar.classList.add('hidden'); return; }
    const names = [...typingPeers.values()];
    bar.querySelector('.typing-text').textContent =
      names.length === 1 ? names[0] + ' is typing…' : names.join(', ') + ' are typing…';
    bar.classList.remove('hidden');
  }

  // ── Read receipts ───────────────────────────────────────────────────────────
  function setupObserver() {
    if (observer) observer.disconnect();
    observer = new IntersectionObserver((entries) => {
      for (const entry of entries) {
        if (!entry.isIntersecting) continue;
        const el     = entry.target;
        const msgId  = el.dataset.msgId;
        const fromId = el.dataset.fromId;
        if (msgId && fromId && Crypto.hasPeer(fromId)) {
          Crypto.encrypt(JSON.stringify({ type: 'receipt', msgId }), fromId).then(enc => {
            socket.emit('encrypted-message', { recipientId: fromId, ...enc });
          });
          socket.emit('read-receipt', { recipientId: fromId, msgId });
          observer.unobserve(el);
        }
      }
    }, { threshold: 0.8 });
  }

  function scheduleReadReceipt(el, msgId, fromId) {
    if (!observer) return;
    el.dataset.msgId  = msgId;
    el.dataset.fromId = fromId;
    observer.observe(el);
  }

  function updateReceiptStatus(msgId, status) {
    const entry = sentMessages.get(msgId);
    if (!entry) return;
    const priority = { sent: 0, delivered: 1, read: 2 };
    if ((priority[status]||0) <= (priority[entry.status]||0)) return;
    entry.status = status;
    const tick = entry.el.querySelector('.msg-receipt');
    if (!tick) return;
    tick.textContent = '✓✓';
    tick.classList.toggle('receipt-read', status === 'read');
  }

  // ── Send message ────────────────────────────────────────────────────────────
  async function sendMessage() {
    const input = $('msg-input');
    const text  = input.value.trim();
    if (!text || !socket) return;
    if (Crypto.peerCount() === 0) { addSystemMsg('⚠️ No peers connected yet'); return; }

    clearTimeout(typingTimer);
    if (iAmTyping) { iAmTyping = false; socket.emit('typing', { isTyping: false }); }

    const msgId = (typeof crypto !== 'undefined' && crypto.randomUUID)
      ? crypto.randomUUID() : Math.random().toString(36).slice(2);

    input.value = '';
    const el = addMessage('You', text, 'outgoing', msgId);
    sentMessages.set(msgId, { el, status: 'sent' });
    if (Crypto.peerCount() > 0) updateReceiptStatus(msgId, 'delivered');

    const payloads = await Crypto.encryptForAll(JSON.stringify({ type: 'msg', text, msgId }));
    for (const payload of payloads) socket.emit('encrypted-message', payload);
  }

  // ── Invite ──────────────────────────────────────────────────────────────────
  async function generateInvite() {
    try {
      const { ok, data } = await xhr('POST', '/api/invite', { room: myRoom, password: myPassword });
      if (!ok) { addSystemMsg('⚠️ ' + (data.error || 'Failed')); return; }
      $('invite-token-display').textContent = data.token;
      $('invite-result').classList.remove('hidden');
      addSystemMsg('🎫 Invite token generated — share over Signal only');
    } catch { addSystemMsg('⚠️ Failed to generate invite token'); }
  }

  function copyInvite() {
    const token = $('invite-token-display').textContent;
    navigator.clipboard.writeText('Room: ' + myRoom + '\nToken: ' + token)
      .then(() => addSystemMsg('✅ Token copied to clipboard'))
      .catch(() => addSystemMsg('⚠️ Copy failed — select and copy manually'));
  }

  // ── Leave ───────────────────────────────────────────────────────────────────
  function leaveRoom() {
    if (socket) { socket.disconnect(); socket = null; }
    if (observer) { observer.disconnect(); observer = null; }
    $('chat-screen').classList.add('hidden');
    $('join-screen').classList.remove('hidden');
    $('messages').innerHTML = '';
    $('peers-list').innerHTML = '';
    $('invite-result').classList.add('hidden');
    $('invite-section').classList.add('hidden');
    $('typing-bar').classList.add('hidden');
    peerNames.clear(); typingPeers.clear(); sentMessages.clear();
    myPassword = ''; isHost = false; iAmTyping = false;
    setLoading('create-btn', false, 'Create Room & Join');
    setLoading('join-btn',   false, 'Join Room');
  }

  // ── Mobile sidebar ──────────────────────────────────────────────────────────
  function toggleSidebar() {
    document.querySelector('.sidebar').classList.toggle('open');
  }

  // ── UI helpers ──────────────────────────────────────────────────────────────
  function addMessage(sender, text, type, msgId) {
    const div = document.createElement('div');
    div.className = 'message ' + type;
    if (msgId) div.dataset.id = msgId;
    const receipt = type === 'outgoing' ? '<span class="msg-receipt">✓</span>' : '';
    div.innerHTML =
      '<div class="msg-sender">' + escapeHtml(sender) + '</div>' +
      '<div class="msg-bubble">'  + escapeHtml(text)   + '</div>' +
      '<div class="msg-time">'    + timestamp() + ' · 🔐 ' + receipt + '</div>';
    const msgs = $('messages');
    msgs.appendChild(div);
    msgs.scrollTop = msgs.scrollHeight;
    return div;
  }

  function addSystemMsg(text) {
    const div = document.createElement('div');
    div.className = 'system-msg';
    div.textContent = text;
    const msgs = $('messages');
    msgs.appendChild(div);
    msgs.scrollTop = msgs.scrollHeight;
  }

  function updatePeersList() {
    const list = $('peers-list');
    list.innerHTML = '';
    for (const [id, name] of peerNames) {
      const div = document.createElement('div');
      div.className = 'peer-item';
      div.innerHTML =
        '<span class="dot online"></span>' +
        '<span>' + escapeHtml(name) + '</span>' +
        '<span class="peer-id">' + id.slice(0,6) + '</span>';
      list.appendChild(div);
    }
  }

  function showError(msg) { const el = $('join-error'); el.textContent = msg; el.classList.remove('hidden'); }
  function hideError()     { $('join-error').classList.add('hidden'); }

  function setLoading(btnId, loading, label) {
    const btn = $(btnId);
    if (!btn) return;
    btn.disabled = loading;
    btn.textContent = label;
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g,'&amp;').replace(/</g,'&lt;')
      .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  function timestamp() {
    return new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }
})();
