window.chatMessages = {};
let currentChatUser = null;
let processedMessages = new Set();
let isInitialized = false;
let isSending = false;


function openChat(user) {
  currentChatUser = user;
  document.querySelectorAll('.user-item').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.user-item').forEach(el => {
    if (el.querySelector('.user-name').textContent === user) el.classList.add('active');
  });

  document.getElementById('welcomeScreen').style.display = 'none';
  document.getElementById('chatHeader').classList.add('active');
  document.getElementById('chatMessages').classList.add('active');
  document.getElementById('chatInput').classList.add('active');
  document.getElementById('chatName').textContent = user;
  document.getElementById('chatAvatar').textContent = user[0].toUpperCase();
  loadChatMessages(user);
  document.getElementById('chatArea').classList.add('active');
}

function loadChatMessages(user) {
  const container = document.getElementById('chatMessages');
  const msgs = window.chatMessages[user] || [];

  container.innerHTML = '';
  msgs.forEach(m => {
    const msgDiv = document.createElement('div');
    msgDiv.className = `message ${m.sender === window.currentUser ? 'sent' : 'received'}`;

    const bubble = document.createElement('div');
    bubble.className = 'message-bubble';


    const textSpan = document.createElement('span');
    textSpan.className = 'message-text';
    textSpan.textContent = m.text;


    const timeSpan = document.createElement('span');
    timeSpan.className = 'message-time';
    timeSpan.textContent = m.time;

    bubble.append(textSpan, timeSpan);
    msgDiv.appendChild(bubble);
    container.appendChild(msgDiv);
  });

  container.scrollTop = container.scrollHeight;
}

async function sendMessage() {
  const input = document.getElementById('messageInput');
  if (!input.value.trim() || !currentChatUser || isSending) return;

  const text = input.value.trim();
  isSending = true;

  try {
    const signature = await signMessage(text, window.userSigningKey);
    const encrypted = await encryptMessage(currentChatUser, text);
    
 
    const now = new Date();
    const clientTimestamp = now.toISOString(); 
    const displayTime = now.toLocaleTimeString('en-IN', {
      hour: '2-digit',
      minute: '2-digit',
      hour12: true,
      timeZone: 'Asia/Kolkata'
    });

    const res = await fetch('/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({
        from_user: window.currentUser,
        to_user: currentChatUser,
        encrypted_message: encrypted.encrypted_message,
        iv: encrypted.iv,
        encrypted_key_for_sender: encrypted.encrypted_key_for_sender,
        encrypted_key_for_recipient: encrypted.encrypted_key_for_recipient,
        signature,
        client_timestamp: clientTimestamp 
      })
    });

    if (!res.ok) throw new Error('Send failed');
    const response = await res.json();

    const messageObj = {
      sender: window.currentUser,
      text,
      time: displayTime,
      verified: true,
      messageId: `${window.currentUser}-${currentChatUser}-${clientTimestamp}`,
      timestamp: clientTimestamp
    };

    window.chatMessages[currentChatUser] = window.chatMessages[currentChatUser] || [];
    window.chatMessages[currentChatUser].push(messageObj);
    processedMessages.add(messageObj.messageId);
    loadChatMessages(currentChatUser);

    input.value = '';
    input.style.height = 'auto';
  } catch (err) {
    console.error('Send message error:', err);
    showMessage('Failed to send message', 'error');
  } finally {
    isSending = false;
  }
}

async function getInbox() {
  if (!window.currentUser) return;

  try {
    const res = await fetch(`/inbox/${encodeURIComponent(window.currentUser)}`, { credentials: 'include' });
    if (!res.ok) throw new Error('Inbox fetch failed');
    const messages = await res.json();

    const temp = {};
    for (const msg of messages) {
      const isSent = msg.from_user === window.currentUser;
      const partner = isSent ? msg.to_user : msg.from_user;
      const serverTimestamp = msg.created_at || msg.timestamp;
      const msgId = `${msg.from_user}-${msg.to_user}-${serverTimestamp}`;

      if (processedMessages.has(msgId)) continue;

      try {
        const plain = await decryptMessage({
          encrypted_message: msg.encrypted_message,
          iv: msg.iv,
          encrypted_key_for_sender: msg.encrypted_key_for_sender,
          encrypted_key_for_recipient: msg.encrypted_key_for_recipient
        }, window.currentUser, msg.from_user, msg.to_user);

        let verified = isSent ? true : null;
        if (!isSent && msg.signature) {
          try {
            const keyRes = await fetch(`/get_key/${msg.from_user}`, { credentials: 'include' });
            if (keyRes.ok) {
              const { public_key } = await keyRes.json();
              verified = public_key
                ? await verifySignature(plain, msg.signature, public_key)
                : false;
            } else {
              verified = false;
            }
          } catch {
            verified = false;
          }
        }

        const time = formatTimestamp(serverTimestamp);
        temp[partner] = temp[partner] || [];
        temp[partner].push({ sender: msg.from_user, text: plain, time, verified, messageId: msgId, timestamp: serverTimestamp });
        processedMessages.add(msgId);
      } catch (err) {
        console.error('Processing error:', err);
        processedMessages.add(msgId);
      }
    }

    let updated = false;
    for (const partner in temp) {
      window.chatMessages[partner] = window.chatMessages[partner] || [];
      const existing = new Set(window.chatMessages[partner].map(m => m.messageId));
      for (const m of temp[partner]) {
        if (!existing.has(m.messageId)) {
          window.chatMessages[partner].push(m);
          updated = true;
        }
      }
      window.chatMessages[partner].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    }

    if (updated && currentChatUser && !isSending) loadChatMessages(currentChatUser);

  } catch (err) {
    console.error('Inbox fetch error:', err);
  }
}

function clearOldProcessedMessages() {
  if (processedMessages.size > 1000) {
    const recent = Array.from(processedMessages).slice(-500);
    processedMessages.clear();
    recent.forEach(id => processedMessages.add(id));
  }
}

window.sendMessage = sendMessage;

document.addEventListener('DOMContentLoaded', async () => {
  if (isInitialized) return;
  isInitialized = true;

  try {
    await restoreSession();
    const hdr = document.querySelector('.sidebar-user-name');
    if (hdr && window.currentUser) hdr.textContent = window.currentUser;
  } catch {}

  const btn = document.getElementById('sendButton');
  const inp = document.getElementById('messageInput');
  if (btn) {
    btn.replaceWith(btn.cloneNode(true));
    document.getElementById('sendButton').addEventListener('click', sendMessage);
  }
  if (inp) {
    inp.replaceWith(inp.cloneNode(true));
    const ni = document.getElementById('messageInput');
    ni.addEventListener('input', e => {
      e.target.style.height = 'auto';
      e.target.style.height = e.target.scrollHeight + 'px';
    });
    ni.addEventListener('keydown', e => {
      if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
    });
  }

  await fetchUsers();
  await getInbox();
  setInterval(getInbox, 5000);
  setInterval(clearOldProcessedMessages, 5 * 60 * 1000);
});
