window.chatMessages = {};
let currentChatUser = null;
// REMOVED: let currentUser = null; - we'll use window.currentUser instead
// REMOVED: let userPrivateKey = null; - we'll use window.userPrivateKey instead  
// REMOVED: let userSigningKey = null; - we'll use window.userSigningKey instead


// ——— Open Chat ———
function openChat(user) {
  currentChatUser = user;
  document
    .querySelectorAll(".user-item")
    .forEach((el) => el.classList.remove("active"));
  document.querySelectorAll(".user-item").forEach((el) => {
    if (el.querySelector(".user-name").textContent === user)
      el.classList.add("active");
  });
  document.getElementById("welcomeScreen").style.display = "none";
  document.getElementById("chatHeader").classList.add("active");
  document.getElementById("chatMessages").classList.add("active");
  document.getElementById("chatInput").classList.add("active");
  document.getElementById("chatName").textContent = user;
  document.getElementById("chatAvatar").textContent =
    user[0].toUpperCase();
  loadChatMessages(user);
  document.getElementById("chatArea").classList.add("active");
}

// ——— Render Messages ———
function loadChatMessages(user) {
  const container = document.getElementById("chatMessages");
  const msgs = window.chatMessages[user] || [];
  if (!msgs.length) {
    container.innerHTML =
      '<div style="text-align:center;padding:2rem;color:#666">No messages yet</div>';
    return;
  }
  container.innerHTML = "";
  msgs.forEach((m) => {
    const msgDiv = document.createElement("div");
    msgDiv.className = `message ${m.sender === window.currentUser ? "sent" : "received"
      }`;
    const bubble = document.createElement("div");
    bubble.className = "message-bubble";

    if (m.sender !== window.currentUser) {
      const indicator = document.createElement("span");
      indicator.className = "verification-indicator";
      indicator.style.cssText = `
        display: inline-block;
        width: 12px;
        height: 12px;
        border-radius: 50%;
        margin-right: 5px;
        background: ${m.verified === true ? '#4CAF50' : m.verified === false ? '#f44336' : '#757575'};
        opacity: 0.7;
      `;
      indicator.title = m.verified === true ? 'Verified' : m.verified === false ? 'Unverified' : 'Unknown';
      bubble.appendChild(indicator);
    }

    const textNode = document.createTextNode(m.text);
    bubble.appendChild(textNode);

    const time = document.createElement("span");
    time.className = "message-time";
    time.textContent = m.time;
    bubble.appendChild(time);
    msgDiv.appendChild(bubble);
    container.appendChild(msgDiv);
  });
  container.scrollTop = container.scrollHeight;
}



// ——— Send Message ———
async function sendMessage() {
  const input = document.getElementById("messageInput");
  if (!input.value.trim() || !currentChatUser) return;
  const text = input.value.trim();
  try {
    const signature = await signMessage(text, window.userSigningKey);

    const encrypted = await encryptMessage(currentChatUser, text);
    await fetch("/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include", // FIXED: Include credentials
      body: JSON.stringify({
        from_user: window.currentUser,
        to_user: currentChatUser,
        message: encrypted,
        signature: signature,
      }),
    });
    const time = new Date().toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
    });
    window.chatMessages[currentChatUser] =
      window.chatMessages[currentChatUser] || [];
    window.chatMessages[currentChatUser].push({
      sender: window.currentUser,
      text,
      time,
      verified: true, // Own messages are always verified
    });
    loadChatMessages(currentChatUser);
    input.value = "";
    input.style.height = "auto";
  } catch (err) {
    console.error(err);
    showMessage("Failed to send message", "error");
  }
}

// ——— Poll Inbox ———
async function getInbox() {
  if (!window.currentUser) return;

  try {
    const res = await fetch(`/inbox/${encodeURIComponent(window.currentUser)}`, {
      credentials: "include" // FIXED: Include credentials
    });
    if (!res.ok) throw new Error("Inbox fetch failed");

    const messages = await res.json();

    for (const msg of messages) {
      if (msg.from_user === window.currentUser) continue;

      const plain = await decryptMessage(
        msg.encrypted_message,
        window.userPrivateKey 
      );

      let verified = null;
      if (msg.signature) {
        try {
          const pubKeyRes = await fetch(`/get_key/${msg.from_user}`, {
            credentials: "include" // FIXED: Include credentials
          });
          if (pubKeyRes.ok) {
            const { public_key } = await pubKeyRes.json();
            verified = await verifySignature(plain, msg.signature, public_key);
          }
        } catch (err) {
          console.error("Error verifying signature:", err);
          verified = false;
        }
      }

      const time = new Date(msg.timestamp).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
      });

      window.chatMessages[msg.from_user] = window.chatMessages[msg.from_user] || [];
      const exists = window.chatMessages[msg.from_user].some(
        (m) => m.text === plain && m.time === time
      );

      if (!exists) {
        window.chatMessages[msg.from_user].push({
          sender: msg.from_user,
          text: plain,
          time,
          verified: verified,
        });
      }

      if (msg.from_user === currentChatUser) {
        const statusText = msg.is_online ? "Online" : "Offline";
        const statusElement = document.getElementById("user-status-text");
        if (statusElement) {
          statusElement.textContent = statusText;
        }
      }
    }

    if (currentChatUser) {
      loadChatMessages(currentChatUser);
    }

  } catch (err) {
    console.error(err);
  }
}

document.addEventListener("DOMContentLoaded", async () => {

  try {
    await restoreSession();
  } catch (err) {
    return;
  }

  document
    .getElementById("sendButton")
    .addEventListener("click", sendMessage);
  document
    .getElementById("messageInput")
    .addEventListener("input", (e) => {
      e.target.style.height = "auto";
      e.target.style.height = e.target.scrollHeight + "px";
    });
  document.addEventListener("keydown", (e) => {
    if (
      e.target.id === "messageInput" &&
      e.key === "Enter" &&
      !e.shiftKey
    ) {
      e.preventDefault();
      sendMessage();
    }
  });
  await fetchUsers();
  await getInbox();
  setInterval(getInbox, 5000);
});