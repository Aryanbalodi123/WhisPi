window.currentUser = window.currentUser || null;
window.userPrivateKey = window.userPrivateKey || null;
window.userSigningKey = window.userSigningKey || null;


// ——— Session Management Functions ———
async function restoreSession() {
  try {

    const raw = sessionStorage.getItem("secureChatSession");
    if (!raw) {
      throw new Error("No session data in sessionStorage");
    }
    
    const { username, keyBuffer } = JSON.parse(raw);
    if (!username || !Array.isArray(keyBuffer)) {
      throw new Error("Invalid session data format");
    }

    const statusRes = await fetch("/session/status", {
      method: "GET",
      credentials: "include", 
    });

    if (!statusRes.ok) {
      throw new Error("Server session invalid or expired");
    }
    
    
    window.currentUser = username; 
    const buf = Uint8Array.from(keyBuffer).buffer;
    
    window.userPrivateKey = await crypto.subtle.importKey(
      "pkcs8",
      buf,
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["decrypt"]
    );
    
    window.userSigningKey = await crypto.subtle.importKey(
      "pkcs8",
      buf,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["sign"]
    );
    
    startAutoLogoutTimer();
    log(`Session restored for ${window.currentUser}`);
    return true;
  } catch (err) {
    log(`Session restore failed: ${err.message}`);
   
    sessionStorage.removeItem("secureChatSession");
    
 
    if (window.location.pathname === '/chat.html') {
      showMessage("Session expired or invalid. Please log in again.", "error");
     
      window.location.href = "/";
    }
    
    return false;
  }
}

function startAutoLogoutTimer() {
  const AUTO_LOGOUT_TIMER = 15 * 60 * 1000; // 15 minutes

  let timer;

  async function logout() {
    try {
      await fetch("/logout", {
        method: "POST",
        credentials: "include",
      });
    } catch (err) {
      console.error("Logout failed:", err);
    }
    sessionStorage.clear();
    window.location.href = "/";
  }

  function reset() {
    clearTimeout(timer);
    timer = setTimeout(() => {
      showMessage("Session expired due to inactivity. Please log in again.", "error");
      logout();
    }, AUTO_LOGOUT_TIMER);
  }

  ["mousemove", "keydown", "click", "touchstart"].forEach((event) => {
    document.addEventListener(event, reset);
  });

  reset();
}

function isLoggedIn() {
  return window.currentUser !== null && window.userPrivateKey !== null && window.userSigningKey !== null;
}

// ——— User Management Functions ———

async function fetchUsers() {
  try {
    const res = await fetch("/users", {
      credentials: "include" 
    });
    if (!res.ok) throw new Error(res.statusText);
    
    const { users } = await res.json();
    const list = document.querySelector(".user-list");
    list.innerHTML = "";
    
    const others = users.filter((u) => u !== window.currentUser);
    if (!others.length) {
      list.innerHTML = '<div class="error-message">No other users</div>';
      return;
    }
    
    const colors = [
      "linear-gradient(135deg,#ff6b6b,#ee5a52)",
      "linear-gradient(135deg,#667eea,#764ba2)",
      "linear-gradient(135deg,#f093fb,#f5576c)",
      "linear-gradient(135deg,#4facfe,#00f2fe)",
      "linear-gradient(135deg,#43e97b,#38f9d7)",
      "linear-gradient(135deg,#fa709a,#fee140)",
    ];
    
    others.forEach((u, i) => {
      const div = document.createElement("div");
      div.className = "user-item";
      div.onclick = () => openChat(u);
      const c = colors[i % colors.length];
      div.innerHTML = `
        <div class="user-avatar" style="background:${c}">${u[0].toUpperCase()}</div>
        <div class="user-info">
          <div class="user-name">${u}</div>
          <div class="user-message" id="lastMsg-${u}">No messages</div>
        </div>
        <div class="user-time" id="lastTime-${u}"></div>
      `;
      list.appendChild(div);
    });
  } catch (err) {
    console.error(err);
    document.querySelector(
      ".user-list"
    ).innerHTML = `<div class="error-message">Error loading users</div>`;
  }
}


document.addEventListener('DOMContentLoaded', async function() {

  const isOnChatPage = window.location.pathname === '/chat.html';
  const isOnLoginPage = window.location.pathname === '/' || window.location.pathname.includes('login');
  
  if (isOnChatPage) {

    const sessionRestored = await restoreSession();
    if (sessionRestored) {

      await fetchUsers();
    }

    return;
  }
  
  if (isOnLoginPage) {

    const raw = sessionStorage.getItem("secureChatSession");
    if (raw) {
      try {
        const { username } = JSON.parse(raw);
        if (username) {
 
          const statusRes = await fetch("/session/status", {
            method: "GET",
            credentials: "include", 
          });
          
          if (statusRes.ok) {
          
            window.location.href = "/chat.html";
            return;
          }
        }
      } catch (err) {
 
        sessionStorage.removeItem("secureChatSession");
      }
    }
    

    setupLoginHandlers();
  }
});

function setupLoginHandlers() {
  // Login form handler
  const loginForm = document.getElementById('loginForm');
  if (loginForm) {
    loginForm.addEventListener('submit', async (event) => {
      event.preventDefault();

      const username = document.getElementById('loginUsername').value.trim();
      const password = document.getElementById('loginPassword').value;
      
      const usernameError = validateUsername(username);
      const passwordError = validatePassword(password);
      
      if (usernameError) return showMessage(usernameError, 'error');
      if (passwordError) return showMessage(passwordError, 'error');

      setButtonLoading('loginBtn', true);
      
      try {
        log('Encrypting login payload');
        const loginPayload = JSON.stringify({ username, password });
        const encryptedPayload = await hybridEncryptPayload(loginPayload);

        log('Sending login request');
        const response = await fetch('/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify(encryptedPayload)
        });
        
        const result = await response.json();
        if (!response.ok) throw new Error(result.error || 'Login failed');

        log('Decrypting private key');
        const encryptedPrivateKey = typeof result.private_key === 'string'
          ? JSON.parse(result.private_key)
          : result.private_key;
        const privateKey = await decryptPrivateKey(encryptedPrivateKey, password);

        log('Exporting private key for session storage');
        const rawPrivateKey = await crypto.subtle.exportKey('pkcs8', privateKey);
        sessionStorage.setItem('secureChatSession', JSON.stringify({
          username: result.username,
          keyBuffer: Array.from(new Uint8Array(rawPrivateKey))
        }));

        showMessage('Login successful! Redirecting to chat…', 'success');
        setTimeout(() => window.location.href = '/chat.html', 800);
      } catch (error) {
        log(`Login error: ${error.message}`);
        showMessage(error.message, 'error');
      } finally {
        setButtonLoading('loginBtn', false);
      }
    });
  }

  // Registration form handler
  const registerForm = document.getElementById('registerForm');
  if (registerForm) {
    registerForm.addEventListener('submit', async (event) => {
      event.preventDefault();

      const username = document.getElementById('registerUsername').value.trim();
      const password = document.getElementById('registerPassword').value;
      const confirmPassword = document.getElementById('confirmPassword').value;
      
      const usernameError = validateUsername(username);
      const passwordError = validatePassword(password);
      
      if (usernameError) return showMessage(usernameError, 'error');
      if (passwordError) return showMessage(passwordError, 'error');
      if (password !== confirmPassword) return showMessage('Passwords do not match', 'error');

      setButtonLoading('registerBtn', true);
      
      try {
        log('Generating RSA key pair');
        updateProgress(5);
        
        const keyPair = await crypto.subtle.generateKey(
          { name: 'RSA-OAEP', modulusLength: 4096, publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' },
          true, ['encrypt','decrypt']
        );
        updateProgress(30);

        log('Exporting keys to PEM');
        const publicKeyBuffer = await crypto.subtle.exportKey('spki', keyPair.publicKey);
        const privateKeyBuffer = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
        const publicKeyPem = arrayBufferToPem(publicKeyBuffer, 'PUBLIC KEY');
        const privateKeyPem = arrayBufferToPem(privateKeyBuffer, 'PRIVATE KEY');
        updateProgress(60);

        log('Encrypting private key');
        const encryptedPrivateKey = await encryptPrivateKey(privateKeyPem, password);
        updateProgress(80);

        log('Preparing registration payload');
        const registrationPayload = JSON.stringify({
          username,
          password,
          public_key: publicKeyPem,
          private_key: JSON.stringify(encryptedPrivateKey)
        });
        const encryptedPayload = await hybridEncryptPayload(registrationPayload);
        updateProgress(90);

        log('Sending registration request');
        const response = await fetch('/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include', 
          body: JSON.stringify(encryptedPayload)
        });
        
        const result = await response.json();
        if (!response.ok) throw new Error(result.error || 'Registration failed');

        updateProgress(100);
        showMessage('Account created! You can now log in.', 'success');
        document.getElementById('registerForm').reset();
        
        setTimeout(() => {
          const signInSection = document.getElementById("SignIn");
          const signUpSection = document.getElementById("SignUp");
          if (signInSection && signUpSection) {
            signInSection.style.display = "block";
            signUpSection.style.display = "none";
          }
        }, 800);
      } catch (error) {
        log(`Registration error: ${error.message}`);
        showMessage(error.message, 'error');
        updateProgress(0);
      } finally {
        setButtonLoading('registerBtn', false);
      }
    });
  }
}
