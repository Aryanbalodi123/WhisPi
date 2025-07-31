function log(msg) {
  console.log(`[DEBUG] ${msg}`);
}


 
      document.getElementById("dropdownButton").addEventListener("click", (e) => {
        e.stopPropagation();
        const dropdown = document.getElementById("dropdownMenu");
        const button = document.getElementById("dropdownButton");
        
        if (dropdown.classList.contains("show")) {
          dropdown.classList.remove("show");
          button.style.transform = "scale(1)";
        } else {
          dropdown.classList.add("show");
          button.style.transform = "scale(0.95)";
        }
      });

      
      document.addEventListener("click", (e) => {
        const dropdown = document.getElementById("dropdownMenu");
        const button = document.getElementById("dropdownButton");
        if (!dropdown.contains(e.target) && !button.contains(e.target)) {
          dropdown.classList.remove("show");
          button.style.transform = "scale(1)";
        }
      });

      
      document.getElementById("logoutButton").addEventListener("click", async (e) => {
        e.preventDefault();
        const button = e.target.closest('.logout-button');
        
        
        button.style.pointerEvents = 'none';
        button.innerHTML = `
          <svg class="logout-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
          </svg>
          <span>Signing out...</span>
        `;
        
        try {
          const response = await fetch("/logout", {
            method: "POST",
            credentials: "include"
          });

          if (response.ok) {
            
            button.innerHTML = `
              <svg class="logout-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
              </svg>
              <span>Success!</span>
            `;
            
            
            sessionStorage.clear();
            localStorage.clear();
            
            setTimeout(() => {
              window.location.href = "/";
            }, 1000);
          } else {
            throw new Error('Logout failed');
          }
        } catch (err) {
          console.error("Logout error:", err);
          
          
          button.innerHTML = `
            <svg class="logout-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
            </svg>
            <span>Failed to logout</span>
          `;
          
          button.style.pointerEvents = 'auto';
          
          
          setTimeout(() => {
            button.innerHTML = `
              <svg class="logout-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/>
              </svg>
              <span>Sign Out</span>
            `;
          }, 2000);
          
          showMessage("Logout failed. Please try again.", "error");
        }
      });
const card = document.getElementById("card");

card.addEventListener("mousemove", (e) => {
  const rect = card.getBoundingClientRect();
  const x = ((e.clientX - rect.left) / rect.width) * 100;
  const y = ((e.clientY - rect.top) / rect.height) * 100;

  card.style.setProperty("--mouse-x", x + "%");
  card.style.setProperty("--mouse-y", y + "%");
});

function switchToSignUp() {
  const signUpSection = document.getElementById("SignUp");
  const signInSection = document.getElementById("SignIn");
  const pill = document.getElementById("tabPill");
  const tabs = document.querySelectorAll(".tab-item");

  signInSection.classList.remove("active");
  signUpSection.classList.add("active");

  pill.classList.remove("slide-right");

  tabs[0].classList.add("active");
  tabs[1].classList.remove("active");
}

function switchToSignIn() {
  const signUpSection = document.getElementById("SignUp");
  const signInSection = document.getElementById("SignIn");
  const pill = document.getElementById("tabPill");
  const tabs = document.querySelectorAll(".tab-item");

  signUpSection.classList.remove("active");
  signInSection.classList.add("active");

  pill.classList.add("slide-right");

  tabs[0].classList.remove("active");
  tabs[1].classList.add("active");
}

function showMessage(message, type) {
  const container = document.getElementById("messageContainer");
  const messageDiv = document.createElement("div");
  messageDiv.className = `message ${type}-message`;
  messageDiv.textContent = message;
  container.appendChild(messageDiv);

  setTimeout(() => {
    if (messageDiv.parentNode) {
      messageDiv.parentNode.removeChild(messageDiv);
    }
  }, 5000);
}

function updateProgress(percent) {
  const progressBar = document.getElementById("progressBar");
  const progressFill = document.getElementById("progressFill");
  if (percent > 0) {
    progressBar.style.display = "block";
    progressFill.style.width = percent + "%";
  } else {
    progressBar.style.display = "none";
  }
}

function setButtonLoading(buttonId, loading) {
  const button = document.getElementById(buttonId);
  if (loading) {
    button.classList.add("loading");
    button.disabled = true;
  } else {
    button.classList.remove("loading");
    button.disabled = false;
  }
}



const messageInput = document.getElementById("messageInput");
messageInput.addEventListener("input", function () {
  this.style.height = "auto";
  this.style.height = Math.min(this.scrollHeight, 120) + "px";
});

function showMessage(message, type = "info") {
  const container = document.getElementById("messageContainer");
  const notification = document.createElement("div");
  notification.className = `notification-message ${type}-message`;
  notification.textContent = message;

  container.appendChild(notification);

  requestAnimationFrame(() => {
    notification.classList.add("show");
  });

  setTimeout(() => {
    notification.classList.remove("show");
    setTimeout(() => {
      if (container.contains(notification)) {
        container.removeChild(notification);
      }
    }, 400);
  }, 4000);
}

window.showMessage = showMessage;

function scrollToBottom(container) {
  if (container) {
    container.scrollTo({
      top: container.scrollHeight,
      behavior: "smooth",
    });
  }
}

function formatTimestamp(timestamp) {
  try {
    const date = new Date(timestamp);
    if (isNaN(date.getTime())) throw new Error("Invalid date");

    return date.toLocaleTimeString("en-IN", {
      hour: "2-digit",
      minute: "2-digit",
      hour12: true,
      timeZone: "Asia/Kolkata",
    });
  } catch (err) {
    console.error("Timestamp format error:", err, timestamp);

    return new Date().toLocaleTimeString("en-IN", {
      hour: "2-digit",
      minute: "2-digit",
      hour12: true,
      timeZone: "Asia/Kolkata",
    });
  }
}

function validateUsername(username) {
  if (!username || username.length < 3 || username.length > 50) {
    return "Username must be between 3 and 50 characters";
  }
  if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
    return "Username may only contain letters, numbers, hyphens, and underscores";
  }
  return null;
}

function validatePassword(password) {
  if (!password || password.length < 8) {
    return "Password must be at least 8 characters long";
  }
  if (
    !/[a-z]/.test(password) ||
    !/[A-Z]/.test(password) ||
    !/\d/.test(password)
  ) {
    return "Password must include uppercase, lowercase, and a number";
  }
  return null;
}
