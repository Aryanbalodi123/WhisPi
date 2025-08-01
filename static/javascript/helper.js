function log(msg) {
  console.log(`[DEBUG] ${msg}`);
}

// Dropdown functionality
document.addEventListener('DOMContentLoaded', function() {
  const dropdownButton = document.getElementById("dropdownButton");
  const dropdownMenu = document.getElementById("dropdownMenu");
  
  if (dropdownButton && dropdownMenu) {
    dropdownButton.addEventListener("click", (e) => {
      e.stopPropagation();
      
      if (dropdownMenu.classList.contains("show")) {
        dropdownMenu.classList.remove("show");
        dropdownButton.style.transform = "scale(1)";
      } else {
        dropdownMenu.classList.add("show");
        dropdownButton.style.transform = "scale(0.95)";
      }
    });
  }
});

// Close dropdown when clicking outside
document.addEventListener("click", (e) => {
  const dropdown = document.getElementById("dropdownMenu");
  const button = document.getElementById("dropdownButton");
  if (dropdown && button && !dropdown.contains(e.target) && !button.contains(e.target)) {
    dropdown.classList.remove("show");
    button.style.transform = "scale(1)";
  }
});

// Logout functionality
document.addEventListener('DOMContentLoaded', function() {
  const logoutButton = document.getElementById("logoutButton");
  
  if (logoutButton) {
    logoutButton.addEventListener("click", async (e) => {
      e.preventDefault();
      const button = e.target.closest('.logout-button');
      
      // Disable button during logout
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
          // Success state
          button.innerHTML = `
            <svg class="logout-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
            </svg>
            <span>Success!</span>
          `;
          
          // Clear storage
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
        
        // Error state
        button.innerHTML = `
          <svg class="logout-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
          </svg>
          <span>Failed to logout</span>
        `;
        
        button.style.pointerEvents = 'auto';
        
        // Reset button after delay
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
  }
});

// Card hover effect (if card exists)
document.addEventListener('DOMContentLoaded', function() {
  const card = document.getElementById("card");
  
  if (card) {
    card.addEventListener("mousemove", (e) => {
      const rect = card.getBoundingClientRect();
      const x = ((e.clientX - rect.left) / rect.width) * 100;
      const y = ((e.clientY - rect.top) / rect.height) * 100;

      card.style.setProperty("--mouse-x", x + "%");
      card.style.setProperty("--mouse-y", y + "%");
    });
  }
});

// Auth form switching functions
function switchToSignUp() {
  const signUpSection = document.getElementById("SignUp");
  const signInSection = document.getElementById("SignIn");
  const pill = document.getElementById("tabPill");
  const tabs = document.querySelectorAll(".tab-item");

  if (signInSection && signUpSection) {
    signInSection.classList.remove("active");
    signUpSection.classList.add("active");
  }

  if (pill) {
    pill.classList.remove("slide-right");
  }

  if (tabs.length >= 2) {
    tabs[0].classList.add("active");
    tabs[1].classList.remove("active");
  }
}

function switchToSignIn() {
  const signUpSection = document.getElementById("SignUp");
  const signInSection = document.getElementById("SignIn");
  const pill = document.getElementById("tabPill");
  const tabs = document.querySelectorAll(".tab-item");

  if (signUpSection && signInSection) {
    signUpSection.classList.remove("active");
    signInSection.classList.add("active");
  }

  if (pill) {
    pill.classList.add("slide-right");
  }

  if (tabs.length >= 2) {
    tabs[0].classList.remove("active");
    tabs[1].classList.add("active");
  }
}

// Message notification system
function showMessage(message, type = "info") {
  const container = document.getElementById("messageContainer");
  if (!container) return;
  
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

// Make showMessage globally available
window.showMessage = showMessage;

// Progress bar functions
function updateProgress(percent) {
  const progressBar = document.getElementById("progressBar");
  const progressFill = document.getElementById("progressFill");
  
  if (progressBar && progressFill) {
    if (percent > 0) {
      progressBar.style.display = "block";
      progressFill.style.width = percent + "%";
    } else {
      progressBar.style.display = "none";
    }
  }
}

function setButtonLoading(buttonId, loading) {
  const button = document.getElementById(buttonId);
  if (button) {
    if (loading) {
      button.classList.add("loading");
      button.disabled = true;
    } else {
      button.classList.remove("loading");
      button.disabled = false;
    }
  }
}

// Message input auto-resize
document.addEventListener('DOMContentLoaded', function() {
  const messageInput = document.getElementById("messageInput");
  
  if (messageInput) {
    messageInput.addEventListener("input", function () {
      this.style.height = "auto";
      this.style.height = Math.min(this.scrollHeight, 120) + "px";
    });
  }
});

// Utility functions
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

// MOBILE CHAT FUNCTIONALITY - INTEGRATED WITH MESSAGING.JS
document.addEventListener('DOMContentLoaded', function() {
  // Mobile back button functionality
  const mobileBackButton = document.getElementById('mobileBackButton');
  if (mobileBackButton) {
    mobileBackButton.addEventListener('click', function() {
      const chatContainer = document.querySelector('.chat-container');
      if (chatContainer) {
        chatContainer.classList.remove('mobile-chat-active');
      }
    });
  }

  // User item click functionality - CALLS openChat() from messaging.js
  document.addEventListener('click', function(e) {
    const userItem = e.target.closest('.user-item');
    if (userItem) {
      // Get user information
      const userName = userItem.querySelector('.user-name')?.textContent || 'User';
      
      // Call the openChat function from messaging.js
      if (window.openChat && typeof window.openChat === 'function') {
        window.openChat(userName);
        log(`Opened chat with: ${userName}`);
      } else {
        // Fallback if openChat is not available yet
        log(`openChat function not available, falling back to basic UI update`);
        
        // Basic UI update as fallback
        const chatName = document.getElementById('chatName');
        const chatAvatar = document.getElementById('chatAvatar');
        
        if (chatName) chatName.textContent = userName;
        if (chatAvatar) chatAvatar.textContent = userName.charAt(0).toUpperCase();
        
        // Remove active class from all user items
        document.querySelectorAll('.user-item').forEach(item => {
          item.classList.remove('active');
        });
        
        // Add active class to clicked item
        userItem.classList.add('active');
        
        // Show mobile chat view
  document.querySelector('.chat-container')
        .classList.add('mobile-chat-active');
      }
      
      log(`User clicked: ${userName}`);
    }
  });
});

// Function to create and add user items (if needed by other scripts)
function createUserItem(userData) {
  const userItem = document.createElement('div');
  userItem.className = 'user-item';
  userItem.dataset.userId = userData.id || '';
  
  userItem.innerHTML = `
    <div class="user-avatar">${(userData.name || 'U').charAt(0).toUpperCase()}</div>
    <div class="user-info">
      <div class="user-name">${userData.name || 'Unknown User'}</div>
      <div class="user-message">${userData.lastMessage || 'No messages yet'}</div>
    </div>
    <div class="user-time">${userData.time || ''}</div>
  `;
  
  return userItem;
}

// Function to add user to list
function addUserToList(userData) {
  const userList = document.querySelector('.user-list');
  if (userList) {
    const userItem = createUserItem(userData);
    userList.appendChild(userItem);
  }
}

// Export functions for use in other scripts
window.switchToSignUp = switchToSignUp;
window.switchToSignIn = switchToSignIn;
window.updateProgress = updateProgress;
window.setButtonLoading = setButtonLoading;
window.scrollToBottom = scrollToBottom;
window.formatTimestamp = formatTimestamp;
window.validateUsername = validateUsername;
window.validatePassword = validatePassword;
window.createUserItem = createUserItem;
window.addUserToList = addUserToList;

