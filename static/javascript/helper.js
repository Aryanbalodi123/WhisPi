function log(msg) {
  console.log(`[DEBUG] ${msg}`);
}

function showMessage(text, type = 'info') {
  const container = document.getElementById('messageContainer');
  const messageDiv = document.createElement('div');
  messageDiv.className = `message ${type}-message`;
  messageDiv.textContent = text;
  container.appendChild(messageDiv);
  setTimeout(() => messageDiv.remove(), 5000);
}

function updateProgress(percent) {
  const progressBar = document.getElementById('progressBar');
  const progressFill = document.getElementById('progressFill');
  progressBar.style.display = 'block';
  progressFill.style.width = percent + '%';
  if (percent >= 100) {
    setTimeout(() => {
      progressBar.style.display = 'none';
      progressFill.style.width = '0%';
    }, 800);
  }
}

function setButtonLoading(buttonId, isLoading) {
  const button = document.getElementById(buttonId);
  button.disabled = isLoading;
  if (isLoading) {
    button.classList.add('loading');
    button.textContent = '';
  } else {
    button.classList.remove('loading');
    button.textContent = buttonId === 'loginBtn' ? 'Sign In' : 'Create Account';
  }
}

function switchTab(tabName) {
  document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('.form-section').forEach(section => section.classList.remove('active'));
  document.getElementById(tabName + 'Section').classList.add('active');
  document.getElementById('messageContainer').innerHTML = '';
}

// Mouse shadow effect
document.addEventListener('DOMContentLoaded', function() {
  const shadow = document.getElementById("shadow");
  const card = document.getElementById("card");

  if (shadow && card) {
    document.body.addEventListener("mousemove", (e) => {
      const { clientX, clientY } = e;
      if (e.target.closest("#card")) {
        shadow.style.setProperty(
          "transform",
          `translateX(${clientX - 60}px) translateY(${clientY - 60}px)`
        );
        shadow.style.setProperty("opacity", "0.5");
      } else {
        shadow.style.setProperty("opacity", "0");
      }
    });
  }

  // Tab switching functionality
  const signUpSection = document.getElementById("SignUp");
  const signInSection = document.getElementById("SignIn");

  if (signUpSection && signInSection) {
    // Sign up tab buttons
    const signUpTabs = document.querySelectorAll('.mb-8 > div:first-child');
    signUpTabs.forEach(tab => {
      tab.addEventListener("click", () => {
        signUpSection.style.display = "block";
        signInSection.style.display = "none";
      });
    });

    // Sign in tab buttons
    const signInTabs = document.querySelectorAll('.mb-8 > div:last-child');
    signInTabs.forEach(tab => {
      tab.addEventListener("click", () => {
        signInSection.style.display = "block";
        signUpSection.style.display = "none";
      });
    });
  }
});