/* =========================================================
   GLOBAL HELPER FUNCTIONS
   ========================================================= */

/**
 * Shows success or error message
 */
function showMessage(msg, text, type = "error") {
  msg.textContent = text;
  msg.style.color = type === "error" ? "#dc2626" : "#16a34a";
}

/**
 * Adds / removes loading state on buttons
 */
function setLoading(btn, loading) {
  if (loading) btn.classList.add("loading");
  else btn.classList.remove("loading");
}

/**
 * Validates email format
 */
function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
  return emailRegex.test(email);
}

/**
 * Checks password strength
 */
function isStrongPassword(password) {
  const regex =
    /^(?=.*[A-Za-z])(?=.*\d)(?=.*[!@#$%^&*_\-()])[A-Za-z\d!@#$%^&*_\-()]{6,}$/;
  return regex.test(password);
}

/**
 * Generic POST helper for auth APIs
 */
async function post(url, data) {
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams(data)
  });
  return res.json();
}

/* =========================================================
   MAIN SCRIPT
   ========================================================= */

document.addEventListener("DOMContentLoaded", () => {

  /**
   * Handles unauthorized (401) responses
   */
  function handleUnauthorized() {
    localStorage.clear();
    window.location.replace("login.html");
  }

  const API_BASE = "http://localhost:8080/api/auth";

  /* =========================================================
     REGISTER
     ========================================================= */
  /* ---------- REGISTER ---------- */
const registerForm = document.getElementById("registerForm");

if (registerForm) {
  registerForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    const btn = document.getElementById("registerBtn");
    const msg = document.getElementById("message");
    const email = document.getElementById("regEmail").value.trim();
    const password = document.getElementById("regPassword").value;

    if (!isValidEmail(email)) {
      showMessage(msg, "Please enter a valid email address");
      return;
    }

    if (!isStrongPassword(password)) {
      showMessage(
        msg,
        "Password must contain at least one letter, one number, one special character and be at least 6 characters long"
      );
      return;
    }

    setLoading(btn, true);

    try {
      const res = await post(`${API_BASE}/register`, { email, password });

      showMessage(msg, res.message, res.status);

      // ✅ SUCCESS → go to OTP page
      if (res.status === "success") {
        localStorage.setItem("email", email);
        location.href = "verify-otp.html";
        return;
      }

      // ✅ EMAIL EXISTS BUT NOT VERIFIED → go to OTP page
      if (
        res.status === "error" &&
        res.message.toLowerCase().includes("email")
      ) {
        localStorage.setItem("email", email);
        location.href = "verify-otp.html";
        return;
      }

    } catch {
      showMessage(msg, "Server error");
    } finally {
      setLoading(btn, false);
    }
  });
}


  /* =========================================================
     OTP VERIFICATION
     ========================================================= */
  const otpForm = document.getElementById("otpForm");

  if (otpForm) {
    setupOtpInputs();

    otpForm.addEventListener("submit", async (e) => {
      e.preventDefault();

      const btn = document.getElementById("verifyBtn");
      const msg = document.getElementById("message");
      const email = localStorage.getItem("email");

      const otp = [...document.querySelectorAll(".otp-input")]
        .map(i => i.value)
        .join("");

      if (!email) {
        showMessage(msg, "Session expired. Please register again.");
        return;
      }

      setLoading(btn, true);

      try {
        const res = await post(`${API_BASE}/verify-otp`, { email, otp });
        showMessage(msg, res.message, res.status);

        if (res.status === "success") {
          location.href = "login.html";
        }
      } catch {
        showMessage(msg, "Server error");
      } finally {
        setLoading(btn, false);
      }
    });
  }

  /* =========================================================
     RESEND OTP
     ========================================================= */
  const resendBtn = document.getElementById("resendOtpBtn");

if (resendBtn) {
  resendBtn.addEventListener("click", async () => {
    const email = localStorage.getItem("email");
    const msg = document.getElementById("message");

    if (!email) {
      showMessage(msg, "Session expired. Please register again.");
      return;
    }

    // Disable button immediately (text stays the same)
    resendBtn.disabled = true;

    try {
      await fetch("http://localhost:8080/api/auth/resend-otp", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({ email })
      });

      showMessage(msg, "OTP sent to your email", "success");

    } catch {
      showMessage(msg, "Failed to resend OTP", "error");
    }

    // Re-enable after 30 seconds
    setTimeout(() => {
      resendBtn.disabled = false;
    }, 30000);
  });
}


  /* =========================================================
     LOGIN
     ========================================================= */
  const loginForm = document.getElementById("loginForm");

  if (loginForm) {
    loginForm.addEventListener("submit", async (e) => {
      e.preventDefault();

      const btn = document.getElementById("loginBtn");
      const msg = document.getElementById("message");
      const email = document.getElementById("loginEmail").value.trim();
      const password = document.getElementById("loginPassword").value;

      setLoading(btn, true);

      try {
        const res = await post(`${API_BASE}/login`, { email, password });
        showMessage(msg, res.message, res.status);

        if (res.status === "success") {
          localStorage.setItem("token", res.token);
          localStorage.setItem("email", email);
          location.href = "dashboard.html";
        }
      } catch {
        showMessage(msg, "Server error");
      } finally {
        setLoading(btn, false);
      }
    });
  }

  /* =========================================================
     FORGOT PASSWORD
     ========================================================= */
  const resetForm = document.getElementById("resetForm");

  if (resetForm) {
    resetForm.addEventListener("submit", async (e) => {
      e.preventDefault();

      const btn = document.getElementById("resetBtn");
      const msg = document.getElementById("message");
      const email = document.getElementById("resetEmail").value.trim();

      if (!isValidEmail(email)) {
        showMessage(msg, "Please enter a valid email address");
        return;
      }

      setLoading(btn, true);

      try {
        const res = await post(`${API_BASE}/forgot-password`, { email });
        showMessage(msg, res.message, res.status);

        if (res.status === "success") {
          localStorage.setItem("email", email);
          location.href = "reset-password.html";
        }
      } catch {
        showMessage(msg, "Server error");
      } finally {
        setLoading(btn, false);
      }
    });
  }

  /* =========================================================
     DELETE ACCOUNT
     ========================================================= */
  const deleteBtn = document.getElementById("deleteAccountBtn");
  const modal = document.getElementById("deleteModal");
  const cancelBtn = document.getElementById("cancelDeleteBtn");
  const confirmBtn = document.getElementById("confirmDeleteBtn");

  if (deleteBtn && modal) {
    deleteBtn.addEventListener("click", () => {
      modal.style.display = "flex";
    });
  }

  if (cancelBtn) {
    cancelBtn.addEventListener("click", () => {
      modal.style.display = "none";
    });
  }

  if (confirmBtn) {
    confirmBtn.addEventListener("click", async () => {

      const token = localStorage.getItem("token");
      const msg = document.getElementById("message");

      if (!token) {
        showMessage(msg, "Session expired. Please login again.");
        handleUnauthorized();
        return;
      }

      try {
        const res = await fetch(`${API_BASE}/delete-account`, {
          method: "POST",
          headers: {
            "Authorization": "Bearer " + token
          }
        });

        if (res.status === 401) {
          handleUnauthorized();
          return;
        }

        const data = await res.json();
        showMessage(msg, data.message, data.status);

      } catch {
        showMessage(msg, "Server error. Please try again.");
      } finally {
        localStorage.clear();
        modal.style.display = "none";
        setTimeout(() => window.location.replace("login.html"), 1200);
      }
    });
  }
});

/* =========================================================
   OTP INPUT UX
   ========================================================= */
function setupOtpInputs() {
  const inputs = document.querySelectorAll(".otp-input");
  const verifyBtn = document.getElementById("verifyBtn");

  function checkComplete() {
    verifyBtn.disabled = [...inputs].some(i => !i.value);
  }

  inputs.forEach((input, i) => {
    input.addEventListener("input", () => {
      if (input.value && i < inputs.length - 1) {
        inputs[i + 1].focus();
      }
      checkComplete();
    });

    input.addEventListener("keydown", e => {
      if (e.key === "Backspace" && !input.value && i > 0) {
        inputs[i - 1].focus();
      }
    });
  });

  document.addEventListener("paste", e => {
    const data = e.clipboardData.getData("text");
    if (/^\d{6}$/.test(data)) {
      inputs.forEach((input, i) => input.value = data[i]);
      checkComplete();
    }
  });
}

/* =========================================================
   RESET PASSWORD
   ========================================================= */

const newPasswordForm = document.getElementById("newPasswordForm");

if (newPasswordForm) {
  newPasswordForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    const btn = document.getElementById("newPasswordBtn");
    const msg = document.getElementById("message");

    const email = localStorage.getItem("email");
    const otp = document.getElementById("resetOtp").value;
    const password = document.getElementById("newPassword").value;

    if (!password) {
      showMessage(msg, "Password cannot be empty");
      return;
    }

    if (!isStrongPassword(password)) {
      showMessage(
        msg,
        "Password must contain at least one letter, one number, one special character and be at least 6 characters long"
      );
      return;
    }

    if (!email) {
      showMessage(msg, "Session expired. Please try again.");
      return;
    }

    setLoading(btn, true);

    try {
      const res = await fetch("http://localhost:8080/api/auth/reset-password", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({
          email,
          otp,
          password
        })
      });

      const data = await res.json(); // ✅ FIX

      showMessage(msg, data.message, data.status);

      if (res.ok && data.status === "success") {
        localStorage.removeItem("email");
        setTimeout(() => {
          location.href = "login.html";
        }, 1500);
      }

    } catch (err) {
      showMessage(msg, "Server error");
    } finally {
      setLoading(btn, false);
    }
  });
}


/* =========================================================
   PASSWORD WRAPPER
   ========================================================= */

document.addEventListener("DOMContentLoaded", () => {
  const toggles = document.querySelectorAll(".toggle-password");

  toggles.forEach(toggle => {
    const inputId = toggle.dataset.target;
    const passwordInput = document.getElementById(inputId);

    if (!passwordInput) return;

    let hideTimeout;

    toggle.addEventListener("click", () => {
      const isHidden = passwordInput.type === "password";

      clearTimeout(hideTimeout);

      if (isHidden) {
        passwordInput.type = "text";
        toggle.innerText = "Hide";

        hideTimeout = setTimeout(() => {
          passwordInput.type = "password";
          toggle.innerText = "Show";
        }, 5000);
      } else {
        passwordInput.type = "password";
        toggle.innerText = "Show";
      }
    });
  });
});
