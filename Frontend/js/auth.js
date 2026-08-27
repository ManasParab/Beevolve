(() => {
  "use strict";

  // Supabase is intentionally NOT initialized in the browser.
  // All Supabase credentials live in Backend/.env.
  const API_BASE = "http://127.0.0.1:8000";
  const $ = (id) => document.getElementById(id);
  const messageBox = $("auth-message");
  const messageCopy = messageBox?.querySelector(".toast-copy");
  const dismissButton = messageBox?.querySelector(".toast-dismiss");
  let messageTimer;

  function showMessage(message, type = "info") {
    if (!messageBox) return;
    window.clearTimeout(messageTimer);
    if (!message) {
      messageBox.hidden = true;
      return;
    }
    if (messageCopy) messageCopy.textContent = message;
    messageBox.className = `auth-message ${type}`;
    messageBox.setAttribute("role", type === "error" ? "alert" : "status");
    messageBox.hidden = false;
    messageTimer = window.setTimeout(() => {
      messageBox.hidden = true;
    }, type === "success" ? 7000 : 5000);
  }

  dismissButton?.addEventListener("click", () => {
    window.clearTimeout(messageTimer);
    messageBox.hidden = true;
  });

  function setLoading(form, loading, loadingText) {
    const button = form?.querySelector(".btn-primary");
    if (!button) return;
    if (loading) {
      button.dataset.originalText = button.innerHTML;
      button.innerHTML = loadingText;
      button.disabled = true;
    } else {
      button.innerHTML = button.dataset.originalText || button.innerHTML;
      button.disabled = false;
    }
  }

  function normalizeMobile(value) {
    return value.replace(/[^\d+]/g, "").trim();
  }

  function validatePassword(password) {
    if (password.length < 8) return "Use at least 8 characters.";
    if (!/[A-Za-z]/.test(password)) return "Include at least one letter.";
    if (!/[0-9]/.test(password)) return "Include at least one number.";
    if (!/[^A-Za-z0-9]/.test(password)) return "Include at least one symbol.";
    return "";
  }

  function friendlyError(error) {
    const msg = String(error?.message || error || "").toLowerCase();
    if (msg.includes("already exists") || msg.includes("already registered")) {
      return "An account with this email already exists. Please sign in.";
    }
    if (msg.includes("invalid login credentials")) return "Incorrect email or password.";
    if (msg.includes("email not confirmed")) return "Please verify your email before signing in.";
    if (msg.includes("rate limit")) return "Too many email attempts. Please wait and try again.";
    if (msg.includes("failed to fetch")) return "Unable to connect to the backend. Make sure FastAPI is running.";
    return error?.message || "Something went wrong. Please try again.";
  }

  async function api(path, options = {}) {
    const response = await fetch(`${API_BASE}${path}`, {
      credentials: "include",
      ...options,
      headers: {
        ...(options.body ? { "Content-Type": "application/json" } : {}),
        ...(options.headers || {})
      }
    });

    let body = {};
    try { body = await response.json(); } catch (_) {}

    if (!response.ok) {
      const err = new Error(
        typeof body.detail === "string" ? body.detail : "Request failed."
      );
      err.status = response.status;
      throw err;
    }

    return body;
  }

  // ------------------------------------------------------------
  // Tabs / UI
  // ------------------------------------------------------------
  const tabs = $("tabs");
  const tabBtns = tabs ? tabs.querySelectorAll(".tab-btn") : [];
  const panelLogin = $("panel-login");
  const panelRegister = $("panel-register");
  const loginForm = $("login-form");
  const registerForm = $("register-form");

  function setMode(mode) {
    const isRegister = mode === "register";
    if (tabs) tabs.classList.toggle("mode-register", isRegister);
    tabBtns.forEach(b => b.classList.toggle("active", b.dataset.tab === mode));
    if (panelLogin) panelLogin.style.display = isRegister ? "none" : "block";
    if (panelRegister) panelRegister.style.display = isRegister ? "block" : "none";
    if (loginForm) loginForm.classList.toggle("active", !isRegister);
    if (registerForm) registerForm.classList.toggle("active", isRegister);
    showMessage("");
  }

  if (panelRegister) panelRegister.style.display = "none";
  tabBtns.forEach(btn => btn.addEventListener("click", () => setMode(btn.dataset.tab)));

  document.querySelectorAll("[data-switch]").forEach(el => {
    el.addEventListener("click", (e) => {
      e.preventDefault();
      setMode(el.dataset.switch);
    });
  });

  // Password visibility
  document.querySelectorAll(".toggle-visibility").forEach(btn => {
    btn.addEventListener("click", () => {
      const input = btn.previousElementSibling;
      if (!input) return;
      const showing = input.type === "text";
      input.type = showing ? "password" : "text";
      btn.setAttribute("aria-label", showing ? "Show password" : "Hide password");
      const svg = btn.querySelector("svg");
      if (svg) {
        svg.innerHTML = showing
          ? '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/>'
          : '<path d="M3 3l18 18"/><path d="M10.6 5.1A9.9 9.9 0 0 1 12 5c6.4 0 10 7 10 7a17.6 17.6 0 0 1-3.4 4.4M6.7 6.7C4 8.4 2 12 2 12s3.6 7 10 7c1.4 0 2.6-.3 3.7-.8M9.9 9.9a3 3 0 0 0 4.2 4.2"/>';
      }
    });
  });

  // Password strength
  const regPass = $("reg-pass");
  const confirmPass = $("reg-confirm-pass");
  const meterBars = document.querySelectorAll(".password-meter i");
  const meterColors = ["#d9704f", "#e8a33d", "#e8a33d", "#7ea678"];

  function updateConfirmHint() {
    const hint = $("confirm-password-hint");
    if (!hint || !confirmPass || !regPass) return;
    if (!confirmPass.value) {
      hint.textContent = "";
      hint.className = "hint";
      return;
    }
    if (confirmPass.value === regPass.value) {
      hint.textContent = "Passwords match.";
      hint.className = "hint success";
    } else {
      hint.textContent = "Passwords do not match.";
      hint.className = "hint error";
    }
  }

  regPass?.addEventListener("input", () => {
    const value = regPass.value;
    let score = 0;
    if (value.length >= 8) score++;
    if (/[0-9]/.test(value)) score++;
    if (/[^A-Za-z0-9]/.test(value)) score++;
    if (/[A-Z]/.test(value) && /[a-z]/.test(value)) score++;
    meterBars.forEach((bar, i) => {
      bar.style.background = i < score ? meterColors[score - 1] : "var(--border)";
    });
    updateConfirmHint();
  });
  confirmPass?.addEventListener("input", updateConfirmHint);

  // ------------------------------------------------------------
  // Registration -> FastAPI -> Supabase
  // ------------------------------------------------------------
  registerForm?.addEventListener("submit", async (e) => {
    e.preventDefault();
    showMessage("");

    const name = $("reg-name")?.value.trim();
    const email = $("reg-email")?.value.trim().toLowerCase();
    const mobile = normalizeMobile($("reg-mobile")?.value || "");
    const password = $("reg-pass")?.value || "";
    const confirm = $("reg-confirm-pass")?.value || "";
    const terms = registerForm.querySelector('input[type="checkbox"][required]')?.checked;

    if (!name || name.length < 2) return showMessage("Please enter your full name.", "error");
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return showMessage("Please enter a valid email address.", "error");
    if (mobile.replace(/\D/g, "").length < 10) return showMessage("Please enter a valid mobile number.", "error");

    const passwordError = validatePassword(password);
    if (passwordError) return showMessage(passwordError, "error");
    if (password !== confirm) return showMessage("Passwords do not match.", "error");
    if (!terms) return showMessage("Please accept the terms and privacy policy.", "error");

    setLoading(registerForm, true, "Creating account…");
    try {
      const result = await api("/api/auth/register", {
        method: "POST",
        body: JSON.stringify({
          name,
          email,
          mobile,
          password
        })
      });

      // First switch to Login
      setMode("login");

      // Automatically fill the registered email
      if ($("login-email")) {
        $("login-email").value = email;
      }

      // Show success message after switching to Login
      showMessage(
        "Account created successfully! Please check your email to verify your account before logging in.",
        "success"
      );

    } catch (error) {
      const errorMessage = String(error?.message || "").toLowerCase();
      const accountExists = error?.status === 409
        || errorMessage.includes("already exists")
        || errorMessage.includes("already registered");

      if (accountExists) {
        setMode("login");
        if ($("login-email")) $("login-email").value = email;
        showMessage("This account already exists. Please log in.", "info");
      } else {
        showMessage(friendlyError(error), "error");
      }

    } finally {
      setLoading(
        registerForm,
        false
      );
    }
  });

  // ------------------------------------------------------------
  // Login -> FastAPI -> Supabase. Tokens stay in HttpOnly cookies.
  // ------------------------------------------------------------
  loginForm?.addEventListener("submit", async (e) => {
    e.preventDefault();
    showMessage("");

    const email = $("login-email")?.value.trim().toLowerCase();
    const password = $("login-pass")?.value || "";

    if (!email || !password) return showMessage("Enter your email and password.", "error");

    setLoading(loginForm, true, "Signing in…");

    try {
      await api("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({ email, password })
      });

      showMessage("Signed in successfully. Redirecting…", "success");
      window.location.href = "dashboard.html";
    } catch (error) {
      showMessage(friendlyError(error), "error");
    } finally {
      setLoading(loginForm, false);
    }
  });

  // Forgot password
  $("forgot-password")?.addEventListener("click", async (e) => {
    e.preventDefault();
    const email = $("login-email")?.value.trim().toLowerCase();
    if (!email) return showMessage("Enter your email first, then click Forgot password.", "error");

    try {
      const result = await api("/api/auth/forgot-password", {
        method: "POST",
        body: JSON.stringify({ email })
      });
      showMessage(result.message, "success");
    } catch (error) {
      showMessage(friendlyError(error), "error");
    }
  });

  // OAuth buttons
  async function startOAuth(provider) {
    try {
      const result = await api(`/api/auth/oauth/${provider}`);
      window.location.href = result.url;
    } catch (error) {
      showMessage(friendlyError(error), "error");
    }
  }

  document.querySelectorAll(".social-google").forEach(btn => {
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      startOAuth("google");
    });
  });

  document.querySelectorAll(".social-btn").forEach(btn => {
    if (btn.classList.contains("social-google")) return;
    if (btn.textContent.toLowerCase().includes("microsoft")) {
      btn.addEventListener("click", (e) => {
        e.preventDefault();
        startOAuth("microsoft");
      });
    }
  });

  // Terms/privacy links should not silently jump to the top.
  document.querySelectorAll(".check .link-amber").forEach(link => {
    link.addEventListener("click", (e) => {
      e.preventDefault();
      showMessage("Terms and privacy policy links can be connected to your final legal pages.", "info");
    });
  });

  // If already authenticated, go to dashboard.
  (async () => {
    try {
      const result = await api("/api/auth/me");
      if (result.authenticated && !window.location.search.includes("reset=1")) {
        window.location.href = "dashboard.html";
      }
    } catch (_) {}
  })();

  // Testimonial rotator
  const quotes = document.querySelectorAll(".quote");
  const dots = document.querySelectorAll(".dots span");
  let qIndex = 0;
  if (quotes.length > 1) {
    setInterval(() => {
      quotes[qIndex]?.classList.remove("active");
      dots[qIndex]?.classList.remove("active");
      qIndex = (qIndex + 1) % quotes.length;
      quotes[qIndex]?.classList.add("active");
      dots[qIndex]?.classList.add("active");
    }, 5000);
  }
})();
