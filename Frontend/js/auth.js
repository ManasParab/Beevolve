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


  // ============================================================
  // MESSAGE
  // ============================================================

  function showMessage(message, type = "info") {

    if (!messageBox) return;

    window.clearTimeout(messageTimer);

    if (!message) {
      messageBox.hidden = true;
      return;
    }

    if (messageCopy) {
      messageCopy.textContent = message;
    }

    messageBox.className = `auth-message ${type}`;

    messageBox.setAttribute(
      "role",
      type === "error" ? "alert" : "status"
    );

    messageBox.hidden = false;

    messageTimer = window.setTimeout(() => {
      messageBox.hidden = true;
    }, type === "success" ? 7000 : 5000);
  }


  dismissButton?.addEventListener("click", () => {

    window.clearTimeout(messageTimer);

    messageBox.hidden = true;

  });


  // ============================================================
  // LOADING
  // ============================================================

  function setLoading(form, loading, loadingText) {

    const button = form?.querySelector(".btn-primary");

    if (!button) return;

    if (loading) {

      button.dataset.originalText = button.innerHTML;

      button.innerHTML = loadingText;

      button.disabled = true;

    } else {

      button.innerHTML =
        button.dataset.originalText || button.innerHTML;

      button.disabled = false;

    }
  }


  // ============================================================
  // MOBILE NORMALIZATION
  // ============================================================

  function normalizeMobile(value) {

    let cleaned = value
      .replace(/[^\d+]/g, "")
      .trim();

    // If they didn't type a country code,
    // assume India (+91).
    if (
      cleaned &&
      !cleaned.startsWith("+")
    ) {
      cleaned = "+91" + cleaned;
    }

    return cleaned;
  }


  // ============================================================
  // PASSWORD VALIDATION
  // ============================================================

  function validatePassword(password) {

    if (password.length < 8) {
      return "Use at least 8 characters.";
    }

    if (!/[A-Za-z]/.test(password)) {
      return "Include at least one letter.";
    }

    if (!/[0-9]/.test(password)) {
      return "Include at least one number.";
    }

    if (!/[^A-Za-z0-9]/.test(password)) {
      return "Include at least one symbol.";
    }

    return "";
  }


  // ============================================================
  // FRIENDLY ERRORS
  // ============================================================

  function friendlyError(error) {

    const msg = String(
      error?.message || error || ""
    ).toLowerCase();


    if (
      msg.includes("already exists") ||
      msg.includes("already registered")
    ) {
      return "An account with this email already exists. Please sign in.";
    }


    if (
      msg.includes("invalid login credentials")
    ) {
      return "Incorrect email or password.";
    }


    if (
      msg.includes("email not confirmed")
    ) {
      return "Please verify your email before signing in.";
    }


    if (
      msg.includes("rate limit")
    ) {
      return "Too many attempts. Please wait and try again.";
    }


    if (
      msg.includes("failed to fetch")
    ) {
      return "Unable to connect to the backend. Make sure FastAPI is running.";
    }


    return (
      error?.message ||
      "Something went wrong. Please try again."
    );
  }


  // ============================================================
  // API HELPER
  // ============================================================

  async function api(path, options = {}) {

    const response = await fetch(
      `${API_BASE}${path}`,
      {
        credentials: "include",

        ...options,

        headers: {

          ...(options.body
            ? {
                "Content-Type":
                  "application/json"
              }
            : {}),

          ...(options.headers || {})
        }
      }
    );


    let body = {};

    try {

      body = await response.json();

    } catch (_) {}


    if (!response.ok) {

      const err = new Error(
        typeof body.detail === "string"
          ? body.detail
          : "Request failed."
      );

      err.status = response.status;

      throw err;
    }


    return body;
  }


  // ============================================================
  // TABS / UI
  // ============================================================

  const tabs = $("tabs");

  const tabBtns =
    tabs
      ? tabs.querySelectorAll(".tab-btn")
      : [];

  const panelLogin = $("panel-login");
  const panelRegister = $("panel-register");
  const panelVerify = $("panel-verify");

  const loginForm = $("login-form");
  const registerForm = $("register-form");


  function setMode(mode) {

    const isRegister =
      mode === "register";


    if (tabs) {

      tabs.style.display = "";

      tabs.classList.toggle(
        "mode-register",
        isRegister
      );
    }


    tabBtns.forEach((button) => {

      button.classList.toggle(
        "active",
        button.dataset.tab === mode
      );

    });


    if (panelLogin) {

      panelLogin.style.display =
        isRegister
          ? "none"
          : "block";
    }


    if (panelRegister) {

      panelRegister.style.display =
        isRegister
          ? "block"
          : "none";
    }


    if (panelVerify) {

      panelVerify.style.display =
        "none";
    }


    if (loginForm) {

      loginForm.classList.toggle(
        "active",
        !isRegister
      );
    }


    if (registerForm) {

      registerForm.classList.toggle(
        "active",
        isRegister
      );
    }


    showMessage("");
  }


  // ============================================================
  // EMAIL OTP VERIFICATION
  // ============================================================

  const verifyChoiceEmailBtn =
    $("verify-choice-email");

  const verifyResendHint =
    $("verify-resend-hint");

  const verifyResendLink =
    $("verify-resend");


  let pendingSignup = {

    userId: null,

    email: null,

    mobile: null

  };


  // ------------------------------------------------------------
  // Show verification panel
  // ------------------------------------------------------------

  function showVerifyPanel({
    userId,
    email,
    mobile
  }) {

    pendingSignup = {

      userId,

      email,

      mobile

    };


    if (tabs) {

      tabs.style.display = "none";
    }


    if (panelLogin) {

      panelLogin.style.display = "none";
    }


    if (panelRegister) {

      panelRegister.style.display = "none";
    }


    if (panelVerify) {

      panelVerify.style.display = "block";
    }


    if (verifyResendHint) {

      verifyResendHint.style.display =
        "none";
    }


    // Remove an old OTP box if one exists.
    const oldOtpArea =
      $("email-otp-area");

    if (oldOtpArea) {

      oldOtpArea.remove();
    }


    showMessage("");
  }


  // ------------------------------------------------------------
  // Send Email OTP
  // ------------------------------------------------------------

  async function sendEmailOtp() {

    if (
      !pendingSignup.email ||
      !pendingSignup.userId
    ) {

      showMessage(
        "Something went wrong. Please create your account again.",
        "error"
      );

      return;
    }


    try {

      verifyChoiceEmailBtn.disabled = true;


      await api(
        "/api/auth/email-otp/send",
        {
          method: "POST",

          body: JSON.stringify({

            email:
              pendingSignup.email,

            user_id:
              pendingSignup.userId

          })

        }
      );


      if (verifyResendHint) {

        verifyResendHint.style.display =
          "block";
      }


      showMessage(
        "A 6-character verification code has been sent to your email.",
        "success"
      );


      showOtpInput();


    } catch (error) {

      showMessage(
        friendlyError(error),
        "error"
      );


    } finally {

      verifyChoiceEmailBtn.disabled =
        false;

    }
  }


  // ------------------------------------------------------------
  // Create OTP input box
  // ------------------------------------------------------------

  function showOtpInput() {

    const existing =
      $("email-otp-area");


    // If the box already exists,
    // just show it again.
    if (existing) {

      existing.style.display =
        "block";

      $("email-otp-code")?.focus();

      return;
    }


    const area =
      document.createElement("div");


    area.id =
      "email-otp-area";


    area.style.marginTop =
      "20px";


    area.innerHTML = `

      <div class="field">

        <label for="email-otp-code">
          Enter the 6-character code
        </label>


        <div class="input-wrap">

          <input
            type="text"
            id="email-otp-code"
            maxlength="6"
            autocomplete="one-time-code"
            inputmode="text"
            placeholder="A7K29P"
            style="text-transform:uppercase;"
          >

        </div>


        <div class="hint">
          The code expires in 5 minutes.
        </div>

      </div>


      <button
        type="button"
        class="btn-primary"
        id="verify-email-otp-btn"
        style="width:100%;"
      >

        Verify email

        <svg
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="2"
          stroke-linecap="round"
        >

          <path d="M5 12h14"/>

          <path d="M13 5l7 7-7 7"/>

        </svg>

      </button>

    `;


    const row =
      document.getElementById(
        "verify-choice-row"
      );


    if (
      row &&
      row.parentNode
    ) {

      row.parentNode.insertBefore(
        area,
        row.nextSibling
      );
    }


    $("email-otp-code")?.focus();


    // ----------------------------------------------------------
    // Verify button
    // ----------------------------------------------------------

    $("verify-email-otp-btn")
      ?.addEventListener(
        "click",
        verifyEmailOtp
      );


    // ----------------------------------------------------------
    // OTP input formatting
    // ----------------------------------------------------------

    $("email-otp-code")
      ?.addEventListener(
        "input",
        (event) => {

          event.target.value =
            event.target.value

              .replace(
                /[^a-zA-Z0-9]/g,
                ""
              )

              .toUpperCase()

              .slice(0, 6);

        }
      );


    // ----------------------------------------------------------
    // Allow pressing Enter
    // ----------------------------------------------------------

    $("email-otp-code")
      ?.addEventListener(
        "keydown",
        (event) => {

          if (
            event.key === "Enter"
          ) {

            event.preventDefault();

            verifyEmailOtp();

          }

        }
      );
  }


  // ------------------------------------------------------------
  // Verify Email OTP
  // ------------------------------------------------------------

  async function verifyEmailOtp() {

    const input =
      $("email-otp-code");

    const button =
      $("verify-email-otp-btn");


    const code =
      input?.value
        .trim()
        .toUpperCase();


    // ----------------------------------------------------------
    // Validate OTP
    // ----------------------------------------------------------

    if (!code) {

      showMessage(
        "Please enter the verification code.",
        "error"
      );

      return;
    }


    if (
      !/^[A-Z0-9]{6}$/.test(code)
    ) {

      showMessage(
        "Please enter the 6-character verification code.",
        "error"
      );

      return;
    }


    if (
      !pendingSignup.email ||
      !pendingSignup.userId
    ) {

      showMessage(
        "Something went wrong. Please create your account again.",
        "error"
      );

      return;
    }


    try {

      button.disabled = true;

      button.textContent =
        "Verifying…";


      const result =
        await api(
          "/api/auth/email-otp/verify",
          {

            method: "POST",

            body: JSON.stringify({

              email:
                pendingSignup.email,

              user_id:
                pendingSignup.userId,

              code:
                code

            })

          }
        );


      showMessage(
        result.message ||
          "Email verified successfully.",
        "success"
      );


      // --------------------------------------------------------
      // Move user to login
      // --------------------------------------------------------

      setTimeout(() => {

        setMode("login");


        if ($("login-email")) {

          $("login-email").value =
            pendingSignup.email;
        }


      }, 800);


    } catch (error) {

      showMessage(
        friendlyError(error),
        "error"
      );


    } finally {

      button.disabled = false;


      button.innerHTML = `

        Verify email

        <svg
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="2"
          stroke-linecap="round"
        >

          <path d="M5 12h14"/>

          <path d="M13 5l7 7-7 7"/>

        </svg>

      `;

    }
  }


  // ------------------------------------------------------------
  // Verify with Email button
  // ------------------------------------------------------------

  verifyChoiceEmailBtn
    ?.addEventListener(
      "click",
      sendEmailOtp
    );


  // ------------------------------------------------------------
  // Resend OTP
  // ------------------------------------------------------------

  verifyResendLink
    ?.addEventListener(
      "click",
      async (event) => {

        event.preventDefault();

        await sendEmailOtp();

      }
    );


  // ============================================================
  // INITIAL UI
  // ============================================================

  if (panelRegister) {

    panelRegister.style.display =
      "none";
  }


  tabBtns.forEach((button) => {

    button.addEventListener(
      "click",
      () => {

        setMode(
          button.dataset.tab
        );

      }
    );

  });


  document
    .querySelectorAll("[data-switch]")
    .forEach((element) => {

      element.addEventListener(
        "click",
        (event) => {

          event.preventDefault();

          setMode(
            element.dataset.switch
          );

        }
      );

    });


  // ============================================================
  // PASSWORD VISIBILITY
  // ============================================================

  document
    .querySelectorAll(".toggle-visibility")
    .forEach((button) => {

      button.addEventListener(
        "click",
        () => {

          const input =
            button.previousElementSibling;

          if (!input) return;


          const showing =
            input.type === "text";


          input.type =
            showing
              ? "password"
              : "text";


          button.setAttribute(
            "aria-label",
            showing
              ? "Show password"
              : "Hide password"
          );


          const svg =
            button.querySelector("svg");


          if (svg) {

            svg.innerHTML =
              showing

                ? '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/>'

                : '<path d="M3 3l18 18"/><path d="M10.6 5.1A9.9 9.9 0 0 1 12 5c6.4 0 10 7 10 7a17.6 17.6 0 0 1-3.4 4.4M6.7 6.7C4 8.4 2 12 2 12s3.6 7 10 7c1.4 0 2.6-.3 3.7-.8M9.9 9.9a3 3 0 0 0 4.2 4.2"/>';

          }

        }
      );

    });


  // ============================================================
  // PASSWORD STRENGTH
  // ============================================================

  const regPass =
    $("reg-pass");

  const confirmPass =
    $("reg-confirm-pass");

  const meterBars =
    document.querySelectorAll(
      ".password-meter i"
    );

  const meterColors = [
    "#d9704f",
    "#e8a33d",
    "#e8a33d",
    "#7ea678"
  ];


  function updateConfirmHint() {

    const hint =
      $("confirm-password-hint");


    if (
      !hint ||
      !confirmPass ||
      !regPass
    ) {
      return;
    }


    if (!confirmPass.value) {

      hint.textContent = "";

      hint.className =
        "hint";

      return;
    }


    if (
      confirmPass.value ===
      regPass.value
    ) {

      hint.textContent =
        "Passwords match.";

      hint.className =
        "hint success";

    } else {

      hint.textContent =
        "Passwords do not match.";

      hint.className =
        "hint error";

    }
  }


  regPass?.addEventListener(
    "input",
    () => {

      const value =
        regPass.value;

      let score = 0;


      if (value.length >= 8) {
        score++;
      }


      if (/[0-9]/.test(value)) {
        score++;
      }


      if (/[^A-Za-z0-9]/.test(value)) {
        score++;
      }


      if (
        /[A-Z]/.test(value) &&
        /[a-z]/.test(value)
      ) {
        score++;
      }


      meterBars.forEach(
        (bar, i) => {

          bar.style.background =
            i < score
              ? meterColors[score - 1]
              : "var(--border)";

        }
      );


      updateConfirmHint();

    }
  );


  confirmPass?.addEventListener(
    "input",
    updateConfirmHint
  );


  // ============================================================
  // REGISTRATION
  // ============================================================

  registerForm?.addEventListener(
    "submit",
    async (e) => {

      e.preventDefault();

      showMessage("");


      const name =
        $("reg-name")
          ?.value
          .trim();


      const email =
        $("reg-email")
          ?.value
          .trim()
          .toLowerCase();


      const mobile =
        normalizeMobile(
          $("reg-mobile")
            ?.value || ""
        );


      const password =
        $("reg-pass")
          ?.value || "";


      const confirm =
        $("reg-confirm-pass")
          ?.value || "";


      const terms =
        registerForm
          .querySelector(
            'input[type="checkbox"][required]'
          )
          ?.checked;


      // --------------------------------------------------------
      // Validation
      // --------------------------------------------------------

      if (
        !name ||
        name.length < 2
      ) {

        return showMessage(
          "Please enter your full name.",
          "error"
        );
      }


      if (
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
          email
        )
      ) {

        return showMessage(
          "Please enter a valid email address.",
          "error"
        );
      }


      if (
        mobile.replace(
          /\D/g,
          ""
        ).length < 10
      ) {

        return showMessage(
          "Please enter a valid mobile number.",
          "error"
        );
      }


      const passwordError =
        validatePassword(password);


      if (passwordError) {

        return showMessage(
          passwordError,
          "error"
        );
      }


      if (
        password !== confirm
      ) {

        return showMessage(
          "Passwords do not match.",
          "error"
        );
      }


      if (!terms) {

        return showMessage(
          "Please accept the terms and privacy policy.",
          "error"
        );
      }


      // --------------------------------------------------------
      // Create account
      // --------------------------------------------------------

      setLoading(
        registerForm,
        true,
        "Creating account…"
      );


      try {

        const result =
          await api(
            "/api/auth/register",
            {

              method: "POST",

              body: JSON.stringify({

                name,

                email,

                mobile,

                password

              })

            }
          );


        // Automatically fill the registered email
        // in case user returns to Login.
        if ($("login-email")) {

          $("login-email").value =
            email;
        }


        // Show email verification screen.
        showVerifyPanel({

          userId:
            result.user_id,

          email,

          mobile

        });


      } catch (error) {

        const errorMessage =
          String(
            error?.message || ""
          ).toLowerCase();


        const accountExists =
          error?.status === 409 ||
          errorMessage.includes(
            "already exists"
          ) ||
          errorMessage.includes(
            "already registered"
          );


        if (accountExists) {

          setMode("login");


          if ($("login-email")) {

            $("login-email").value =
              email;
          }


          showMessage(
            "This account already exists. Please log in.",
            "info"
          );


        } else {

          showMessage(
            friendlyError(error),
            "error"
          );

        }


      } finally {

        setLoading(
          registerForm,
          false
        );

      }

    }
  );


  // ============================================================
  // LOGIN
  // ============================================================

  loginForm?.addEventListener(
    "submit",
    async (e) => {

      e.preventDefault();

      showMessage("");


      const email =
        $("login-email")
          ?.value
          .trim()
          .toLowerCase();


      const password =
        $("login-pass")
          ?.value || "";


      if (
        !email ||
        !password
      ) {

        return showMessage(
          "Enter your email and password.",
          "error"
        );
      }


      setLoading(
        loginForm,
        true,
        "Signing in…"
      );


      try {

        await api(
          "/api/auth/login",
          {

            method: "POST",

            body: JSON.stringify({
              email,
              password
            })

          }
        );


        showMessage(
          "Signed in successfully. Redirecting…",
          "success"
        );


        window.location.href =
          "dashboard.html";


      } catch (error) {

        showMessage(
          friendlyError(error),
          "error"
        );


      } finally {

        setLoading(
          loginForm,
          false
        );

      }

    }
  );


  // ============================================================
  // FORGOT PASSWORD
  // ============================================================

  $("forgot-password")
    ?.addEventListener(
      "click",
      async (e) => {

        e.preventDefault();


        const email =
          $("login-email")
            ?.value
            .trim()
            .toLowerCase();


        if (!email) {

          return showMessage(
            "Enter your email first, then click Forgot password.",
            "error"
          );
        }


        try {

          const result =
            await api(
              "/api/auth/forgot-password",
              {

                method: "POST",

                body: JSON.stringify({
                  email
                })

              }
            );


          showMessage(
            result.message,
            "success"
          );


        } catch (error) {

          showMessage(
            friendlyError(error),
            "error"
          );

        }

      }
    );


  // ============================================================
  // OAUTH
  // ============================================================

  async function startOAuth(
    provider
  ) {

    try {

      const result =
        await api(
          `/api/auth/oauth/${provider}`
        );


      window.location.href =
        result.url;


    } catch (error) {

      showMessage(
        friendlyError(error),
        "error"
      );

    }
  }


  // Google
  document
    .querySelectorAll(".social-google")
    .forEach((button) => {

      button.addEventListener(
        "click",
        (e) => {

          e.preventDefault();

          startOAuth("google");

        }
      );

    });


  // Microsoft
  document
    .querySelectorAll(".social-btn")
    .forEach((button) => {

      if (
        button.classList.contains(
          "social-google"
        )
      ) {
        return;
      }


      if (
        button.textContent
          .toLowerCase()
          .includes("microsoft")
      ) {

        button.addEventListener(
          "click",
          (e) => {

            e.preventDefault();

            startOAuth("microsoft");

          }
        );

      }

    });


  // ============================================================
  // TERMS / PRIVACY
  // ============================================================

  document
    .querySelectorAll(
      ".check .link-amber"
    )
    .forEach((link) => {

      link.addEventListener(
        "click",
        (e) => {

          e.preventDefault();

          showMessage(
            "Terms and privacy policy links can be connected to your final legal pages.",
            "info"
          );

        }
      );

    });


  // ============================================================
  // AUTHENTICATION CHECK
  // ============================================================

  // If the user already has a valid session,
  // send them to the dashboard.
  //
  // We no longer handle a Supabase email
  // confirmation URL here because email
  // verification is now done using our custom OTP.

  (async () => {

    try {

      const result =
        await api("/api/auth/me");


      if (
        result.authenticated &&
        !window.location.search.includes(
          "reset=1"
        )
      ) {

        window.location.href =
          "dashboard.html";

      }

    } catch (_) {}

  })();


  // ============================================================
  // TESTIMONIAL ROTATOR
  // ============================================================

  const quotes =
    document.querySelectorAll(
      ".quote"
    );

  const dots =
    document.querySelectorAll(
      ".dots span"
    );


  let qIndex = 0;


  if (quotes.length > 1) {

    setInterval(() => {

      quotes[qIndex]
        ?.classList
        .remove("active");


      dots[qIndex]
        ?.classList
        .remove("active");


      qIndex =
        (qIndex + 1) %
        quotes.length;


      quotes[qIndex]
        ?.classList
        .add("active");


      dots[qIndex]
        ?.classList
        .add("active");


    }, 5000);

  }

})();