(() => {
  const $ = id => document.getElementById(id);

  document.querySelectorAll('[data-password-toggle]').forEach(button => {
    button.addEventListener('click', () => {
      const input = $(button.dataset.passwordToggle);
      if (!input) return;

      const showPassword = input.type === 'password';
      input.type = showPassword ? 'text' : 'password';
      button.setAttribute(
        'aria-label',
        showPassword ? 'Hide password' : 'Show password'
      );
      button.setAttribute('aria-pressed', String(showPassword));

      const slash = button.querySelector('[data-eye-slash]');
      if (slash) slash.hidden = !showPassword;
    });
  });

  const PANELS = ['Start', 'Questions', 'Otp', 'Change', 'Done'];

  const STEP = {
    start: 0,
    questions: 1,
    otp: 2,
    change: 3,
    done: 3
  };

  function show(name) {
    PANELS.forEach(panel => {
      $('p' + panel).hidden = panel.toLowerCase() !== name;
    });

    [...$('steps').children].forEach((li, index) => {
      li.classList.toggle(
        'active',
        index === STEP[name] && name !== 'done'
      );

      li.classList.toggle(
        'done',
        index < STEP[name] || name === 'done'
      );
    });
  }

  function msg(el, text, ok = false) {
    el.textContent = text || '';
    el.className = 'msg' + (text ? (ok ? ' ok' : ' err') : '');
  }

  async function api(action, data = {}) {
    const fd = new FormData();

    fd.append('action', action);

    Object.entries(data).forEach(([key, value]) => {
      fd.append(key, value);
    });

    try {
      const res = await fetch('../php/forgot_api.php', {
        method: 'POST',
        body: fd,
        credentials: 'same-origin'
      });

      return await res.json();
    } catch (e) {
      return {
        success: false,
        message: 'Unable to connect. Please try again.'
      };
    }
  }

  const fmt = seconds =>
    Math.floor(seconds / 60) + ':' +
    String(seconds % 60).padStart(2, '0');

  // ---------- CAPTCHA ----------

  function refreshCaptcha() {
    $('captchaImage').src = '../php/captcha.php?t=' + Date.now();
    $('captcha').value = '';
  }

  // ---------- Step 1: Account ----------

  let startTimer = null;

  function lockStart(seconds) {
    clearInterval(startTimer);

    let left = Math.max(1, Number(seconds) || 10);

    const tick = () => {
      if (left <= 0) {
        clearInterval(startTimer);

        $('startBtn').disabled = false;
        $('startBtn').textContent = 'Continue';

        msg($('startMsg'), 'You can try again now.', true);
        return;
      }

      $('startBtn').disabled = true;
      $('startBtn').textContent = 'Cooldown (' + left + 's)';

      msg(
        $('startMsg'),
        'Too many failed attempts. Please wait ' + left + ' seconds.'
      );

      left--;
    };

    tick();
    startTimer = setInterval(tick, 1000);
  }

  function backToStart(r = {}) {
    stopOtp();
    clearInterval(startTimer);

    show('start');
    refreshCaptcha();

    if (r.lockedOut) {
      lockStart(r.remainingSeconds);
    } else {
      msg($('startMsg'), r.message || '');
    }
  }

  $('refreshCaptcha').addEventListener('click', refreshCaptcha);

  $('fStart').addEventListener('submit', async e => {
    e.preventDefault();

    msg($('startMsg'), '');

    const btn = $('startBtn');
    btn.disabled = true;
    btn.textContent = 'Checking...';

    const r = await api('start', {
      username: $('username').value.trim(),
      captcha: $('captcha').value.trim()
    });

    if (r.refreshCaptcha) {
      refreshCaptcha();
    }

    if (r.success) {
      btn.disabled = false;
      btn.textContent = 'Continue';

      apply(r);
      return;
    }

    if (r.lockedOut) {
      lockStart(r.remainingSeconds);
      return;
    }

    btn.disabled = false;
    btn.textContent = 'Continue';

    msg($('startMsg'), r.message);
  });

  // ---------- Step 2: Security Questions ----------

  function populateQuestions(questions) {
    const select = $('questionCode');

    select.innerHTML = '';

    const defaultOption = document.createElement('option');
    defaultOption.value = '';
    defaultOption.textContent = 'Select a security question';
    select.appendChild(defaultOption);

    if (!questions || typeof questions !== 'object') {
      return;
    }

    Object.entries(questions).forEach(([code, question]) => {
      const option = document.createElement('option');

      option.value = code;
      option.textContent = question;

      select.appendChild(option);
    });
  }

  $('fQ').addEventListener('submit', async e => {
    e.preventDefault();

    const questionCode = $('questionCode').value;
    const answer = $('answer').value.trim();
    const confirmAnswer = $('confirmAnswer').value.trim();

    msg($('qMsg'), '');

    if (!questionCode) {
      msg($('qMsg'), 'Please choose a security question.');
      return;
    }

    if (!answer || !confirmAnswer) {
      msg($('qMsg'), 'Please complete both answer fields.');
      return;
    }

    // Answers must match before the server checks the stored answer.
    if (answer !== confirmAnswer) {
      msg($('qMsg'), 'Your answers do not match.');
      $('confirmAnswer').focus();
      return;
    }

    const btn = $('qBtn');

    btn.disabled = true;
    btn.textContent = 'Checking...';

    const r = await api('answer', {
      question_code: questionCode,
      answer: answer,
      confirm_answer: confirmAnswer
    });

    btn.disabled = false;
    btn.textContent = 'Continue';

    if (r.success) {
      apply(r);
      return;
    }

    if (r.restart) {
      backToStart(r);
      return;
    }

    // Keep the selected question and answers available for correction.
    msg($('qMsg'), r.message);
  });

  // ---------- Step 3: OTP Verification ----------

  let expiresAt = 0;
  let resendAt = 0;
  let lockAt = 0;
  let exhausted = false;
  let busy = false;
  let otpTimer = null;

  function startOtp(s) {
    const now = Date.now();

    expiresAt = now + (Number(s.expiresIn) || 0) * 1000;
    resendAt = now + (Number(s.resendIn) || 0) * 1000;
    lockAt = now + (Number(s.lockIn) || 0) * 1000;

    exhausted = !!s.exhausted;
    busy = false;

    $('otpCode').value = '';
    msg($('otpMsg'), '');

    clearInterval(otpTimer);

    tickOtp();
    otpTimer = setInterval(tickOtp, 500);

    $('otpCode').focus();
  }

  function stopOtp() {
    clearInterval(otpTimer);
  }

  function tickOtp() {
    const now = Date.now();

    const exp = Math.max(
      0,
      Math.ceil((expiresAt - now) / 1000)
    );

    const lock = Math.max(
      0,
      Math.ceil((lockAt - now) / 1000)
    );

    const rs = Math.max(
      0,
      Math.ceil((resendAt - now) / 1000)
    );

    const el = $('otpExpiry');

    el.textContent = exp > 0
      ? 'Code expires in ' + fmt(exp)
      : 'Code expired. Request a new one.';

    el.classList.toggle('warning', exp > 0 && exp <= 10);
    el.classList.toggle('expired', exp === 0);

    const canVerify = exp > 0 && lock === 0 && !exhausted;

    $('otpCode').disabled = !canVerify;
    $('verifyBtn').disabled = busy || !canVerify;

    if (!busy) {
      $('verifyBtn').textContent = lock > 0
        ? 'Locked (' + lock + 's)'
        : 'Verify and continue';

      $('resendBtn').textContent = (rs > 0 || lock > 0)
        ? 'Resend available in ' + Math.max(rs, lock) + 's'
        : 'Resend verification code';
    }

    $('resendBtn').disabled = busy || rs > 0 || lock > 0;
  }

  $('fOtp').addEventListener('submit', async e => {
    e.preventDefault();

    const code = $('otpCode').value.trim();

    if (!/^\d{6}$/.test(code)) {
      msg($('otpMsg'), 'Enter a valid six-digit code.');
      return;
    }

    busy = true;
    $('verifyBtn').textContent = 'Verifying...';

    tickOtp();

    const r = await api('verify_otp', {
      otp: code
    });

    busy = false;

    if (r.success) {
      apply(r);
      return;
    }

    if (r.restart) {
      backToStart(r);
      return;
    }

    if (r.lockedOut) {
      exhausted = true;

      lockAt = Date.now() +
        (Number(r.remainingSeconds) || 60) * 1000;

    } else if (r.needResend) {
      exhausted = true;
    }

    $('otpCode').value = '';

    msg($('otpMsg'), r.message);
    tickOtp();
  });

  $('resendBtn').addEventListener('click', async () => {
    busy = true;

    tickOtp();
    $('resendBtn').textContent = 'Sending...';

    const r = await api('resend_otp');

    busy = false;

    if (r.restart) {
      backToStart(r);
      return;
    }

    if (r.success) {
      startOtp({
        expiresIn: r.expiresIn,
        resendIn: r.resendIn,
        lockIn: 0,
        exhausted: false
      });

      msg($('otpMsg'), r.message, true);
      return;
    }

    if (r.lockedOut) {
      exhausted = true;

      lockAt = Date.now() +
        (Number(r.remainingSeconds) || 60) * 1000;

    } else if (r.remainingSeconds) {
      resendAt = Date.now() +
        Number(r.remainingSeconds) * 1000;
    }

    msg($('otpMsg'), r.message);
    tickOtp();
  });

  // ---------- Step 4: Password Change ----------

  // These are the same password requirements used during registration:
  // 8-64 characters and at least 3 of the 4 character categories.
  const RULES = [
    ['At least 8 characters', p => p.length >= 8],
    ['A lowercase letter', p => /[a-z]/.test(p)],
    ['An uppercase letter', p => /[A-Z]/.test(p)],
    ['A number', p => /[0-9]/.test(p)],
    ['A special character', p => /[^A-Za-z0-9]/.test(p)]
  ];

  RULES.forEach(([text]) => {
    const li = document.createElement('li');
    li.textContent = text;
    $('rules').appendChild(li);
  });

  function getPasswordStrength(password) {
    const categories = [
      /[a-z]/.test(password),
      /[A-Z]/.test(password),
      /[0-9]/.test(password),
      /[^A-Za-z0-9]/.test(password)
    ];

    const categoryCount = categories.filter(Boolean).length;

    if (password.length < 8 || password.length > 64 || categoryCount < 3) {
      return {
        level: 'Weak',
        accepted: false
      };
    }

    if (password.length >= 12 && categoryCount === 4) {
      return {
        level: 'Strong',
        accepted: true
      };
    }

    return {
      level: 'Medium',
      accepted: true
    };
  }

  function checkPassword() {
    const password = $('newPw').value;
    const confirmPassword = $('confirmPw').value;

    RULES.forEach(([, test], index) => {
      const passed = test(password);

      $('rules').children[index].classList.toggle('ok', passed);
    });

    const strength = getPasswordStrength(password);

    $('meterBar').className = 'strength-' +
      (password.length ? strength.level.toLowerCase() : 'empty');

    $('meterLabel').textContent = 'Strength: ' +
      (password.length ? strength.level : 'none');

    const passwordsMatch =
      password.length > 0 &&
      confirmPassword.length > 0 &&
      password === confirmPassword;

    const canChange =
      strength.accepted &&
      passwordsMatch;

    $('changeBtn').disabled = !canChange;

    if (confirmPassword && password !== confirmPassword) {
      msg($('changeMsg'), 'Mismatch Password');
    } else {
      msg($('changeMsg'), '');
    }

    return canChange;
  }

  $('newPw').addEventListener('input', checkPassword);
  $('confirmPw').addEventListener('input', checkPassword);

  $('fChange').addEventListener('submit', async e => {
    e.preventDefault();

    if (!checkPassword()) {
      if ($('newPw').value !== $('confirmPw').value) {
        msg($('changeMsg'), 'Mismatch Password');
      } else {
        msg(
          $('changeMsg'),
          'Your password is too weak. Use at least 3 character types.'
        );
      }

      return;
    }

    const btn = $('changeBtn');

    btn.disabled = true;
    btn.textContent = 'Saving...';

    const r = await api('change', {
      password: $('newPw').value,
      confirm: $('confirmPw').value
    });

    btn.textContent = 'Change password';

    if (r.success) {
      if (r.redirect) {
        $('loginLink').href = r.redirect;
      }

      $('doneMessage').textContent = 'Successfully Change Password';

      show('done');
      return;
    }

    if (r.restart) {
      backToStart(r);
      return;
    }

    // This displays server messages such as:
    // "You cannot reuse a recent password."
    // "Mismatch Password"
    msg($('changeMsg'), r.message);

    checkPassword();
  });

  // ---------- Shared Functions ----------

  document.querySelectorAll('[data-cancel]').forEach(button => {
    button.addEventListener('click', async () => {
      await api('cancel');

      backToStart({
        message: ''
      });
    });
  });

  function apply(r) {
    if (r.stage === 'questions') {
      populateQuestions(r.questions);

      $('answer').value = '';
      $('confirmAnswer').value = '';

      msg($('qMsg'), '');

      show('questions');

      $('questionCode').focus();

    } else if (r.stage === 'otp') {
      $('otpDesc').textContent =
        'A verification code was sent to ' + r.maskedEmail + '.';

      startOtp(r);
      show('otp');

    } else if (r.stage === 'change') {
      stopOtp();

      $('newPw').value = '';
      $('confirmPw').value = '';

      msg($('changeMsg'), '');

      checkPassword();
      show('change');

    } else {
      show('start');
      refreshCaptcha();
    }
  }

  // ---------- Initial Page State ----------

  // Resume the current reset step based on the server session.
  api('state').then(r => {
    if (r && r.success) {
      apply(r);
    } else {
      show('start');
      refreshCaptcha();
    }
  });
})();
