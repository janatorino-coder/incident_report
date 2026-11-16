
document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('loginForm');
    const loginMessage = document.getElementById('loginMessage');
    const loginButton = document.getElementById('loginSubmitButton');

    const captchaImage = document.getElementById('captchaImage');
    const captchaInput = document.getElementById('loginCaptcha');
    const refreshCaptcha = document.getElementById('refreshCaptcha');

    const otpModal = document.getElementById('otpModal');
    const otpForm = document.getElementById('otpForm');
    const otpInput = document.getElementById('otpCode');
    const otpMessage = document.getElementById('otpMessage');
    const otpDescription = document.getElementById('otpDescription');
    const otpClose = document.getElementById('otpClose');

    const verifyButton = document.getElementById('verifyOtpButton');
    const resendButton = document.getElementById('resendOtpButton');

    let currentAuthType = 'login';

    if (!loginForm) return;
    if (
    !loginMessage ||
    !loginButton ||
    !captchaImage ||
    !captchaInput ||
    !refreshCaptcha ||
    !otpModal ||
    !otpForm ||
    !otpInput ||
    !otpMessage ||
    !otpDescription ||
    !otpClose ||
    !verifyButton ||
    !resendButton
) {
    console.error('Secure login: One or more required HTML elements are missing.');
    return;
}

    function refreshCaptchaImage() {
        captchaImage.src = '../php/captcha.php?t=' + Date.now();

        if (captchaInput) {
            captchaInput.value = '';
        }
    }

    function showMessage(element, message, isError = true) {
        if (!element) return;

        element.textContent = message || '';
        element.style.color = isError ? '#c62828' : '#239447';

        element.classList.toggle('show', Boolean(message));
        element.classList.toggle('success', !isError && Boolean(message));
    }

    function startLoginCooldown(seconds) {
        let secondsLeft = Math.max(1, Number(seconds) || 1);

        loginButton.disabled = true;

        const timer = setInterval(() => {
            loginMessage.textContent =
                `Too many failed login attempts. Please wait ${secondsLeft} seconds.`;

            loginMessage.style.color = '#c62828';
            loginMessage.classList.add('show');

            loginButton.textContent = `Cooldown (${secondsLeft}s)`;

            secondsLeft--;

            if (secondsLeft < 0) {
                clearInterval(timer);

                loginButton.disabled = false;
                loginButton.innerHTML =
                    'Log in <i class="fa-solid fa-arrow-right"></i>';

                showMessage(
                    loginMessage,
                    'You can try logging in again now.',
                    false
                );
            }
        }, 1000);
    }

    function openOtpModal(email, authType = 'login') {
        currentAuthType = authType;

        otpModal.hidden = false;
        unlockOtpInputs();
        showMessage(otpMessage, '');

        const expirationText =
            authType === 'registration' ? '4 minutes' : '60 seconds';

        const purposeText =
            authType === 'registration'
                ? 'registration verification code'
                : 'login verification code';

        otpDescription.textContent =
            `A ${purposeText} was sent to ${email}. ` +
            `It expires in ${expirationText}. Enter the six-digit code below.`;

        startOtpCountdown(60);
        otpInput.focus();
    }

    window.showRegistrationOtp = function (email) {
        openOtpModal(
            email || 'your registered email',
            'registration'
        );
    };

    function closeOtpModal() {
        clearInterval(otpTimer);
        otpModal.hidden = true;
    }


    let otpTimer = null;

    // Countdown sa resend button. Kung lockInputs=true, naka-disable pud ang input ug verify.
    function startOtpCountdown(seconds, lockInputs = false, message = '') {
        clearInterval(otpTimer);

        let left = Math.max(1, Number(seconds) || 1);

        resendButton.disabled = true;

        if (lockInputs) {
            otpInput.disabled = true;
            verifyButton.disabled = true;
        }

        const tick = () => {
            if (left <= 0) {
                clearInterval(otpTimer);
                resendButton.disabled = false;
                resendButton.textContent = 'Resend verification code';

                if (lockInputs) {
                    verifyButton.textContent = 'Verify and continue';
                    showMessage(otpMessage, 'You can now request a new verification code.', false);
                }
                return;
            }

            resendButton.textContent = `Resend available in ${left}s`;

            if (lockInputs) {
                verifyButton.textContent = `Locked (${left}s)`;
                showMessage(otpMessage, message || `Please wait ${left} seconds, then click Resend.`);
            }

            left--;
        };

        tick();
        otpTimer = setInterval(tick, 1000);
    }

    function unlockOtpInputs() {
        otpInput.disabled = false;
        otpInput.value = '';
        if (!otpInput.disabled) {
            verifyButton.disabled = false;
            verifyButton.innerHTML =
                'Verify and continue <i class="fa-solid fa-arrow-right"></i>';
        }
    }

    function restartLogin(message) {
        closeOtpModal();

        showMessage(loginMessage, message);
        refreshCaptchaImage();

        loginButton.disabled = false;
        loginButton.innerHTML =
            'Log in <i class="fa-solid fa-arrow-right"></i>';
    }

    refreshCaptcha.addEventListener('click', refreshCaptchaImage);

    otpClose.addEventListener('click', () => {
        closeOtpModal();
    });

    loginForm.addEventListener('submit', async (event) => {
        event.preventDefault();

        loginMessage.textContent = '';

        if (!loginForm.reportValidity()) return;

        loginButton.disabled = true;
        loginButton.textContent = 'Verifying...';

        const formData = new FormData(loginForm);
        formData.append('ajax', '1');

        try {
            const response = await fetch('../php/login.php', {
                method: 'POST',
                body: formData
            });

            const result = await response.json();

            if (!result.success) {
                // Show the failed login message.
                showMessage(loginMessage, result.message, true);

                // Refresh CAPTCHA without clearing the error message.
                if (result.refreshCaptcha) {
                    refreshCaptchaImage();
                }

                loginButton.disabled = false;
                loginButton.innerHTML =
                    'Log in <i class="fa-solid fa-arrow-right"></i>';

                // Handle the 10-second cooldown.
                if (result.lockedOut && result.remainingSeconds) {
                    startLoginCooldown(result.remainingSeconds);
                }

                return;
            }

            if (result.otpRequired) {
                if (result.refreshCaptcha) {
                    refreshCaptchaImage();
                }

                openOtpModal(
                    result.maskedEmail || 'your registered email',
                    'login'
                );

                loginButton.disabled = false;
                loginButton.innerHTML =
                    'Log in <i class="fa-solid fa-arrow-right"></i>';

                return;
            }

            if (result.redirect) {
                window.location.href = result.redirect;
            }

        } catch (error) {
            showMessage(loginMessage, 'Unable to connect. Please try again.');

            loginButton.disabled = false;
            loginButton.innerHTML =
                'Log in <i class="fa-solid fa-arrow-right"></i>';
        }
    });

    otpForm.addEventListener('submit', async (event) => {
        event.preventDefault();

        const otp = otpInput.value.trim();

        if (!/^\d{6}$/.test(otp)) {
            showMessage(otpMessage, 'Enter a valid six-digit code.');
            return;
        }

        verifyButton.disabled = true;
        verifyButton.textContent = 'Verifying...';

        const formData = new FormData();
        formData.append('otp', otp);

        try {
            const response = await fetch('../php/verify_otp.php', {
                method: 'POST',
                body: formData
            });

            const result = await response.json();

            // REGISTRATION OTP SUCCESS
            if (result.success && result.registrationVerified) {
                clearInterval(otpTimer);

                showMessage(
                    otpMessage,
                    result.message || 'Your account has been successfully verified!',
                    false
                );

                otpInput.disabled = true;
                verifyButton.disabled = true;
                resendButton.disabled = true;

                // Notify torino.js that registration is complete.
                window.dispatchEvent(
                    new CustomEvent('incidentHub:registration-verified', {
                        detail: {
                            message: result.message ||
                                'Registration successful! You can now log in.'
                        }
                    })
                );

                setTimeout(() => {
                    closeOtpModal();
                }, 1800);

                return;
            }

            // LOGIN OTP SUCCESS
            if (result.success && result.redirect) {
                window.location.href = result.redirect;
                return;
            }

            if (result.restartLogin) {
                showMessage(otpMessage, result.message);
                setTimeout(() => restartLogin(result.message), 1200);
                return;
            }

            // 3 wrong attempts: 60-second lock, bag-ong OTP ra human
            if (result.lockedOut) {
                startOtpCountdown(result.remainingSeconds || 60, true, '');
                return;
            }

            // Expired OTP: Resend na lang
            if (result.needResend) {
                showMessage(otpMessage, result.message);
                otpInput.disabled = true;
                verifyButton.disabled = true;
                verifyButton.innerHTML =
                    'Verify and continue <i class="fa-solid fa-arrow-right"></i>';
                resendButton.disabled = false;
                resendButton.textContent = 'Resend verification code';
                return;
            }

            showMessage(otpMessage, result.message);

        } catch (error) {
            showMessage(otpMessage, 'Verification failed. Please try again.');
        }

        verifyButton.disabled = false;
        verifyButton.innerHTML =
            'Verify and continue <i class="fa-solid fa-arrow-right"></i>';
    });

    resendButton.addEventListener('click', async () => {
        resendButton.disabled = true;
        resendButton.textContent = 'Sending...';

        try {
            const response = await fetch('../php/resend_otp.php', {
                method: 'POST'
            });

            const result = await response.json();

            if (result.restartLogin) {
                showMessage(otpMessage, result.message);
                setTimeout(() => restartLogin(result.message), 1200);
                return;
            }

            if (result.success) {
                unlockOtpInputs();
                // Clear any previous lockout countdown.
                clearInterval(otpTimer);
                showMessage(otpMessage, result.message, false);
                startOtpCountdown(
                    result.remainingSeconds || 60
                );
                otpInput.focus();
                return;
            }

            showMessage(otpMessage, result.message, true);

            if (result.remainingSeconds) {
                startOtpCountdown(result.remainingSeconds, Boolean(result.lockedOut));
                return;
            }

        } catch (error) {
            showMessage(otpMessage, 'Unable to resend the code.');
        }

        resendButton.disabled = false;
        resendButton.textContent = 'Resend verification code';
    });
});
