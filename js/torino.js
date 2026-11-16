/* Incident Hub public home page + sliding login/registration form. */

// ==========================================
// PASSWORD VISIBILITY
// ==========================================

function togglePassword(icon) {
    const input = icon.parentElement.querySelector("input");
    if (!input) return;

    const reveal = input.type === "password";
    input.type = reveal ? "text" : "password";

    icon.classList.toggle("fa-eye", !reveal);
    icon.classList.toggle("fa-eye-slash", reveal);

    icon.setAttribute(
        "aria-label",
        reveal ? "Hide password" : "Show password"
    );
}


// ==========================================
// REGISTRATION FIELD HELPERS
// ==========================================

const registrationErrorFallbacks = {
    username: "usernameError",
    email: "emailError",
    password: "passwordError",
    confirm_password: "confirmPasswordError"
};

function getRegistrationField(name) {
    const form = document.getElementById("registerForm");

    if (!form) return null;

    return form.querySelector(`[name="${name}"]`);
}


function getRegistrationErrorElement(name) {
    const form = document.getElementById("registerForm");

    if (!form) return null;

    let error = form.querySelector(`#error-${name}`);

    if (!error && registrationErrorFallbacks[name]) {
        error = form.querySelector(
            `#${registrationErrorFallbacks[name]}`
        );
    }

    // Automatically create an error message below the input box.
    if (!error) {
        const field = getRegistrationField(name);

        if (!field) return null;

        error = document.createElement("p");

        error.id = `error-${name}`;
        error.className = "field-error";
        error.setAttribute("role", "alert");

        if (name === "privacy_consent") {
            const group = form.querySelector(
                ".privacy-consent-group"
            );

            if (group) {
                group.appendChild(error);
            }

            return error;
        }

        const inputGroup = field.closest(".input-group");

        const inputBox = field.closest(".input-box");

        if (inputBox && inputGroup) {
            inputBox.insertAdjacentElement("afterend", error);
        } else if (inputGroup) {
            inputGroup.appendChild(error);
        } else {
            field.insertAdjacentElement("afterend", error);
        }
    }

    return error;
}


function setRegistrationFieldError(name, message) {
    const field = getRegistrationField(name);
    const errorElement = getRegistrationErrorElement(name);

    if (errorElement) {
        errorElement.textContent = message || "";
        errorElement.hidden = !message;
    }

    if (field) {
        field.classList.toggle(
            "input-error",
            Boolean(message)
        );

        field.setAttribute(
            "aria-invalid",
            message ? "true" : "false"
        );
    }

    if (name === "privacy_consent") {
        const group = document.querySelector(
            ".privacy-consent-group"
        );

        if (group) {
            group.classList.toggle(
                "input-error",
                Boolean(message)
            );
        }
    }
}


// ==========================================
// DISPLAY ALL SERVER ERRORS AT ONCE
// ==========================================

function displayRegistrationErrors(errors) {
    clearRegistrationErrors();

    if (!errors || typeof errors !== "object") return;

    let firstInvalidField = null;

    Object.entries(errors).forEach(([name, message]) => {
        setRegistrationFieldError(name, message);

        if (!firstInvalidField) {
            firstInvalidField = getRegistrationField(name);
        }
    });

    // Focus only the first invalid field.
    // All other error messages remain visible.
    if (firstInvalidField) {
        firstInvalidField.focus({
            preventScroll: false
        });
    }
}


// ==========================================
// CLEAR ALL REGISTRATION ERRORS
// ==========================================

function clearRegistrationErrors() {
    const form = document.getElementById("registerForm");

    if (!form) return;

    form.querySelectorAll(
        ".field-error, .error-msg"
    ).forEach(error => {
        error.textContent = "";
        error.hidden = true;
    });

    form.querySelectorAll(".input-error").forEach(field => {
        field.classList.remove("input-error");
        field.setAttribute("aria-invalid", "false");
    });

    const privacyGroup = form.querySelector(
        ".privacy-consent-group"
    );

    privacyGroup?.classList.remove("input-error");
}


// ==========================================
// CLEAR ONE FIELD ERROR
// ==========================================

function clearRegistrationFieldError(name) {
    setRegistrationFieldError(name, "");
}


// ==========================================
// VALIDATION HELPERS
// ==========================================

function getFieldValue(name) {
    const field = getRegistrationField(name);

    return field ? field.value.trim() : "";
}


function isTitleCase(value) {
    return value
        .split(" ")
        .every(word => {
            if (!word) return false;

            return (
                word.charAt(0) === word.charAt(0).toUpperCase() &&
                word.slice(1) === word.slice(1).toLowerCase()
            );
        });
}


function hasThreeRepeatedLetters(value) {
    return /(.)\1\1/i.test(value);
}


function getAge(birthdate) {
    const today = new Date();
    const birth = new Date(birthdate + "T00:00:00");

    let age = today.getFullYear() - birth.getFullYear();

    const monthDifference =
        today.getMonth() - birth.getMonth();

    if (
        monthDifference < 0 ||
        (
            monthDifference === 0 &&
            today.getDate() < birth.getDate()
        )
    ) {
        age--;
    }

    return age;
}


// ==========================================
// STUDENT ID VALIDATION
// Format: xxx-xxxxx
// ==========================================

function validateStudentId() {
    const value = getFieldValue("id_number");

    let error = "";

    if (!value) {
        error = "Student ID Number is required.";
    } else if (!/^\d{3}-\d{5}$/.test(value)) {
        error = "Student ID Number must follow the format xxx-xxxxx.";
    }

    setRegistrationFieldError("id_number", error);

    return !error;
}


// ==========================================
// NAME VALIDATION
// ==========================================

function validateNameField(name, label, required = true) {
    const value = getFieldValue(name);

    let error = "";

    if (!value && required) {
        error = `${label} is required.`;
    } else if (!value && !required) {
        error = "";
    } else if (value.length < 2 || value.length > 50) {
        error = `${label} must be between 2 and 50 characters.`;
    } else if (/\s{2,}/.test(value)) {
        error = `${label} must not contain double spaces.`;
    } else if (/\d/.test(value)) {
        error = `Numbers are not allowed in ${label}.`;
    } else if (/[^A-Za-z ]/.test(value)) {
        error = `Special characters are not allowed in ${label}.`;
    } else if (hasThreeRepeatedLetters(value)) {
        error = "Three consecutive identical letters are not allowed.";
    } else if (value === value.toUpperCase()) {
        error = "Do not use all capital letters.";
    } else if (!isTitleCase(value)) {
        error = "First letter of your name must be capital.";
    }

    setRegistrationFieldError(name, error);

    return !error;
}


function validateNames() {
    const first = validateNameField(
        "first_name",
        "First Name"
    );

    const middle = validateNameField(
        "middle_name",
        "Middle Name",
        false
    );

    const family = validateNameField(
        "family_name",
        "Family Name"
    );

    return first && middle && family;
}


// ==========================================
// NAME EXTENSION VALIDATION
// ==========================================

function validateNameExtension() {
    const extension = getFieldValue("name_extension");

    const other = getFieldValue("other_extension");

    let error = "";

    if (extension === "Other") {
        if (!other) {
            error = "Please select your other name extension.";
        } else if (!["I", "II", "III", "IV", "IX", "X"].includes(other)) {
            error = "Please select a valid name extension.";
        }
    }

    setRegistrationFieldError("other_extension", error);

    return !error;
}


// ==========================================
// BIRTHDATE VALIDATION
// ==========================================

function validateBirthdate() {
    const value = getFieldValue("birthdate");

    let error = "";

    if (!value) {
        error = "Birthdate is required.";
    } else {
        const birth = new Date(value + "T00:00:00");
        const today = new Date();

        today.setHours(0, 0, 0, 0);

        if (Number.isNaN(birth.getTime())) {
            error = "Please enter a valid birthdate.";
        } else if (birth > today) {
            error = "Birthdate cannot be in the future.";
        } else if (getAge(value) < 18) {
            error = "You must be at least 18 years old to register.";
        }
    }

    setRegistrationFieldError("birthdate", error);

    return !error;
}


// ==========================================
// PUROK / STREET VALIDATION
// ==========================================

function validatePurokStreet() {
    const value = getFieldValue("purok_street");

    let error = "";

    if (!value) {
        error = "Purok / Street is required.";
    } else if (value.length < 3 || value.length > 50) {
        error = "Purok / Street must be between 3 and 50 characters.";
    } else if (!/^[A-Za-z0-9 ]+$/.test(value)) {
        error = "Purok / Street may contain only letters, numbers, and spaces.";
    } else if (/\s{2,}/.test(value)) {
        error = "Purok / Street must not contain double spaces.";
    }

    setRegistrationFieldError("purok_street", error);

    return !error;
}


// ==========================================
// ADDRESS VALIDATION
// ==========================================

function validateAddressField(name, label) {
    const value = getFieldValue(name);

    let error = "";

    if (!value) {
        error = `${label} is required.`;
    } else if (value.length < 2 || value.length > 50) {
        error = `${label} must be between 2 and 50 characters.`;
    } else if (!/^[A-Za-z ]+$/.test(value)) {
        error = `${label} must contain letters and spaces only.`;
    } else if (/\s{2,}/.test(value)) {
        error = `${label} must not contain double spaces.`;
    } else if (!isTitleCase(value)) {
        error = `${label} must use Title Case.`;
    }

    setRegistrationFieldError(name, error);

    return !error;
}


function validateAddress() {
    const barangay = validateAddressField(
        "barangay",
        "Barangay"
    );

    const municipality = validateAddressField(
        "municipality_city",
        "Municipality / City"
    );

    const province = validateAddressField(
        "province",
        "Province"
    );

    const country = validateAddressField(
        "country",
        "Country"
    );

    return (
        barangay &&
        municipality &&
        province &&
        country
    );
}


// ==========================================
// ZIP CODE VALIDATION
// ==========================================

function validateZipCode() {
    const value = getFieldValue("zip_code");

    let error = "";

    if (!value) {
        error = "ZIP Code is required.";
    } else if (!/^\d{4}$/.test(value)) {
        error = "ZIP Code must contain exactly 4 digits.";
    }

    setRegistrationFieldError("zip_code", error);

    return !error;
}


// ==========================================
// USERNAME VALIDATION
// ==========================================

function validateFormUsername() {
    const value = getFieldValue("username");

    let error = "";

    if (!value) {
        error = "Username is required.";
    } else if (!/^[A-Za-z][A-Za-z0-9]{5,19}$/.test(value)) {
        error =
            "Username must contain 6–20 letters and numbers and start with a letter.";
    }

    setRegistrationFieldError("username", error);

    return !error;
}


// ==========================================
// EMAIL VALIDATION
// ==========================================

function validateFormEmail() {
    const value = getFieldValue("email");

    let error = "";

    if (!value) {
        error = "Email is required.";
    } else if (value.length > 100) {
        error = "Email must not exceed 100 characters.";
    } else if (/\s/.test(value)) {
        error = "Email must not contain spaces.";
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
        error = "Please enter a valid email address.";
    } else if (!/@csucc\.edu\.ph$/.test(value)) {
        error =
            "Please use your official school email ending in @csucc.edu.ph.";
    } else if (value !== value.toLowerCase()) {
        error = "Email must be in lowercase.";
    }

    setRegistrationFieldError("email", error);

    return !error;
}


// ==========================================
// PASSWORD VALIDATION
// ==========================================

function validateFormPassword() {
    const value = getRegistrationField("password")?.value || "";

    let error = "";

    if (!value) {
        error = "Password is required.";
    } else if (value.length < 8 || value.length > 64) {
        error = "Password must be between 8 and 64 characters.";
    } else {
        let categories = 0;

        if (/[a-z]/.test(value)) categories++;
        if (/[A-Z]/.test(value)) categories++;
        if (/[0-9]/.test(value)) categories++;
        if (/[^A-Za-z0-9]/.test(value)) categories++;

        if (categories < 3) {
            error =
                "Your password is too weak. Use at least 3 character types.";
        }
    }

    setRegistrationFieldError("password", error);

    return !error;
}


// ==========================================
// CONFIRM PASSWORD VALIDATION
// ==========================================

function validateFormConfirmPassword() {
    const password =
        getRegistrationField("password")?.value || "";

    const confirm =
        getRegistrationField("confirm_password")?.value || "";

    let error = "";

    if (!confirm) {
        error = "Confirm password is required.";
    } else if (confirm !== password) {
        error = "Passwords do not match.";
    }

    setRegistrationFieldError("confirm_password", error);

    return !error;
}


// ==========================================
// SECURITY QUESTIONS VALIDATION
// ==========================================

function validateSecurityAnswer(name, label) {
    const value = getFieldValue(name);

    let error = "";

    if (!value) {
        error = `${label} is required.`;
    } else if (value.length < 2 || value.length > 50) {
        error = `${label} must be between 2 and 50 characters.`;
    } else if (!/^[A-Za-z ]+$/.test(value)) {
        error = `${label} must contain letters and spaces only.`;
    } else if (/\s{2,}/.test(value)) {
        error = `${label} must not contain double spaces.`;
    }

    setRegistrationFieldError(name, error);

    return !error;
}


function validateSecurityQuestions() {
    const q2 = validateSecurityAnswer(
        "security_answer_q2",
        "Security answer"
    );

    const q5 = validateSecurityAnswer(
        "security_answer_q5",
        "Security answer"
    );

    const q7 = validateSecurityAnswer(
        "security_answer_q7",
        "Security answer"
    );

    return q2 && q5 && q7;
}


// ==========================================
// PRIVACY CONSENT VALIDATION
// ==========================================

function validatePrivacyConsent() {
    const field = getRegistrationField("privacy_consent");

    let error = "";

    if (!field || !field.checked) {
        error = "You must agree to the Privacy Notice to register.";
    }

    setRegistrationFieldError("privacy_consent", error);

    return !error;
}


// ==========================================
// VALIDATE EVERY REGISTRATION FIELD
// ==========================================

function validateForm() {
    // IMPORTANT:
    // Every validation runs independently.
    // Do not combine validation calls in a way
    // that stops after the first false result.

    const results = [];

    results.push(validateStudentId());

    results.push(validateNames());

    results.push(validateNameExtension());

    results.push(validateBirthdate());

    results.push(validatePurokStreet());

    results.push(validateAddress());

    results.push(validateZipCode());

    results.push(validateFormUsername());

    results.push(validateFormEmail());

    results.push(validateFormPassword());

    results.push(validateFormConfirmPassword());

    results.push(validateSecurityQuestions());

    results.push(validatePrivacyConsent());

    // All errors have already been displayed.
    return results.every(Boolean);
}


// ==========================================
// GENERAL FORM MESSAGE
// ==========================================

function showFormMessage(element, message, type = "error") {
    if (!element) return;

    element.textContent = message || "";

    element.classList.toggle(
        "show",
        Boolean(message)
    );

    element.classList.toggle(
        "success",
        type === "success"
    );

    element.classList.toggle(
        "lockout",
        type === "lockout"
    );
}


// ==========================================
// LOGIN COOLDOWN
// ==========================================

function startLoginCooldown(seconds) {
    const message = document.getElementById("loginMessage");
    const button = document.getElementById("loginSubmitButton");

    if (!message || !button) return;

    if (window.loginCooldownTimer) {
        clearInterval(window.loginCooldownTimer);
    }

    let secondsLeft = Math.max(1, Number(seconds) || 1);

    const originalLabel = "Log in";

    button.disabled = true;

    const tick = () => {
        showFormMessage(
            message,
            `Too many failed login attempts. Please wait about ${secondsLeft} second(s) before trying again.`,
            "lockout"
        );

        button.innerHTML = `Cooldown (${secondsLeft}s)`;

        if (secondsLeft <= 0) {
            clearInterval(window.loginCooldownTimer);

            window.loginCooldownTimer = null;

            button.disabled = false;

            button.innerHTML =
                `${originalLabel} <i class="fa-solid fa-arrow-right"></i>`;

            showFormMessage(
                message,
                "You can try logging in again now.",
                ""
            );

            return;
        }

        secondsLeft--;
    };

    tick();

    window.loginCooldownTimer = setInterval(tick, 1000);
}


// ==========================================
// DOCUMENT READY
// ==========================================

document.addEventListener("DOMContentLoaded", () => {
    const authModal = document.getElementById("authModal");
    const authBox = document.getElementById("authBox");

    const welcomeHeading = document.getElementById("welcomeHeading");
    const welcomeText = document.getElementById("welcomeText");
    const dialogTitle = document.getElementById("authDialogTitle");

    const registerForm = document.getElementById("registerForm");
    const loginForm = document.getElementById("loginForm");

    const registerMessage = document.getElementById("registerMessage");
    const loginMessage = document.getElementById("loginMessage");

    const loginButton = document.getElementById("loginButton");
    const registerButton = document.getElementById("registerButton");

    const closeAuthButton = document.getElementById("closeAuthButton");

    const mobileMenuButton = document.getElementById("mobileMenuButton");
    const mobileNav = document.getElementById("mobileNav");

    if (!authModal || !authBox || !registerForm || !loginForm) {
        return;
    }


    // ==========================================
    // LIVE PASSWORD STRENGTH
    // ==========================================

    const passwordInput = document.getElementById("password");

    const strengthText = document.getElementById("strengthText");
    const strengthBar = document.getElementById("strengthBar");

    if (passwordInput && strengthText && strengthBar) {
        function updatePasswordStrength() {
            const password = passwordInput.value;

            if (password.length === 0) {
                strengthText.textContent = "Not entered";

                strengthBar.style.width = "0%";

                strengthBar.className = "strength-meter-fill";

                return;
            }

            let categories = 0;

            if (/[a-z]/.test(password)) categories++;
            if (/[A-Z]/.test(password)) categories++;
            if (/[0-9]/.test(password)) categories++;
            if (/[^A-Za-z0-9]/.test(password)) categories++;

            let strength;

            if (password.length < 8 || categories < 3) {
                strength = "Weak";
            } else if (password.length >= 12 && categories === 4) {
                strength = "Strong";
            } else {
                strength = "Medium";
            }

            strengthText.textContent = strength;

            strengthBar.className =
                "strength-meter-fill " + strength.toLowerCase();

            if (strength === "Weak") {
                strengthBar.style.width = "33%";
            } else if (strength === "Medium") {
                strengthBar.style.width = "66%";
            } else {
                strengthBar.style.width = "100%";
            }
        }

        passwordInput.addEventListener(
            "input",
            updatePasswordStrength
        );

        updatePasswordStrength();
    }


    // ==========================================
    // ID NUMBER FORMATTING
    // Format: xxx-xxxxx
    // ==========================================

    const idNumberInput = document.getElementById("idNumber");

    if (idNumberInput) {
        idNumberInput.addEventListener("input", function () {
            let value = this.value
                .replace(/\D/g, "")
                .slice(0, 8);

            if (value.length > 3) {
                value =
                    value.slice(0, 3) +
                    "-" +
                    value.slice(3);
            }

            this.value = value;
        });
    }


    // ==========================================
    // NAME EXTENSION
    // ==========================================

    const extensionSelect = document.getElementById("nameExtension");

    const otherGroup = document.getElementById("otherExtensionGroup");

    const otherExtension = document.getElementById("otherExtension");

    if (extensionSelect && otherGroup && otherExtension) {
        function updateExtensionField() {
            const isOther = extensionSelect.value === "Other";

            otherGroup.hidden = !isOther;

            otherExtension.required = isOther;

            if (!isOther) {
                otherExtension.value = "";

                clearRegistrationFieldError("other_extension");
            }
        }

        extensionSelect.addEventListener(
            "change",
            updateExtensionField
        );

        updateExtensionField();
    }


    // ==========================================
    // CLEAR ERRORS WHEN A FIELD IS EDITED
    // ==========================================

    registerForm.querySelectorAll("[name]").forEach(field => {
        const name = field.name;

        const eventType =
            field.type === "checkbox" ||
            field.tagName === "SELECT"
                ? "change"
                : "input";

        field.addEventListener(eventType, () => {
            clearRegistrationFieldError(name);

            // If password changes, the confirmation
            // may no longer match.
            if (name === "password") {
                clearRegistrationFieldError("confirm_password");
            }
        });
    });


    // ==========================================
    // AUTH MODE
    // ==========================================

    function setAuthMode(mode) {
        const isLogin = mode === "login";

        authBox.classList.toggle(
            "login-active",
            isLogin
        );

        welcomeHeading.textContent =
            isLogin ? "Welcome back!" : "Welcome!";

        welcomeText.textContent = isLogin
            ? "Log in to continue and stay connected with your school community."
            : "Create your account and be part of a safer school community.";

        if (dialogTitle) {
            dialogTitle.textContent =
                isLogin ? "Log in" : "Create account";
        }

        if (isLogin) {
            showFormMessage(registerMessage, "", "");
        } else {
            showFormMessage(loginMessage, "", "");
        }
    }


    // ==========================================
    // OPEN AUTH MODAL
    // ==========================================

    function openAuth(mode = "register") {
        setAuthMode(mode);

        authModal.hidden = false;

        document.body.classList.add("modal-open");

        if (mobileNav) {
            mobileNav.hidden = true;
        }

        if (mobileMenuButton) {
            mobileMenuButton.setAttribute(
                "aria-expanded",
                "false"
            );
        }

        window.setTimeout(() => {
            const target = mode === "login"
                ? document.getElementById("loginUsername")
                : document.getElementById("username");

            target?.focus();
        }, 120);
    }


    // ==========================================
    // CLOSE AUTH MODAL
    // ==========================================

    function closeAuth() {
        authModal.hidden = true;

        document.body.classList.remove("modal-open");
    }


    // ==========================================
    // AUTH BUTTONS
    // ==========================================

    document.querySelectorAll("[data-open-auth]").forEach(button => {
        button.addEventListener("click", () => {
            openAuth(button.dataset.openAuth);
        });
    });

    document.querySelectorAll("[data-close-auth]").forEach(button => {
        button.addEventListener("click", closeAuth);
    });

    closeAuthButton?.addEventListener("click", closeAuth);

    document.addEventListener("keydown", event => {
        if (event.key === "Escape" && !authModal.hidden) {
            closeAuth();
        }
    });

    loginButton?.addEventListener("click", () => {
        setAuthMode("login");
    });

    registerButton?.addEventListener("click", () => {
        setAuthMode("register");
    });


    // ==========================================
    // MOBILE NAVIGATION
    // ==========================================

    mobileMenuButton?.addEventListener("click", () => {
        const opening = mobileNav.hidden;

        mobileNav.hidden = !opening;

        mobileMenuButton.setAttribute(
            "aria-expanded",
            String(opening)
        );

        mobileMenuButton.innerHTML = opening
            ? '<i class="fa-solid fa-xmark"></i>'
            : '<i class="fa-solid fa-bars"></i>';
    });

    mobileNav?.querySelectorAll("a").forEach(link => {
        link.addEventListener("click", () => {
            mobileNav.hidden = true;

            mobileMenuButton?.setAttribute(
                "aria-expanded",
                "false"
            );

            if (mobileMenuButton) {
                mobileMenuButton.innerHTML =
                    '<i class="fa-solid fa-bars"></i>';
            }
        });
    });


    // ==========================================
    // REGISTRATION FORM SUBMISSION
    // ==========================================

    registerForm.addEventListener("submit", async event => {
        event.preventDefault();

        showFormMessage(registerMessage, "", "");

        // Validate EVERY field before sending.
        // All invalid fields will show their errors together.
        const isValid = validateForm();

        if (!isValid) {
            const firstInvalid = registerForm.querySelector(
                '.input-error:not([type="checkbox"])'
            );

            firstInvalid?.focus({
                preventScroll: false
            });

            return;
        }

        const submitButton = document.getElementById(
            "registerSubmitButton"
        );

        const originalButton =
            submitButton?.innerHTML || "Create account";

        if (submitButton) {
            submitButton.disabled = true;

            submitButton.textContent = "Creating account...";
        }

        try {
            const formData = new FormData(registerForm);

            formData.set("ajax", "1");

            const response = await fetch(registerForm.action, {
                method: "POST",
                body: formData,
                headers: {
                    "X-Requested-With": "XMLHttpRequest"
                }
            });

            const raw = await response.text();

            let data;

            try {
                data = JSON.parse(raw);
            } catch {
                data = {
                    success: response.ok,
                    message: raw
                };
            }


            // ======================================
            // SERVER FIELD ERRORS
            // ======================================

            if (!data.success && data.errors) {
                displayRegistrationErrors(data.errors);

                showFormMessage(
                    registerMessage,
                    "",
                    ""
                );
            }


            // ======================================
            // REGISTRATION SUCCESS - OTP REQUIRED
            // ======================================

            else if (
                response.ok &&
                data.success &&
                data.otpRequired
            ) {
                clearRegistrationErrors();

                showFormMessage(
                    registerMessage,
                    data.message ||
                        "Your account was created. Please verify your email address.",
                    "success"
                );

                if (
                    typeof window.showRegistrationOtp === "function"
                ) {
                    window.showRegistrationOtp(
                        data.maskedEmail || "your registered email"
                    );
                } else {
                    showFormMessage(
                        registerMessage,
                        "Your account was created, but the OTP verification window could not be opened. Please check your JavaScript files.",
                        "error"
                    );
                }
            }


            // ======================================
            // SUCCESS WITHOUT OTP
            // ======================================

            else if (response.ok && data.success) {
                clearRegistrationErrors();

                showFormMessage(
                    registerMessage,
                    data.message ||
                        "Registration successful. You can now log in.",
                    "success"
                );

                registerForm.reset();

                window.setTimeout(() => {
                    setAuthMode("login");

                    showFormMessage(
                        loginMessage,
                        "Registration successful. You can now log in.",
                        "success"
                    );
                }, 1100);
            }


            // ======================================
            // GENERAL SERVER ERROR
            // ======================================

            else {
                showFormMessage(
                    registerMessage,
                    data.message ||
                        "Registration failed. Please try again.",
                    "error"
                );
            }

        } catch (error) {
            console.error("Registration error:", error);

            showFormMessage(
                registerMessage,
                "Connection error. Please try again.",
                "error"
            );

        } finally {
            if (submitButton) {
                submitButton.disabled = false;

                submitButton.innerHTML = originalButton;
            }
        }
    });


    // ==========================================
    // SUCCESSFUL OTP VERIFICATION
    // ==========================================

    window.addEventListener(
        "incidentHub:registration-verified",
        event => {
            const message =
                event.detail?.message ||
                "Registration successful! You can now log in.";

            registerForm.reset();

            clearRegistrationErrors();

            setAuthMode("login");

            showFormMessage(
                loginMessage,
                message,
                "success"
            );
        }
    );


    // ==========================================
    // SUPPORT PHP REDIRECT URLS
    // ==========================================

    const params = new URLSearchParams(
        window.location.search
    );

    if (
        params.get("mode") === "login" ||
        params.get("registered") === "1"
    ) {
        openAuth("login");

        if (params.get("registered") === "1") {
            showFormMessage(
                loginMessage,
                "Registration successful. Please log in.",
                "success"
            );
        }
    }

});