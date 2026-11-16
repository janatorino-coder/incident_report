
<?php
session_start();

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/mailer.php';

const MAX_ATTEMPTS = 3;
const COOLDOWN_SECONDS = 60;
const CAPTCHA_EXPIRY = 300;

$isAjax = isset($_POST['ajax']) ||
    strtolower($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '') === 'xmlhttprequest';

function loginResponse(
    bool $success,
    string $message = '',
    array $extra = []
): void  {
    global $conn, $isAjax;

    if ($isAjax) {
        header('Content-Type: application/json; charset=utf-8');

        echo json_encode(array_merge([
            'success' => $success,
            'message' => $message
        ], $extra));
    } else {
        header(
            'Location: ../html/Torino.html?mode=login&error=' .
            rawurlencode($message)
        );
    }

    if (isset($conn) && $conn instanceof mysqli) {
        $conn->close();
    }

    exit;
}

function maskEmail(string $email): string
{
    $parts = explode('@', $email, 2);

    if (count($parts) !== 2) {
        return 'your registered email';
    }

    $name = $parts[0];
    $domain = $parts[1];

    return substr($name, 0, 1) .
        str_repeat('*', max(2, strlen($name) - 1)) .
        '@' . $domain;
}

// Only POST requests are accepted.
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: ../html/Torino.html');
    exit;
}

// Get submitted values.
$username = trim((string)($_POST['username'] ?? ''));
$password = (string)($_POST['password'] ?? '');
$captcha = strtoupper(trim((string)($_POST['captcha'] ?? '')));

$ip = substr(
    (string)($_SERVER['REMOTE_ADDR'] ?? 'unknown'),
    0,
    45
);

if ($username === '' || $password === '') {
    loginResponse(false, 'Please enter your username and password.');
}

// ==========================================
// STEP 1: CAPTCHA VALIDATION
// ==========================================

$captchaHash = $_SESSION['captcha_hash'] ?? null;
$captchaCreated = (int)($_SESSION['captcha_created'] ?? 0);

// Consume the CAPTCHA so it cannot be reused.
unset(
    $_SESSION['captcha_hash'],
    $_SESSION['captcha_created']
);

if (
    !$captchaHash ||
    !$captchaCreated ||
    (time() - $captchaCreated) > CAPTCHA_EXPIRY ||
    $captcha === '' ||
    !password_verify($captcha, (string)$captchaHash)
) {
    loginResponse(false, 'Incorrect or expired CAPTCHA. Please try again.', [
        'refreshCaptcha' => true
    ]);
}

// ==========================================
// STEP 2: CHECK FAILED LOGIN ATTEMPTS
// ==========================================

$stmt = $conn->prepare(
    'SELECT failed_attempts,
            TIMESTAMPDIFF(SECOND, last_failed_at, NOW()) AS seconds_since_fail
     FROM login_attempts
     WHERE username = ? AND ip_address = ?
     LIMIT 1'
);

if (!$stmt) {
    loginResponse(false, 'Login is temporarily unavailable.');
}

$stmt->bind_param('ss', $username, $ip);
$stmt->execute();

$attemptRow = $stmt->get_result()->fetch_assoc();
$stmt->close();

$currentFailedCount = (int)($attemptRow['failed_attempts'] ?? 0);

if ($currentFailedCount >= MAX_ATTEMPTS) {

    $elapsed = (int)($attemptRow['seconds_since_fail'] ?? 0);

    if ($elapsed < COOLDOWN_SECONDS) {

        $remaining = COOLDOWN_SECONDS - $elapsed;

        loginResponse(
            false,
            "Too many failed login attempts. Please wait {$remaining} seconds.",
            [
                'lockedOut' => true,
                'remainingSeconds' => $remaining,
                'remainingAttempts' => 0,
                'refreshCaptcha' => true
            ]
        );
    }

    // Reset attempts only after cooldown expires.
    $reset = $conn->prepare(
        'UPDATE login_attempts
         SET failed_attempts = 0,
             last_failed_at = NULL
         WHERE username = ? AND ip_address = ?'
    );

    if (!$reset) {
        loginResponse(false, 'Unable to reset login attempts.');
    }

    $reset->bind_param('ss', $username, $ip);
    $reset->execute();
    $reset->close();
}

// ==========================================
// STEP 3: CHECK USERNAME AND PASSWORD
// ==========================================

$stmt = $conn->prepare(
    'SELECT id, username, password, role, email, is_verified
     FROM users
     WHERE username = ?
     LIMIT 1'
);

if (!$stmt) {
    loginResponse(false, 'Login is temporarily unavailable.');
}

$stmt->bind_param('s', $username);
$stmt->execute();

$user = $stmt->get_result()->fetch_assoc();

$stmt->close();

$valid = $user &&
    password_verify($password, (string)$user['password']);

// ==========================================
// STEP 4: RECORD INCORRECT PASSWORD
// ==========================================

if (!$valid) {

    // Count failed attempts using username + IP address.
    $record = $conn->prepare(
        'INSERT INTO login_attempts
            (username, ip_address, failed_attempts, last_failed_at)
         VALUES (?, ?, 1, NOW())
         ON DUPLICATE KEY UPDATE
            failed_attempts = failed_attempts + 1,
            last_failed_at = NOW()'
    );

    if (!$record) {
        loginResponse(false, 'Unable to record login attempt. Please try again.');
    }

    $record->bind_param('ss', $username, $ip);

    if (!$record->execute()) {
        $record->close();

        loginResponse(false, 'Unable to record login attempt. Please try again.');
    }

    $record->close();

    // Retrieve the actual updated attempt count.
    $countStmt = $conn->prepare(
        'SELECT failed_attempts
         FROM login_attempts
         WHERE username = ? AND ip_address = ?
         LIMIT 1'
    );

    if (!$countStmt) {
        loginResponse(false, 'Unable to check login attempts.');
    }

    $countStmt->bind_param('ss', $username, $ip);
    $countStmt->execute();

    $countResult = $countStmt->get_result()->fetch_assoc();

    $countStmt->close();

    $newCount = (int)($countResult['failed_attempts'] ?? 1);

    // Record the failed login in both log tables.
    $knownUserId = $user ? (int)$user['id'] : null;

    logFailedLogin(
        $conn,
        $username,
        $ip,
        $knownUserId,
        $newCount
    );

    // SEND OWNER LOCKOUT EMAIL
    if ($newCount === MAX_ATTEMPTS) {
        $emailSent = sendOwnerLockoutAlert(
            'jana.torino@csucc.edu.ph',
            'login',
            $username,
            $ip,
            $newCount,
            MAX_ATTEMPTS
        );

        if (!$emailSent) {
            error_log('Login lockout alert email was not sent.');
        }
    }

    $remainingAttempts = max(0, MAX_ATTEMPTS - $newCount);
    $lockedNow = $newCount >= MAX_ATTEMPTS;

    if ($lockedNow) {
        loginResponse(
            false,
            'Too many failed login attempts. Please wait ' . COOLDOWN_SECONDS . ' seconds.',
            [
                'lockedOut' => true,
                'remainingSeconds' => COOLDOWN_SECONDS,
                'remainingAttempts' => 0,
                'refreshCaptcha' => true
            ]
        );
    }

    loginResponse(
        false,
        "Incorrect username or password. {$remainingAttempts} attempt(s) remaining.",
        [
            'lockedOut' => false,
            'remainingAttempts' => $remainingAttempts,
            'refreshCaptcha' => true
        ]
    );
}

// ==========================================
// STEP 5: CHECK REGISTERED EMAIL
// ==========================================

// Reject accounts that have not completed registration verification.

if ((int)$user['is_verified'] !== 1) {
    loginResponse(
        false,
        'Your account is not verified yet. Please complete your email verification during registration.',
        ['refreshCaptcha' => true]
    );
}

$clear = $conn->prepare('DELETE FROM login_attempts WHERE username = ? AND ip_address = ?');
if ($clear) {
    $clear->bind_param('ss', $username, $ip);
    $clear->execute();
    $clear->close();
}

$email = trim((string)($user['email'] ?? ''));

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    loginResponse(
        false,
        'Your account does not have a valid registered email address.',
        ['refreshCaptcha' => true]
    );
}

// ==========================================
// STEP 6: GENERATE EMAIL OTP
// ==========================================

$otp = (string)random_int(100000, 999999);

$otpHash = password_hash($otp, PASSWORD_DEFAULT);

$userId = (int)$user['id'];

// Replace any previous pending OTP for this account.
$delete = $conn->prepare(
    'DELETE FROM login_otp WHERE user_id = ?'
);

if (!$delete) {
    loginResponse(false, 'Unable to prepare OTP verification.');
}

$delete->bind_param('i', $userId);
$delete->execute();
$delete->close();

// Insert the new OTP.
$insert = $conn->prepare(
    'INSERT INTO login_otp
        (user_id, otp_hash, expires_at, attempts, resend_count, last_sent_at, locked_until)
     VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 60 SECOND), 0, 0, NOW(), NULL)'
);

if (!$insert) {
    loginResponse(false, 'Unable to create your verification code.');
}

$insert->bind_param('is', $userId, $otpHash);

if (!$insert->execute()) {
    $insert->close();

    loginResponse(
        false,
        'Unable to create your verification code. Please try again.',
        ['refreshCaptcha' => true]
    );
}

$insert->close();

// ==========================================
// STEP 7: SEND OTP THROUGH BREVO
// ==========================================

if (!sendLoginOTP($email, $otp)) {

    $delete = $conn->prepare(
        'DELETE FROM login_otp WHERE user_id = ?'
    );

    if ($delete) {
        $delete->bind_param('i', $userId);
        $delete->execute();
        $delete->close();
    }

    loginResponse(
        false,
        'Unable to send your verification code. Please try again.',
        ['refreshCaptcha' => true]
    );
}

// ==========================================
// STEP 8: CREATE PENDING SESSION ONLY
// ==========================================

// Do NOT create user_id, username or role here.
// Authentication happens only after successful OTP verification.

unset(
    $_SESSION['user_id'],
    $_SESSION['username'],
    $_SESSION['role']
);

// Prevent session fixation before creating the pending authentication session.
if (!session_regenerate_id(true)) {
    loginResponse(
        false,
        'Unable to start secure login verification. Please try again.',
        ['refreshCaptcha' => true]
    );
}

// Remove any previous pending authentication information.
unset(
    $_SESSION['pending_auth_type'],
    $_SESSION['pending_user_id'],
    $_SESSION['pending_username'],
    $_SESSION['pending_ip']
);

$_SESSION['pending_auth_type'] = 'login';
$_SESSION['pending_user_id'] = $userId;
$_SESSION['pending_username'] = (string)$user['username'];
$_SESSION['pending_ip'] = (string)($_SERVER['REMOTE_ADDR'] ?? '');

loginResponse(
    true,
    'Verification code sent to your email.',
    [
        'otpRequired' => true,
        'maskedEmail' => maskEmail($email),
        'refreshCaptcha' => true
    ]
);

// ==========================================
// ACTIVITY AND SECURITY LOGGING
// ==========================================

function logFailedLogin(
    mysqli $conn,
    string $username,
    string $ip,
    ?int $userId,
    int $attemptCount
): void {

    $details = "Incorrect password. IP: {$ip}. Failed attempts: {$attemptCount}/" . MAX_ATTEMPTS;

    // Write to activity_logs.
    $activity = $conn->prepare(
        'INSERT INTO activity_logs
            (user_id, actor_name, action, details)
         VALUES (?, ?, ?, ?)'
    );

    if ($activity) {
        $action = 'Failed login';

        $activity->bind_param(
            'isss',
            $userId,
            $username,
            $action,
            $details
        );

        $activity->execute();
        $activity->close();
    }

    // Write to security_events.
    $security = $conn->prepare(
        'INSERT INTO security_events
            (user_id, username, ip_address, event_type, details)
         VALUES (?, ?, ?, ?, ?)'
    );

    if ($security) {
        $eventType = 'failed_login';

        $security->bind_param(
            'issss',
            $userId,
            $username,
            $ip,
            $eventType,
            $details
        );

        $security->execute();
        $security->close();
    }
}
