
<?php

session_start();

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/activity_logger.php';
require_once __DIR__ . '/mailer.php';
require_once __DIR__ . '/session.php';

header('Content-Type: application/json; charset=utf-8');


// ==========================================
// RESPONSE HELPER
// ==========================================

function otpResponse(array $data, int $status = 200): void
{
    global $conn;

    http_response_code($status);

    echo json_encode($data);

    if (isset($conn) && $conn instanceof mysqli) {
        $conn->close();
    }

    exit;
}


// ==========================================
// CLEAR TEMPORARY OTP SESSION
// ==========================================

function clearPendingOTP(): void
{
    unset(
        $_SESSION['pending_auth_type'],
        $_SESSION['pending_user_id'],
        $_SESSION['pending_username'],
        $_SESSION['pending_ip']
    );
}


// ==========================================
// GET PENDING AUTHENTICATION INFORMATION
// ==========================================

$userId = isset($_SESSION['pending_user_id'])
    ? (int) $_SESSION['pending_user_id']
    : 0;

$pendingUsername = $_SESSION['pending_username'] ?? '';
$pendingIP = $_SESSION['pending_ip'] ?? '';

// Existing login sessions without pending_auth_type
// are treated as login for backward compatibility.

$authType = $_SESSION['pending_auth_type'] ?? 'login';

$currentIP = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

$otp = trim((string) ($_POST['otp'] ?? ''));


// ==========================================
// VALIDATE PENDING SESSION
// ==========================================

if (
    $userId <= 0 ||
    $pendingUsername === '' ||
    $pendingIP === '' ||
    $pendingIP !== $currentIP ||
    !in_array($authType, ['login', 'registration'], true)
) {

    clearPendingOTP();

    otpResponse([
        'success' => false,
        'message' => 'Your verification session is invalid. Please try again.',
        'restartLogin' => true
    ], 401);
}


// ==========================================
// VALIDATE OTP FORMAT
// ==========================================

if (!preg_match('/^\d{6}$/', $otp)) {
    otpResponse([
        'success' => false,
        'message' => 'Please enter a valid 6-digit OTP.'
    ], 400);
}

// ==========================================
// RETRIEVE OTP RECORD
// ==========================================

$stmt = $conn->prepare(
    'SELECT
        o.otp_hash,
        o.attempts,
        (o.expires_at > NOW()) AS is_valid,
        (o.locked_until IS NOT NULL AND o.locked_until > NOW()) AS is_locked,
        IFNULL(TIMESTAMPDIFF(SECOND, NOW(), o.locked_until), 0) AS lock_remaining,
        u.email
     FROM login_otp o
     INNER JOIN users u ON u.id = o.user_id
     WHERE o.user_id = ?
     LIMIT 1'
);

if (!$stmt) {

    otpResponse([
        'success' => false,
        'message' => 'Unable to verify OTP. Please try again.'
    ], 500);
}

$stmt->bind_param('i', $userId);

$stmt->execute();

$otpRecord = $stmt->get_result()->fetch_assoc();

$stmt->close();


// ==========================================
// CHECK IF OTP EXISTS
// ==========================================

if (!$otpRecord) {

    logActivity(
        $conn,
        $userId,
        $pendingUsername,
        'OTP verification unavailable',
        'OTP record was not found.',
        $currentIP,
        'otp_unavailable'
    );

    clearPendingOTP();

    otpResponse([
        'success' => false,
        'message' => 'OTP is no longer available. Please restart the verification process.',
        'restartLogin' => true
    ]);
}


$attempts = (int) $otpRecord['attempts'];


// ==========================================
// CHECK LOCKOUT
// ==========================================

if ((int) $otpRecord['is_locked'] === 1) {

    $remaining = max(
        1,
        (int) $otpRecord['lock_remaining']
    );

    otpResponse([
        'success' => false,
        'message' => "Too many incorrect OTP attempts. Please wait {$remaining} seconds, then request a new code.",
        'lockedOut' => true,
        'remainingSeconds' => $remaining
    ], 429);
}


// ==========================================
// CHECK ATTEMPTS
// ==========================================

if ($attempts >= 3) {

    otpResponse([
        'success' => false,
        'message' => 'Please request a new verification code.',
        'needResend' => true
    ]);
}


// ==========================================
// CHECK OTP EXPIRATION
// ==========================================

if (!(bool) $otpRecord['is_valid']) {

    logActivity(
        $conn,
        $userId,
        $pendingUsername,
        'Expired OTP verification',
        'OTP expired before verification.',
        $currentIP,
        'otp_expired'
    );

    otpResponse([
        'success' => false,
        'message' => 'Your OTP has expired. Please click "Resend verification code".',
        'needResend' => true
    ]);
}


// ==========================================
// VERIFY OTP
// ==========================================

if (!password_verify($otp, $otpRecord['otp_hash'])) {

    $newAttempts = $attempts + 1;

    $isLockNow = $newAttempts >= 3;

    if ($isLockNow) {

        $update = $conn->prepare(
            'UPDATE login_otp
             SET attempts = ?,
                 locked_until = DATE_ADD(NOW(), INTERVAL 60 SECOND)
             WHERE user_id = ?'
        );

    } else {

        $update = $conn->prepare(
            'UPDATE login_otp
             SET attempts = ?
             WHERE user_id = ?'
        );
    }

    if (!$update) {

        otpResponse([
            'success' => false,
            'message' => 'Unable to update OTP attempts. Please try again.'
        ], 500);
    }

    $update->bind_param('ii', $newAttempts, $userId);

    if (!$update->execute()) {
        $update->close();

        otpResponse([
            'success' => false,
            'message' => 'Unable to update OTP attempts. Please try again.'
        ], 500);
    }

    $update->close();

    logActivity(
        $conn,
        $userId,
        $pendingUsername,
        'Failed OTP verification',
        "Incorrect OTP. Failed attempts: {$newAttempts}/3",
        $currentIP,
        'OTP_FAILED'
    );


    // Third incorrect attempt: lock for 60 seconds.

    if ($isLockNow) {

        logActivity(
            $conn,
            $userId,
            $pendingUsername,
            'OTP verification locked',
            "OTP verification locked for 60 seconds after {$newAttempts} failed attempts.",
            $currentIP,
            'OTP_LOCKOUT'
        );

        try {

            $recipientEmail = (string)($otpRecord['email'] ?? '');
            $alertSent = filter_var(
                $recipientEmail,
                FILTER_VALIDATE_EMAIL
            ) && sendLockoutAlert(
                $recipientEmail,
                'otp',
                $pendingUsername,
                $currentIP,
                $newAttempts,
                3,
                (string)($_SERVER['HTTP_USER_AGENT'] ?? '')
            );

            logActivity(
                $conn,
                $userId,
                $pendingUsername,
                $alertSent
                    ? 'OTP lockout alert email sent'
                    : 'OTP lockout alert email failed',
                $alertSent
                    ? "OTP lockout alert sent to the affected account after {$newAttempts} failed attempts."
                    : "OTP lockout alert could not be sent after {$newAttempts} failed attempts.",
                $currentIP,
                $alertSent ? 'ALERT_EMAIL_SENT' : 'ALERT_EMAIL_FAILED'
            );

        } catch (Throwable $e) {

            error_log(
                'OTP lockout alert exception: ' . $e->getMessage()
            );
        }


        otpResponse([
            'success' => false,
            'message' => 'Too many incorrect OTP attempts. Please wait 60 seconds, then request a new code.',
            'lockedOut' => true,
            'remainingSeconds' => 60,
            'remainingAttempts' => 0
        ], 429);
    }


    $remaining = 3 - $newAttempts;

    otpResponse([
        'success' => false,
        'message' => 'Incorrect OTP. You have ' . $remaining . ' attempt(s) remaining.',
        'remainingAttempts' => $remaining
    ]);
}


// ==========================================
// CORRECT OTP: GET USER INFORMATION
// ==========================================

$stmt = $conn->prepare(
    'SELECT id, username, role, is_verified
     FROM users
     WHERE id = ?
     LIMIT 1'
);

if (!$stmt) {

    otpResponse([
        'success' => false,
        'message' => 'Unable to retrieve your account. Please try again.'
    ], 500);
}

$stmt->bind_param('i', $userId);

$stmt->execute();

$user = $stmt->get_result()->fetch_assoc();

$stmt->close();

// Check if user exists.

if (!$user) {

    logActivity(
        $conn,
        $userId,
        $pendingUsername,
        'OTP verification failed',
        'User account could not be found after OTP verification.',
        $currentIP,
        'otp_user_not_found'
    );

    clearPendingOTP();

    otpResponse([
        'success' => false,
        'message' => 'Account not found. Please try again.',
        'restartLogin' => true
    ]);
}


// Verify pending username matches database account.

if (!hash_equals(
    (string) $user['username'],
    (string) $pendingUsername
)) {

    clearPendingOTP();

    otpResponse([
        'success' => false,
        'message' => 'Your verification session is invalid. Please try again.',
        'restartLogin' => true
    ], 401);
}


// ==========================================
// REGISTRATION OTP SUCCESS
// ==========================================

if ($authType === 'registration') {

    // Only student accounts can use registration verification.

    if ($user['role'] !== 'student') {

        clearPendingOTP();

        otpResponse([
            'success' => false,
            'message' => 'Invalid registration verification session.',
            'restartLogin' => true
        ], 403);
    }


    // Verify the student account and remove the OTP atomically.

    try {

        if (!$conn->begin_transaction()) {
            throw new RuntimeException('Could not start verification transaction.');
        }

        $updateUser = $conn->prepare(
            'UPDATE users
            SET is_verified = 1
            WHERE id = ?
            AND role = ?
            AND is_verified = 0'
        );

        if (!$updateUser) {
            throw new RuntimeException('Could not prepare account verification.');
        }

        $studentRole = 'student';

        $updateUser->bind_param(
            'is',
            $userId,
            $studentRole
        );

        if (!$updateUser->execute()) {
            throw new RuntimeException('Could not verify student account.');
        }

        if ($updateUser->affected_rows !== 1) {
            $updateUser->close();

            throw new RuntimeException(
                'Account is already verified or is no longer eligible for verification.'
            );
        }

        $updateUser->close();

        $delete = $conn->prepare(
            'DELETE FROM login_otp WHERE user_id = ?'
        );

        if (!$delete) {
            throw new RuntimeException('Could not prepare OTP deletion.');
        }

        $delete->bind_param('i', $userId);

        if (!$delete->execute()) {
            throw new RuntimeException('Could not delete verified OTP.');
        }

        $delete->close();

        if (!$conn->commit()) {
            throw new RuntimeException('Could not commit verification transaction.');
        }

    } catch (Throwable $error) {

        $conn->rollback();

        error_log(
            'Registration OTP verification error: ' . $error->getMessage()
        );

        otpResponse([
            'success' => false,
            'message' => 'Unable to complete registration verification. Please try again.'
        ], 500);
    }


    // Record registration verification.

    logActivity(
        $conn,
        $userId,
        $user['username'],
        'Successful registration verification',
        'Student email OTP verified. Account is now verified.',
        $currentIP,
        'ACCOUNT_VERIFIED'
    );


    // IMPORTANT:
    // Do not create an authenticated login session here.

    clearPendingOTP();

    otpResponse([
        'success' => true,
        'message' => 'Your account has been successfully verified! You can now log in.',
        'registrationVerified' => true,
        'redirect' => '../html/Torino.html?mode=login&verified=1'
    ]);
}


// ==========================================
// LOGIN OTP SUCCESS
// ==========================================

// Prevent unverified students from logging in.

if ((int) $user['is_verified'] !== 1) {

    clearPendingOTP();

    otpResponse([
        'success' => false,
        'message' => 'Your account has not been verified yet. Please complete your registration verification.',
        'restartLogin' => true
    ], 403);
}


// ==========================================
// ESTABLISH LOGIN SESSION
// ==========================================

if (!in_array($user['role'], ['admin', 'student'], true)) {

    clearPendingOTP();

    otpResponse([
        'success' => false,
        'message' => 'Invalid account role. Please contact the administrator.',
        'restartLogin' => true
    ], 403);
}

$role = $user['role'];

$username = $user['username'];

$authenticatedUserId = (int) $user['id'];


// Delete verified OTP before establishing the login session.

$delete = $conn->prepare(
    'DELETE FROM login_otp WHERE user_id = ?'
);

if (!$delete) {
    otpResponse([
        'success' => false,
        'message' => 'Unable to complete OTP verification. Please try again.'
    ], 500);
}

$delete->bind_param('i', $authenticatedUserId);

if (!$delete->execute()) {
    $delete->close();

    otpResponse([
        'success' => false,
        'message' => 'Unable to complete OTP verification. Please try again.'
    ], 500);
}

$delete->close();


// Clear failed password attempts.

$clearAttempts = $conn->prepare(
    'DELETE FROM login_attempts
     WHERE username = ? AND ip_address = ?'
);

if ($clearAttempts) {

    $clearAttempts->bind_param(
        'ss',
        $username,
        $currentIP
    );

    $clearAttempts->execute();

    $clearAttempts->close();
}


// Move the authenticated session to a role-specific cookie.

if (!migrateSirsSessionToRole($role)) {
    otpResponse([
        'success' => false,
        'message' => 'Unable to start a secure login session. Please try again.'
    ], 500);
}


// Establish authenticated session.

$_SESSION['user_id'] = $authenticatedUserId;
$_SESSION['username'] = $username;
$_SESSION['role'] = $role;
$_SESSION['last_activity'] = time();


// Clear temporary OTP information.

clearPendingOTP();


// Record successful login OTP.

logActivity(
    $conn,
    $authenticatedUserId,
    $username,
    'Successful login',
    'Email OTP verified successfully. User authenticated.',
    $currentIP,
    'LOGIN_SUCCESS'
);


// Determine dashboard destination.

$redirect = ($role === 'admin')
    ? '../admin/admin_dashboard.php'
    : '../student/student_dashboard.php';


otpResponse([
    'success' => true,
    'message' => 'OTP verified successfully.',
    'redirect' => $redirect
]);
