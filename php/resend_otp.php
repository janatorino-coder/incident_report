
<?php

session_start();

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/mailer.php';

header('Content-Type: application/json; charset=utf-8');


// ==========================================
// SETTINGS
// ==========================================

const MAX_OTP_RESENDS = 3;
const OTP_RESEND_COOLDOWN = 60;


// ==========================================
// RESPONSE HELPER
// ==========================================

function resendResponse(
    bool $success,
    string $message,
    array $extra = [],
    int $status = 200
): never {

    global $conn;

    http_response_code($status);

    echo json_encode(array_merge([
        'success' => $success,
        'message' => $message
    ], $extra));

    if (isset($conn) && $conn instanceof mysqli) {
        $conn->close();
    }

    exit;
}


// ==========================================
// CLEAR PENDING SESSION
// ==========================================

function clearPendingResendSession(): void
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

$userId = (int)($_SESSION['pending_user_id'] ?? 0);

$pendingUsername = (string)(
    $_SESSION['pending_username'] ?? ''
);

$pendingIp = (string)(
    $_SESSION['pending_ip'] ?? ''
);

// Backward compatibility for older login sessions.
$authType = (string)(
    $_SESSION['pending_auth_type'] ?? 'login'
);

$currentIp = (string)(
    $_SERVER['REMOTE_ADDR'] ?? ''
);


// ==========================================
// VALIDATE PENDING SESSION
// ==========================================

if (
    $userId <= 0 ||
    $pendingUsername === '' ||
    $pendingIp === '' ||
    $pendingIp !== $currentIp ||
    !in_array($authType, ['login', 'registration'], true)
) {

    clearPendingResendSession();

    resendResponse(
        false,
        'Your verification session expired. Please try again.',
        [
            'restartLogin' => true
        ],
        401
    );
}


// ==========================================
// GET USER AND OTP INFORMATION
// ==========================================

$stmt = $conn->prepare(
    'SELECT
        u.username,
        u.email,
        u.role,
        u.is_verified,
        o.resend_count,
        TIMESTAMPDIFF(
            SECOND,
            o.last_sent_at,
            NOW()
        ) AS seconds_since_sent,
        (
            o.locked_until IS NOT NULL
            AND o.locked_until > NOW()
        ) AS is_locked,
        IFNULL(
            TIMESTAMPDIFF(
                SECOND,
                NOW(),
                o.locked_until
            ),
            0
        ) AS lock_remaining
     FROM users u
     INNER JOIN login_otp o
        ON o.user_id = u.id
     WHERE u.id = ?
     LIMIT 1'
);

if (!$stmt) {

    resendResponse(
        false,
        'Unable to process your request. Please try again.',
        [],
        500
    );
}

$stmt->bind_param('i', $userId);

if (!$stmt->execute()) {

    $stmt->close();

    resendResponse(
        false,
        'Unable to retrieve your verification information. Please try again.',
        [],
        500
    );
}

$row = $stmt->get_result()->fetch_assoc();

$stmt->close();


// ==========================================
// CHECK ACCOUNT AND OTP RECORD
// ==========================================

if (!$row) {

    if ($authType === 'login') {

        clearPendingResendSession();

        resendResponse(
            false,
            'Your login session expired. Please log in again.',
            [
                'restartLogin' => true
            ]
        );
    }

    // Keep registration session to avoid duplicate registration.

    resendResponse(
        false,
        'Your registration verification code is unavailable. Please contact the system administrator.',
        [
            'resendLimitReached' => true
        ]
    );
}


// ==========================================
// VERIFY PENDING USERNAME
// ==========================================

if (!hash_equals(
    $pendingUsername,
    (string)$row['username']
)) {

    clearPendingResendSession();

    resendResponse(
        false,
        'Your verification session is invalid. Please try again.',
        [
            'restartLogin' => true
        ],
        401
    );
}


// ==========================================
// CHECK VERIFICATION PURPOSE
// ==========================================

if ($authType === 'registration') {

    // Only unverified student accounts can receive
    // registration verification OTPs.

    if (
        $row['role'] !== 'student' ||
        (int)$row['is_verified'] === 1
    ) {

        clearPendingResendSession();

        resendResponse(
            false,
            'This account is already verified or is not eligible for registration verification.',
            [
                'registrationVerified' =>
                    (int)$row['is_verified'] === 1,
                'restartLogin' => true
            ]
        );
    }

} else {

    // Login OTP must only be sent to verified accounts.

    if ((int)$row['is_verified'] !== 1) {

        clearPendingResendSession();

        resendResponse(
            false,
            'Your account is not verified. Please complete registration verification first.',
            [
                'restartLogin' => true
            ],
            403
        );
    }
}


// ==========================================
// CHECK OTP LOCKOUT
// ==========================================

if ((int)$row['is_locked'] === 1) {

    $remaining = max(
        1,
        (int)$row['lock_remaining']
    );

    resendResponse(
        false,
        "Too many incorrect attempts. Please wait {$remaining} seconds before requesting a new code.",
        [
            'lockedOut' => true,
            'remainingSeconds' => $remaining
        ],
        429
    );
}


// ==========================================
// CHECK RESEND LIMIT
// ==========================================

if ((int)$row['resend_count'] >= MAX_OTP_RESENDS) {

    if ($authType === 'login') {

        clearPendingResendSession();

        resendResponse(
            false,
            'You have reached the maximum number of resend requests. Please log in again.',
            [
                'restartLogin' => true
            ]
        );
    }

    // Preserve registration session so the student
    // does not need to register again.

    resendResponse(
        false,
        'You have reached the maximum number of verification code resend requests. Please contact the system administrator for assistance.',
        [
            'resendLimitReached' => true
        ],
        429
    );
}


// ==========================================
// CHECK 60-SECOND RESEND COOLDOWN
// ==========================================

$elapsed = max(
    0,
    (int)$row['seconds_since_sent']
);

if ($elapsed < OTP_RESEND_COOLDOWN) {

    $remaining = OTP_RESEND_COOLDOWN - $elapsed;

    resendResponse(
        false,
        "Please wait {$remaining} seconds before requesting another code.",
        [
            'remainingSeconds' => $remaining
        ],
        429
    );
}


// ==========================================
// VALIDATE REGISTERED EMAIL
// ==========================================

$email = (string)$row['email'];

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {

    resendResponse(
        false,
        'Your registered email address is invalid.'
    );
}


// ==========================================
// GENERATE NEW OTP
// ==========================================

$otp = (string)random_int(100000, 999999);

$otpHash = password_hash(
    $otp,
    PASSWORD_DEFAULT
);

if ($otpHash === false) {

    resendResponse(
        false,
        'Unable to generate a verification code. Please try again.',
        [],
        500
    );
}


// ==========================================
// SET OTP EXPIRATION
// ==========================================

$expirationMinutes = (
    $authType === 'registration'
) ? 4 : 1;


// ==========================================
// UPDATE OTP RECORD FIRST
// ==========================================

// The conditional UPDATE helps prevent simultaneous
// resend requests from bypassing the cooldown or limit.

$update = $conn->prepare(
    'UPDATE login_otp
     SET otp_hash = ?,
         expires_at = DATE_ADD(
             NOW(),
             INTERVAL ? MINUTE
         ),
         attempts = 0,
         locked_until = NULL,
         resend_count = resend_count + 1,
         last_sent_at = NOW()
     WHERE user_id = ?
       AND resend_count < ?
       AND last_sent_at <= DATE_SUB(
           NOW(),
           INTERVAL ? SECOND
       )
       AND (
           locked_until IS NULL
           OR locked_until <= NOW()
       )'
);

if (!$update) {

    error_log(
        'OTP resend preparation failed: ' . $conn->error
    );

    resendResponse(
        false,
        'Unable to update your verification code. Please try again.',
        [],
        500
    );
}

$maxResends = MAX_OTP_RESENDS;

$cooldown = OTP_RESEND_COOLDOWN;

$update->bind_param(
    'siiii',
    $otpHash,
    $expirationMinutes,
    $userId,
    $maxResends,
    $cooldown
);

if (!$update->execute()) {

    error_log(
        'OTP resend update failed: ' . $update->error
    );

    $update->close();

    resendResponse(
        false,
        'Unable to update your verification code. Please try again.',
        [],
        500
    );
}

$updatedRows = $update->affected_rows;

$update->close();


// ==========================================
// CHECK IF OTP RECORD WAS UPDATED
// ==========================================

if ($updatedRows !== 1) {

    resendResponse(
        false,
        'Your resend request could not be processed. Please wait before trying again.',
        [
            'remainingSeconds' => OTP_RESEND_COOLDOWN
        ],
        429
    );
}


// ==========================================
// SEND OTP BASED ON PURPOSE
// ==========================================

try {

    if ($authType === 'registration') {

        $emailSent = sendRegistrationOTP(
            $email,
            $otp
        );

    } else {

        $emailSent = sendLoginOTP(
            $email,
            $otp
        );
    }

} catch (Throwable $e) {

    error_log(
        'OTP resend email error: ' . $e->getMessage()
    );

    $emailSent = false;
}


// ==========================================
// CHECK EMAIL DELIVERY RESULT
// ==========================================

if (!$emailSent) {

    // The new OTP is already stored in the database.
    // The user can request another one after 60 seconds.

    resendResponse(
        false,
        'The verification code could not be emailed. Please wait 60 seconds before requesting another code.',
        [
            'emailFailed' => true,
            'remainingSeconds' => OTP_RESEND_COOLDOWN
        ],
        500
    );
}


// ==========================================
// SUCCESS RESPONSE
// ==========================================

$expirationSeconds = $expirationMinutes * 60;

resendResponse(
    true,
    'A new verification code has been sent to your registered email address.',
    [
        'otpRequired' => true,
        'authType' => $authType,
        'remainingSeconds' => OTP_RESEND_COOLDOWN,
        'expirationSeconds' => $expirationSeconds
    ]
);

