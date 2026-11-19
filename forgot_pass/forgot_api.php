
<?php
/**
 * Incident Hub - Forgot Password API
 *
 * Flow:
 * start -> questions -> otp -> change -> done
 */

session_start();

require_once __DIR__ . '/../php/config.php';
require_once __DIR__ . '/../php/activity_logger.php';
require_once __DIR__ . '/../php/mailer.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate');

const RS_MAX_ATTEMPTS = 3;
const RS_LOCKOUT_TIERS = [15, 30, 60];

const RS_CAPTCHA_EXPIRY = 300;
const RS_OTP_LIFETIME = 300;
const RS_OTP_MAX_ATTEMPTS = 3;
const RS_OTP_LOCK_SECONDS = 60;
const RS_RESEND_WAIT = 60;
const RS_RESEND_MAX = 3;

const RS_FLOW_LIFETIME = 900;
const RS_CHANGE_WINDOW = 600;

const RS_OWNER_EMAIL = 'jana.torino@csucc.edu.ph';

/*
 * Question code-to-label mapping.
 * Only questions actually registered by the student
 * will be displayed.
 */
const RS_QUESTIONS = [
    '1' => 'What was the name of your first pet?',
    '4' => "What is your mother's maiden first name?",
    '8' => 'What dish did you cook for the first time?'
];

/* ---------------------------------------------------------
   GENERAL HELPERS
--------------------------------------------------------- */

function respond(array $data, int $status = 200): never
{
    http_response_code($status);
    echo json_encode($data);
    exit;
}

function clientIp(): string
{
    return substr($_SERVER['REMOTE_ADDR'] ?? 'unknown', 0, 45);
}

function clearResetFlow(): void
{
    unset(
        $_SESSION['reset_stage'],
        $_SESSION['reset_user_id'],
        $_SESSION['reset_username'],
        $_SESSION['reset_ip'],
        $_SESSION['reset_started'],
        $_SESSION['reset_verified_at'],
        $_SESSION['reset_questions']
    );
}

function restartFlow(string $message): never
{
    clearResetFlow();

    respond([
        'success' => false,
        'message' => $message,
        'restart' => true,
        'refreshCaptcha' => true
    ]);
}

function requireStage(string $stage): void
{
    if (
        ($_SESSION['reset_stage'] ?? '') !== $stage ||
        ($_SESSION['reset_ip'] ?? '') !== clientIp() ||
        (time() - (int)($_SESSION['reset_started'] ?? 0)) > RS_FLOW_LIFETIME
    ) {
        restartFlow('Your session has expired. Please start again.');
    }
}

function query(
    mysqli $conn,
    string $sql,
    string $types = '',
    array $params = []
): mysqli_stmt {
    $stmt = $conn->prepare($sql);

    if (!$stmt) {
        throw new RuntimeException(
            'Database prepare failed: ' . $conn->error
        );
    }

    if ($types !== '') {
        $stmt->bind_param($types, ...$params);
    }

    if (!$stmt->execute()) {
        $error = $stmt->error;
        $stmt->close();

        throw new RuntimeException(
            'Database execute failed: ' . $error
        );
    }

    return $stmt;
}

function fetchRow(
    mysqli $conn,
    string $sql,
    string $types = '',
    array $params = []
): ?array {
    $stmt = query($conn, $sql, $types, $params);
    $result = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    return $result ?: null;
}

function executeQuery(
    mysqli $conn,
    string $sql,
    string $types = '',
    array $params = []
): void {
    query($conn, $sql, $types, $params)->close();
}

function normalizeAnswer(string $answer): string
{
    $answer = mb_strtolower(trim($answer), 'UTF-8');

    return preg_replace('/\s+/u', ' ', $answer);
}

function dummyHash(): string
{
    static $hash = null;

    if ($hash === null) {
        $hash = password_hash(
            'dummy-answer-value',
            PASSWORD_DEFAULT
        );
    }

    return $hash;
}

function maskEmail(string $email): string
{
    $parts = explode('@', $email, 2);

    if (count($parts) !== 2) {
        return 'your registered email';
    }

    $name = $parts[0];

    return substr($name, 0, 1)
        . str_repeat('*', max(2, strlen($name) - 1))
        . '@' . $parts[1];
}

/* ---------------------------------------------------------
   REGISTERED SECURITY QUESTIONS
--------------------------------------------------------- */

/**
 * Return only the security questions registered by this user.
 *
 * Unknown users receive the same generic question choices
 * so the API does not reveal whether an account exists.
 */
function getResetQuestions(
    mysqli $conn,
    int $userId
): array {
    if ($userId <= 0) {
        return RS_QUESTIONS;
    }

    $stmt = query(
        $conn,
        'SELECT question_code
         FROM student_security_questions
         WHERE user_id = ?
         ORDER BY question_code ASC',
        'i',
        [$userId]
    );

    $rows = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
    $stmt->close();

    $questions = [];

    foreach ($rows as $row) {
        $code = (string)$row['question_code'];

        if (isset(RS_QUESTIONS[$code])) {
            $questions[$code] = RS_QUESTIONS[$code];
        }
    }

    return $questions;
}

/* ---------------------------------------------------------
   SHARED LOGIN LOCKOUT
--------------------------------------------------------- */

function lockRemaining(
    mysqli $conn,
    string $username,
    string $ip
): int {
    $record = fetchRow(
        $conn,
        'SELECT failed_attempts,
                TIMESTAMPDIFF(SECOND, last_failed_at, NOW()) AS elapsed
         FROM login_attempts
         WHERE username = ? AND ip_address = ?
         LIMIT 1',
        'ss',
        [$username, $ip]
    );

    if (!$record) {
        return 0;
    }

    $count = (int)$record['failed_attempts'];

    if (
        $count < RS_MAX_ATTEMPTS ||
        $count % RS_MAX_ATTEMPTS !== 0
    ) {
        return 0;
    }

    $tier = min(
        count(RS_LOCKOUT_TIERS) - 1,
        intdiv($count - 1, RS_MAX_ATTEMPTS)
    );

    $duration = RS_LOCKOUT_TIERS[$tier];
    $elapsed = (int)$record['elapsed'];

    return max(0, $duration - $elapsed);
}

function recordFailure(
    mysqli $conn,
    string $username,
    string $ip,
    ?int $userId
): int {
    executeQuery(
        $conn,
        'INSERT INTO login_attempts
            (username, ip_address, failed_attempts, last_failed_at)
         VALUES (?, ?, 1, NOW())
         ON DUPLICATE KEY UPDATE
            failed_attempts = failed_attempts + 1,
            last_failed_at = NOW()',
        'ss',
        [$username, $ip]
    );

    $record = fetchRow(
        $conn,
        'SELECT failed_attempts
         FROM login_attempts
         WHERE username = ? AND ip_address = ?
         LIMIT 1',
        'ss',
        [$username, $ip]
    );

    $count = (int)($record['failed_attempts'] ?? 1);

    if ($userId !== null) {
        logActivity(
            $conn,
            $userId,
            $username,
            'Failed password reset',
            "Incorrect security answer. IP: {$ip}. Attempts: {$count}",
            $ip,
            'failed_reset'
        );
    }

    if ($count % RS_MAX_ATTEMPTS === 0) {
        try {
            sendOwnerLockoutAlert(
                RS_OWNER_EMAIL,
                'reset',
                $username,
                $ip,
                $count,
                RS_MAX_ATTEMPTS
            );
        } catch (Throwable $e) {
            error_log(
                'Reset lockout email error: ' . $e->getMessage()
            );
        }
    }

    return $count;
}

function failSecurityAnswer(mysqli $conn): never
{
    $username = (string)$_SESSION['reset_username'];
    $userId = (int)$_SESSION['reset_user_id'];

    $count = recordFailure(
        $conn,
        $username,
        clientIp(),
        $userId > 0 ? $userId : null
    );

    if (
        $count >= RS_MAX_ATTEMPTS &&
        $count % RS_MAX_ATTEMPTS === 0
    ) {
        $tier = min(
            count(RS_LOCKOUT_TIERS) - 1,
            intdiv($count - 1, RS_MAX_ATTEMPTS)
        );

        $seconds = RS_LOCKOUT_TIERS[$tier];

        clearResetFlow();

        respond([
            'success' => false,
            'message' => "Too many failed attempts. Please wait {$seconds} seconds.",
            'lockedOut' => true,
            'restart' => true,
            'remainingSeconds' => $seconds,
            'refreshCaptcha' => true
        ]);
    }

    $remaining = RS_MAX_ATTEMPTS - ($count % RS_MAX_ATTEMPTS);

    respond([
        'success' => false,
        'message' => "The information you provided is incorrect. {$remaining} attempt(s) remaining.",
        'remainingAttempts' => $remaining
    ]);
}

/* ---------------------------------------------------------
   CURRENT FLOW STATE
--------------------------------------------------------- */

function currentState(mysqli $conn): array
{
    $stage = $_SESSION['reset_stage'] ?? '';

    if (
        !$stage ||
        ($_SESSION['reset_ip'] ?? '') !== clientIp() ||
        (time() - (int)($_SESSION['reset_started'] ?? 0)) > RS_FLOW_LIFETIME
    ) {
        clearResetFlow();

        return [
            'success' => true,
            'stage' => 'start'
        ];
    }

    if ($stage === 'questions') {
        return [
            'success' => true,
            'stage' => 'questions',
            'questions' => $_SESSION['reset_questions'] ?? RS_QUESTIONS
        ];
    }

    if ($stage === 'otp') {
        $userId = (int)$_SESSION['reset_user_id'];

        $record = fetchRow(
            $conn,
            'SELECT u.email, o.attempts,
                    GREATEST(0, TIMESTAMPDIFF(SECOND, NOW(), o.expires_at)) AS expires_in,
                    GREATEST(0, ' . RS_RESEND_WAIT . ' -
                        TIMESTAMPDIFF(SECOND, o.last_sent_at, NOW())) AS resend_in,
                    IF(o.locked_until IS NOT NULL AND o.locked_until > NOW(),
                        TIMESTAMPDIFF(SECOND, NOW(), o.locked_until), 0) AS lock_in
             FROM users u
             INNER JOIN password_reset_otp o ON o.user_id = u.id
             WHERE u.id = ?
             LIMIT 1',
            'i',
            [$userId]
        );

        if (!$record) {
            clearResetFlow();

            return [
                'success' => true,
                'stage' => 'start'
            ];
        }

        return [
            'success' => true,
            'stage' => 'otp',
            'maskedEmail' => maskEmail($record['email']),
            'expiresIn' => (int)$record['expires_in'],
            'resendIn' => (int)$record['resend_in'],
            'lockIn' => (int)$record['lock_in'],
            'exhausted' => (int)$record['attempts'] >= RS_OTP_MAX_ATTEMPTS
        ];
    }

    if ($stage === 'change') {
        if (
            time() - (int)($_SESSION['reset_verified_at'] ?? 0)
            > RS_CHANGE_WINDOW
        ) {
            clearResetFlow();

            return [
                'success' => true,
                'stage' => 'start'
            ];
        }

        return [
            'success' => true,
            'stage' => 'change'
        ];
    }

    clearResetFlow();

    return [
        'success' => true,
        'stage' => 'start'
    ];
}

/* ---------------------------------------------------------
   STEP 1: USERNAME + CAPTCHA
--------------------------------------------------------- */

function actionStart(mysqli $conn): never
{
    $username = trim((string)($_POST['username'] ?? ''));
    $captcha = strtoupper(trim((string)($_POST['captcha'] ?? '')));
    $ip = clientIp();

    if (strlen($username) < 6 || strlen($username) > 50) {
        respond([
            'success' => false,
            'message' => 'Please enter a valid username.'
        ]);
    }

    $captchaHash = $_SESSION['captcha_hash'] ?? null;
    $captchaCreated = (int)($_SESSION['captcha_created'] ?? 0);

    unset(
        $_SESSION['captcha_hash'],
        $_SESSION['captcha_created']
    );

    if (
        !$captchaHash ||
        !$captchaCreated ||
        time() - $captchaCreated > RS_CAPTCHA_EXPIRY ||
        $captcha === '' ||
        !password_verify($captcha, (string)$captchaHash)
    ) {
        respond([
            'success' => false,
            'message' => 'Incorrect or expired CAPTCHA. Please try again.',
            'refreshCaptcha' => true
        ]);
    }

    clearResetFlow();

    $lock = lockRemaining($conn, $username, $ip);

    if ($lock > 0) {
        respond([
            'success' => false,
            'message' => "Too many failed attempts. Please wait {$lock} seconds.",
            'lockedOut' => true,
            'remainingSeconds' => $lock,
            'refreshCaptcha' => true
        ]);
    }

    /*
     * Password recovery is for student accounts.
     * An unknown username and a non-student account
     * receive the same generic response.
     */
    $user = fetchRow(
        $conn,
        'SELECT id
         FROM users
         WHERE username = ? AND role = "student"
         LIMIT 1',
        's',
        [$username]
    );

    $userId = $user ? (int)$user['id'] : 0;

    $questions = getResetQuestions($conn, $userId);

    /*
     * Store the permitted question codes in the session.
     * The answer endpoint will validate against this list.
     */
    session_regenerate_id(true);

    $_SESSION['reset_stage'] = 'questions';
    $_SESSION['reset_user_id'] = $userId;
    $_SESSION['reset_username'] = $username;
    $_SESSION['reset_ip'] = $ip;
    $_SESSION['reset_started'] = time();
    $_SESSION['reset_questions'] = $questions;

    respond([
        'success' => true,
        'stage' => 'questions',
        'questions' => $questions,
        'refreshCaptcha' => true
    ]);
}

/* ---------------------------------------------------------
   STEP 2: SECURITY QUESTION + ANSWERS
--------------------------------------------------------- */

function actionAnswer(mysqli $conn): never
{
    requireStage('questions');

    $username = (string)$_SESSION['reset_username'];
    $userId = (int)$_SESSION['reset_user_id'];
    $ip = clientIp();

    $lock = lockRemaining($conn, $username, $ip);

    if ($lock > 0) {
        clearResetFlow();

        respond([
            'success' => false,
            'message' => "Too many failed attempts. Please wait {$lock} seconds.",
            'lockedOut' => true,
            'restart' => true,
            'remainingSeconds' => $lock,
            'refreshCaptcha' => true
        ]);
    }

    $code = trim((string)($_POST['question_code'] ?? ''));
    $answer = normalizeAnswer((string)($_POST['answer'] ?? ''));
    $confirmAnswer = normalizeAnswer(
        (string)($_POST['confirm_answer'] ?? '')
    );

    $allowedQuestions = $_SESSION['reset_questions'] ?? [];

    if (
        !is_array($allowedQuestions) ||
        !array_key_exists($code, $allowedQuestions)
    ) {
        respond([
            'success' => false,
            'message' => 'Please select a valid security question.'
        ]);
    }

    if ($answer === '' || $confirmAnswer === '') {
        respond([
            'success' => false,
            'message' => 'Please enter and re-enter your answer.'
        ]);
    }

    /*
     * Check that both answers match BEFORE checking
     * the saved security answer.
     */
    if (!hash_equals($answer, $confirmAnswer)) {
        respond([
            'success' => false,
            'message' => 'Your answers do not match.'
        ]);
    }

    $savedHash = null;

    if ($userId > 0) {
        $record = fetchRow(
            $conn,
            'SELECT answer_hash
             FROM student_security_questions
             WHERE user_id = ? AND question_code = ?
             LIMIT 1',
            'is',
            [$userId, $code]
        );

        $savedHash = $record['answer_hash'] ?? null;
    }

    $matches = password_verify(
        $answer,
        $savedHash ?? dummyHash()
    );

    if ($savedHash === null || !$matches) {
        failSecurityAnswer($conn);
    }

    $user = fetchRow(
        $conn,
        'SELECT email
         FROM users
         WHERE id = ? AND role = "student"
         LIMIT 1',
        'i',
        [$userId]
    );

    $email = trim((string)($user['email'] ?? ''));

    if (!$user || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        respond([
            'success' => false,
            'message' => 'Your account has no valid registered email. Please contact the administrator.'
        ]);
    }

    $otp = (string)random_int(100000, 999999);
    $otpHash = password_hash($otp, PASSWORD_DEFAULT);

    executeQuery(
        $conn,
        'INSERT INTO password_reset_otp
            (user_id, otp_hash, expires_at, attempts, resend_count, last_sent_at, locked_until)
         VALUES (?, ?, DATE_ADD(NOW(), INTERVAL ' . RS_OTP_LIFETIME . ' SECOND),
                 0, 0, NOW(), NULL)
         ON DUPLICATE KEY UPDATE
            otp_hash = VALUES(otp_hash),
            expires_at = VALUES(expires_at),
            attempts = 0,
            resend_count = 0,
            last_sent_at = NOW(),
            locked_until = NULL',
        'is',
        [$userId, $otpHash]
    );

    if (!sendResetOTP($email, $otp)) {
        executeQuery(
            $conn,
            'DELETE FROM password_reset_otp WHERE user_id = ?',
            'i',
            [$userId]
        );

        respond([
            'success' => false,
            'message' => 'Unable to send the verification code. Please try again.'
        ]);
    }

    $_SESSION['reset_stage'] = 'otp';

    logActivity(
        $conn,
        $userId,
        $username,
        'Password reset OTP sent',
        'Security answer verified. Reset OTP sent.',
        $ip,
        'reset_otp_sent'
    );

    respond([
        'success' => true,
        'stage' => 'otp',
        'maskedEmail' => maskEmail($email),
        'expiresIn' => RS_OTP_LIFETIME,
        'resendIn' => RS_RESEND_WAIT,
        'lockIn' => 0,
        'exhausted' => false
    ]);
}

/* ---------------------------------------------------------
   STEP 3: VERIFY OTP
--------------------------------------------------------- */

function actionVerifyOtp(mysqli $conn): never
{
    requireStage('otp');

    $userId = (int)$_SESSION['reset_user_id'];
    $username = (string)$_SESSION['reset_username'];
    $ip = clientIp();

    $otp = trim((string)($_POST['otp'] ?? ''));

    if (!preg_match('/^\d{6}$/', $otp)) {
        respond([
            'success' => false,
            'message' => 'Please enter a valid 6-digit code.'
        ]);
    }

    $record = fetchRow(
        $conn,
        'SELECT otp_hash, attempts,
                (expires_at > NOW()) AS is_valid,
                (locked_until IS NOT NULL AND locked_until > NOW()) AS is_locked,
                GREATEST(0, TIMESTAMPDIFF(SECOND, NOW(), locked_until)) AS lock_remaining
         FROM password_reset_otp
         WHERE user_id = ?
         LIMIT 1',
        'i',
        [$userId]
    );

    if (!$record) {
        restartFlow(
            'Your verification code is no longer available. Please start again.'
        );
    }

    if ((int)$record['is_locked']) {
        $seconds = max(1, (int)$record['lock_remaining']);

        respond([
            'success' => false,
            'message' => "Too many incorrect codes. Please wait {$seconds} seconds.",
            'lockedOut' => true,
            'remainingSeconds' => $seconds,
            'needResend' => true
        ]);
    }

    if ((int)$record['attempts'] >= RS_OTP_MAX_ATTEMPTS) {
        respond([
            'success' => false,
            'message' => 'Please request a new verification code.',
            'needResend' => true
        ]);
    }

    if (!(int)$record['is_valid']) {
        respond([
            'success' => false,
            'message' => 'Your code has expired. Please request a new one.',
            'needResend' => true
        ]);
    }

    if (!password_verify($otp, (string)$record['otp_hash'])) {
        $attempts = (int)$record['attempts'] + 1;

        $lockedUntil = $attempts >= RS_OTP_MAX_ATTEMPTS
            ? 'DATE_ADD(NOW(), INTERVAL ' . RS_OTP_LOCK_SECONDS . ' SECOND)'
            : 'NULL';

        executeQuery(
            $conn,
            "UPDATE password_reset_otp
             SET attempts = ?,
                 locked_until = {$lockedUntil}
             WHERE user_id = ?",
            'ii',
            [$attempts, $userId]
        );

        logActivity(
            $conn,
            $userId,
            $username,
            'Failed reset OTP verification',
            "Incorrect reset OTP. IP: {$ip}. Attempts: {$attempts}",
            $ip,
            'failed_reset_otp'
        );

        if ($attempts >= RS_OTP_MAX_ATTEMPTS) {
            try {
                sendOwnerLockoutAlert(
                    RS_OWNER_EMAIL,
                    'otp',
                    $username,
                    $ip,
                    $attempts,
                    RS_OTP_MAX_ATTEMPTS
                );
            } catch (Throwable $e) {
                error_log(
                    'Reset OTP lockout email error: ' . $e->getMessage()
                );
            }

            respond([
                'success' => false,
                'message' => 'Too many incorrect codes. Please wait 60 seconds, then request a new code.',
                'lockedOut' => true,
                'remainingSeconds' => RS_OTP_LOCK_SECONDS,
                'needResend' => true
            ]);
        }

        $remaining = RS_OTP_MAX_ATTEMPTS - $attempts;

        respond([
            'success' => false,
            'message' => "Incorrect code. {$remaining} attempt(s) remaining.",
            'remainingAttempts' => $remaining
        ]);
    }

    /*
     * Consume the OTP after successful verification.
     * It cannot be used again.
     */
    executeQuery(
        $conn,
        'DELETE FROM password_reset_otp WHERE user_id = ?',
        'i',
        [$userId]
    );

    $_SESSION['reset_stage'] = 'change';
    $_SESSION['reset_verified_at'] = time();

    logActivity(
        $conn,
        $userId,
        $username,
        'Password reset OTP verified',
        'Reset OTP verified successfully.',
        $ip,
        'reset_otp_verified'
    );

    respond([
        'success' => true,
        'stage' => 'change'
    ]);
}

/* ---------------------------------------------------------
   RESEND OTP
--------------------------------------------------------- */

function actionResendOtp(mysqli $conn): never
{
    requireStage('otp');

    $userId = (int)$_SESSION['reset_user_id'];

    $record = fetchRow(
        $conn,
        'SELECT u.email, o.resend_count,
                TIMESTAMPDIFF(SECOND, o.last_sent_at, NOW()) AS elapsed,
                (o.locked_until IS NOT NULL AND o.locked_until > NOW()) AS is_locked,
                GREATEST(0, TIMESTAMPDIFF(SECOND, NOW(), o.locked_until)) AS lock_remaining
         FROM users u
         INNER JOIN password_reset_otp o ON o.user_id = u.id
         WHERE u.id = ?
         LIMIT 1',
        'i',
        [$userId]
    );

    if (!$record) {
        restartFlow('Your session expired. Please start again.');
    }

    if ((int)$record['is_locked']) {
        $seconds = max(1, (int)$record['lock_remaining']);

        respond([
            'success' => false,
            'message' => "Please wait {$seconds} seconds before requesting a new code.",
            'lockedOut' => true,
            'remainingSeconds' => $seconds
        ]);
    }

    if ((int)$record['resend_count'] >= RS_RESEND_MAX) {
        restartFlow(
            'You have reached the maximum number of resend requests. Please start again.'
        );
    }

    $elapsed = max(0, (int)$record['elapsed']);

    if ($elapsed < RS_RESEND_WAIT) {
        $seconds = RS_RESEND_WAIT - $elapsed;

        respond([
            'success' => false,
            'message' => "Please wait {$seconds} seconds before requesting another code.",
            'remainingSeconds' => $seconds
        ]);
    }

    $otp = (string)random_int(100000, 999999);
    $hash = password_hash($otp, PASSWORD_DEFAULT);

    if (!sendResetOTP((string)$record['email'], $otp)) {
        respond([
            'success' => false,
            'message' => 'Unable to send the new code. Please try again.'
        ]);
    }

    executeQuery(
        $conn,
        'UPDATE password_reset_otp
         SET otp_hash = ?,
             expires_at = DATE_ADD(NOW(), INTERVAL ' . RS_OTP_LIFETIME . ' SECOND),
             attempts = 0,
             locked_until = NULL,
             resend_count = resend_count + 1,
             last_sent_at = NOW()
         WHERE user_id = ?',
        'si',
        [$hash, $userId]
    );

    respond([
        'success' => true,
        'message' => 'A new verification code has been sent.',
        'expiresIn' => RS_OTP_LIFETIME,
        'resendIn' => RS_RESEND_WAIT
    ]);
}

/* ---------------------------------------------------------
   PASSWORD VALIDATION
   Matches registration password rules.
--------------------------------------------------------- */

function passwordProblem(
    string $password,
    string $username
): ?string {
    $length = strlen($password);

    if ($length < 8 || $length > 64) {
        return 'Password must be between 8 and 64 characters.';
    }

    $score = 0;

    if (preg_match('/[a-z]/', $password)) {
        $score++;
    }

    if (preg_match('/[A-Z]/', $password)) {
        $score++;
    }

    if (preg_match('/[0-9]/', $password)) {
        $score++;
    }

    if (preg_match('/[^A-Za-z0-9]/', $password)) {
        $score++;
    }

    if ($score < 3) {
        return 'Your password is too weak. Use at least 3 character types.';
    }

    if (
        $username !== '' &&
        stripos($password, $username) !== false
    ) {
        return 'Password must not contain your username.';
    }

    return null;
}

/* ---------------------------------------------------------
   STEP 4: CHANGE PASSWORD
--------------------------------------------------------- */

function actionChange(mysqli $conn): never
{
    requireStage('change');

    if (
        time() - (int)($_SESSION['reset_verified_at'] ?? 0)
        > RS_CHANGE_WINDOW
    ) {
        restartFlow(
            'Your verification has expired. Please start again.'
        );
    }

    $userId = (int)$_SESSION['reset_user_id'];
    $username = (string)$_SESSION['reset_username'];
    $ip = clientIp();

    $newPassword = (string)($_POST['password'] ?? '');
    $confirmPassword = (string)($_POST['confirm'] ?? '');

    if ($newPassword !== $confirmPassword) {
        respond([
            'success' => false,
            'message' => 'Mismatch Password'
        ]);
    }

    $problem = passwordProblem($newPassword, $username);

    if ($problem !== null) {
        respond([
            'success' => false,
            'message' => $problem
        ]);
    }

    $conn->begin_transaction();

    try {
        /*
         * Lock the user row while checking and changing
         * the password.
         */
        $user = fetchRow(
            $conn,
            'SELECT password, email
             FROM users
             WHERE id = ? AND role = "student"
             LIMIT 1
             FOR UPDATE',
            'i',
            [$userId]
        );

        if (!$user) {
            throw new RuntimeException('Reset account unavailable.');
        }

        /*
         * Current password + two previous password hashes
         * represent the last three passwords.
         */
        $blockedHashes = [
            (string)$user['password']
        ];

        $stmt = query(
            $conn,
            'SELECT password_hash
             FROM password_history
             WHERE user_id = ?
             ORDER BY id DESC
             LIMIT 2',
            'i',
            [$userId]
        );

        $historyRows = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
        $stmt->close();

        foreach ($historyRows as $history) {
            $blockedHashes[] = (string)$history['password_hash'];
        }

        foreach ($blockedHashes as $oldHash) {
            if (
                $oldHash !== '' &&
                password_verify($newPassword, $oldHash)
            ) {
                $conn->rollback();

                respond([
                    'success' => false,
                    'message' => 'You cannot reuse a recent password.'
                ]);
            }
        }

        $newHash = password_hash(
            $newPassword,
            PASSWORD_DEFAULT
        );

        /*
         * Save the old password before updating it.
         */
        executeQuery(
            $conn,
            'INSERT INTO password_history
                (user_id, password_hash)
             VALUES (?, ?)',
            'is',
            [$userId, (string)$user['password']]
        );

        executeQuery(
            $conn,
            'UPDATE users
             SET password = ?
             WHERE id = ?',
            'si',
            [$newHash, $userId]
        );

        /*
         * Keep only the two most recent old passwords.
         */
        executeQuery(
            $conn,
            'DELETE FROM password_history
             WHERE user_id = ?
             AND id NOT IN (
                 SELECT id FROM (
                     SELECT id
                     FROM password_history
                     WHERE user_id = ?
                     ORDER BY id DESC
                     LIMIT 2
                 ) AS recent_passwords
             )',
            'ii',
            [$userId, $userId]
        );

        executeQuery(
            $conn,
            'DELETE FROM login_attempts
             WHERE username = ?',
            's',
            [$username]
        );

        /*
         * Ensure any remaining reset OTP is invalidated.
         */
        executeQuery(
            $conn,
            'DELETE FROM password_reset_otp
             WHERE user_id = ?',
            'i',
            [$userId]
        );

        $conn->commit();

    } catch (Throwable $e) {
        if ($conn->errno === 0) {
            // The transaction may already have been rolled back.
        }

        try {
            $conn->rollback();
        } catch (Throwable $rollbackError) {
            error_log(
                'Password reset rollback error: '
                . $rollbackError->getMessage()
            );
        }

        error_log(
            'Forgot password update error: ' . $e->getMessage()
        );

        respond([
            'success' => false,
            'message' => 'Unable to change your password. Please try again.'
        ]);
    }

    logActivity(
        $conn,
        $userId,
        $username,
        'Password reset',
        'Password changed through Forgot Password.',
        $ip,
        'password_reset'
    );

    try {
        if (
            !sendPasswordChangedNotice(
                (string)$user['email'],
                $username
            )
        ) {
            error_log(
                'Password changed notification email was not sent.'
            );
        }
    } catch (Throwable $e) {
        error_log(
            'Password changed notification error: '
            . $e->getMessage()
        );
    }

    /*
     * Clear authorization after a successful password change.
     * Reloading or going back cannot reuse this reset session.
     */
    clearResetFlow();

    respond([
        'success' => true,
        'stage' => 'done',
        'message' => 'Successfully Change Password',
        'redirect' => '../html/Torino.html?mode=login'
    ]);
}

/* ---------------------------------------------------------
   REQUEST DISPATCH
--------------------------------------------------------- */

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    respond([
        'success' => false,
        'message' => 'Invalid request.'
    ], 405);
}

try {
    switch ((string)($_POST['action'] ?? '')) {

        case 'state':
            respond(currentState($conn));

        case 'start':
            actionStart($conn);

        case 'answer':
            actionAnswer($conn);

        case 'verify_otp':
            actionVerifyOtp($conn);

        case 'resend_otp':
            actionResendOtp($conn);

        case 'change':
            actionChange($conn);

        case 'cancel':
            clearResetFlow();

            respond([
                'success' => true,
                'stage' => 'start'
            ]);

        default:
            respond([
                'success' => false,
                'message' => 'Invalid request.'
            ], 400);
    }

} catch (Throwable $e) {
    error_log(
        'Forgot password API error: ' . $e->getMessage()
    );

    respond([
        'success' => false,
        'message' => 'Something went wrong. Please try again.'
    ], 500);
}
