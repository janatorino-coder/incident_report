<?php
/**
 * forgot_api.php - Forgot Password flow (JSON API)
 *
 * Stages, enforced on the server through $_SESSION['reset_stage']:
 *   start -> questions (2 rounds) -> otp -> change -> done
 * Any call made out of order clears the flow and sends the user back to the start.
 */

session_start();

require_once __DIR__ . '/../php/config.php';
require_once __DIR__ . '/../php/activity_logger.php';
require_once __DIR__ . '/../php/mailer.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

// Keep these lockout tiers in sync with login.php.
const RS_MAX_ATTEMPTS     = 3;
const RS_LOCKOUT_TIERS    = [15, 30, 60];

const RS_CAPTCHA_EXPIRY   = 300;
const RS_OTP_LIFETIME     = 300;  // seconds
const RS_OTP_MAX_ATTEMPTS = 3;
const RS_OTP_LOCK_SECONDS = 60;
const RS_RESEND_WAIT      = 60;
const RS_RESEND_MAX       = 3;
const RS_FLOW_LIFETIME    = 900;  // whole flow must finish within 15 minutes
const RS_CHANGE_WINDOW    = 600;  // after OTP success, 10 minutes to set the password
const RS_QUESTION_ROUNDS  = 2;
const RS_PREVIOUS_BLOCKED = 2;    // current + 2 previous = last 3 passwords
const RS_OWNER_EMAIL      = 'jana.torino@csucc.edu.ph';

// Change this to any long random string. It only makes question selection
// look the same for real and non-existing usernames.
const RS_DECOY_KEY        = 'CHANGE-THIS-TO-A-LONG-RANDOM-STRING';

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

function respond(array $data, int $status = 200): never
{
    global $conn;

    http_response_code($status);
    echo json_encode($data);

    if (isset($conn) && $conn instanceof mysqli) {
        $conn->close();
    }

    exit;
}

function clientIp(): string
{
    return substr((string)($_SERVER['REMOTE_ADDR'] ?? 'unknown'), 0, 45);
}

function clearFlow(): void
{
    unset(
        $_SESSION['reset_stage'],
        $_SESSION['reset_user_id'],
        $_SESSION['reset_username'],
        $_SESSION['reset_ip'],
        $_SESSION['reset_qids'],
        $_SESSION['reset_round'],
        $_SESSION['reset_started'],
        $_SESSION['reset_verified_at']
    );
}

function restart(string $message): never
{
    clearFlow();
    respond(['success' => false, 'message' => $message, 'restart' => true, 'refreshCaptcha' => true]);
}

function respondLocked(int $seconds): never
{
    respond([
        'success' => false,
        'message' => "Too many failed attempts. Please wait {$seconds} seconds.",
        'restart' => true,
        'lockedOut' => true,
        'remainingSeconds' => $seconds,
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
        restart('Your session is no longer valid. Please start again.');
    }
}

function q(mysqli $conn, string $sql, string $types = '', array $params = []): mysqli_stmt
{
    $stmt = $conn->prepare($sql);

    if (!$stmt) {
        throw new RuntimeException('Prepare failed: ' . $conn->error);
    }

    if ($types !== '') {
        $stmt->bind_param($types, ...$params);
    }

    if (!$stmt->execute()) {
        $err = $stmt->error;
        $stmt->close();
        throw new RuntimeException('Execute failed: ' . $err);
    }

    return $stmt;
}

function row(mysqli $conn, string $sql, string $types = '', array $params = []): ?array
{
    $stmt = q($conn, $sql, $types, $params);
    $result = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    return $result ?: null;
}

function run(mysqli $conn, string $sql, string $types = '', array $params = []): void
{
    q($conn, $sql, $types, $params)->close();
}

function maskEmail(string $email): string
{
    $parts = explode('@', $email, 2);

    if (count($parts) !== 2) {
        return 'your registered email';
    }

    return substr($parts[0], 0, 1) .
        str_repeat('*', max(2, strlen($parts[0]) - 1)) .
        '@' . $parts[1];
}

function dummyHash(): string
{
    static $hash = null;

    return $hash ??= password_hash('dummy-value', PASSWORD_DEFAULT);
}

function normalizeAnswer(string $answer): string
{
    $answer = mb_strtolower(trim($answer), 'UTF-8');

    return (string)preg_replace('/\s+/u', ' ', $answer);
}

function questionText(mysqli $conn, int $id): string
{
    $r = row($conn, 'SELECT question FROM security_questions WHERE id = ? LIMIT 1', 'i', [$id]);

    return $r['question'] ?? 'Security question';
}

// Pick two different questions from $ids. The pick depends only on the username,
// so a real and a non-existing username behave the same when retried.
function pickQuestionIds(array $ids, string $username): array
{
    $h = hash_hmac('sha256', strtolower($username), RS_DECOY_KEY, true);
    $n = count($ids);

    $first  = ord($h[0]) % $n;
    $second = (ord($h[1]) % ($n - 1) + 1 + $first) % $n;

    return [(int)$ids[$first], (int)$ids[$second]];
}

// ------------------------------------------------------------------
// Shared lockout (same login_attempts table as login.php)
// ------------------------------------------------------------------

function lockRemaining(mysqli $conn, string $username, string $ip): int
{
    $r = row(
        $conn,
        'SELECT failed_attempts,
                TIMESTAMPDIFF(SECOND, last_failed_at, NOW()) AS seconds_since_fail
         FROM login_attempts
         WHERE username = ? AND ip_address = ?
         LIMIT 1',
        'ss',
        [$username, $ip]
    );

    $failedAttempts = (int)($r['failed_attempts'] ?? 0);

    if (
        !$r ||
        $failedAttempts < RS_MAX_ATTEMPTS ||
        $failedAttempts % RS_MAX_ATTEMPTS !== 0
    ) {
        return 0;
    }

    $elapsed = (int)($r['seconds_since_fail'] ?? 0);
    $tier = min(
        count(RS_LOCKOUT_TIERS) - 1,
        intdiv($failedAttempts - 1, RS_MAX_ATTEMPTS)
    );
    $cooldown = RS_LOCKOUT_TIERS[$tier];

    if ($elapsed < $cooldown) {
        return $cooldown - $elapsed;
    }

    return 0;
}

function recordFailure(mysqli $conn, string $username, string $ip, ?int $userId, string $what): int
{
    run(
        $conn,
        'INSERT INTO login_attempts (username, ip_address, failed_attempts, last_failed_at)
         VALUES (?, ?, 1, NOW())
         ON DUPLICATE KEY UPDATE
            failed_attempts = failed_attempts + 1,
            last_failed_at = NOW()',
        'ss',
        [$username, $ip]
    );

    $r = row(
        $conn,
        'SELECT failed_attempts FROM login_attempts WHERE username = ? AND ip_address = ? LIMIT 1',
        'ss',
        [$username, $ip]
    );

    $count = (int)($r['failed_attempts'] ?? 1);

    if ($userId) {
        logActivity(
            $conn,
            $userId,
            $username,
            'Failed password reset',
            "Incorrect {$what}. IP: {$ip}. Failed attempts: {$count}/" . RS_MAX_ATTEMPTS,
            $ip,
            'failed_reset'
        );
    }

    if ($count % RS_MAX_ATTEMPTS === 0) {
        try {
            if (!sendOwnerLockoutAlert(RS_OWNER_EMAIL, 'reset', $username, $ip, $count, RS_MAX_ATTEMPTS)) {
                error_log('Reset lockout alert email was not sent.');
            }
        } catch (Throwable $e) {
            error_log('Reset lockout alert exception: ' . $e->getMessage());
        }
    }

    return $count;
}

// Wrong security answer. The message never says which part was wrong.
function failAttempt(mysqli $conn, string $what): never
{
    $username = (string)$_SESSION['reset_username'];
    $userId   = (int)$_SESSION['reset_user_id'] ?: null;

    $count = recordFailure($conn, $username, clientIp(), $userId, $what);

    if ($count >= RS_MAX_ATTEMPTS && $count % RS_MAX_ATTEMPTS === 0) {
        clearFlow();
        $tier = min(
            count(RS_LOCKOUT_TIERS) - 1,
            intdiv($count - 1, RS_MAX_ATTEMPTS)
        );
        respondLocked(RS_LOCKOUT_TIERS[$tier]);
    }

    $attemptsInTier = $count % RS_MAX_ATTEMPTS;
    $remaining = RS_MAX_ATTEMPTS - $attemptsInTier;

    respond([
        'success' => false,
        'message' => "The information you provided is incorrect. {$remaining} attempt(s) remaining.",
        'remainingAttempts' => $remaining
    ]);
}

// ------------------------------------------------------------------
// State (used by the page on load, so a refresh resumes the right step)
// ------------------------------------------------------------------

function currentState(mysqli $conn): array
{
    $stage = (string)($_SESSION['reset_stage'] ?? '');

    if (
        $stage === '' ||
        ($_SESSION['reset_ip'] ?? '') !== clientIp() ||
        (time() - (int)($_SESSION['reset_started'] ?? 0)) > RS_FLOW_LIFETIME
    ) {
        clearFlow();
        return ['success' => true, 'stage' => 'start'];
    }

    if ($stage === 'questions') {
        $round = (int)$_SESSION['reset_round'];

        return [
            'success' => true,
            'stage' => 'questions',
            'question' => questionText($conn, (int)$_SESSION['reset_qids'][$round]),
            'step' => $round + 1,
            'total' => RS_QUESTION_ROUNDS
        ];
    }

    if ($stage === 'otp') {
        $userId = (int)$_SESSION['reset_user_id'];

        $r = row(
            $conn,
            'SELECT u.email, o.attempts,
                    GREATEST(0, TIMESTAMPDIFF(SECOND, NOW(), o.expires_at)) AS expires_in,
                    GREATEST(0, ' . RS_RESEND_WAIT . ' - TIMESTAMPDIFF(SECOND, o.last_sent_at, NOW())) AS resend_in,
                    IF(o.locked_until IS NOT NULL AND o.locked_until > NOW(),
                       TIMESTAMPDIFF(SECOND, NOW(), o.locked_until), 0) AS lock_in
             FROM users u
             INNER JOIN password_reset_otp o ON o.user_id = u.id
             WHERE u.id = ?
             LIMIT 1',
            'i',
            [$userId]
        );

        if (!$r) {
            clearFlow();
            return ['success' => true, 'stage' => 'start'];
        }

        return [
            'success' => true,
            'stage' => 'otp',
            'maskedEmail' => maskEmail((string)$r['email']),
            'expiresIn' => (int)$r['expires_in'],
            'resendIn' => (int)$r['resend_in'],
            'lockIn' => (int)$r['lock_in'],
            'exhausted' => (int)$r['attempts'] >= RS_OTP_MAX_ATTEMPTS
        ];
    }

    if ($stage === 'change') {
        return ['success' => true, 'stage' => 'change'];
    }

    clearFlow();
    return ['success' => true, 'stage' => 'start'];
}

// ------------------------------------------------------------------
// STEP 1: username + CAPTCHA
// ------------------------------------------------------------------

function actionStart(mysqli $conn): never
{
    $ip = clientIp();
    $username = trim((string)($_POST['username'] ?? ''));
    $captcha  = strtoupper(trim((string)($_POST['captcha'] ?? '')));

    if (strlen($username) < 6 || strlen($username) > 20) {
        respond(['success' => false, 'message' => 'Username must be between 6 and 20 characters.']);
    }

    $captchaHash    = $_SESSION['captcha_hash'] ?? null;
    $captchaCreated = (int)($_SESSION['captcha_created'] ?? 0);

    unset($_SESSION['captcha_hash'], $_SESSION['captcha_created']);

    if (
        !$captchaHash ||
        !$captchaCreated ||
        (time() - $captchaCreated) > RS_CAPTCHA_EXPIRY ||
        $captcha === '' ||
        !password_verify($captcha, (string)$captchaHash)
    ) {
        respond([
            'success' => false,
            'message' => 'Incorrect or expired CAPTCHA. Please try again.',
            'refreshCaptcha' => true
        ]);
    }

    clearFlow();

    $lock = lockRemaining($conn, $username, $ip);

    if ($lock > 0) {
        respondLocked($lock);
    }

    // Look up the account and its 3 saved questions.
    $userId = 0;
    $ids = [];

    $user = row($conn, 'SELECT id FROM users WHERE username = ? LIMIT 1', 's', [$username]);

    if ($user) {
        $stmt = q(
            $conn,
            'SELECT question_id FROM user_security_answers WHERE user_id = ? ORDER BY question_id',
            'i',
            [(int)$user['id']]
        );

        foreach ($stmt->get_result()->fetch_all(MYSQLI_ASSOC) as $r) {
            $ids[] = (int)$r['question_id'];
        }

        $stmt->close();

        if (count($ids) >= 2) {
            $userId = (int)$user['id'];
        }
    }

    // Unknown username, or no questions saved: show questions from the bank.
    // Every answer fails, and the page looks the same as for a real account.
    if ($userId === 0) {
        $ids = [];
        $stmt = q($conn, 'SELECT id FROM security_questions ORDER BY id');

        foreach ($stmt->get_result()->fetch_all(MYSQLI_ASSOC) as $r) {
            $ids[] = (int)$r['id'];
        }

        $stmt->close();

        if (count($ids) < 2) {
            respond(['success' => false, 'message' => 'Password recovery is temporarily unavailable.']);
        }
    }

    $qids = pickQuestionIds($ids, $username);

    session_regenerate_id(true);

    $_SESSION['reset_stage']    = 'questions';
    $_SESSION['reset_user_id']  = $userId;
    $_SESSION['reset_username'] = $username;
    $_SESSION['reset_ip']       = $ip;
    $_SESSION['reset_qids']     = $qids;
    $_SESSION['reset_round']    = 0;
    $_SESSION['reset_started']  = time();

    respond([
        'success' => true,
        'stage' => 'questions',
        'question' => questionText($conn, $qids[0]),
        'step' => 1,
        'total' => RS_QUESTION_ROUNDS,
        'refreshCaptcha' => true
    ]);
}

// ------------------------------------------------------------------
// STEP 2: security questions (twice) -> send reset OTP
// ------------------------------------------------------------------

function actionAnswer(mysqli $conn): never
{
    requireStage('questions');

    $ip = clientIp();
    $username = (string)$_SESSION['reset_username'];

    $lock = lockRemaining($conn, $username, $ip);

    if ($lock > 0) {
        clearFlow();
        respondLocked($lock);
    }

    $answer = normalizeAnswer((string)($_POST['answer'] ?? ''));

    if ($answer === '') {
        respond(['success' => false, 'message' => 'Please enter your answer.']);
    }

    $userId = (int)$_SESSION['reset_user_id'];
    $round  = (int)$_SESSION['reset_round'];
    $qid    = (int)$_SESSION['reset_qids'][$round];

    $hash = null;

    if ($userId > 0) {
        $r = row(
            $conn,
            'SELECT answer_hash FROM user_security_answers WHERE user_id = ? AND question_id = ? LIMIT 1',
            'ii',
            [$userId, $qid]
        );

        $hash = $r['answer_hash'] ?? null;
    }

    $matches = password_verify($answer, $hash ?? dummyHash());

    if ($hash === null || !$matches) {
        failAttempt($conn, 'security answer');
    }

    // Correct, but another round is left.
    if ($round + 1 < RS_QUESTION_ROUNDS) {
        $_SESSION['reset_round'] = $round + 1;

        respond([
            'success' => true,
            'stage' => 'questions',
            'question' => questionText($conn, (int)$_SESSION['reset_qids'][$round + 1]),
            'step' => $round + 2,
            'total' => RS_QUESTION_ROUNDS
        ]);
    }

    // All answers correct: send the reset OTP.
    $u = row($conn, 'SELECT email FROM users WHERE id = ? LIMIT 1', 'i', [$userId]);
    $email = trim((string)($u['email'] ?? ''));

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        respond([
            'success' => false,
            'message' => 'Your account has no valid registered email. Please contact the administrator.'
        ]);
    }

    $otp = (string)random_int(100000, 999999);
    $otpHash = password_hash($otp, PASSWORD_DEFAULT);

    run($conn, 'DELETE FROM password_reset_otp WHERE user_id = ?', 'i', [$userId]);

    run(
        $conn,
        'INSERT INTO password_reset_otp
            (user_id, otp_hash, expires_at, attempts, resend_count, last_sent_at, locked_until)
         VALUES (?, ?, DATE_ADD(NOW(), INTERVAL ' . RS_OTP_LIFETIME . ' SECOND), 0, 0, NOW(), NULL)',
        'is',
        [$userId, $otpHash]
    );

    if (!sendResetOTP($email, $otp)) {
        run($conn, 'DELETE FROM password_reset_otp WHERE user_id = ?', 'i', [$userId]);

        respond(['success' => false, 'message' => 'Unable to send the verification code. Please try again.']);
    }

    $_SESSION['reset_stage'] = 'otp';

    logActivity($conn, $userId, $username, 'Password reset OTP sent',
        'Security questions answered. Reset OTP sent.', $ip, 'reset_otp_sent');

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

// ------------------------------------------------------------------
// STEP 3: reset OTP (same rules as login OTP)
// ------------------------------------------------------------------

function actionVerifyOtp(mysqli $conn): never
{
    requireStage('otp');

    $userId   = (int)$_SESSION['reset_user_id'];
    $username = (string)$_SESSION['reset_username'];
    $ip       = clientIp();
    $otp      = trim((string)($_POST['otp'] ?? ''));

    if (!preg_match('/^\d{6}$/', $otp)) {
        respond(['success' => false, 'message' => 'Please enter a valid 6-digit code.']);
    }

    $rec = row(
        $conn,
        'SELECT otp_hash, attempts,
                (expires_at > NOW()) AS is_valid,
                (locked_until IS NOT NULL AND locked_until > NOW()) AS is_locked,
                IFNULL(TIMESTAMPDIFF(SECOND, NOW(), locked_until), 0) AS lock_remaining
         FROM password_reset_otp
         WHERE user_id = ?
         LIMIT 1',
        'i',
        [$userId]
    );

    if (!$rec) {
        restart('Your verification code is no longer available. Please start again.');
    }

    if ((int)$rec['is_locked']) {
        $remaining = max(1, (int)$rec['lock_remaining']);

        respond([
            'success' => false,
            'message' => "Too many incorrect codes. Please wait {$remaining} seconds, then request a new code.",
            'lockedOut' => true,
            'remainingSeconds' => $remaining
        ]);
    }

    $attempts = (int)$rec['attempts'];

    if ($attempts >= RS_OTP_MAX_ATTEMPTS) {
        respond([
            'success' => false,
            'message' => 'Please request a new verification code.',
            'needResend' => true
        ]);
    }

    if (!(int)$rec['is_valid']) {
        respond([
            'success' => false,
            'message' => 'Your code has expired. Please request a new one.',
            'needResend' => true
        ]);
    }

    if (!password_verify($otp, (string)$rec['otp_hash'])) {
        $newAttempts = $attempts + 1;
        $lockNow = $newAttempts >= RS_OTP_MAX_ATTEMPTS;

        if ($lockNow) {
            run(
                $conn,
                'UPDATE password_reset_otp
                 SET attempts = ?, locked_until = DATE_ADD(NOW(), INTERVAL ' . RS_OTP_LOCK_SECONDS . ' SECOND)
                 WHERE user_id = ?',
                'ii',
                [$newAttempts, $userId]
            );
        } else {
            run($conn, 'UPDATE password_reset_otp SET attempts = ? WHERE user_id = ?', 'ii', [$newAttempts, $userId]);
        }

        logActivity($conn, $userId, $username, 'Failed reset OTP verification',
            "Incorrect reset OTP. IP: {$ip}. Failed attempts: {$newAttempts}/" . RS_OTP_MAX_ATTEMPTS,
            $ip, 'failed_reset_otp');

        if ($lockNow) {
            try {
                if (!sendOwnerLockoutAlert(RS_OWNER_EMAIL, 'otp', $username, $ip, $newAttempts, RS_OTP_MAX_ATTEMPTS)) {
                    error_log('Reset OTP lockout alert email was not sent.');
                }
            } catch (Throwable $e) {
                error_log('Reset OTP lockout alert exception: ' . $e->getMessage());
            }

            respond([
                'success' => false,
                'message' => 'Too many incorrect codes. Please wait ' . RS_OTP_LOCK_SECONDS . ' seconds, then request a new code.',
                'lockedOut' => true,
                'remainingSeconds' => RS_OTP_LOCK_SECONDS
            ]);
        }

        $remaining = RS_OTP_MAX_ATTEMPTS - $newAttempts;

        respond([
            'success' => false,
            'message' => "Incorrect code. {$remaining} attempt(s) remaining.",
            'remainingAttempts' => $remaining
        ]);
    }

    run($conn, 'DELETE FROM password_reset_otp WHERE user_id = ?', 'i', [$userId]);

    $_SESSION['reset_stage'] = 'change';
    $_SESSION['reset_verified_at'] = time();

    logActivity($conn, $userId, $username, 'Password reset OTP verified',
        'Reset OTP verified successfully.', $ip, 'reset_otp_verified');

    respond(['success' => true, 'stage' => 'change']);
}

function actionResendOtp(mysqli $conn): never
{
    requireStage('otp');

    $userId = (int)$_SESSION['reset_user_id'];

    $r = row(
        $conn,
        'SELECT u.email, o.resend_count,
                TIMESTAMPDIFF(SECOND, o.last_sent_at, NOW()) AS seconds_since_sent,
                (o.locked_until IS NOT NULL AND o.locked_until > NOW()) AS is_locked,
                IFNULL(TIMESTAMPDIFF(SECOND, NOW(), o.locked_until), 0) AS lock_remaining
         FROM users u
         INNER JOIN password_reset_otp o ON o.user_id = u.id
         WHERE u.id = ?
         LIMIT 1',
        'i',
        [$userId]
    );

    if (!$r) {
        restart('Your session expired. Please start again.');
    }

    if ((int)$r['is_locked']) {
        $remaining = max(1, (int)$r['lock_remaining']);

        respond([
            'success' => false,
            'message' => "Too many incorrect codes. Please wait {$remaining} seconds before requesting a new code.",
            'lockedOut' => true,
            'remainingSeconds' => $remaining
        ]);
    }

    if ((int)$r['resend_count'] >= RS_RESEND_MAX) {
        restart('You have reached the maximum number of resend requests. Please start again.');
    }

    $elapsed = max(0, (int)$r['seconds_since_sent']);

    if ($elapsed < RS_RESEND_WAIT) {
        $remaining = RS_RESEND_WAIT - $elapsed;

        respond([
            'success' => false,
            'message' => "Please wait {$remaining} seconds before requesting another code.",
            'remainingSeconds' => $remaining
        ]);
    }

    $otp = (string)random_int(100000, 999999);
    $hash = password_hash($otp, PASSWORD_DEFAULT);

    if (!sendResetOTP((string)$r['email'], $otp)) {
        respond(['success' => false, 'message' => 'Unable to send the new code. Please try again.']);
    }

    run(
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

// ------------------------------------------------------------------
// STEP 4: change password
// ------------------------------------------------------------------

function passwordProblem(string $pw, string $username): ?string
{
    if (strlen($pw) < 8 || strlen($pw) > 64) {
        return 'Password must be between 8 and 64 characters.';
    }

    if (!preg_match('/[a-z]/', $pw) || !preg_match('/[A-Z]/', $pw) ||
        !preg_match('/\d/', $pw) || !preg_match('/[^A-Za-z0-9]/', $pw)) {
        return 'Password must include a lowercase letter, an uppercase letter, a number and a symbol.';
    }

    if ($username !== '' && stripos($pw, $username) !== false) {
        return 'Password must not contain your username.';
    }

    return null;
}

function actionChange(mysqli $conn): never
{
    requireStage('change');

    if ((time() - (int)($_SESSION['reset_verified_at'] ?? 0)) > RS_CHANGE_WINDOW) {
        restart('Your verification expired. Please start again.');
    }

    $userId   = (int)$_SESSION['reset_user_id'];
    $username = (string)$_SESSION['reset_username'];
    $ip       = clientIp();

    $new     = (string)($_POST['password'] ?? '');
    $confirm = (string)($_POST['confirm'] ?? '');

    if ($new !== $confirm) {
        respond(['success' => false, 'message' => 'The passwords do not match.']);
    }

    $problem = passwordProblem($new, $username);

    if ($problem !== null) {
        respond(['success' => false, 'message' => $problem]);
    }

    $user = row($conn, 'SELECT password, email FROM users WHERE id = ? LIMIT 1', 'i', [$userId]);

    if (!$user) {
        restart('Account not found. Please start again.');
    }

    // No reuse of the last 3 passwords: current + 2 previous.
    $blocked = [(string)$user['password']];

    $stmt = q(
        $conn,
        'SELECT password_hash FROM password_history WHERE user_id = ? ORDER BY id DESC LIMIT ' . RS_PREVIOUS_BLOCKED,
        'i',
        [$userId]
    );

    foreach ($stmt->get_result()->fetch_all(MYSQLI_ASSOC) as $h) {
        $blocked[] = (string)$h['password_hash'];
    }

    $stmt->close();

    foreach ($blocked as $oldHash) {
        if ($oldHash !== '' && password_verify($new, $oldHash)) {
            respond(['success' => false, 'message' => 'You cannot reuse any of your last 3 passwords.']);
        }
    }

    $newHash = password_hash($new, PASSWORD_DEFAULT);

    $conn->begin_transaction();

    try {
        run($conn, 'INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)', 'is', [$userId, (string)$user['password']]);
        run($conn, 'UPDATE users SET password = ? WHERE id = ?', 'si', [$newHash, $userId]);
        run($conn, 'DELETE FROM login_attempts WHERE username = ?', 's', [$username]);
        run($conn, 'DELETE FROM password_reset_otp WHERE user_id = ?', 'i', [$userId]);

        $conn->commit();
    } catch (Throwable $e) {
        $conn->rollback();
        error_log('Password change failed: ' . $e->getMessage());

        respond(['success' => false, 'message' => 'Unable to change your password. Please try again.']);
    }

    logActivity($conn, $userId, $username, 'Password reset',
        'Password changed through Forgot Password.', $ip, 'password_reset');

    try {
        if (!sendPasswordChangedNotice((string)$user['email'], $username)) {
            error_log('Password changed email was not sent.');
        }
    } catch (Throwable $e) {
        error_log('Password changed email exception: ' . $e->getMessage());
    }

    clearFlow();

    respond([
        'success' => true,
        'stage' => 'done',
        'message' => 'Your password was changed.',
        'redirect' => '../html/Torino.html?mode=login'
    ]);
}

// ------------------------------------------------------------------
// Dispatch
// ------------------------------------------------------------------

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    respond(['success' => false, 'message' => 'Invalid request.'], 405);
}

try {
    switch ((string)($_POST['action'] ?? '')) {
        case 'state':      respond(currentState($conn));
        case 'start':      actionStart($conn);
        case 'answer':     actionAnswer($conn);
        case 'verify_otp': actionVerifyOtp($conn);
        case 'resend_otp': actionResendOtp($conn);
        case 'change':     actionChange($conn);
        case 'cancel':
            clearFlow();
            respond(['success' => true, 'stage' => 'start']);
        default:
            respond(['success' => false, 'message' => 'Invalid request.'], 400);
    }
} catch (Throwable $e) {
    error_log('forgot_api error: ' . $e->getMessage());
    respond(['success' => false, 'message' => 'Something went wrong. Please try again.'], 500);
}