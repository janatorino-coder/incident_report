
<?php

require_once __DIR__ . '/../vendor/autoload.php';

use PHPMailer\PHPMailer\PHPMailer;


// ==========================================
// CREATE MAILER
// ==========================================

function createMailer(): PHPMailer
{
    global $appConfig;

    $mail = new PHPMailer(true);

    $smtp = $appConfig['smtp'] ?? [];
    $host = $smtp['host'] ?? '';
    $username = $smtp['username'] ?? '';
    $password = $smtp['password'] ?? '';
    $fromEmail = $smtp['from_email'] ?? '';
    $fromName = $smtp['from_name'] ?? 'Incident Hub';
    $port = filter_var(
        $smtp['port'] ?? 587,
        FILTER_VALIDATE_INT,
        ['options' => ['min_range' => 1, 'max_range' => 65535]]
    );

    if (
        !is_string($host) ||
        $host === '' ||
        !is_string($username) ||
        $username === '' ||
        !is_string($password) ||
        $password === '' ||
        !is_string($fromEmail) ||
        !filter_var($fromEmail, FILTER_VALIDATE_EMAIL) ||
        $port === false
    ) {
        throw new RuntimeException(
            'SMTP configuration is incomplete. Check the private config.php file.'
        );
    }

    $mail->isSMTP();
    $mail->Host = $host;
    $mail->SMTPAuth = true;
    $mail->Username = $username;
    $mail->Password = $password;
    $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
    $mail->Port = $port;
    $mail->CharSet = 'UTF-8';

    $mail->setFrom($fromEmail, $fromName);

    return $mail;
}


// ==========================================
// REGISTRATION OTP - 4 MINUTES
// ==========================================

function sendRegistrationOTP(string $recipient, string $otp): bool
{
    try {

        $mail = createMailer();

        $safeOTP = htmlspecialchars(
            $otp,
            ENT_QUOTES,
            'UTF-8'
        );

        $mail->addAddress($recipient);
        $mail->isHTML(true);

        $mail->Subject = 'Incident Hub - Verify Your Registration';

        $mail->Body = "
            <h2>Verify Your Incident Hub Account</h2>
            <p>Thank you for registering with Incident Hub.</p>
            <p>Your registration verification code is:</p>
            <h1>{$safeOTP}</h1>
            <p>This code expires in <strong>5 minutes</strong>.</p>
            <p>If you did not create this account, please ignore this email.</p>
        ";

        $mail->AltBody =
            "Your Incident Hub registration OTP is: {$otp}. "
            . "It expires in 5 minutes.";

        return $mail->send();

    } catch (Throwable $e) {

        error_log(
            'Registration OTP email failed: ' . $e->getMessage()
        );

        return false;
    }
}


// ==========================================
// LOGIN OTP - 5 MINUTES
// ==========================================

function sendLoginOTP(string $recipient, string $otp): bool
{
    try {

        $mail = createMailer();

        $safeOTP = htmlspecialchars(
            $otp,
            ENT_QUOTES,
            'UTF-8'
        );

        $mail->addAddress($recipient);
        $mail->isHTML(true);

        $mail->Subject = 'Incident Hub - Login Verification Code';

        $mail->Body = "
            <h2>Incident Hub Verification</h2>
            <p>Your login verification code is:</p>
            <h1>{$safeOTP}</h1>
            <p>This code expires in 5 minutes.</p>
            <p>If you did not attempt to log in, please ignore this email.</p>
        ";

        $mail->AltBody =
            "Your Incident Hub verification code is {$otp}. "
            . "It expires in 5 minutes.";

        return $mail->send();

    } catch (Throwable $e) {

        error_log(
            'Login OTP email failed: ' . $e->getMessage()
        );

        return false;
    }
}


// ==========================================
// ACCOUNT LOCKOUT SECURITY ALERT
// ==========================================

function sendLockoutAlert(
    string $recipientEmail,
    string $lockoutType,
    string $username,
    string $ip,
    int $failedAttempts = 3,
    int $maxAttempts = 3,
    string $userAgent = ''
): bool {

    if ($lockoutType === 'login') {

        $subject = 'Incident Hub: Login Lockout Security Alert';
        $title = 'Login Lockout Alert';
        $reason = 'Incorrect password entered repeatedly.';

    } elseif ($lockoutType === 'otp') {

        $subject = 'Incident Hub: OTP Lockout Security Alert';
        $title = 'OTP Lockout Alert';
        $reason = 'Incorrect OTP entered repeatedly.';

    } elseif ($lockoutType === 'reset') {

        $subject = 'Incident Hub: Password Reset Lockout Security Alert';
        $title = 'Password Reset Lockout Alert';
        $reason = 'Incorrect security answers entered repeatedly during password reset.';

    } else {

        error_log('Invalid lockout alert type.');

        return false;
    }

    try {

        $mail = createMailer();

        $safeUsername = htmlspecialchars(
            $username,
            ENT_QUOTES,
            'UTF-8'
        );

        $safeIP = htmlspecialchars(
            $ip,
            ENT_QUOTES,
            'UTF-8'
        );

        $userAgent = substr(
            preg_replace('/[\r\n]+/', ' ', $userAgent) ?? '',
            0,
            255
        );
        $safeUserAgent = htmlspecialchars(
            $userAgent,
            ENT_QUOTES,
            'UTF-8'
        );

        $dateTime = date('F j, Y h:i:s A');

        $mail->addAddress($recipientEmail);
        $mail->isHTML(true);
        $mail->Subject = $subject;

        $mail->Body = "
            <h2>Incident Hub Account Security Alert</h2>
            <h3>{$title}</h3>
            <p>Your account reached the maximum number of failed attempts.</p>

            <table cellpadding='8' cellspacing='0' border='1'>
                <tr>
                    <td><strong>Username</strong></td>
                    <td>{$safeUsername}</td>
                </tr>
                <tr>
                    <td><strong>IP Address</strong></td>
                    <td>{$safeIP}</td>
                </tr>
                <tr>
                    <td><strong>Browser / Device</strong></td>
                    <td>{$safeUserAgent}</td>
                </tr>
                <tr>
                    <td><strong>Failed Attempts</strong></td>
                    <td>{$failedAttempts}/{$maxAttempts}</td>
                </tr>
                <tr>
                    <td><strong>Reason</strong></td>
                    <td>{$reason}</td>
                </tr>
                <tr>
                    <td><strong>Date and Time</strong></td>
                    <td>{$dateTime}</td>
                </tr>
            </table>

            <p>If this was not you, secure your account and contact your school administrator.</p>
        ";

        $mail->AltBody =
            "Incident Hub Security Alert\n" .
            "Type: {$title}\n" .
            "Username: {$username}\n" .
            "IP Address: {$ip}\n" .
            "Browser / Device: {$userAgent}\n" .
            "Failed Attempts: {$failedAttempts}/{$maxAttempts}\n" .
            "Reason: {$reason}\n" .
            "Date and Time: {$dateTime}";

        return $mail->send();

    } catch (Throwable $e) {

        error_log(
            'Account lockout alert failed: ' . $e->getMessage()
        );

        return false;
    }
}


// ==========================================
// PASSWORD RESET OTP - 5 MINUTES
// ==========================================

function sendResetOTP(string $recipient, string $otp): bool
{
    try {

        $mail = createMailer();

        $safeOTP = htmlspecialchars(
            $otp,
            ENT_QUOTES,
            'UTF-8'
        );

        $mail->addAddress($recipient);
        $mail->isHTML(true);

        $mail->Subject = 'Incident Hub - Password Reset Code';

        $mail->Body = "
            <h2>Incident Hub Password Reset</h2>
            <p>Your password reset code is:</p>
            <h1>{$safeOTP}</h1>
            <p>This code expires in 5 minutes.</p>
            <p>If you did not request a password reset, please ignore this email.</p>
        ";

        $mail->AltBody =
            "Your Incident Hub password reset code is {$otp}. "
            . "It expires in 5 minutes.";

        return $mail->send();

    } catch (Throwable $e) {

        error_log(
            'Reset OTP email failed: ' . $e->getMessage()
        );

        return false;
    }
}


// ==========================================
// PASSWORD CHANGED NOTIFICATION
// ==========================================

function sendPasswordChangedNotice(
    string $recipient,
    string $username
): bool {

    try {

        $mail = createMailer();

        $safeUser = htmlspecialchars(
            $username,
            ENT_QUOTES,
            'UTF-8'
        );

        $when = date('F j, Y h:i:s A');

        $mail->addAddress($recipient);
        $mail->isHTML(true);

        $mail->Subject = 'Incident Hub - Your password was changed';

        $mail->Body = "
            <h2>Your password was changed</h2>
            <p>
                The password for account
                <strong>{$safeUser}</strong>
                was changed on {$when}.
            </p>
            <p>If this was not you, contact the administrator immediately.</p>
        ";

        $mail->AltBody =
            "Your Incident Hub password for {$username} "
            . "was changed on {$when}. "
            . "If this was not you, contact the administrator immediately.";

        return $mail->send();

    } catch (Throwable $e) {

        error_log(
            'Password changed email failed: ' . $e->getMessage()
        );

        return false;
    }
}
