<?php

function sirsRoleSessionName(string $role): string
{
    return match ($role) {
        'admin' => 'SIRS_ADMIN_SESSION',
        'student' => 'SIRS_STUDENT_SESSION',
        default => throw new InvalidArgumentException('Invalid session role.')
    };
}

function startSirsRoleSession(string $role): void
{
    session_name(sirsRoleSessionName($role));
    session_start();
}

function migrateSirsSessionToRole(string $role): bool
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        return false;
    }

    $sessionData = $_SESSION;
    $previousSessionName = session_name();
    $cookieParams = session_get_cookie_params();
    $_SESSION = [];

    if (!session_destroy()) {
        return false;
    }

    if (ini_get('session.use_cookies')) {
        setcookie(
            $previousSessionName,
            '',
            time() - 42000,
            $cookieParams['path'],
            $cookieParams['domain'],
            $cookieParams['secure'],
            $cookieParams['httponly']
        );
    }

    session_name(sirsRoleSessionName($role));

    if (!session_start() || !session_regenerate_id(true)) {
        return false;
    }

    $_SESSION = $sessionData;

    return true;
}
