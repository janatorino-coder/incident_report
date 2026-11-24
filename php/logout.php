<?php
$role = (string)($_GET['role'] ?? '');

if (in_array($role, ['admin', 'student'], true)) {
    require_once __DIR__ . '/session.php';
    startSirsRoleSession($role);
} else {
    session_start();
}

$_SESSION = [];
if (ini_get('session.use_cookies')) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
}
session_destroy();
header('Location: ../html/Torino.html');
exit;
