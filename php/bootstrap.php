<?php

$configPath = getenv('SIRS_CONFIG_PATH');
if ($configPath === false || $configPath === '') {
    $configPath = 'C:\\xampp\\private\\TORINO_SIRS\\config.php';
}

if (!is_file($configPath) || !is_readable($configPath)) {
    error_log('Incident Hub private configuration is unavailable.');
    http_response_code(500);
    exit('Private configuration is unavailable.');
}

$appConfig = require $configPath;
if (!is_array($appConfig)) {
    error_log('Incident Hub private configuration has an invalid format.');
    http_response_code(500);
    exit('Private configuration is invalid.');
}

$database = $appConfig['database'] ?? null;
if (
    !is_array($database) ||
    !isset($database['host'], $database['username'], $database['name']) ||
    !is_string($database['host']) ||
    !is_string($database['username']) ||
    !is_string($database['name']) ||
    $database['host'] === '' ||
    $database['username'] === '' ||
    $database['name'] === '' ||
    !is_string($database['password'] ?? '')
) {
    error_log('Incident Hub database configuration is invalid.');
    http_response_code(500);
    exit('Database configuration is invalid.');
}

$databasePort = filter_var(
    $database['port'] ?? 3306,
    FILTER_VALIDATE_INT,
    ['options' => ['min_range' => 1, 'max_range' => 65535]]
);
if ($databasePort === false) {
    error_log('Incident Hub database port is invalid.');
    http_response_code(500);
    exit('Database configuration is invalid.');
}

require_once __DIR__ . '/../vendor/autoload.php';

mysqli_report(MYSQLI_REPORT_OFF);
$conn = new mysqli(
    $database['host'],
    $database['username'],
    $database['password'] ?? '',
    $database['name'],
    $databasePort
);

if ($conn->connect_errno) {
    error_log('Incident Hub database connection failed: ' . $conn->connect_error);
    http_response_code(500);
    exit('Database connection failed. Check the private configuration and ensure MySQL is running.');
}

if (!$conn->set_charset('utf8mb4')) {
    error_log('Incident Hub could not set the database connection character set.');
    http_response_code(500);
    exit('Database connection setup failed.');
}
