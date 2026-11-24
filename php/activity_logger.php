
<?php

function logActivity(
    mysqli $conn,
    ?int $userId,
    string $actorName,
    string $action,
    string $details = '',
    string $ip = 'unknown',
    string $eventType = 'SYSTEM_ACTIVITY'
): void {

    // Get the user's IP address if one was not supplied.
    if ($ip === 'unknown') {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
    }

    // Get the browser or device information.
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';

    // Keep values within the database column limits.
    $eventType = substr($eventType, 0, 50);
    $actorName = substr($actorName, 0, 100);
    $ip = substr($ip, 0, 45);
    $userAgent = substr($userAgent, 0, 255);

    // Preserve the action description and additional details.
    $logDetails = $action;

    if ($details !== '') {
        $logDetails .= ' - ' . $details;
    }

    $logDetails = substr($logDetails, 0, 255);

    // Insert the activity/security event into one table only.
    $stmt = $conn->prepare(
        'INSERT INTO activity_logs
            (event_type, username_typed, user_id, ip_address,
             user_agent, details)
         VALUES (?, ?, ?, ?, ?, ?)'
    );

    if (!$stmt) {
        error_log('Activity log prepare failed: ' . $conn->error);
        return;
    }

    $stmt->bind_param(
        'ssisss',
        $eventType,
        $actorName,
        $userId,
        $ip,
        $userAgent,
        $logDetails
    );

    if (!$stmt->execute()) {
        error_log('Activity log insert failed: ' . $stmt->error);
    }

    $stmt->close();
}
