<?php

function logActivity(
    mysqli $conn,
    ?int $userId,
    string $actorName,
    string $action,
    string $details = '',
    string $ip = 'unknown',
    string $eventType = 'system_activity'
): void {

    // Record in activity_logs
    $activity = $conn->prepare(
        'INSERT INTO activity_logs
            (user_id, actor_name, action, details)
         VALUES (?, ?, ?, ?)'
    );

    if (!$activity) {
        error_log('Activity log prepare failed: ' . $conn->error);
        return;
    }

    $activity->bind_param(
        'isss',
        $userId,
        $actorName,
        $action,
        $details
    );

    if (!$activity->execute()) {
        error_log('Activity log insert failed: ' . $activity->error);
        $activity->close();
        return;
    }

    $activityId = $conn->insert_id;
    $activity->close();

    // Also record the same activity in security_events
    $security = $conn->prepare(
        'INSERT INTO security_events
            (activity_log_id, user_id, username, ip_address,
             event_type, details)
         VALUES (?, ?, ?, ?, ?, ?)'
    );

    if (!$security) {
        error_log('Security event prepare failed: ' . $conn->error);
        return;
    }

    $security->bind_param(
        'iissss',
        $activityId,
        $userId,
        $actorName,
        $ip,
        $eventType,
        $details
    );

    if (!$security->execute()) {
        error_log('Security event insert failed: ' . $security->error);
    }

    $security->close();
}