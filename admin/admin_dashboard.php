<?php
require_once __DIR__ . '/../php/session.php';
startSirsRoleSession('admin');

if (
    isset($_SESSION['user_id']) &&
    time() - (int)($_SESSION['last_activity'] ?? 0) > 900
) {
    session_unset();
    session_destroy();
    header("Location: ../html/Torino.html?sessionExpired=1");
    exit;
}

if (!isset($_SESSION["user_id"]) || strtolower((string)($_SESSION["role"] ?? "")) !== "admin") {
    header("Location: ../html/Torino.html");
    exit;
}

$_SESSION['last_activity'] = time();

mysqli_report(MYSQLI_REPORT_OFF);

function h($value): string {
    return htmlspecialchars((string)($value ?? ""), ENT_QUOTES, "UTF-8");
}

function incidentStatusClass(string $status): string {
    return match (strtolower(trim($status))) {
        "pending" => "pending",
        "in review", "under review", "in_review" => "review",
        "resolved" => "resolved",
        default => "neutral"
    };
}

function severityClass(string $severity): string {
    return match (strtolower(trim($severity))) {
        "high" => "high",
        "medium" => "med",
        default => "low"
    };
}

function formatIncidentDate(?string $value, string $format = "M j, Y · g:i A"): string {
    if (!$value) return "—";
    $timestamp = strtotime($value);
    return $timestamp ? date($format, $timestamp) : "—";
}

function validActivityDate(string $date): bool {
    $parsed = DateTimeImmutable::createFromFormat("!Y-m-d", $date);
    return $parsed !== false && $parsed->format("Y-m-d") === $date;
}

function activityEventClass(string $eventType): string {
    if (str_contains($eventType, "SUCCESS") || str_contains($eventType, "VERIFIED")) {
        return "success";
    }
    if (str_contains($eventType, "LOCKED") || str_contains($eventType, "ALERT")) {
        return "warning";
    }
    if (str_contains($eventType, "LOCKOUT")) {
        return "warning";
    }
    if (str_contains($eventType, "FAILED")) {
        return "danger";
    }
    if (str_contains($eventType, "OTP_SENT")) {
        return "info";
    }
    return "neutral";
}

function activityBrowserLabel(?string $userAgent): string {
    $userAgent = trim((string)$userAgent);
    if ($userAgent === "") return "Unknown";

    $browser = "Browser";
    $version = "";
    foreach ([
        "Edge" => "/Edg\\/([0-9.]+)/",
        "Opera" => "/OPR\\/([0-9.]+)/",
        "Chrome" => "/Chrome\\/([0-9.]+)/",
        "Firefox" => "/Firefox\\/([0-9.]+)/",
        "Safari" => "/Version\\/([0-9.]+).*Safari/"
    ] as $name => $pattern) {
        if (preg_match($pattern, $userAgent, $matches)) {
            $browser = $name;
            $version = " " . explode(".", $matches[1])[0];
            break;
        }
    }

    if (str_contains($userAgent, "Windows")) {
        $platform = "Windows";
    } elseif (str_contains($userAgent, "Android")) {
        $platform = "Android";
    } elseif (str_contains($userAgent, "iPhone") || str_contains($userAgent, "iPad")) {
        $platform = "iOS";
    } elseif (str_contains($userAgent, "Mac OS") || str_contains($userAgent, "Macintosh")) {
        $platform = "macOS";
    } elseif (str_contains($userAgent, "Linux")) {
        $platform = "Linux";
    } else {
        $platform = "Unknown platform";
    }

    return $browser . $version . " · " . $platform;
}

function logAdminActivity(
    ?mysqli $conn,
    int $userId,
    string $actor,
    string $action,
    string $details
): void {

    if (!$conn) {
        return;
    }

    // Convert admin actions into consistent event codes.
    $eventTypes = [
        'Created incident report' => 'ADMIN_CREATED_INCIDENT',
        'Updated incident status' => 'ADMIN_UPDATED_INCIDENT_STATUS',
        'Viewed admin dashboard' => 'ADMIN_VIEWED_DASHBOARD'
    ];

    $eventType = $eventTypes[$action] ?? 'ADMIN_ACTIVITY';

    // Prefer the actual logged-in username.
    $username = trim((string)($_SESSION['username'] ?? $actor));

    $ip = substr(
        (string)($_SERVER['REMOTE_ADDR'] ?? ''),
        0,
        45
    );

    $userAgent = substr(
        (string)($_SERVER['HTTP_USER_AGENT'] ?? ''),
        0,
        255
    );

    $logDetails = substr($action . ' - ' . $details, 0, 255);

    $stmt = $conn->prepare(
        'INSERT INTO activity_logs
            (event_type, username_typed, user_id, ip_address,
             user_agent, details)
         VALUES (?, ?, ?, ?, ?, ?)'
    );

    if (!$stmt) {
        error_log('Admin activity log prepare failed: ' . $conn->error);
        return;
    }

    $stmt->bind_param(
        'ssisss',
        $eventType,
        $username,
        $userId,
        $ip,
        $userAgent,
        $logDetails
    );

    if (!$stmt->execute()) {
        error_log('Admin activity log insert failed: ' . $stmt->error);
    }

    $stmt->close();
}

function renderIncidentRows(array $reports, string $csrfToken, bool $editable = false): void {
    if (!$reports) {
        $colspan = $editable ? 7 : 7;
        echo '<tr><td colspan="' . $colspan . '"><div class="table-empty"><i class="fa-regular fa-folder-open"></i><strong>No incident reports yet</strong><span>When a student submits a report, it will appear here automatically.</span></div></td></tr>';
        return;
    }

    foreach ($reports as $report) {
        $id = (int)$report["id"];
        $reportCode = "#INC-" . str_pad((string)$id, 4, "0", STR_PAD_LEFT);
        $student = trim((string)($report["student_name"] ?? "")) ?: "Name not provided";
        $grade = trim((string)($report["grade_level"] ?? ""));
        $category = (string)($report["category"] ?? "Uncategorized");
        $severity = (string)($report["severity"] ?? "Low");
        $status = (string)($report["status"] ?? "Pending");
        $date = formatIncidentDate($report["created_at"] ?? null);
        $description = (string)($report["description"] ?? "");
        $statusClass = incidentStatusClass($status);
        $severityClass = severityClass($severity);

        echo '<tr class="incident-row" data-category="' . h(strtolower($category)) . '" data-status="' . h(strtolower($status)) . '" data-search="' . h(strtolower($reportCode . ' ' . $student . ' ' . $grade . ' ' . $category . ' ' . $severity . ' ' . $status . ' ' . $description)) . '">';
        echo '<td><strong class="report-code">' . h($reportCode) . '</strong></td>';
        echo '<td><span class="student-name">' . h($student) . '</span>';
        if ($grade !== "") echo '<small class="cell-subtitle">' . h($grade) . '</small>';
        echo '</td>';
        echo '<td>' . h($category) . '</td>';
        echo '<td><span class="sev"><span class="sev-dot ' . h($severityClass) . '"></span>' . h($severity) . '</span></td>';
        echo '<td><span class="pill ' . h($statusClass) . '">' . h($status) . '</span></td>';
        echo '<td>' . h($date) . '</td>';
        echo '<td class="actions-cell">';
        echo '<button type="button" class="btn-quiet view-details" data-report-id="' . h($reportCode) . '" data-student="' . h($student) . '" data-grade="' . h($grade) . '" data-category="' . h($category) . '" data-severity="' . h($severity) . '" data-status="' . h($status) . '" data-date="' . h($date) . '" data-description="' . h($description) . '"><i class="fa-regular fa-eye"></i> Details</button>';
        if ($editable) {
            echo '<form method="post" class="status-form">';
            echo '<input type="hidden" name="csrf_token" value="' . h($csrfToken) . '">';
            echo '<input type="hidden" name="action" value="update_status">';
            echo '<input type="hidden" name="incident_id" value="' . $id . '">';
            echo '<select name="status" class="status-select" aria-label="Change status for ' . h($reportCode) . '">';
            foreach (["Pending", "In review", "Resolved"] as $option) {
                echo '<option value="' . h($option) . '"' . ($status === $option ? ' selected' : '') . '>' . h($option) . '</option>';
            }
            echo '</select><button class="btn-small" type="submit">Save</button></form>';
        }
        echo '</td></tr>';
    }
}

$adminNameRaw = "Admin";
$adminName = h($adminNameRaw);
$initials = "A";
$csrfToken = $_SESSION["csrf_token"] ??= bin2hex(random_bytes(32));

$conn = null;
$dbReady = false;
$dbMessage = "";
$activityLogsReady = false;
$loginAttemptsReady = false;

if (is_file(dirname(__DIR__) . "/php/config.php")) {
    require_once dirname(__DIR__) . "/php/config.php";
    if (isset($conn) && $conn instanceof mysqli && !$conn->connect_errno) {
        $conn->set_charset("utf8mb4");
        $tableCheck = @$conn->query("SHOW TABLES LIKE 'incidents'");
        if ($tableCheck && $tableCheck->num_rows > 0) {
            $dbReady = true;
        } else {
            $dbMessage = "The database connection is available, but the incidents table was not found. Run schema.sql in the same database used by config.php.";
        }
        $logsCheck = @$conn->query("SHOW TABLES LIKE 'activity_logs'");
        $activityLogsReady = $logsCheck && $logsCheck->num_rows > 0;
        $attemptsCheck = @$conn->query("SHOW TABLES LIKE 'login_attempts'");
        $loginAttemptsReady = $attemptsCheck && $attemptsCheck->num_rows > 0;
    } else {
        $dbMessage = "Database connection was not available. Check that config.php creates a working MySQLi connection named \$conn.";
    }
} else {
    $dbMessage = "config.php was not found. Put admin_dashboard.php in the same project folder as your database configuration file.";
}

// Record every successful admin dashboard visit.
if ($dbReady && $activityLogsReady && $conn) {
    logAdminActivity(
        $conn,
        (int)($_SESSION['user_id'] ?? 0),
        'Admin',
        'Viewed admin dashboard',
        'Administrator opened the dashboard.'
    );
}

$allowedStatuses = ["Pending", "In review", "Resolved"];
$allowedCategories = ["Bullying", "Fighting", "Property damage", "Attendance", "Harassment", "Theft", "Vandalism", "Other"];

if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST["action"])) {
    $postToken = (string)($_POST["csrf_token"] ?? "");
    if (!hash_equals($csrfToken, $postToken)) {
        $_SESSION["sirs_flash"] = ["type" => "error", "message" => "Your form session expired. Please try again."];
    } elseif (!$dbReady || !$conn) {
        $_SESSION["sirs_flash"] = ["type" => "error", "message" => $dbMessage ?: "The incident database is not ready yet."];
    } else {
        $actorId = (int)($_SESSION["user_id"] ?? 0);

        if ($_POST["action"] === "create_incident") {
            $studentName = trim((string)($_POST["student_name"] ?? ""));
            $gradeLevel = trim((string)($_POST["grade_level"] ?? ""));
            $category = trim((string)($_POST["category"] ?? ""));
            $severity = trim((string)($_POST["severity"] ?? "Low"));
            $description = trim((string)($_POST["description"] ?? ""));

            if ($studentName === "" || $category === "" || $description === "") {
                $_SESSION["sirs_flash"] = ["type" => "error", "message" => "Please complete the student name, category, and incident description."];
            } elseif (!in_array($category, $allowedCategories, true) || !in_array($severity, ["Low", "Medium", "High"], true)) {
                $_SESSION["sirs_flash"] = ["type" => "error", "message" => "Please choose a valid incident category and severity."];
            } else {
                $stmt = @$conn->prepare("INSERT INTO incidents (student_name, grade_level, category, severity, status, description, reported_by) VALUES (?, ?, ?, ?, 'Pending', ?, ?)");
                if ($stmt) {
                    $stmt->bind_param("sssssi", $studentName, $gradeLevel, $category, $severity, $description, $actorId);
                    if ($stmt->execute()) {
                        $newId = (int)$stmt->insert_id;
                        logAdminActivity($conn, $actorId, $adminNameRaw, "Created incident report", "Report #INC-" . str_pad((string)$newId, 4, "0", STR_PAD_LEFT) . " · " . $category);
                        $_SESSION["sirs_flash"] = ["type" => "success", "message" => "Incident report created successfully. It now appears in the dashboard."];
                    } else {
                        $_SESSION["sirs_flash"] = ["type" => "error", "message" => "The report could not be saved. Check your incidents table and required fields."];
                    }
                    $stmt->close();
                } else {
                    $_SESSION["sirs_flash"] = ["type" => "error", "message" => "Could not prepare the incident insert query. Check your database schema."];
                }
            }
        } elseif ($_POST["action"] === "update_status") {
            $incidentId = filter_var($_POST["incident_id"] ?? null, FILTER_VALIDATE_INT);
            $status = trim((string)($_POST["status"] ?? ""));
            if (!$incidentId || !in_array($status, $allowedStatuses, true)) {
                $_SESSION["sirs_flash"] = ["type" => "error", "message" => "Invalid report or status selection."];
            } else {
                $stmt = @$conn->prepare("UPDATE incidents SET status = ?, resolved_at = CASE WHEN ? = 'Resolved' THEN CURRENT_TIMESTAMP ELSE NULL END WHERE id = ?");
                if ($stmt) {
                    $stmt->bind_param("ssi", $status, $status, $incidentId);
                    if ($stmt->execute() && $stmt->affected_rows >= 0) {
                        logAdminActivity($conn, $actorId, $adminNameRaw, "Updated incident status", "Report #INC-" . str_pad((string)$incidentId, 4, "0", STR_PAD_LEFT) . " → " . $status);
                        $_SESSION["sirs_flash"] = ["type" => "success", "message" => "Incident status updated."];
                    } else {
                        $_SESSION["sirs_flash"] = ["type" => "error", "message" => "The incident status could not be updated."];
                    }
                    $stmt->close();
                }
            }
        }
    }

    header("Location: admin_dashboard.php");
    exit;
}

$flash = $_SESSION["sirs_flash"] ?? null;
unset($_SESSION["sirs_flash"]);

$stats = ["total" => 0, "pending" => 0, "in_review" => 0, "resolved" => 0];
$reports = [];
$categoryData = [];
$weeklyData = ["labels" => [], "values" => []];
$monthlyData = ["labels" => [], "values" => []];
$logs = [];
$activityEventTypes = [];
$activityMetrics = [
    "successful_logins" => 0,
    "failed_logins" => 0,
    "locked_accounts" => 0,
    "blocked_ips" => 0,
    "otp_sent" => 0,
    "otp_failed" => 0,
    "alert_emails" => 0,
];
$hourlyFailures = array_fill(0, 24, 0);
$hourlyLabels = [];
$topFailureIps = [];
$blockedIpAddresses = [];
$securityFlags = [];
$activityLogsError = "";
$today = date("Y-m-d");
$dateFromInput = $_GET["date_from"] ?? $today;
$dateToInput = $_GET["date_to"] ?? $today;
$activityDateFrom = is_string($dateFromInput) && validActivityDate($dateFromInput)
    ? $dateFromInput
    : $today;
$activityDateTo = is_string($dateToInput) && validActivityDate($dateToInput)
    ? $dateToInput
    : $today;
if ($activityDateFrom > $activityDateTo) {
    [$activityDateFrom, $activityDateTo] = [$activityDateTo, $activityDateFrom];
}
$eventTypeInput = $_GET["event_type"] ?? "";
$activityEventType = is_string($eventTypeInput) ? substr(trim($eventTypeInput), 0, 100) : "";
$usernameInput = $_GET["username"] ?? "";
$activityUsername = is_string($usernameInput) ? substr(trim($usernameInput), 0, 100) : "";
$ipInput = $_GET["ip"] ?? "";
$activityIp = is_string($ipInput) ? substr(trim($ipInput), 0, 45) : "";
$resolvedRate = 0;

if ($dbReady && $conn) {
    $statsResult = @$conn->query("SELECT COUNT(*) AS total, COALESCE(SUM(status = 'Pending'), 0) AS pending, COALESCE(SUM(status = 'In review'), 0) AS in_review, COALESCE(SUM(status = 'Resolved'), 0) AS resolved FROM incidents");
    if ($statsResult) {
        $statsRow = $statsResult->fetch_assoc();
        $stats = [
            "total" => (int)($statsRow["total"] ?? 0),
            "pending" => (int)($statsRow["pending"] ?? 0),
            "in_review" => (int)($statsRow["in_review"] ?? 0),
            "resolved" => (int)($statsRow["resolved"] ?? 0),
        ];
    }
    $resolvedRate = $stats["total"] > 0 ? (int)round(($stats["resolved"] / $stats["total"]) * 100) : 0;

    $reportsResult = @$conn->query("SELECT id, student_name, grade_level, category, severity, status, description, reported_by, created_at, resolved_at FROM incidents ORDER BY created_at DESC, id DESC LIMIT 250");
    if ($reportsResult) $reports = $reportsResult->fetch_all(MYSQLI_ASSOC);

    $categoryResult = @$conn->query("SELECT category, COUNT(*) AS total FROM incidents GROUP BY category ORDER BY total DESC, category ASC");
    if ($categoryResult) {
        while ($row = $categoryResult->fetch_assoc()) {
            $categoryData[] = ["label" => (string)$row["category"], "value" => (int)$row["total"]];
        }
    }

    // Last seven calendar days, including today.
    $weekStart = new DateTimeImmutable("today");
    $weekStart = $weekStart->modify("-6 days");
    $weeklyMap = [];
    $trendStmt = @$conn->prepare("SELECT DATE(created_at) AS period, COUNT(*) AS total FROM incidents WHERE created_at >= ? GROUP BY DATE(created_at)");
    if ($trendStmt) {
        $weekStartValue = $weekStart->format("Y-m-d 00:00:00");
        $trendStmt->bind_param("s", $weekStartValue);
        if ($trendStmt->execute()) {
            $trendResult = $trendStmt->get_result();
            while ($row = $trendResult->fetch_assoc()) $weeklyMap[$row["period"]] = (int)$row["total"];
        }
        $trendStmt->close();
    }
    for ($offset = 0; $offset < 7; $offset++) {
        $day = $weekStart->modify("+" . $offset . " days");
        $key = $day->format("Y-m-d");
        $weeklyData["labels"][] = $day->format("D");
        $weeklyData["values"][] = $weeklyMap[$key] ?? 0;
    }

    // Current month and the previous five months.
    $firstOfMonth = new DateTimeImmutable("first day of this month");
    $monthlyStart = $firstOfMonth->modify("-5 months");
    $monthlyMap = [];
    $monthlyStmt = @$conn->prepare("SELECT DATE_FORMAT(created_at, '%Y-%m') AS period, COUNT(*) AS total FROM incidents WHERE created_at >= ? GROUP BY DATE_FORMAT(created_at, '%Y-%m')");
    if ($monthlyStmt) {
        $monthlyStartValue = $monthlyStart->format("Y-m-d 00:00:00");
        $monthlyStmt->bind_param("s", $monthlyStartValue);
        if ($monthlyStmt->execute()) {
            $monthlyResult = $monthlyStmt->get_result();
            while ($row = $monthlyResult->fetch_assoc()) $monthlyMap[$row["period"]] = (int)$row["total"];
        }
        $monthlyStmt->close();
    }
    for ($offset = 0; $offset < 6; $offset++) {
        $month = $monthlyStart->modify("+" . $offset . " months");
        $key = $month->format("Y-m");
        $monthlyData["labels"][] = $month->format("M Y");
        $monthlyData["values"][] = $monthlyMap[$key] ?? 0;
    }

    if ($activityLogsReady) {
        $statsResult = $conn->query(
            "SELECT
                SUM(event_type = 'LOGIN_SUCCESS') AS successful_logins,
                SUM(event_type = 'LOGIN_FAILED') AS failed_logins,
                SUM(event_type = 'OTP_SENT') AS otp_sent,
                SUM(event_type = 'OTP_FAILED') AS otp_failed,
                SUM(event_type = 'ALERT_EMAIL_SENT') AS alert_emails
            FROM activity_logs
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)"
        );
        if ($statsResult) {
            $statsRow = $statsResult->fetch_assoc() ?: [];
            foreach ($activityMetrics as $metric => $value) {
                if (array_key_exists($metric, $statsRow)) {
                    $activityMetrics[$metric] = (int)$statsRow[$metric];
                }
            }
        } else {
            error_log("Activity log metrics query failed: " . $conn->error);
            $activityLogsError = "Some activity monitoring data could not be loaded. Check the activity_logs table schema and server error log.";
        }

        for ($hoursAgo = 23; $hoursAgo >= 0; $hoursAgo--) {
            $hourlyLabels[] = date("H:00", time() - ($hoursAgo * 3600));
        }

        $hourlyResult = $conn->query(
            "SELECT TIMESTAMPDIFF(HOUR, created_at, NOW()) AS hours_ago,
                    COUNT(*) AS failures
            FROM activity_logs
            WHERE event_type = 'LOGIN_FAILED'
              AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            GROUP BY hours_ago"
        );
        if ($hourlyResult) {
            while ($row = $hourlyResult->fetch_assoc()) {
                $hoursAgo = (int)$row["hours_ago"];
                if ($hoursAgo >= 0 && $hoursAgo < 24) {
                    $hourlyFailures[23 - $hoursAgo] = (int)$row["failures"];
                }
            }
        } else {
            error_log("Hourly activity log query failed: " . $conn->error);
            $activityLogsError = "Some activity monitoring data could not be loaded. Check the activity_logs table schema and server error log.";
        }

        $ipFlagDisplayCount = 0;
        $ipFlagsResult = $conn->query(
            "SELECT ip_address, COUNT(*) AS failures,
                    COUNT(DISTINCT username_typed) AS usernames
            FROM activity_logs
            WHERE event_type = 'LOGIN_FAILED'
              AND ip_address IS NOT NULL
              AND ip_address <> ''
              AND created_at >= DATE_SUB(NOW(), INTERVAL 10 MINUTE)
            GROUP BY ip_address
            HAVING COUNT(*) >= 10
            ORDER BY failures DESC"
        );
        if ($ipFlagsResult) {
            while ($row = $ipFlagsResult->fetch_assoc()) {
                $ip = (string)$row["ip_address"];
                $blockedIpAddresses[$ip] = true;
                if ($ipFlagDisplayCount < 3) {
                    $securityFlags[] = [
                        "type" => "danger",
                        "title" => "IP over threshold",
                        "description" => $ip . " — " . (int)$row["failures"] .
                            " failures across " . (int)$row["usernames"] . " usernames"
                    ];
                    $ipFlagDisplayCount++;
                }
            }
            $activityMetrics["blocked_ips"] = count($blockedIpAddresses);
        } else {
            error_log("IP activity flag query failed: " . $conn->error);
            $activityLogsError = "Some activity monitoring data could not be loaded. Check the activity_logs table schema and server error log.";
        }

        $targetedAccountsResult = $conn->query(
            "SELECT username_typed, COUNT(*) AS failures,
                    COUNT(DISTINCT ip_address) AS source_ips
            FROM activity_logs
            WHERE event_type = 'LOGIN_FAILED'
              AND username_typed IS NOT NULL
              AND created_at >= DATE_SUB(NOW(), INTERVAL 10 MINUTE)
            GROUP BY username_typed
            HAVING COUNT(*) >= 5 AND COUNT(DISTINCT ip_address) >= 3
            ORDER BY failures DESC
            LIMIT 3"
        );
        if ($targetedAccountsResult) {
            while ($row = $targetedAccountsResult->fetch_assoc()) {
                $securityFlags[] = [
                    "type" => "warning",
                    "title" => "Account targeted",
                    "description" => (string)$row["username_typed"] . " — " .
                        (int)$row["failures"] . " failures from " .
                        (int)$row["source_ips"] . " different IPs"
                ];
            }
        } else {
            error_log("Targeted account activity query failed: " . $conn->error);
            $activityLogsError = "Some activity monitoring data could not be loaded. Check the activity_logs table schema and server error log.";
        }

        $otpFlagsResult = $conn->query(
            "SELECT username_typed, COUNT(*) AS failures
            FROM activity_logs
            WHERE event_type = 'OTP_FAILED'
              AND details LIKE '%Incorrect OTP%'
              AND username_typed IS NOT NULL
              AND created_at >= DATE_SUB(NOW(), INTERVAL 10 MINUTE)
            GROUP BY username_typed
            HAVING COUNT(*) >= 5
            ORDER BY failures DESC
            LIMIT 3"
        );
        if ($otpFlagsResult) {
            while ($row = $otpFlagsResult->fetch_assoc()) {
                $securityFlags[] = [
                    "type" => "warning",
                    "title" => "OTP guessing",
                    "description" => (string)$row["username_typed"] . " — " .
                        (int)$row["failures"] . " wrong OTPs in 10 minutes"
                ];
            }
        } else {
            error_log("OTP activity flag query failed: " . $conn->error);
            $activityLogsError = "Some activity monitoring data could not be loaded. Check the activity_logs table schema and server error log.";
        }

        if ($loginAttemptsReady) {
            $lockedAccountsResult = $conn->query(
                "SELECT COUNT(DISTINCT username) AS total
                FROM login_attempts
                WHERE failed_attempts >= 3
                  AND MOD(failed_attempts, 3) = 0
                  AND TIMESTAMPDIFF(SECOND, last_failed_at, NOW()) <
                    CASE
                        WHEN failed_attempts < 6 THEN 15
                        WHEN failed_attempts < 9 THEN 30
                        ELSE 60
                    END"
            );
            if ($lockedAccountsResult) {
                $lockedRow = $lockedAccountsResult->fetch_assoc() ?: [];
                $activityMetrics["locked_accounts"] = (int)($lockedRow["total"] ?? 0);
            } else {
                error_log("Locked account count query failed: " . $conn->error);
                $activityLogsError = "Some activity monitoring data could not be loaded. Check the login_attempts table and server error log.";
            }
        }

        $topIpsResult = $conn->query(
            "SELECT ip_address, COUNT(*) AS failures
            FROM activity_logs
            WHERE event_type = 'LOGIN_FAILED'
              AND ip_address IS NOT NULL
              AND ip_address <> ''
              AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            GROUP BY ip_address
            ORDER BY failures DESC, ip_address ASC
            LIMIT 4"
        );
        if ($topIpsResult) {
            $topFailureIps = $topIpsResult->fetch_all(MYSQLI_ASSOC);
        } else {
            error_log("Top failed login IP query failed: " . $conn->error);
            $activityLogsError = "Some activity monitoring data could not be loaded. Check the activity_logs table schema and server error log.";
        }

        $eventTypesResult = $conn->query(
            "SELECT DISTINCT event_type FROM activity_logs
            WHERE event_type <> '' ORDER BY event_type ASC"
        );
        if ($eventTypesResult) {
            while ($row = $eventTypesResult->fetch_assoc()) {
                $activityEventTypes[] = (string)$row["event_type"];
            }
        } else {
            error_log("Activity event type query failed: " . $conn->error);
            $activityLogsError = "Activity event types could not be loaded. Check the activity_logs table schema and server error log.";
        }

        if (!in_array($activityEventType, $activityEventTypes, true)) {
            $activityEventType = "";
        }

        $logsStmt = $conn->prepare(
            "SELECT username_typed, event_type, details, ip_address,
                    user_agent, created_at
            FROM activity_logs
            WHERE created_at >= CONCAT(?, ' 00:00:00')
              AND created_at < DATE_ADD(CONCAT(?, ' 00:00:00'), INTERVAL 1 DAY)
              AND (? = '' OR event_type = ?)
              AND (? = '' OR username_typed LIKE CONCAT('%', ?, '%'))
              AND (? = '' OR ip_address LIKE CONCAT('%', ?, '%'))
            ORDER BY created_at DESC, id DESC
            LIMIT 50"
        );
        if ($logsStmt) {
            $logsStmt->bind_param(
                "ssssssss",
                $activityDateFrom,
                $activityDateTo,
                $activityEventType,
                $activityEventType,
                $activityUsername,
                $activityUsername,
                $activityIp,
                $activityIp
            );
            if ($logsStmt->execute()) {
                $logs = $logsStmt->get_result()->fetch_all(MYSQLI_ASSOC);
            } else {
                error_log("Recent activity list query failed: " . $logsStmt->error);
                $activityLogsError = "Recent activity could not be loaded. Check the activity_logs table schema and server error log.";
            }
            $logsStmt->close();
        } else {
            error_log("Recent activity list prepare failed: " . $conn->error);
            $activityLogsError = "Recent activity could not be loaded. Check the activity_logs table schema and server error log.";
        }
    }
}

$recentReports = array_slice($reports, 0, 5);
$attentionReports = array_values(array_filter($reports, static fn($report) => ($report["status"] ?? "") !== "Resolved"));
$notificationsCount = count(array_filter($reports, static fn($report) => ($report["status"] ?? "") === "Pending"));
$chartPayload = [
    "total" => $stats["total"],
    "weekly" => $weeklyData,
    "monthly" => $monthlyData,
    "categories" => $categoryData,
];
$activeView = (($_GET["section"] ?? "") === "logs") ? "logs" : "dashboard";
$maxHourlyFailures = max($hourlyFailures);
$hasHourlyFailures = $maxHourlyFailures > 0;
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Dashboard · School Incident Report System</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
<link rel="stylesheet" href="admin.css">
</head>
<body>
<div class="app">
    <aside class="sidebar">
        <div class="brand">
            <div class="brand-mark"><i class="fa-solid fa-shield-halved"></i></div>
            <div class="brand-text"><h1>Incident Hub</h1><span>SCHOOL INCIDENT REPORT SYSTEM</span></div>
        </div>

        <p class="nav-group-label">WORKSPACE</p>
        <nav class="nav-list" aria-label="Admin navigation">
            <button type="button" class="nav-item <?= $activeView === "dashboard" ? "active" : "" ?>" data-page="dashboard" data-title="Dashboard overview"><i class="fa-solid fa-table-columns"></i><span>Dashboard</span></button>
            <button type="button" class="nav-item" data-page="incidents" data-title="Incident reports"><i class="fa-solid fa-file-lines"></i><span>Incident Report</span><span class="nav-badge"><?= number_format($stats["total"]) ?></span></button>
            <button type="button" class="nav-item" data-page="analytics" data-title="Analytics and reports"><i class="fa-solid fa-chart-line"></i><span>Analytics and Report</span></button>
            <button type="button" class="nav-item" data-page="notifications" data-title="Notifications"><i class="fa-solid fa-bell"></i><span>Notifications</span><?php if ($notificationsCount > 0): ?><span class="nav-badge"><?= number_format($notificationsCount) ?></span><?php endif; ?></button>
            <button type="button" class="nav-item <?= $activeView === "logs" ? "active" : "" ?>" data-page="logs" data-title="Activity logs"><i class="fa-solid fa-clock-rotate-left"></i><span>Activity Logs</span></button>
        </nav>

        <p class="nav-group-label">MANAGEMENT</p>

        <nav class="nav-list" aria-label="Management navigation">

            <button
                type="button"
                class="nav-item"
                data-page="settings"
                data-title="Settings"
            >
                <i class="fa-solid fa-gear"></i>
                <span>Settings</span>
            </button>

            <!-- LOG OUT -->
            <a class="nav-item sidebar-logout" href="../php/logout.php?role=admin">
                <i class="fa-solid fa-arrow-right-from-bracket"></i>
                <span>Log out</span>
            </a>

        </nav>

        <div class="sidebar-spacer"></div>

        <div class="sidebar-spacer"></div>
    </aside>

    <div class="main">
        <header class="topbar">
            <div class="breadcrumb"><span>Workspace</span><i class="fa-solid fa-chevron-right" style="font-size:10px"></i><span class="current" id="breadcrumbCurrent">Dashboard overview</span></div>
            <div class="topbar-right">
                <button type="button" class="bell" id="notificationsButton" aria-label="Open notifications"><i class="fa-regular fa-bell"></i><?php if ($notificationsCount > 0): ?><span class="dot"></span><?php endif; ?></button>
                <div class="topbar-divider"></div>
                <div class="admin-chip"><div class="avatar"><?= h($initials ?: "A") ?></div><div class="who"><strong><?= $adminName ?></strong><small>Administrator</small></div><i class="fa-solid fa-chevron-down"></i></div>
            </div>
        </header>

        <main class="content">
            <?php if ($flash): ?>
                <div class="alert <?= h($flash["type"] ?? "info") ?>" role="status"><i class="fa-solid <?= ($flash["type"] ?? "") === "success" ? "fa-circle-check" : "fa-circle-exclamation" ?>"></i><span><?= h($flash["message"] ?? "") ?></span><button type="button" class="alert-close" aria-label="Dismiss message">×</button></div>
            <?php endif; ?>
            <!-- DASHBOARD VIEW -->
            <section class="view-section <?= $activeView === "dashboard" ? "active-view" : "" ?>" data-view="dashboard" <?= $activeView !== "dashboard" ? "hidden" : "" ?>>
                <div class="page-head"><div><h2>Dashboard overview</h2><p>Live school safety information from submitted incident reports.</p></div><button type="button" class="btn-primary open-report-modal" <?= !$dbReady ? "disabled" : "" ?>><i class="fa-solid fa-plus"></i> New report</button></div>
                <div class="hero"><div class="hero-inner"><div class="hero-eyebrow">STUDENT SAFETY. SHARED RESPONSIBILITY.</div><h3>Every report makes a difference.</h3><p>Stay informed. Take action. Build a safer school community.</p></div></div>

                <div class="stat-grid">
                    <div class="stat-card"><div class="stat-top"><span class="label">Total incidents</span><div class="stat-icon green"><i class="fa-solid fa-file-lines"></i></div></div><div class="stat-value"><?= number_format($stats["total"]) ?></div><div class="stat-foot">All reports saved in the database</div></div>
                    <div class="stat-card"><div class="stat-top"><span class="label">Pending review</span><div class="stat-icon amber"><i class="fa-solid fa-clock"></i></div></div><div class="stat-value"><?= number_format($stats["pending"]) ?></div><div class="stat-foot">Awaiting initial assessment</div></div>
                    <div class="stat-card"><div class="stat-top"><span class="label">In review</span><div class="stat-icon blue"><i class="fa-solid fa-magnifying-glass"></i></div></div><div class="stat-value"><?= number_format($stats["in_review"]) ?></div><div class="stat-foot">Currently being investigated</div></div>
                    <div class="stat-card"><div class="stat-top"><span class="label">Resolved incidents</span><div class="stat-icon teal"><i class="fa-solid fa-circle-check"></i></div></div><div class="stat-value"><?= number_format($stats["resolved"]) ?></div><div class="stat-foot"><?= $resolvedRate ?>% of all reports resolved</div></div>
                </div>

                <div class="panel-row">
                    <div class="panel"><div class="panel-head"><div><h4>Incident trends</h4><p>Actual submissions over time</p></div><div class="toggle-group"><button type="button" class="active" data-range="weekly">Weekly</button><button type="button" data-range="monthly">Monthly</button></div></div><div class="chart-shell" data-chart-shell="trendChart"><canvas id="trendChart" height="160"></canvas><div class="chart-empty" hidden><i class="fa-solid fa-chart-line"></i><strong>No reports in this period</strong><span>New submissions will appear in this chart.</span></div></div></div>
                    <div class="panel"><div class="panel-head"><div><h4>Incidents by category</h4><p>Distribution across saved reports</p></div></div><div class="chart-shell category-chart-shell" data-chart-shell="categoryChart"><div class="donut-wrap"><canvas id="categoryChart" width="180" height="180"></canvas></div><div class="chart-empty" hidden><i class="fa-solid fa-chart-pie"></i><strong>No categories yet</strong><span>Category breakdown appears after a report is submitted.</span></div></div><ul class="donut-legend" id="categoryLegend"></ul></div>
                </div>

                <div class="table-panel"><div class="panel-head"><div><h4>Recent incident reports</h4><p>The five latest reports in your database</p></div><button type="button" class="btn-quiet" data-go-page="incidents">View all reports <i class="fa-solid fa-arrow-right"></i></button></div><div class="table-scroll"><table><thead><tr><th>Report ID</th><th>Student</th><th>Category</th><th>Severity</th><th>Status</th><th>Date reported</th><th>Action</th></tr></thead><tbody><?php renderIncidentRows($recentReports, $csrfToken, false); ?></tbody></table></div></div>
            </section>

            <!-- ALL INCIDENTS VIEW -->
            <section class="view-section" data-view="incidents" hidden>
                <div class="page-head"><div><h2>Incident reports</h2><p>Search submitted reports and update the workflow status.</p></div><button type="button" class="btn-primary open-report-modal" <?= !$dbReady ? "disabled" : "" ?>><i class="fa-solid fa-plus"></i> New report</button></div>
                <div class="filter-bar"><label class="search-box"><i class="fa-solid fa-magnifying-glass"></i><input type="search" id="incidentSearch" placeholder="Search report ID, student, or category…" aria-label="Search incident reports"></label><label class="filter-select-label"><span>Status</span><select id="statusFilter"><option value="all">All statuses</option><option value="pending">Pending</option><option value="in review">In review</option><option value="resolved">Resolved</option></select></label><span class="filter-count" id="filterCount"><?= count($reports) ?> report(s) shown</span></div>
                <div class="table-panel"><div class="panel-head"><div><h4>All incident reports</h4><p>Up to 250 most recent reports are displayed.</p></div></div><div class="table-scroll"><table id="incidentsTable"><thead><tr><th>Report ID</th><th>Student</th><th>Category</th><th>Severity</th><th>Status</th><th>Date reported</th><th>Actions / status</th></tr></thead><tbody><?php renderIncidentRows($reports, $csrfToken, true); ?></tbody></table><div class="table-empty filtered-empty" id="filteredEmpty" hidden><i class="fa-solid fa-filter-circle-xmark"></i><strong>No matching reports</strong><span>Try another search term or status filter.</span></div></div></div>
            </section>

            <!-- ANALYTICS VIEW -->
            <section class="view-section" data-view="analytics" hidden>
                <div class="page-head"><div><h2>Analytics and reports</h2><p>Summaries generated from the incident records currently saved in the database.</p></div></div>
                <div class="stat-grid analytics-stat-grid"><div class="stat-card"><div class="stat-top"><span class="label">Total reports</span><div class="stat-icon green"><i class="fa-solid fa-file-lines"></i></div></div><div class="stat-value"><?= number_format($stats["total"]) ?></div><div class="stat-foot">All stored incidents</div></div><div class="stat-card"><div class="stat-top"><span class="label">Pending</span><div class="stat-icon amber"><i class="fa-solid fa-clock"></i></div></div><div class="stat-value"><?= number_format($stats["pending"]) ?></div><div class="stat-foot">Need initial review</div></div><div class="stat-card"><div class="stat-top"><span class="label">Resolved rate</span><div class="stat-icon teal"><i class="fa-solid fa-check"></i></div></div><div class="stat-value"><?= $resolvedRate ?>%</div><div class="stat-foot">Resolved divided by total</div></div></div>
                <div class="panel-row"><div class="panel"><div class="panel-head"><div><h4>Category breakdown</h4><p>Counts from all stored incidents</p></div></div><div class="table-scroll"><table><thead><tr><th>Category</th><th>Reports</th><th>Share</th></tr></thead><tbody>
                    <?php if (!$categoryData): ?><tr><td colspan="3"><div class="table-empty"><i class="fa-solid fa-chart-column"></i><strong>No analytics available yet</strong><span>There will be a breakdown after reports have been submitted.</span></div></td></tr><?php else: foreach ($categoryData as $category): $share = $stats["total"] ? round(($category["value"] / $stats["total"]) * 100, 1) : 0; ?><tr><td><?= h($category["label"]) ?></td><td><?= number_format($category["value"]) ?></td><td><div class="share-cell"><span class="share-track"><span style="width: <?= min(100, $share) ?>%"></span></span><strong><?= h($share) ?>%</strong></div></td></tr><?php endforeach; endif; ?>
                </tbody></table></div></div><div class="panel"><div class="panel-head"><div><h4>Report status summary</h4><p>Current workflow snapshot</p></div></div><div class="status-summary"><div><span class="summary-bullet pending-bullet"></span><span>Pending</span><strong><?= number_format($stats["pending"]) ?></strong></div><div><span class="summary-bullet review-bullet"></span><span>In review</span><strong><?= number_format($stats["in_review"]) ?></strong></div><div><span class="summary-bullet resolved-bullet"></span><span>Resolved</span><strong><?= number_format($stats["resolved"]) ?></strong></div></div><p class="muted-note">These values update when the page reloads after a report is created or its status changes.</p></div></div>
                <div class="table-panel"><div class="panel-head"><div><h4>Monthly report totals</h4><p>Last six months, including months with zero reports</p></div></div><div class="table-scroll"><table><thead><tr><th>Month</th><th>Number of reports</th></tr></thead><tbody><?php foreach ($monthlyData["labels"] as $index => $label): ?><tr><td><?= h($label) ?></td><td><?= number_format((int)($monthlyData["values"][$index] ?? 0)) ?></td></tr><?php endforeach; ?></tbody></table></div></div>
            </section>

            <!-- NOTIFICATIONS VIEW -->
            <section class="view-section" data-view="notifications" hidden>
                <div class="page-head"><div><h2>Notifications</h2><p>Items needing attention, derived from current incident statuses.</p></div><button type="button" class="btn-quiet" data-go-page="incidents">Open incident reports <i class="fa-solid fa-arrow-right"></i></button></div>
                <div class="notification-summary"><div class="notification-icon"><i class="fa-solid fa-inbox"></i></div><div><strong><?= number_format(count($attentionReports)) ?> report(s) need attention</strong><p><?= number_format($stats["pending"]) ?> pending and <?= number_format($stats["in_review"]) ?> currently in review. This list is calculated from incident status; it is not a separate read/unread notification system.</p></div></div>
                <div class="table-panel"><div class="panel-head"><div><h4>Follow-up queue</h4><p>All reports not marked as resolved</p></div></div><div class="table-scroll"><table><thead><tr><th>Report ID</th><th>Student</th><th>Category</th><th>Severity</th><th>Status</th><th>Date reported</th><th>Action</th></tr></thead><tbody><?php renderIncidentRows($attentionReports, $csrfToken, false); ?></tbody></table></div></div>
            </section>

            <!-- ACTIVITY LOGS VIEW -->
            <section class="view-section <?= $activeView === "logs" ? "active-view" : "" ?>" data-view="logs" <?= $activeView !== "logs" ? "hidden" : "" ?>>
                <div class="page-head"><div><h2>Activity logs</h2><p>Authentication events and security activity recorded by the system.</p></div></div>
                <?php if ($activityLogsError !== ""): ?><div class="alert error" role="alert"><i class="fa-solid fa-circle-exclamation"></i><span><?= h($activityLogsError) ?></span></div><?php endif; ?>

                <div class="stat-grid security-stat-grid">
                    <div class="stat-card"><div class="security-stat-label">Successful log-ins</div><div class="stat-value"><?= number_format($activityMetrics["successful_logins"]) ?></div></div>
                    <div class="stat-card"><div class="security-stat-label">Failed log-ins</div><div class="stat-value danger-value"><?= number_format($activityMetrics["failed_logins"]) ?></div></div>
                    <div class="stat-card"><div class="security-stat-label">Accounts locked now</div><div class="stat-value warning-value"><?= number_format($activityMetrics["locked_accounts"]) ?></div></div>
                    <div class="stat-card"><div class="security-stat-label">IPs blocked now</div><div class="stat-value danger-value"><?= number_format($activityMetrics["blocked_ips"]) ?></div></div>
                    <div class="stat-card"><div class="security-stat-label">OTPs sent / failed</div><div class="stat-value"><?= number_format($activityMetrics["otp_sent"]) ?> / <?= number_format($activityMetrics["otp_failed"]) ?></div></div>
                    <div class="stat-card"><div class="security-stat-label">Alert emails sent</div><div class="stat-value"><?= number_format($activityMetrics["alert_emails"]) ?></div></div>
                    <div class="security-stat-period">Counts cover the last 24 hours unless the card says “now”.</div>
                </div>

                <div class="panel-row security-panel-row">
                    <section class="panel security-panel">
                        <div class="panel-head"><div><h4>Failed log-ins per hour — last 24 hours</h4><p>Each bar represents one hour</p></div></div>
                        <?php if (!$activityLogsReady): ?>
                            <div class="security-empty">Activity log table is not available.</div>
                        <?php elseif (!$hasHourlyFailures): ?>
                            <div class="security-empty">No failed log-ins recorded in the last 24 hours.</div>
                        <?php else: ?>
                            <div class="hourly-chart" role="img" aria-label="Failed log-ins per hour for the last 24 hours">
                                <?php foreach ($hourlyFailures as $index => $failures): $barHeight = $failures > 0 ? max(5, (int)round(($failures / $maxHourlyFailures) * 100)) : 0; ?>
                                    <span class="hourly-bar-wrap" title="<?= h($hourlyLabels[$index] . " — " . $failures . " failed log-ins") ?>"><span class="hourly-bar <?= $failures === $maxHourlyFailures && $failures > 0 ? "peak" : "" ?>" style="height: <?= $barHeight ?>%"></span></span>
                                <?php endforeach; ?>
                            </div>
                            <div class="hourly-axis"><span><?= h($hourlyLabels[0] ?? "") ?></span><span><?= h($hourlyLabels[6] ?? "") ?></span><span><?= h($hourlyLabels[12] ?? "") ?></span><span><?= h($hourlyLabels[18] ?? "") ?></span><span><?= h($hourlyLabels[23] ?? "") ?></span></div>
                        <?php endif; ?>
                    </section>

                    <section class="panel security-panel">
                        <div class="panel-head"><div><h4>Top IP addresses by failures</h4><p>Last 24 hours</p></div></div>
                        <?php if (!$activityLogsReady): ?>
                            <div class="security-empty">Activity log table is not available.</div>
                        <?php elseif (!$topFailureIps): ?>
                            <div class="security-empty">No failed log-ins recorded yet.</div>
                        <?php else: ?>
                            <div class="security-mini-table">
                                <div class="security-mini-head"><span>IP address</span><span>Failures</span><span>Status</span></div>
                                <?php foreach ($topFailureIps as $ipRow): $rowIp = (string)$ipRow["ip_address"]; ?>
                                    <div class="security-mini-row"><span><?= h($rowIp) ?></span><strong><?= number_format((int)$ipRow["failures"]) ?></strong><span><?= isset($blockedIpAddresses[$rowIp]) ? '<b class="security-status blocked">BLOCKED</b>' : '<span class="security-status neutral">—</span>' ?></span></div>
                                <?php endforeach; ?>
                            </div>
                        <?php endif; ?>
                    </section>

                    <section class="panel security-panel">
                        <div class="panel-head"><div><h4>Security monitoring flags</h4><p>Threshold checks over the last 10 minutes</p></div></div>
                        <?php if (!$activityLogsReady): ?>
                            <div class="security-empty">Activity log table is not available.</div>
                        <?php elseif (!$securityFlags): ?>
                            <div class="security-empty">No current authentication flags.</div>
                        <?php else: ?>
                            <ul class="security-flags">
                                <?php foreach ($securityFlags as $flag): ?>
                                    <li class="<?= h($flag["type"]) ?>"><span class="security-flag-dot"></span><span><strong><?= h($flag["title"]) ?></strong><small><?= h($flag["description"]) ?></small></span></li>
                                <?php endforeach; ?>
                            </ul>
                        <?php endif; ?>
                    </section>
                </div>

                <div class="table-panel security-events-panel">
                    <div class="panel-head"><div><h4>Recent events (latest 50)</h4><p>Filter authentication and system activity by date, event, username, or IP.</p></div></div>
                    <form class="activity-filter-bar" method="get" action="admin_dashboard.php">
                        <input type="hidden" name="section" value="logs">
                        <label><span>Date from</span><input type="date" name="date_from" value="<?= h($activityDateFrom) ?>"></label>
                        <label><span>Date to</span><input type="date" name="date_to" value="<?= h($activityDateTo) ?>"></label>
                        <label><span>Event type</span><select name="event_type"><option value="">All</option><?php foreach ($activityEventTypes as $eventType): ?><option value="<?= h($eventType) ?>" <?= $activityEventType === $eventType ? "selected" : "" ?>><?= h(str_replace("_", " ", $eventType)) ?></option><?php endforeach; ?></select></label>
                        <label><span>Username</span><input type="search" name="username" maxlength="100" placeholder="Any username" value="<?= h($activityUsername) ?>"></label>
                        <label><span>IP address</span><input type="search" name="ip" maxlength="45" placeholder="Any IP" value="<?= h($activityIp) ?>"></label>
                        <button class="btn-primary activity-filter-submit" type="submit"><i class="fa-solid fa-filter"></i> Apply filter</button>
                        <a class="btn-quiet activity-filter-reset" href="admin_dashboard.php?section=logs">Reset</a>
                    </form>
                    <div class="table-scroll"><table class="security-events-table"><thead><tr><th>Time</th><th>Event</th><th>Username</th><th>IP address</th><th>Browser</th></tr></thead><tbody>
                        <?php if (!$activityLogsReady): ?><tr><td colspan="5"><div class="table-empty"><i class="fa-solid fa-clock-rotate-left"></i><strong>Activity log table is not set up</strong><span>Run the activity log schema setup to enable monitoring.</span></div></td></tr><?php elseif ($activityLogsError !== "" && !$logs): ?><tr><td colspan="5"><div class="table-empty"><i class="fa-solid fa-triangle-exclamation"></i><strong>Unable to load activity events</strong><span>Check the database schema and server error log.</span></div></td></tr><?php elseif (!$logs): ?><tr><td colspan="5"><div class="table-empty"><i class="fa-regular fa-folder-open"></i><strong>No matching activity found</strong><span>Try changing the date range or filters.</span></div></td></tr><?php else: foreach ($logs as $log): $eventType = (string)($log["event_type"] ?? ""); ?>
                            <tr><td><?= h(formatIncidentDate($log["created_at"] ?? null, "H:i:s")) ?></td><td><span class="activity-event <?= h(activityEventClass($eventType)) ?>" title="<?= h($log["details"] ?? "") ?>"><?= h(str_replace("_", " ", strtoupper($eventType))) ?></span></td><td><?= h($log["username_typed"] ?? "—") ?></td><td><?= h($log["ip_address"] ?? "—") ?></td><td><?= h(activityBrowserLabel($log["user_agent"] ?? null)) ?></td></tr>
                        <?php endforeach; endif; ?>
                    </tbody></table></div>
                </div>
            </section>

            <!-- SETTINGS VIEW -->
            <section class="view-section" data-view="settings" hidden>
                <div class="page-head"><div><h2>Settings</h2><p>Manage incident archiving, reporter privacy, and response expectations.</p></div></div>
                <section class="admin-settings-panel">
                    <div class="admin-setting-row">
                        <span class="admin-setting-icon"><i class="fa-solid fa-box-archive"></i></span>
                        <div class="admin-setting-copy"><strong>Incident Auto-Archiving</strong><p>Choose how long resolved reports stay visible before archiving.</p></div>
                        <select id="autoArchiveDays" class="admin-setting-select" aria-label="Resolved report archiving period"><option value="30">30 days</option><option value="90" selected>90 days</option><option value="semester">End of semester</option></select>
                    </div>
                    <div class="admin-setting-row">
                        <span class="admin-setting-icon"><i class="fa-solid fa-user-shield"></i></span>
                        <div class="admin-setting-copy"><strong>Anonymity Policy</strong><p>Require elevated admin permission before reporter identities can be viewed.</p><small>Reporter identity is protected by default.</small></div>
                        <label class="admin-setting-toggle"><input type="checkbox" id="anonymityElevated" checked><span></span></label>
                    </div>
                    <div class="admin-settings-heading"><div><strong>Response Expectations (SLA)</strong><p>Set target response deadlines based on incident severity.</p></div><i class="fa-solid fa-clock"></i></div>
                    <div class="admin-setting-row">
                        <span class="admin-setting-icon severity-high"><i class="fa-solid fa-triangle-exclamation"></i></span>
                        <div class="admin-setting-copy"><strong>High Severity SLA</strong><p>Urgent incidents requiring immediate attention.</p></div>
                        <select id="highSlaHours" class="admin-setting-select" aria-label="High severity deadline"><option value="12" selected>12 hours</option><option value="24">24 hours</option></select>
                    </div>
                    <div class="admin-setting-row">
                        <span class="admin-setting-icon severity-medium"><i class="fa-solid fa-clock"></i></span>
                        <div class="admin-setting-copy"><strong>Medium Severity SLA</strong><p>Incidents requiring timely investigation and action.</p></div>
                        <select id="mediumSlaHours" class="admin-setting-select" aria-label="Medium severity deadline"><option value="48" selected>48 hours</option><option value="72">72 hours</option></select>
                    </div>
                    <div class="admin-setting-row">
                        <span class="admin-setting-icon severity-low"><i class="fa-solid fa-calendar-check"></i></span>
                        <div class="admin-setting-copy"><strong>Low Severity SLA</strong><p>Non-urgent incidents that still require follow-up.</p></div>
                        <select id="lowSlaDays" class="admin-setting-select" aria-label="Low severity deadline"><option value="3">3 business days</option><option value="5" selected>5 business days</option><option value="10">10 business days</option></select>
                    </div>
                    <div class="admin-settings-footer"><p id="settingsSaveMessage" role="status" aria-live="polite">Changes are saved to this browser only.</p><button type="button" class="btn-primary" id="saveAdminSettings"><i class="fa-solid fa-floppy-disk"></i> Save settings</button></div>
                    <div class="admin-settings-notice"><i class="fa-solid fa-circle-info"></i><p>These controls save preferences in this browser. Actual automatic archiving, identity permissions, and SLA enforcement require server-side implementation.</p></div>
                </section>
            </section>
        </main>
    </div>
</div>

<!-- CREATE INCIDENT MODAL -->
<div class="modal-backdrop" id="createReportModal" hidden>
    <section class="modal-card" role="dialog" aria-modal="true" aria-labelledby="createReportTitle">
        <div class="modal-head"><div><span class="modal-eyebrow">INCIDENT MANAGEMENT</span><h2 id="createReportTitle">Create incident report</h2><p>Save a report directly to the incidents database.</p></div><button type="button" class="modal-close" data-close-modal aria-label="Close">×</button></div>
        <form method="post" class="report-form" id="createIncidentForm">
            <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>"><input type="hidden" name="action" value="create_incident">
            <div class="form-grid"><label>Student involved <span>*</span><input type="text" name="student_name" maxlength="100" required placeholder="Student name"></label><label>Grade / year level<input type="text" name="grade_level" maxlength="20" placeholder="e.g. Grade 10"></label><label>Incident category <span>*</span><select name="category" required><option value="">Select category</option><?php foreach ($allowedCategories as $category): ?><option value="<?= h($category) ?>"><?= h($category) ?></option><?php endforeach; ?></select></label><label>Severity<select name="severity"><option>Low</option><option selected>Medium</option><option>High</option></select></label><label class="form-span-2">Incident description <span>*</span><textarea name="description" rows="4" required maxlength="5000" placeholder="Describe what happened, when, and where. Avoid including unnecessary sensitive information."></textarea></label></div>
            <div class="modal-actions"><button type="button" class="btn-secondary" data-close-modal>Cancel</button><button type="submit" class="btn-primary" <?= !$dbReady ? "disabled" : "" ?>><i class="fa-solid fa-floppy-disk"></i> Save report</button></div>
        </form>
    </section>
</div>

<!-- INCIDENT DETAILS MODAL -->
<div class="modal-backdrop" id="detailsModal" hidden>
    <section class="modal-card details-card" role="dialog" aria-modal="true" aria-labelledby="detailsTitle">
        <div class="modal-head"><div><span class="modal-eyebrow">INCIDENT DETAILS</span><h2 id="detailsTitle">Report details</h2><p id="detailReportId">Report ID</p></div><button type="button" class="modal-close" data-close-modal aria-label="Close">×</button></div>
        <div class="details-grid"><div><span>Student</span><strong id="detailStudent">—</strong></div><div><span>Grade / year level</span><strong id="detailGrade">—</strong></div><div><span>Category</span><strong id="detailCategory">—</strong></div><div><span>Severity</span><strong id="detailSeverity">—</strong></div><div><span>Status</span><strong id="detailStatus">—</strong></div><div><span>Date reported</span><strong id="detailDate">—</strong></div><div class="detail-description"><span>Description</span><p id="detailDescription">No description provided.</p></div></div>
        <div class="modal-actions"><button type="button" class="btn-secondary" data-close-modal>Close</button><button type="button" class="btn-primary" data-go-page="incidents" data-close-modal>Manage reports <i class="fa-solid fa-arrow-right"></i></button></div>
    </section>
</div>

<script>window.SIRS_DASHBOARD_DATA = <?= json_encode($chartPayload, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) ?>;</script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.4/chart.umd.min.js"></script>
<script src="admin.js"></script>
</body>
</html>
