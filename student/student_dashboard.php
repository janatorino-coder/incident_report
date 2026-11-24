
<?php
require_once __DIR__ . '/../php/session.php';
startSirsRoleSession('student');

if (
    isset($_SESSION['user_id']) &&
    time() - (int)($_SESSION['last_activity'] ?? 0) > 900
) {
    session_unset();
    session_destroy();
    header('Location: ../html/Torino.html?sessionExpired=1');
    exit;
}

/*
 * Only a logged-in student can open this dashboard.
 * Register first, then log in.
 */
if (
    !isset($_SESSION['user_id']) ||
    ($_SESSION['role'] ?? '') !== 'student'
) {
    header('Location: ../html/Torino.html');
    exit;
}

$_SESSION['last_activity'] = time();

if (is_file(dirname(__DIR__) . "/php/config.php")) {
    require_once dirname(__DIR__) . "/php/config.php";
}

if (!isset($conn) || !($conn instanceof mysqli) || $conn->connect_errno) {
    http_response_code(500);
    exit('Database connection failed. Check config.php.');
}

$conn->set_charset('utf8mb4');

function h($value): string {
    return htmlspecialchars(
        (string)($value ?? ''),
        ENT_QUOTES,
        'UTF-8'
    );
}

$userId = (int) $_SESSION['user_id'];
$username = (string) ($_SESSION['username'] ?? 'Student');

$view = $_GET['view'] ?? 'home';

$allowedViews = [
    'home',
    'reports',
    'make-report',
    'my-reports',
    'profile',
    'settings'
];

if (!in_array($view, $allowedViews, true)) {
    $view = 'home';
}

$categories = [
    'Bullying',
    'Property damage',
    'Harassment',
    'Fighting',
    'Safety concern',
    'Theft',
    'Vandalism',
    'Other'
];

$severities = ['Low', 'Medium', 'High'];

$csrf = $_SESSION['student_csrf']
    ??= bin2hex(random_bytes(32));

$error = '';
$flash = $_SESSION['student_flash'] ?? null;

unset($_SESSION['student_flash']);

/* =========================================
   GET SIGNED-IN STUDENT PROFILE
========================================= */

$profile = [
    'username' => $username,
    'email' => ''
];

$stmt = $conn->prepare(
    "SELECT username, email
     FROM users
     WHERE id = ?
     LIMIT 1"
);

if ($stmt) {
    $stmt->bind_param('i', $userId);

    if ($stmt->execute()) {
        $row = $stmt->get_result()->fetch_assoc();

        if ($row) {
            $profile = array_merge($profile, $row);
        }
    }

    $stmt->close();
}

$username = (string) ($profile['username'] ?: 'Student');
$initials = strtoupper(substr($username, 0, 2));

/* =========================================
   SUBMIT INCIDENT REPORT
========================================= */

if (
    $_SERVER['REQUEST_METHOD'] === 'POST' &&
    ($_POST['action'] ?? '') === 'submit_report'
) {
    $view = 'make-report';

    if (!hash_equals(
        $csrf,
        (string) ($_POST['csrf_token'] ?? '')
    )) {
        $error = 'Your session expired. Please refresh and try again.';

    } else {
        $category = trim((string) ($_POST['category'] ?? ''));
        $severity = trim((string) ($_POST['severity'] ?? 'Medium'));
        $location = trim((string) ($_POST['location'] ?? ''));
        $description = trim((string) ($_POST['description'] ?? ''));

        if (
            !in_array($category, $categories, true) ||
            !in_array($severity, $severities, true) ||
            $location === '' ||
            $description === ''
        ) {
            $error = 'Please complete all required fields.';

        } else {
            /*
             * Use the shared incidents table.
             * The reporter is linked privately using reported_by.
             * The student name shown in the public report data
             * is not the reporting account's name.
             */
            $stmt = $conn->prepare(
                "INSERT INTO incidents
                    (
                        student_name,
                        grade_level,
                        category,
                        severity,
                        status,
                        location,
                        description,
                        reported_by
                    )
                 VALUES
                    ('Confidential', NULL, ?, ?, 'Pending', ?, ?, ?)"
            );

            if (!$stmt) {
                $error =
                    'Could not save the report. Check the incidents table and location column.';

            } else {
                $stmt->bind_param(
                    'ssssi',
                    $category,
                    $severity,
                    $location,
                    $description,
                    $userId
                );

                if ($stmt->execute()) {
                    $newId = (int) $stmt->insert_id;
                    $stmt->close();

                    /*
                     * Optional activity log.
                     * This doesn't add sample incident data.
                     */
                    $log = $conn->prepare(
                        "INSERT INTO activity_logs
                            (user_id, actor_name, action, details)
                         VALUES (?, ?, 'Submitted incident report', ?)"
                    );

                    if ($log) {
                        $details = 'Report #INC-' .
                            str_pad((string) $newId, 4, '0', STR_PAD_LEFT);

                        $log->bind_param(
                            'iss',
                            $userId,
                            $username,
                            $details
                        );

                        $log->execute();
                        $log->close();
                    }

                    $_SESSION['student_flash'] = [
                        'type' => 'success',
                        'message' => 'Your report was submitted successfully.'
                    ];

                    header('Location: student_dashboard.php?view=my-reports');
                    exit;

                } else {
                    $error = 'The report could not be saved.';
                    $stmt->close();
                }
            }
        }
    }
}

/* =========================================
   LOAD REAL INCIDENTS - NO DEFAULT ROWS
========================================= */

$allReports = [];
$myReports = [];

$stats = [
    'total' => 0,
    'pending' => 0,
    'review' => 0,
    'resolved' => 0
];

/*
 * PUBLIC REPORT LIST.
 * Notice that this query does NOT select reported_by,
 * reporter username, or reporter account information.
 */
$result = $conn->query(
    "SELECT
        id,
        category,
        severity,
        status,
        location,
        description,
        created_at
     FROM incidents
     ORDER BY created_at DESC, id DESC"
);

if ($result) {
    while ($row = $result->fetch_assoc()) {
        $allReports[] = $row;

        $stats['total']++;

        $status = strtolower(trim((string) $row['status']));

        if ($status === 'pending') {
            $stats['pending']++;

        } elseif (in_array(
            $status,
            ['in review', 'under review', 'in_review'],
            true
        )) {
            $stats['review']++;

        } elseif ($status === 'resolved') {
            $stats['resolved']++;
        }
    }

    $result->free();
}

/*
 * MY REPORTS.
 * This list is restricted to the currently logged-in student.
 */
$stmt = $conn->prepare(
    "SELECT
        id,
        category,
        severity,
        status,
        location,
        description,
        created_at
     FROM incidents
     WHERE reported_by = ?
     ORDER BY created_at DESC, id DESC"
);

if ($stmt) {
    $stmt->bind_param('i', $userId);

    if ($stmt->execute()) {
        $result = $stmt->get_result();

        while ($row = $result->fetch_assoc()) {
            $myReports[] = $row;
        }
    }

    $stmt->close();
}

function statusClass($status): string {
    return match (strtolower(trim((string) $status))) {
        'pending' => 'pending',
        'in review', 'under review', 'in_review' => 'review',
        'resolved' => 'resolved',
        default => 'neutral'
    };
}

/* =========================================
   RENDER REPORTS
========================================= */

function renderReports(array $reports): void {
    if (empty($reports)) {
        echo '
        <div class="empty-state">
            <div class="empty-icon">
                <i class="fa-regular fa-folder-open"></i>
            </div>
            <h3>No incident reports yet</h3>
            <p>Reports will appear here after a student submits one.</p>
        </div>';
        return;
    }

    foreach ($reports as $report) {
        $id = (int) $report['id'];

        $reportNumber = '#INC-' .
            str_pad((string) $id, 4, '0', STR_PAD_LEFT);

        $date = !empty($report['created_at'])
            ? date('M j, Y', strtotime($report['created_at']))
            : '—';

        echo '<article class="report-row"
            data-search="' . h(strtolower(
                $reportNumber . ' ' .
                $report['category'] . ' ' .
                $report['status'] . ' ' .
                $report['location']
            )) . '"
            data-status="' . h(strtolower($report['status'])) . '">';

        echo '<div class="report-kind">
            <span class="document-icon">
                <i class="fa-regular fa-file-lines"></i>
            </span>
            <div>
                <strong>' . h($reportNumber) . '</strong>
                <small><i class="fa-solid fa-lock"></i> Anonymous reporter</small>
            </div>
        </div>';

        echo '<div class="report-category">
            <strong>' . h($report['category']) . '</strong>
            <small>' . h($report['location'] ?: 'Location not provided') . '</small>
        </div>';

        echo '<div>
            <span class="status-pill ' .
                h(statusClass($report['status'])) . '">' .
                h($report['status']) .
            '</span>
        </div>';

        echo '<div class="report-date">' . h($date) . '</div>';

        echo '<button
            type="button"
            class="view-report"
            data-id="' . $id . '"
            data-category="' . h($report['category']) . '"
            data-severity="' . h($report['severity']) . '"
            data-status="' . h($report['status']) . '"
            data-location="' . h($report['location']) . '"
            data-date="' . h($date) . '"
            data-description="' . h($report['description']) . '">
            <i class="fa-regular fa-eye"></i> View
        </button>';

        echo '</article>';
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Student Portal | Incident Hub</title>

    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap"
          rel="stylesheet">

    <link rel="stylesheet"
          href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">

    <link rel="stylesheet" href="student.css">
</head>
<body>

<div class="app-shell">

    <aside class="sidebar">

        <a class="brand" href="?view=home">
            <span class="brand-mark">
                <i class="fa-solid fa-shield-halved"></i>
            </span>
            <span>
                <strong>Incident Hub</strong>
                <small>STUDENT PORTAL</small>
            </span>
        </a>

        <p class="side-label">YOUR SPACE</p>

        <nav class="side-nav">
            <a class="<?= $view === 'home' ? 'active' : '' ?>"
               href="?view=home">
                <i class="fa-solid fa-house"></i> Home
            </a>

            <a class="<?= $view === 'reports' ? 'active' : '' ?>"
               href="?view=reports">
                <i class="fa-regular fa-file-lines"></i>
                All reports
                <b><?= (int) $stats['total'] ?></b>
            </a>

            <a class="<?= $view === 'make-report' ? 'active' : '' ?>"
               href="?view=make-report">
                <i class="fa-solid fa-plus"></i> Make a report
            </a>

            <a class="<?= $view === 'my-reports' ? 'active' : '' ?>"
               href="?view=my-reports">
                <i class="fa-regular fa-clipboard"></i> My reports
            </a>

            <a class="<?= $view === 'profile' ? 'active' : '' ?>"
               href="?view=profile">
                <i class="fa-regular fa-user"></i> My profile
            </a>

            <a class="<?= $view === 'settings' ? 'active' : '' ?>"
               href="?view=settings">
                <i class="fa-solid fa-gear"></i> Settings
            </a>

            <!-- Sign out moved from Settings into the sidebar -->
            <a class="sign-out-link" href="../php/logout.php?role=student">
                <i class="fa-solid fa-arrow-right-from-bracket"></i>
                Sign out
            </a>
        </nav>

        <div class="privacy-card">
            <i class="fa-solid fa-lock"></i>
            <div>
                <strong>Your privacy matters</strong>
                <p>Your identity is hidden from other students. Authorized staff can review reports.</p>
            </div>
        </div>

    </aside>

    <main class="main-area">

        <header class="topbar">
            <div class="breadcrumb">
                Student portal <i class="fa-solid fa-chevron-right"></i>
                <strong><?= h(ucwords(str_replace('-', ' ', $view))) ?></strong>
            </div>

            <div class="user-chip">
                <button type="button" id="helpButton" aria-label="Help">
                    <i class="fa-regular fa-circle-question"></i>
                </button>
                <span class="avatar"><?= h($initials) ?></span>
                <span>
                    <strong><?= h($username) ?></strong>
                    <small>Student account</small>
                </span>
            </div>
        </header>

        <div class="page-content">

            <?php if ($flash): ?>
                <div class="alert">
                    <?= h($flash['message'] ?? '') ?>
                </div>
            <?php endif; ?>

            <?php if ($error): ?>
                <div class="alert error"><?= h($error) ?></div>
            <?php endif; ?>

            <?php if ($view === 'home'): ?>

                <section class="welcome-banner">
                    <div>
                        <span class="eyebrow">
                            WELCOME BACK, <?= h(strtoupper($username)) ?>
                        </span>
                        <h1>Help keep your school safe.</h1>
                        <p>If something does not feel right, you can report it safely. Your voice matters.</p>
                        <a class="button button-mint" href="?view=make-report">
                            <i class="fa-solid fa-plus"></i> Make a report
                        </a>
                    </div>

                    <div class="banner-emblem">
                        <i class="fa-solid fa-shield-halved"></i>
                    </div>
                </section>

                <section class="stats-grid">

                    <article class="stat-card">
                        <span class="stat-icon green">
                            <i class="fa-regular fa-file-lines"></i>
                        </span>
                        <div>
                            <small>Community reports</small>
                            <strong><?= (int) $stats['total'] ?></strong>
                            <p>Actual submitted reports</p>
                        </div>
                    </article>

                    <article class="stat-card">
                        <span class="stat-icon amber">
                            <i class="fa-regular fa-clock"></i>
                        </span>
                        <div>
                            <small>Awaiting action</small>
                            <strong><?= (int) ($stats['pending'] + $stats['review']) ?></strong>
                            <p>Pending or being reviewed</p>
                        </div>
                    </article>

                    <article class="stat-card">
                        <span class="stat-icon blue">
                            <i class="fa-regular fa-circle-check"></i>
                        </span>
                        <div>
                            <small>Resolved</small>
                            <strong><?= (int) $stats['resolved'] ?></strong>
                            <p>Actual resolved reports</p>
                        </div>
                    </article>

                </section>

                <div class="home-grid">
                    <section class="panel recent-panel">
                        <div class="panel-heading">
                            <div>
                                <h2>Recent community reports</h2>
                                <p>Reporter names are not displayed.</p>
                            </div>
                            <a class="button button-outline" href="?view=reports">
                                View all →
                            </a>
                        </div>

                        <div class="table-head">
                            <span>REPORT</span>
                            <span>CATEGORY</span>
                            <span>STATUS</span>
                            <span>DATE</span>
                            <span></span>
                        </div>

                        <?php renderReports(array_slice($allReports, 0, 5)); ?>
                    </section>

                    <aside class="encouragement">
                        <span class="stat-icon green">
                            <i class="fa-solid fa-shield-halved"></i>
                        </span>
                        <span class="eyebrow">A SAFER COMMUNITY</span>
                        <h2>Not sure if you should report it?</h2>
                        <p>If it affects someone's safety, wellbeing, or ability to learn, tell the school. You do not need to have all the details.</p>
                        <a href="?view=make-report">Start a report →</a>
                    </aside>
                </div>

            <?php elseif ($view === 'reports'): ?>

                <section class="page-heading">
                    <div>
                        <span class="eyebrow">COMMUNITY TRANSPARENCY</span>
                        <h1>All incident reports</h1>
                        <p>See submitted reports and their status. Reporter identities are not displayed.</p>
                    </div>
                    <a class="button button-primary" href="?view=make-report">
                        <i class="fa-solid fa-plus"></i> Make a report
                    </a>
                </section>

                <section class="filter-panel">
                    <label class="search-box">
                        <i class="fa-solid fa-magnifying-glass"></i>
                        <input id="reportSearch" type="search"
                               placeholder="Search category, status, location or report ID">
                    </label>

                    <span class="privacy-inline">
                        <i class="fa-solid fa-lock"></i> Reporter identity protected
                    </span>

                    <select id="statusFilter">
                        <option value="all">All statuses</option>
                        <option value="pending">Pending</option>
                        <option value="review">In review</option>
                        <option value="resolved">Resolved</option>
                    </select>
                </section>

                <section class="panel all-reports-panel">
                    <div class="table-head">
                        <span>REPORT</span>
                        <span>CATEGORY</span>
                        <span>STATUS</span>
                        <span>DATE</span>
                        <span></span>
                    </div>

                    <div id="allReportsList">
                        <?php renderReports($allReports); ?>
                    </div>

                    <div id="noMatches" class="empty-state" hidden>
                        No reports match your search.
                    </div>
                </section>

            <?php elseif ($view === 'make-report'): ?>

                <section class="page-heading">
                    <div>
                        <span class="eyebrow">SPEAK UP SAFELY</span>
                        <h1>Make an incident report</h1>
                        <p>Share what happened so authorized school staff can respond.</p>
                    </div>
                </section>

                <section class="panel form-panel">
                    <div class="form-title">
                        <span class="number-badge">1</span>
                        <div>
                            <h2>Tell us what happened</h2>
                            <p>Required fields are marked with an asterisk.</p>
                        </div>
                    </div>

                    <form method="post" id="incidentForm">
                        <input type="hidden" name="csrf_token" value="<?= h($csrf) ?>">
                        <input type="hidden" name="action" value="submit_report">

                        <div class="form-grid">

                            <label>
                                Incident category *
                                <select name="category" required>
                                    <option value="">Select a category</option>
                                    <?php foreach ($categories as $category): ?>
                                        <option value="<?= h($category) ?>">
                                            <?= h($category) ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                            </label>

                            <label>
                                How urgent is it? *
                                <select name="severity" required>
                                    <?php foreach ($severities as $severity): ?>
                                        <option value="<?= h($severity) ?>"
                                            <?= $severity === 'Medium' ? 'selected' : '' ?>>
                                            <?= h($severity) ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                            </label>

                            <label class="full-width">
                                Where did it happen? *
                                <input name="location" maxlength="180" required
                                       placeholder="e.g. Cafeteria, east hallway, online">
                            </label>

                            <label class="full-width">
                                Describe the incident *
                                <textarea name="description" rows="6" maxlength="5000" required
                                    placeholder="Describe what happened, when, and any details that may help. Avoid unnecessary personal information."></textarea>
                            </label>

                        </div>

                        <div class="private-notice">
                            <i class="fa-solid fa-lock"></i>
                            <div>
                                <strong>Private submission</strong>
                                <p>Your account identity is not shown in the public student report list. Authorized staff can access reports for follow-up.</p>
                            </div>
                        </div>

                        <div class="form-actions">
                            <a class="button button-outline" href="?view=home">Cancel</a>
                            <button class="button button-mint" type="submit">
                                <i class="fa-solid fa-shield-halved"></i>
                                Submit report securely
                            </button>
                        </div>
                    </form>
                </section>

            <?php elseif ($view === 'my-reports'): ?>

                <section class="page-heading">
                    <div>
                        <span class="eyebrow">YOUR SUBMISSIONS</span>
                        <h1>My reports</h1>
                        <p>Track reports submitted from your own account.</p>
                    </div>
                    <a class="button button-primary" href="?view=make-report">
                        <i class="fa-solid fa-plus"></i> Make a report
                    </a>
                </section>

                <section class="panel all-reports-panel">
                    <div class="table-head">
                        <span>REPORT</span>
                        <span>CATEGORY</span>
                        <span>STATUS</span>
                        <span>DATE</span>
                        <span></span>
                    </div>
                    <?php renderReports($myReports); ?>
                </section>

            <?php elseif ($view === 'profile'): ?>

                <section class="page-heading">
                    <div>
                        <span class="eyebrow">YOUR ACCOUNT</span>
                        <h1>My profile</h1>
                        <p>Account information loaded from the database.</p>
                    </div>
                </section>

                <div class="profile-grid">
                    <section class="panel profile-summary">
                        <span class="profile-avatar"><?= h($initials) ?></span>
                        <h2><?= h($username) ?></h2>
                        <p>Student account</p>
                    </section>

                    <section class="panel profile-details">
                        <h2>Account information</h2>

                        <div class="detail-row">
                            <span>Username</span>
                            <strong><?= h($profile['username']) ?></strong>
                        </div>

                        <div class="detail-row">
                            <span>Email address</span>
                            <strong><?= h($profile['email'] ?: 'Not provided') ?></strong>
                        </div>

                        <div class="detail-row">
                            <span>Account role</span>
                            <strong>Student</strong>
                        </div>

                        <div class="detail-row">
                            <span>Reports submitted</span>
                            <strong><?= count($myReports) ?></strong>
                        </div>
                    </section>
                </div>

            <?php elseif ($view === 'settings'): ?>

                <section class="page-heading">
                    <div>
                        <span class="eyebrow">PREFERENCES</span>
                        <h1>Settings</h1>
                        <p>Manage preferences and review privacy information.</p>
                    </div>
                </section>

                <section class="panel settings-panel">

                    <div class="setting-row">
                        <span class="setting-icon"><i class="fa-regular fa-bell"></i></span>
                        <div>
                            <strong>Email notifications</strong>
                            <p>Preference only; email delivery must be configured separately.</p>
                        </div>
                        <label class="switch">
                            <input type="checkbox" data-setting="email">
                            <span></span>
                        </label>
                    </div>

                    <div class="setting-row">
                        <span class="setting-icon"><i class="fa-regular fa-file-lines"></i></span>
                        <div>
                            <strong>Report status updates</strong>
                            <p>Save this browser preference.</p>
                        </div>
                        <label class="switch">
                            <input type="checkbox" data-setting="updates" checked>
                            <span></span>
                        </label>
                    </div>

                    <button class="setting-row setting-button" id="privacyReview" type="button">
                        <span class="setting-icon"><i class="fa-solid fa-lock"></i></span>
                        <span>
                            <strong>Privacy and security</strong>
                            <p>Your account identity is hidden from other students in the report list.</p>
                        </span>
                        <b>Review →</b>
                    </button>


                </section>

            <?php endif; ?>

        </div>
    </main>
</div>

<dialog id="reportDialog" class="report-dialog">
    <form method="dialog">
        <button class="dialog-close" aria-label="Close">×</button>
    </form>
    <span class="eyebrow" id="modalId"></span>
    <h2 id="modalCategory"></h2>
    <p>
        <span id="modalStatus" class="status-pill"></span>
        <span id="modalSeverity"></span>
        <span id="modalDate"></span>
    </p>
    <p><strong>Location</strong><br><span id="modalLocation"></span></p>
    <p><strong>Description</strong></p>
    <p id="modalDescription" class="modal-description"></p>
    <div class="private-notice">
        <i class="fa-solid fa-lock"></i>
        <div>
            <strong>Anonymous reporter</strong>
            <p>The reporter's account identity is not shown in this student view.</p>
        </div>
    </div>
</dialog>

<dialog id="helpDialog" class="report-dialog">
    <form method="dialog">
        <button class="dialog-close" aria-label="Close">×</button>
    </form>
    <span class="eyebrow">STUDENT PORTAL HELP</span>
    <h2>Report safely</h2>
    <p>Reports are saved to the shared database so authorized school staff can review them. The student report list does not display the reporter's account name.</p>
    <p>If someone is in immediate danger, contact a trusted teacher or school office directly.</p>
</dialog>

<script src="student.js"></script>
</body>
</html>
