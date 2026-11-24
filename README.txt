INCIDENT HUB — STUDENT INCIDENT REPORT SYSTEM
==============================================

FOLDER CONTENTS
---------------
Torino.html                 Public homepage (new design; no plushies)
style.css                   Homepage + sliding login/registration design
 torino.js                  Homepage interactions and AJAX authentication
school-hero.png             Campus hero image
config.php                  MySQL connection settings (edit if needed)
php/login.php                   Login handler with role-based dashboard redirect
register.php                Public registration (always creates Student accounts)
php/logout.php                  Destroys the session and returns to homepage
database.sql                Fresh MySQL database and table setup
admin/admin_dashboard.php   Admin dashboard, reports, charts, notifications, logs, settings
admin/admin.css             Admin dashboard stylesheet
admin/admin.js              Admin dashboard interactions
admin/school-hero.png        Campus hero image used by admin dashboard
student/student_dashboard.php  Student dashboard, report submission, profile, settings
student/student.css         Student dashboard stylesheet
student/student.js          Student dashboard interactions

NO LAB TEST PAGE
----------------
This folder intentionally does not include lab_test.php or a lab-test module.
It is the Student Incident Report System only.

INSTALLATION (XAMPP)
--------------------
1. Extract this folder into C:\xampp\htdocs\TORINO_SIRS\
2. Start Apache and MySQL in XAMPP.
3. Open phpMyAdmin, select the SQL tab, and import/run database.sql.
4. Open config.php and check DB_HOST, DB_USER, DB_PASS, and DB_NAME.
   Defaults are localhost / root / blank password / incident_report.
5. Open http://localhost/TORINO_SIRS/Torino.html
6. Create your first account using Create account. Public registrations are
   always assigned the student role.
7. To create an admin account, register a separate account, then run this in
   phpMyAdmin (replace the username):
      USE incident_report;
      UPDATE users SET role='admin' WHERE username='YOUR_ADMIN_USERNAME';
8. Log out and log in using that admin account. It opens the Admin Dashboard.
   Student accounts open the Student Dashboard.

IMPORTANT
---------
- Keep the root config.php private. It is listed in .gitignore.
- Existing database users and incidents are not copied into this new folder;
  import your own SQL backup if you want to keep existing records.
- This package contains the current coursework baseline authentication flow:
  password_hash/password_verify, role-based access, prepared SQL statements,
  and a 10-failure / 10-second username+IP cooldown. It does NOT yet implement
  every security requirement in the IT 107 handout (such as email OTP, CAPTCHA,
  security questions, password history, comprehensive IP blocking, or the
  monitoring CLI script). It also does not include a lab-test page.
- Admin Settings controls are currently browser-local preferences. Automatic
  archiving, identity-permission enforcement, and SLA enforcement require
  server-side database logic before they affect incident processing.
- Student All reports displays public report summaries and does not select the
  reporter account ID/name. Admin-only details remain protected by the role gate.

Username: admin
Password: admin123
Role: admin

Username: janadt
Password: Jana@12345!
Role: student

composer require phpmailer/phpmailer
