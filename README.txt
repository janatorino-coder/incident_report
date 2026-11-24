INCIDENT HUB - STUDENT INCIDENT REPORT SYSTEM
=============================================

FOLDER LAYOUT
-------------
css/                         All application stylesheets
js/                          Application scripts and the local Chart.js bundle
php/                         PHP endpoints, dashboards, and shared server code
images/                      Application images
html/                         Public home and forgotten-password pages
config.sample.php             Fake-value configuration template
database.sql                  Database schema and setup

INSTALLATION (XAMPP)
--------------------
1. Extract this folder into C:\xampp\htdocs\TORINO_SIRS\.
2. Start Apache and MySQL in XAMPP.
3. Import database.sql using phpMyAdmin.
4. Copy config.sample.php to
   C:\xampp\private\TORINO_SIRS\config.php and replace its placeholder values.
   Keep the real file outside htdocs. The application reads that path by
   default; set SIRS_CONFIG_PATH in the PHP environment to use another path.
5. Run composer install to install PHPMailer.
6. Open http://localhost/TORINO_SIRS/html/Torino.html.
7. Public registrations create student accounts. To grant admin access, use
   phpMyAdmin to update the chosen account's role:
      USE incident_report;
      UPDATE users SET role='admin' WHERE username='YOUR_ADMIN_USERNAME';

ROUTES AND ASSETS
-----------------
- Apache mod_rewrite and AllowOverride must be enabled for the compatibility
  routes in .htaccess. Existing admin/student dashboard URLs remain available.
- Chart.js is stored locally in js/chart.umd.js; package.json pins its source
  version for updates.
- The project has no standalone scripts/monitor.php. The scripts/ URL path is
  denied by .htaccess; admin activity logs are shown in the admin dashboard.
- Keep config.php, .env files, vendor/, and logs out of version control.
- Existing user accounts and incidents are not included; import a database
  backup if existing records need to be retained.
