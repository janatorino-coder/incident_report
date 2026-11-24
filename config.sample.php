<?php

return [
    'database' => [
        'host' => 'localhost',
        'username' => 'REPLACE_WITH_DATABASE_USER',
        'password' => 'REPLACE_WITH_DATABASE_PASSWORD',
        'name' => 'incident_report',
        'port' => 3306,
    ],
    'smtp' => [
        'host' => 'smtp.example.com',
        'username' => 'REPLACE_WITH_SMTP_USERNAME',
        'password' => 'REPLACE_WITH_SMTP_PASSWORD',
        'from_email' => 'noreply@example.com',
        'from_name' => 'Incident Hub',
        'port' => 587,
    ],
];
