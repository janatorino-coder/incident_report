-- Incident Hub / Student Incident Report System
-- Fresh database schema. Run this entire script in phpMyAdmin.
CREATE DATABASE IF NOT EXISTS incident_report CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE incident_report;

CREATE TABLE IF NOT EXISTS users (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role ENUM('admin','student') NOT NULL DEFAULT 'student',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS login_attempts (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    failed_attempts INT UNSIGNED NOT NULL DEFAULT 0,
    last_failed_at TIMESTAMP NULL DEFAULT NULL,
    UNIQUE KEY unique_login_source (username, ip_address),
    INDEX idx_login_attempt_ip (ip_address)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS incidents (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    student_name VARCHAR(100) NOT NULL DEFAULT 'Confidential',
    grade_level VARCHAR(20) DEFAULT NULL,
    category VARCHAR(50) NOT NULL,
    severity ENUM('Low','Medium','High') NOT NULL DEFAULT 'Low',
    location VARCHAR(180) DEFAULT NULL,
    status ENUM('Pending','In review','Resolved') NOT NULL DEFAULT 'Pending',
    description TEXT NOT NULL,
    reported_by INT UNSIGNED DEFAULT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP NULL DEFAULT NULL,
    INDEX idx_incidents_created_at (created_at),
    INDEX idx_incidents_status (status),
    INDEX idx_incidents_category (category),
    INDEX idx_incidents_reported_by (reported_by),
    CONSTRAINT fk_incidents_reported_by FOREIGN KEY (reported_by)
        REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS activity_logs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id INT UNSIGNED DEFAULT NULL,
    actor_name VARCHAR(100) NOT NULL,
    action VARCHAR(100) NOT NULL,
    details VARCHAR(255) DEFAULT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_activity_logs_created_at (created_at),
    INDEX idx_activity_logs_user_id (user_id)
) ENGINE=InnoDB;

-- Public registration always creates the student role.
-- To promote your manually-created account to admin after registering:
-- UPDATE users SET role='admin' WHERE username='YOUR_ADMIN_USERNAME';

CREATE TABLE IF NOT EXISTS login_otp (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    otp_hash VARCHAR(255) NOT NULL,
    expires_at DATETIME NOT NULL,
    attempts INT NOT NULL DEFAULT 0,
    resend_count INT NOT NULL DEFAULT 0,
    last_sent_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_otp_user (user_id),
    CONSTRAINT fk_otp_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS security_events (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    username VARCHAR(100) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    details TEXT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_security_user (user_id),
    INDEX idx_security_created (created_at)
);

CREATE TABLE IF NOT EXISTS student_profiles (
    id_number VARCHAR(9) NOT NULL PRIMARY KEY,
    user_id INT(10) UNSIGNED NOT NULL UNIQUE,

    first_name VARCHAR(21) NOT NULL,
    middle_name VARCHAR(21) DEFAULT NULL,
    family_name VARCHAR(21) NOT NULL,
    name_extension VARCHAR(5) DEFAULT NULL,

    birthdate DATE NOT NULL,

    purok_street VARCHAR(50) NOT NULL,
    barangay VARCHAR(50) NOT NULL,
    municipality_city VARCHAR(50) NOT NULL,
    province VARCHAR(50) NOT NULL,
    country VARCHAR(50) NOT NULL,
    zip_code CHAR(4) NOT NULL,

    privacy_consent TINYINT(1) NOT NULL DEFAULT 1,
    privacy_consent_at DATETIME NOT NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_student_profile_user
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS student_security_questions (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id INT(10) UNSIGNED NOT NULL,
    question_code VARCHAR(2) NOT NULL,
    answer_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    UNIQUE KEY unique_user_question (user_id, question_code),

    CONSTRAINT fk_security_question_user
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


-- 1. Bank of security questions users can choose from
CREATE TABLE IF NOT EXISTS security_questions (
    id TINYINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    question VARCHAR(255) NOT NULL
);
 
 
-- 3. Reset OTP (same columns and rules as login_otp)
CREATE TABLE IF NOT EXISTS password_reset_otp (
    user_id INT NOT NULL PRIMARY KEY,
    otp_hash VARCHAR(255) NOT NULL,
    expires_at DATETIME NOT NULL,
    attempts TINYINT NOT NULL DEFAULT 0,
    resend_count TINYINT NOT NULL DEFAULT 0,
    last_sent_at DATETIME NOT NULL,
    locked_until DATETIME NULL DEFAULT NULL
);
 
-- 4. Previous passwords, used to block reuse of the last 3
CREATE TABLE IF NOT EXISTS password_history (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user (user_id)
);