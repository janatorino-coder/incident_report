
<?php

session_start();

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/mailer.php';

$isAjax = isset($_POST['ajax']) ||
    strtolower($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '') === 'xmlhttprequest';


// ==========================================
// RESPONSE HANDLER
// ==========================================

function registerResponse(
    bool $success,
    string $message,
    array $extra = []
): never {

    global $conn, $isAjax;

    if ($isAjax) {

        header('Content-Type: application/json; charset=utf-8');

        echo json_encode(array_merge([
            'success' => $success,
            'message' => $message
        ], $extra));

    } elseif ($success) {

        header('Location: ../html/Torino.html?mode=login&registered=1');

    } else {

        http_response_code(400);

        echo htmlspecialchars(
            $message,
            ENT_QUOTES,
            'UTF-8'
        );
    }

    if (isset($conn) && $conn instanceof mysqli) {
        $conn->close();
    }

    exit;
}


// ==========================================
// NAME VALIDATION
// ==========================================

function validateName(string $value, string $field): ?string
{
    $value = trim($value);

    if ($value === '') {
        return "$field is required.";
    }

    if (preg_match('/[0-9]/', $value)) {
        return "Numbers are not allowed in $field.";
    }

    if (preg_match('/[^A-Za-z ]/', $value)) {
        return "Special characters are not allowed in $field.";
    }

    if (preg_match('/  +/', $value)) {
        return "Double space is not allowed in $field.";
    }

    if (strtoupper($value) === $value) {
        return "Do not use all capital letters in $field.";
    }

    if (!preg_match('/^[A-Z]/', $value)) {
        return 'First letter of your name must be capital.';
    }

    if (preg_match('/(.)\1\1/i', $value)) {
        return "Three consecutive identical letters are not allowed in $field.";
    }

    if (strlen($value) < 2 || strlen($value) > 50) {
        return "$field must contain 2–50 characters.";
    }

    if (!preg_match('/^[A-Z][a-z]*(?: [A-Z][a-z]*)*$/', $value)) {
        return "$field must use Title Case for every word.";
    }

    return null;
}


// ==========================================
// ADDRESS VALIDATION
// ==========================================

function cleanAddressName(
    string $value,
    int $minimum = 2,
    int $maximum = 50
): ?string {

    $value = trim($value);

    if (
        strlen($value) < $minimum ||
        strlen($value) > $maximum ||
        !preg_match('/^[A-Za-z]+(?: [A-Za-z]+)*$/', $value)
    ) {
        return null;
    }

    return ucwords(strtolower($value));
}


// ==========================================
// SECURITY ANSWER VALIDATION
// ==========================================

function cleanSecurityAnswer(string $value): ?string
{
    $value = trim($value);

    if (
        strlen($value) < 2 ||
        strlen($value) > 50 ||
        !preg_match('/^[A-Za-z]+(?: [A-Za-z]+)*$/', $value)
    ) {
        return null;
    }

    return strtolower($value);
}


// ==========================================
// MASK EMAIL
// ==========================================

function maskEmail(string $email): string
{
    $parts = explode('@', $email, 2);

    if (count($parts) !== 2) {
        return 'your registered email';
    }

    $local = $parts[0];

    return substr($local, 0, 1) .
        str_repeat('*', max(3, strlen($local) - 1)) .
        '@' . $parts[1];
}


// ==========================================
// REQUEST METHOD
// ==========================================

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: ../html/Torino.html');
    exit;
}


// ==========================================
// COLLECT ALL VALIDATION ERRORS
// ==========================================

$errors = [];


// ==========================================
// ACCOUNT INFORMATION
// ==========================================

$username = trim((string)($_POST['username'] ?? ''));

$email = strtolower(
    trim((string)($_POST['email'] ?? ''))
);

$password = (string)($_POST['password'] ?? '');

$confirm = (string)($_POST['confirm_password'] ?? '');


// ==========================================
// USERNAME VALIDATION
// ==========================================

if ($username === '') {

    $errors['username'] = 'Username is required.';

} elseif (!preg_match('/^[A-Za-z][A-Za-z0-9]{5,19}$/', $username)) {

    $errors['username'] =
        'Username must contain 6–20 letters and numbers and start with a letter.';
}


// ==========================================
// EMAIL VALIDATION
// ==========================================

if ($email === '') {

    $errors['email'] = 'Email is required.';

} elseif (
    !filter_var($email, FILTER_VALIDATE_EMAIL) ||
    strlen($email) > 100 ||
    preg_match('/\s/', $email)
) {

    $errors['email'] = 'Please enter a valid email address.';

} elseif (!preg_match('/@csucc\.edu\.ph$/i', $email)) {

    $errors['email'] =
        'Please use your official school email ending in @csucc.edu.ph.';
}


// ==========================================
// PASSWORD VALIDATION
// ==========================================

if ($password === '') {

    $errors['password'] = 'Password is required.';

} elseif (strlen($password) < 8 || strlen($password) > 64) {

    $errors['password'] =
        'Password must be between 8 and 64 characters.';

} else {

    $categories = 0;

    $categories += preg_match('/[a-z]/', $password) ? 1 : 0;
    $categories += preg_match('/[A-Z]/', $password) ? 1 : 0;
    $categories += preg_match('/[0-9]/', $password) ? 1 : 0;
    $categories += preg_match('/[^A-Za-z0-9]/', $password) ? 1 : 0;

    if ($categories < 3) {

        $errors['password'] =
            'Your password is too weak. Use at least 3 of these: lowercase letters, uppercase letters, numbers, and special characters.';
    }
}


// ==========================================
// CONFIRM PASSWORD
// ==========================================

if ($confirm === '') {

    $errors['confirm_password'] =
        'Confirm password is required.';

} elseif ($password !== $confirm) {

    $errors['confirm_password'] =
        'Passwords do not match.';
}


// ==========================================
// STUDENT INFORMATION
// ==========================================


// ==========================================
// ID NUMBER
// ==========================================

$idNumber = trim(
    (string)($_POST['id_number'] ?? '')
);

if ($idNumber === '') {

    $errors['id_number'] = 'Student ID Number is required.';

} elseif (!preg_match('/^[0-9]{3}-[0-9]{5}$/', $idNumber)) {

    $errors['id_number'] =
        'ID Number must follow the format xxx-xxxxx.';
}


// ==========================================
// FIRST NAME
// ==========================================

$firstName = trim(
    (string)($_POST['first_name'] ?? '')
);

$nameError = validateName($firstName, 'First Name');

if ($nameError !== null) {
    $errors['first_name'] = $nameError;
}


// ==========================================
// MIDDLE NAME (OPTIONAL)
// ==========================================

$middleInput = trim(
    (string)($_POST['middle_name'] ?? '')
);

$middleName = null;

if ($middleInput !== '') {

    $nameError = validateName($middleInput, 'Middle Name');

    if ($nameError !== null) {
        $errors['middle_name'] = $nameError;
    } else {
        $middleName = $middleInput;
    }
}


// ==========================================
// FAMILY NAME
// ==========================================

$familyName = trim(
    (string)($_POST['family_name'] ?? '')
);

$nameError = validateName($familyName, 'Family Name');

if ($nameError !== null) {
    $errors['family_name'] = $nameError;
}


// ==========================================
// NAME EXTENSION
// ==========================================

$nameExtensionChoice = trim(
    (string)($_POST['name_extension'] ?? '')
);

$otherExtension = trim(
    (string)($_POST['other_extension'] ?? '')
);

$nameExtension = null;

if ($nameExtensionChoice === '') {

    $nameExtension = null;

} elseif (
    $nameExtensionChoice === 'Jr.' ||
    $nameExtensionChoice === 'Sr.'
) {

    $nameExtension = $nameExtensionChoice;

} elseif ($nameExtensionChoice === 'Other') {

    $allowedOtherExtensions = [
        'I',
        'II',
        'III',
        'IV',
        'IX',
        'X'
    ];

    if (!in_array($otherExtension, $allowedOtherExtensions, true)) {

        $errors['other_extension'] =
            'Please select a valid name extension: I, II, III, IV, IX, or X.';

    } else {

        $nameExtension = $otherExtension;
    }

} else {

    $errors['name_extension'] =
        'Please select a valid name extension.';
}


// ==========================================
// BIRTHDATE AND AGE
// ==========================================

$birthdate = trim(
    (string)($_POST['birthdate'] ?? '')
);

$date = false;

if ($birthdate === '') {

    $errors['birthdate'] = 'Birthdate is required.';

} else {

    $date = DateTime::createFromFormat('!Y-m-d', $birthdate);

    if (
        !$date ||
        $date->format('Y-m-d') !== $birthdate
    ) {

        $errors['birthdate'] =
            'Please enter a valid birthdate.';

        $date = false;
    }
}

if ($date !== false) {

    $today = new DateTime('today');

    if ($date > $today) {

        $errors['birthdate'] =
            'Birthdate cannot be in the future.';

    } else {

        $age = $date->diff($today)->y;

        if ($age < 18) {

            $errors['birthdate'] =
                'You must be at least 18 years old to register.';
        }
    }
}


// ==========================================
// ADDRESS INFORMATION
// ==========================================


// ==========================================
// PUROK / STREET
// ==========================================

$purokStreet = trim(
    (string)($_POST['purok_street'] ?? '')
);

if ($purokStreet === '') {

    $errors['purok_street'] = 'Purok / Street is required.';

} elseif (
    strlen($purokStreet) < 3 ||
    strlen($purokStreet) > 50 ||
    !preg_match('/^[A-Za-z0-9]+(?: [A-Za-z0-9]+)*$/', $purokStreet)
) {

    $errors['purok_street'] =
        'Purok / Street must contain 3–50 letters, numbers, and spaces without double spaces.';
}


// ==========================================
// BARANGAY
// ==========================================

$barangay = cleanAddressName(
    (string)($_POST['barangay'] ?? '')
);

if ($barangay === null) {

    $errors['barangay'] =
        'Barangay is required and must contain 2–50 letters and spaces only.';
}


// ==========================================
// MUNICIPALITY / CITY
// ==========================================

$municipality = cleanAddressName(
    (string)($_POST['municipality_city'] ?? '')
);

if ($municipality === null) {

    $errors['municipality_city'] =
        'Municipality / City is required and must contain 2–50 letters and spaces only.';
}


// ==========================================
// PROVINCE
// ==========================================

$province = cleanAddressName(
    (string)($_POST['province'] ?? '')
);

if ($province === null) {

    $errors['province'] =
        'Province is required and must contain 2–50 letters and spaces only.';
}


// ==========================================
// COUNTRY
// ==========================================

$country = cleanAddressName(
    (string)($_POST['country'] ?? '')
);

if ($country === null) {

    $errors['country'] =
        'Country is required and must contain 2–50 letters and spaces only.';
}


// ==========================================
// ZIP CODE
// ==========================================

$zipCode = trim(
    (string)($_POST['zip_code'] ?? '')
);

if ($zipCode === '') {

    $errors['zip_code'] = 'ZIP Code is required.';

} elseif (!preg_match('/^[0-9]{4}$/', $zipCode)) {

    $errors['zip_code'] =
        'ZIP Code must contain exactly 4 digits.';
}


// ==========================================
// SECURITY QUESTIONS
// ==========================================

$answer1 = cleanSecurityAnswer(
    (string)($_POST['security_answer_1'] ?? '')
);

$answer4 = cleanSecurityAnswer(
    (string)($_POST['security_answer_4'] ?? '')
);

$answer8 = cleanSecurityAnswer(
    (string)($_POST['security_answer_8'] ?? '')
);

if ($answer1 === null) {
    $errors['security_answer_1'] =
        'Answer must contain 2–50 letters and spaces only.';
}

if ($answer4 === null) {
    $errors['security_answer_4'] =
        'Answer must contain 2–50 letters and spaces only.';
}

if ($answer8 === null) {
    $errors['security_answer_8'] =
        'Answer must contain 2–50 letters and spaces only.';
}


// ==========================================
// PRIVACY CONSENT
// ==========================================

if (($_POST['privacy_consent'] ?? '') !== '1') {

    $errors['privacy_consent'] =
        'You must agree to the Privacy Notice to register.';
}


// ==========================================
// RETURN ALL VALIDATION ERRORS
// ==========================================

if (!empty($errors)) {

    registerResponse(
        false,
        'Please correct the highlighted fields.',
        [
            'errors' => $errors
        ]
    );
}


// ==========================================
// CREATE ACCOUNT
// ==========================================

try {

    if (!$conn->begin_transaction()) {
        throw new RuntimeException(
            'Could not start database transaction.'
        );
    }


    // ======================================
    // CHECK ALL DUPLICATE RECORDS
    // ======================================

    $duplicateErrors = [];


    // Check ID Number.

    $checkId = $conn->prepare(
        'SELECT id_number
         FROM student_profiles
         WHERE id_number = ?
         LIMIT 1'
    );

    if (!$checkId) {
        throw new RuntimeException('Database query failed.');
    }

    $checkId->bind_param('s', $idNumber);
    $checkId->execute();

    $existingId = $checkId->get_result()->fetch_assoc();

    $checkId->close();

    if ($existingId) {

        $duplicateErrors['id_number'] =
            'This ID Number is already registered.';
    }


    // Check username.

    $checkUsername = $conn->prepare(
        'SELECT id
         FROM users
         WHERE username = ?
         LIMIT 1'
    );

    if (!$checkUsername) {
        throw new RuntimeException('Database query failed.');
    }

    $checkUsername->bind_param('s', $username);
    $checkUsername->execute();

    $existingUsername = $checkUsername->get_result()->fetch_assoc();

    $checkUsername->close();

    if ($existingUsername) {

        $duplicateErrors['username'] =
            'This username is already taken.';
    }


    // Check email.

    $checkEmail = $conn->prepare(
        'SELECT id
         FROM users
         WHERE email = ?
         LIMIT 1'
    );

    if (!$checkEmail) {
        throw new RuntimeException('Database query failed.');
    }

    $checkEmail->bind_param('s', $email);
    $checkEmail->execute();

    $existingEmail = $checkEmail->get_result()->fetch_assoc();

    $checkEmail->close();

    if ($existingEmail) {

        $duplicateErrors['email'] =
            'This email is already registered.';
    }


    // Return all duplicate errors together.

    if (!empty($duplicateErrors)) {

        $conn->rollback();

        registerResponse(
            false,
            'Please correct the highlighted fields.',
            [
                'errors' => $duplicateErrors
            ]
        );
    }


    // ======================================
    // HASH PASSWORD
    // ======================================

    $passwordHash = password_hash(
        $password,
        PASSWORD_DEFAULT
    );

    if ($passwordHash === false) {
        throw new RuntimeException('Password hashing failed.');
    }


    // ======================================
    // INSERT UNVERIFIED USER
    // ======================================

    $role = 'student';
    $isVerified = 0;

    $insertUser = $conn->prepare(
        'INSERT INTO users
            (username, email, password, role, is_verified)
         VALUES (?, ?, ?, ?, ?)'
    );

    if (!$insertUser) {
        throw new RuntimeException(
            'Could not prepare account creation.'
        );
    }

    $insertUser->bind_param(
        'ssssi',
        $username,
        $email,
        $passwordHash,
        $role,
        $isVerified
    );

    if (!$insertUser->execute()) {
        throw new RuntimeException('Could not create account.');
    }

    $userId = $conn->insert_id;

    $insertUser->close();


    // ======================================
    // INSERT STUDENT PROFILE
    // ======================================

    $privacyConsent = 1;

    $insertProfile = $conn->prepare(
        'INSERT INTO student_profiles (
            id_number,
            user_id,
            first_name,
            middle_name,
            family_name,
            name_extension,
            birthdate,
            purok_street,
            barangay,
            municipality_city,
            province,
            country,
            zip_code,
            privacy_consent,
            privacy_consent_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())'
    );

    if (!$insertProfile) {
        throw new RuntimeException(
            'Could not prepare student profile.'
        );
    }

    $insertProfile->bind_param(
        'sisssssssssssi',
        $idNumber,
        $userId,
        $firstName,
        $middleName,
        $familyName,
        $nameExtension,
        $birthdate,
        $purokStreet,
        $barangay,
        $municipality,
        $province,
        $country,
        $zipCode,
        $privacyConsent
    );

    if (!$insertProfile->execute()) {
        throw new RuntimeException(
            'Could not save student information.'
        );
    }

    $insertProfile->close();


    // ==========================================
    // HASH AND INSERT SECURITY ANSWERS
    // ==========================================

    $securityAnswers = [
        '1' => $answer1,
        '4' => $answer4,
        '8' => $answer8
    ];

    $insertQuestion = $conn->prepare(
        'INSERT INTO student_security_questions
            (user_id, question_code, answer_hash)
        VALUES (?, ?, ?)'
    );

    if (!$insertQuestion) {
        throw new RuntimeException(
            'Could not prepare security questions.'
        );
    }

    foreach ($securityAnswers as $questionCode => $answer) {

        $answerHash = password_hash(
            $answer,
            PASSWORD_DEFAULT
        );

        if ($answerHash === false) {
            throw new RuntimeException(
                'Security answer hashing failed.'
            );
        }

        $insertQuestion->bind_param(
            'iss',
            $userId,
            $questionCode,
            $answerHash
        );

        if (!$insertQuestion->execute()) {
            throw new RuntimeException(
                'Could not save security questions.'
            );
        }
    }

    $insertQuestion->close();


    // ======================================
    // GENERATE REGISTRATION OTP
    // ======================================

    $otp = (string) random_int(100000, 999999);

    $otpHash = password_hash(
        $otp,
        PASSWORD_DEFAULT
    );

    if ($otpHash === false) {
        throw new RuntimeException('OTP generation failed.');
    }


    // ======================================
    // STORE OTP
    // Five-minute expiration
    // ======================================

    $insertOtp = $conn->prepare(
        'INSERT INTO login_otp (
            user_id,
            otp_hash,
            expires_at,
            attempts,
            resend_count,
            last_sent_at,
            created_at,
            locked_until
        ) VALUES (
            ?, ?, DATE_ADD(NOW(), INTERVAL 5 MINUTE),
            0, 0, NOW(), NOW(), NULL
        )'
    );

    if (!$insertOtp) {
        throw new RuntimeException(
            'Could not prepare OTP storage.'
        );
    }

    $insertOtp->bind_param(
        'is',
        $userId,
        $otpHash
    );

    if (!$insertOtp->execute()) {
        throw new RuntimeException(
            'Could not save registration OTP.'
        );
    }

    $insertOtp->close();


    // ======================================
    // COMMIT TRANSACTION
    // ======================================

    if (!$conn->commit()) {
        throw new RuntimeException(
            'Could not commit registration transaction.'
        );
    }


    // ======================================
    // SAVE PENDING REGISTRATION SESSION
    // ======================================

    $_SESSION['pending_auth_type'] = 'registration';
    $_SESSION['pending_user_id'] = $userId;
    $_SESSION['pending_username'] = $username;
    $_SESSION['pending_ip'] = $_SERVER['REMOTE_ADDR'] ?? '';


    // ======================================
    // SEND REGISTRATION OTP EMAIL
    // ======================================

    try {

        $emailSent = sendRegistrationOTP($email, $otp);

    } catch (Throwable $mailError) {

        error_log(
            'Registration OTP email error: ' .
            $mailError->getMessage()
        );

        $emailSent = false;
    }


    // ======================================
    // EMAIL FAILED
    // ======================================

    if (!$emailSent) {

        registerResponse(
            true,
            'Your account was created, but the verification email could not be sent. Please use the resend OTP option.',
            [
                'otpRequired' => true,
                'maskedEmail' => maskEmail($email),
                'emailSent' => false
            ]
        );
    }


    // ======================================
    // REGISTRATION SUCCESS
    // ======================================

    registerResponse(
        true,
        'Registration successful! Please check your email for your verification code.',
        [
            'otpRequired' => true,
            'maskedEmail' => maskEmail($email),
            'emailSent' => true
        ]
    );


} catch (Throwable $error) {

    if (isset($conn) && $conn instanceof mysqli) {
        $conn->rollback();
    }

    error_log(
        'Registration error: ' . $error->getMessage()
    );

    registerResponse(
        false,
        'Registration could not be completed. Please check your information and try again.'
    );
}
