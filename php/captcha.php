<?php
session_start();

error_reporting(0);

$characters = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
$code = '';

for ($i = 0; $i < 5; $i++) {
    $code .= $characters[random_int(0, strlen($characters) - 1)];
}

$captchaHash = password_hash($code, PASSWORD_DEFAULT);

if (($_GET['purpose'] ?? '') === 'registration') {
    $_SESSION['registration_captcha_hash'] = $captchaHash;
    $_SESSION['registration_captcha_created'] = time();
} else {
    $_SESSION['captcha_hash'] = $captchaHash;
    $_SESSION['captcha_created'] = time();
}

$image = imagecreatetruecolor(180, 60);

$background = imagecolorallocate($image, 245, 248, 246);
$textColor = imagecolorallocate($image, 24, 65, 48);

imagefill($image, 0, 0, $background);

imagestring($image, 5, 30, 22, $code, $textColor);

ob_start();
imagepng($image);
$png = ob_get_clean();

imagedestroy($image);

if (headers_sent()) {
    exit;
}

header('Content-Type: image/png');
header('Content-Length: ' . strlen($png));
header('Cache-Control: no-store, no-cache, must-revalidate');

echo $png;
exit;
