<?php
// Form handler for lannamountain.coffee — emails submissions to Tom via Hostinger mail.
// Replaces the old Formspree placeholder. No third-party service, no monthly cap.

declare(strict_types=1);

const TO_ADDRESS   = 'tom@lannamountain.coffee';
const FROM_ADDRESS = 'tom@lannamountain.coffee';
const FROM_NAME    = 'lannamountain.coffee website';
const THANKS_URL   = '/thank-you.html';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: /contact', true, 303);
    exit;
}

// Honeypot: real visitors never see or fill this field.
if (!empty($_POST['website'])) {
    header('Location: ' . THANKS_URL, true, 303);
    exit;
}

function clean(string $key, int $max = 2000): string {
    $v = isset($_POST[$key]) && is_string($_POST[$key]) ? trim($_POST[$key]) : '';
    $v = str_replace(["\0"], '', $v);
    return mb_substr($v, 0, $max);
}
function oneLine(string $v): string {
    return trim(preg_replace('/[\r\n]+/', ' ', $v));
}

$email = oneLine(clean('email', 254));
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    echo '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
       . '<p style="font-family:sans-serif;max-width:480px;margin:60px auto;padding:0 16px">'
       . 'Please go back and enter a valid email address.<br><br><a href="javascript:history.back()">&larr; Back to the form</a></p>';
    exit;
}

$formType = oneLine(clean('form_type', 40)) ?: 'enquiry';
$source   = oneLine(clean('source_page', 120)) ?: 'Unknown page';

$fields = [
    'First name'       => oneLine(clean('first_name', 100)),
    'Last name'        => oneLine(clean('last_name', 100)),
    'Email'            => $email,
    'Phone / WhatsApp' => oneLine(clean('phone', 60)),
    'Business type'    => oneLine(clean('business_type', 100)),
    'Service'          => oneLine(clean('service_interest', 120)),
    'Budget'           => oneLine(clean('budget', 100)),
    'Store URL'        => oneLine(clean('store_url', 300)),
    'Platform'         => oneLine(clean('platform', 60)),
    'Country'          => oneLine(clean('country', 80)),
    'Message'          => clean('message', 5000),
];

$name = trim($fields['First name'] . ' ' . $fields['Last name']);
if ($formType === 'newsletter') {
    $subject = "Newsletter signup — $email";
} elseif ($formType === 'concierge') {
    $subject = 'Coffee Concierge setup — ' . ($name !== '' ? $name : $email)
             . ($fields['Store URL'] !== '' ? ' (' . $fields['Store URL'] . ')' : '');
} else {
    $subject = 'New lead — ' . ($name !== '' ? $name : $email) . " ($source)";
}

$body  = "Source: $source\nForm: $formType\n";
$body .= 'Submitted: ' . gmdate('Y-m-d H:i') . " UTC\n";
$body .= 'Page URL: ' . oneLine((string)($_SERVER['HTTP_REFERER'] ?? '')) . "\n\n";
foreach ($fields as $label => $value) {
    if ($value === '') continue;
    $body .= $label === 'Message' ? "\nMessage:\n$value\n" : "$label: $value\n";
}
$body .= "\nIP: " . ($_SERVER['REMOTE_ADDR'] ?? '') . "\n";

$headers = [
    'From: ' . FROM_NAME . ' <' . FROM_ADDRESS . '>',
    'Reply-To: ' . ($name !== '' ? mb_encode_mimeheader($name) . " <$email>" : $email),
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=UTF-8',
    'Content-Transfer-Encoding: 8bit',
];

$sent = mail(TO_ADDRESS, mb_encode_mimeheader($subject, 'UTF-8'), $body, implode("\r\n", $headers), '-f' . FROM_ADDRESS);

if (!$sent) {
    error_log('contact.php: mail() failed for ' . $email);
    http_response_code(500);
    echo '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
       . '<p style="font-family:sans-serif;max-width:480px;margin:60px auto;padding:0 16px">'
       . 'Sorry, your message could not be sent. Please email <a href="mailto:' . TO_ADDRESS . '">' . TO_ADDRESS . '</a> '
       . 'or message us on <a href="https://wa.me/66623094689">WhatsApp</a>.</p>';
    exit;
}

header('Location: ' . THANKS_URL . ($formType === 'newsletter' ? '?type=newsletter' : ''), true, 303);
exit;
