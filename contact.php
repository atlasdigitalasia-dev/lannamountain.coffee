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

// -- Spam filter ----------------------------------------------------------
// A rejected post gets the normal thank-you redirect (so bots learn nothing) and is
// logged above the web root in contact-spam.log, so a real lead caught by mistake
// is never lost. No email is sent for a rejected post.
function spam_exit(string $reason): void {
    $p = function (string $k, int $n): string {
        $v = isset($_POST[$k]) && is_string($_POST[$k]) ? $_POST[$k] : '';
        return mb_substr(trim((string)preg_replace('/\s+/', ' ', $v)), 0, $n);
    };
    $line = gmdate('Y-m-d H:i:s') . " UTC | $reason | IP " . ($_SERVER['REMOTE_ADDR'] ?? '')
          . ' | ' . $p('first_name', 60) . ' ' . $p('last_name', 60) . ' <' . $p('email', 120) . '>'
          . ' | ' . $p('source_page', 60) . ' | ' . $p('message', 300) . "\n";
    $log = dirname(__DIR__) . '/contact-spam.log';
    if (is_file($log) && filesize($log) > 2000000) @rename($log, $log . '.old');
    @file_put_contents($log, $line, FILE_APPEND | LOCK_EX);
    header('Location: ' . THANKS_URL, true, 303);
    exit;
}

// Honeypot: real visitors never see or fill this field.
if (!empty($_POST['website'])) spam_exit('honeypot');

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

// Bot checks. Every form page adds lm_t (seconds spent on the page) with JavaScript
// at submit time; form-spam bots usually post straight to this script without it.
$lmT = isset($_POST['lm_t']) && is_string($_POST['lm_t']) ? $_POST['lm_t'] : '';
if (!ctype_digit($lmT)) spam_exit('no-js-token');
if ((int)$lmT < 3)      spam_exit('too-fast');
$fn  = $fields['First name'];
$ln  = $fields['Last name'];
$all = implode(' ', $fields);
if (preg_match('/\d/', $fn . $ln)) spam_exit('digits-in-name');
if ($fn !== '' && strcasecmp($fn, $ln) === 0 && preg_match('/\p{Ll}\p{Lu}{2}$/u', $fn)) spam_exit('bot-name');
if (preg_match('/\p{Cyrillic}/u', $all)) spam_exit('cyrillic');
if (preg_match('/<a\s|href\s*=|\[url/i', $all)) spam_exit('link-markup');
if (preg_match('/\b(xevil|xrumer)\b/i', $all)) spam_exit('spam-keyword');
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

// ── Sending ──────────────────────────────────────────────────────────────
// Preferred: authenticated SMTP via Hostinger's mail server, so the message is
// DKIM-signed and passes SPF (mail() from the web server is neither, and lands in spam).
// Credentials live OUTSIDE the web root / git repo, in:
//   domains/lannamountain.coffee/mail-config.php   (one level above public_html)
// returning ['host'=>'smtp.hostinger.com','port'=>465,'user'=>'forms@lannamountain.coffee','pass'=>'...'].
// If that file is missing, falls back to mail().

$replyTo = $name !== '' ? mb_encode_mimeheader($name) . " <$email>" : $email;
$cfgFile = null;
foreach ([dirname(__DIR__) . '/mail-config.php', __DIR__ . '/.mail-config.php'] as $f) {
    if (is_file($f)) { $cfgFile = $f; break; }
}
$smtp    = $cfgFile ? (require $cfgFile) : null;

function smtp_send(array $c, string $to, string $subject, string $body, string $replyTo, string &$err): bool {
    $host = $c['host'] ?? 'smtp.hostinger.com';
    $port = (int)($c['port'] ?? 465);
    $user = (string)$c['user'];
    $fp = @stream_socket_client("ssl://$host:$port", $errno, $errstr, 15);
    if (!$fp) { $err = "connect: $errstr"; return false; }
    stream_set_timeout($fp, 15);
    $read = function () use ($fp) { $d = ''; while (($l = fgets($fp, 515)) !== false) { $d .= $l; if (isset($l[3]) && $l[3] === ' ') break; } return $d; };
    $cmd  = function (string $line, string $expect) use ($fp, $read, &$err) {
        if ($line !== '') fwrite($fp, $line . "\r\n");
        $r = $read();
        if (strpos($r, $expect) !== 0) { $err = trim($line === '' ? 'greeting' : explode(' ', $line)[0]) . ': ' . trim($r); return false; }
        return true;
    };
    $domain = substr(strrchr($user, '@'), 1) ?: 'localhost';
    $date   = date('r');
    $msgId  = '<' . bin2hex(random_bytes(12)) . '@' . $domain . '>';
    $data   = "Date: $date\r\nMessage-ID: $msgId\r\n"
            . 'From: ' . mb_encode_mimeheader(FROM_NAME) . " <$user>\r\n"
            . "To: <$to>\r\nReply-To: $replyTo\r\n"
            . 'Subject: ' . mb_encode_mimeheader($subject, 'UTF-8') . "\r\n"
            . "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n"
            . preg_replace('/^\./m', '..', str_replace(["\r\n", "\r", "\n"], "\r\n", $body)) . "\r\n.";
    $ok = $cmd('', '220')
       && $cmd("EHLO $domain", '250')
       && $cmd('AUTH LOGIN', '334')
       && $cmd(base64_encode($user), '334')
       && $cmd(base64_encode((string)$c['pass']), '235')
       && $cmd("MAIL FROM:<$user>", '250')
       && $cmd("RCPT TO:<$to>", '250')
       && $cmd('DATA', '354')
       && $cmd($data, '250');
    fwrite($fp, "QUIT\r\n");
    fclose($fp);
    return $ok;
}

$sent = false;
if (is_array($smtp) && !empty($smtp['user']) && !empty($smtp['pass'])) {
    $smtpErr = '';
    $sent = smtp_send($smtp, TO_ADDRESS, $subject, $body, $replyTo, $smtpErr);
    if (!$sent) error_log('contact.php: SMTP failed — ' . $smtpErr);
}
if (!$sent) {
    $headers = [
        'From: ' . FROM_NAME . ' <' . FROM_ADDRESS . '>',
        'Reply-To: ' . $replyTo,
        'MIME-Version: 1.0',
        'Content-Type: text/plain; charset=UTF-8',
        'Content-Transfer-Encoding: 8bit',
    ];
    $sent = mail(TO_ADDRESS, mb_encode_mimeheader($subject, 'UTF-8'), $body, implode("\r\n", $headers), '-f' . FROM_ADDRESS);
}

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
