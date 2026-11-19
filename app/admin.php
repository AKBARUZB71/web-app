<?php

declare(strict_types=1);

/**
 * AKBARTECH — ADMIN PANEL · v5
 *
 * Kirish (parol yoki Telegram), boshqaruv paneli, buyurtmalar,
 * foydalanuvchilar, profil va kontent, loyihalar, xizmatlar,
 * xabar tarqatish, AI yordamchi va Telegram bot sozlamalari.
 *
 * Darslar, vazifalar va sertifikatlar v5 da menyudan olib tashlangan;
 * ularning ma'lumotlari store/ va store/archive_v4/ da saqlanadi.
 */

if (!is_file(__DIR__ . '/index.php')) {
    exit('index.php topilmadi. Barcha fayllar bitta papkada bo\'lishi kerak.');
}

/* ADMIN_ONLY — index.php barcha funksiyalarni yuklaydi, lekin
   marshrutlarni ishga tushirmaydi va sozlamalarni qaytaradi. */
define('ADMIN_ONLY', true);
$CONFIG = require __DIR__ . '/index.php';

/* ==================================================================
   SEANS VA XAVFSIZLIK SARLAVHALARI
   ================================================================== */

$secure = is_https();
session_name('atz_admin');
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => base_path() !== '' ? base_path() . '/' : '/',
    'secure'   => $secure,
    'httponly' => true,
    // Telegram Web'da panel iframe ichida ochiladi — u yerda Lax cookie
    // yuborilmaydi. Barcha POST amallar CSRF token bilan himoyalangan.
    'samesite' => $secure ? 'None' : 'Lax',
]);
session_start();

header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin');
header('Cache-Control: no-store, max-age=0');
header("Content-Security-Policy: frame-ancestors 'self' https://web.telegram.org https://*.web.telegram.org https://webk.telegram.org https://webz.telegram.org");

const ADMIN_SALT   = 'akbartech$';   // faqat eski SHA-256 xesh bilan moslik uchun
const MAX_TRIES    = 5;
const LOCK_MINUTES = 15;
const SESSION_HOURS = 8;

function admin_logged_in(): bool
{
    return !empty($_SESSION['admin_ok']) && $_SESSION['admin_ok'] === true;
}

function admin_ip(): string
{
    return (string) ($_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
}

/* ------------------------------------------------------------------
   Noto'g'ri urinishlar: IP bo'yicha + umumiy (ko'p IP'dan hujum)
   ------------------------------------------------------------------ */

function login_blocked(): int
{
    $tries = store_read('login_tries');
    $now = time();

    $record = $tries['ip:' . admin_ip()] ?? null;
    if (is_array($record) && (int) ($record['count'] ?? 0) >= MAX_TRIES && (int) ($record['until'] ?? 0) > $now) {
        return (int) ceil(((int) $record['until'] - $now) / 60);
    }

    // Umumiy himoya: 15 daqiqada 25 tadan ko'p xato — hamma uchun pauza.
    $global = array_filter((array) ($tries['global'] ?? []), static fn ($t): bool => $now - (int) $t < LOCK_MINUTES * 60);
    if (count($global) >= 25) {
        return LOCK_MINUTES;
    }
    return 0;
}

function login_failed(): void
{
    $count = 0;
    store_update('login_tries', static function (array $tries) use (&$count): array {
        $now = time();
        $key = 'ip:' . admin_ip();
        $record = (array) ($tries[$key] ?? []);
        // Blok muddati o'tgan bo'lsa — hisob boshidan
        if ((int) ($record['until'] ?? 0) < $now - LOCK_MINUTES * 60) {
            $record = [];
        }
        $count = (int) ($record['count'] ?? 0) + 1;
        $tries[$key] = ['count' => $count, 'until' => $now + LOCK_MINUTES * 60, 'last' => date('c')];

        $global = array_values(array_filter((array) ($tries['global'] ?? []), static fn ($t): bool => $now - (int) $t < LOCK_MINUTES * 60));
        $global[] = $now;
        $tries['global'] = array_slice($global, -50);

        foreach ($tries as $k => $value) {
            if ($k !== 'global' && (int) ($value['until'] ?? 0) < $now - 86400) {
                unset($tries[$k]);
            }
        }
        return $tries;
    });

    if ($count === 3 || $count === MAX_TRIES) {
        admin_alert('⚠️ <b>Admin panel:</b> ' . $count . ' marta noto‘g‘ri parol kiritildi.' . "\nIP: <code>" . e(admin_ip()) . '</code>');
    }
}

function login_succeeded(string $how): void
{
    store_update('login_tries', static function (array $tries): array {
        unset($tries['ip:' . admin_ip()]);
        return $tries;
    });
    $ua = mb_substr((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 120);
    admin_alert('🔐 <b>Admin panelga kirildi</b> (' . e($how) . ")\nIP: <code>" . e(admin_ip()) . "</code>\n" . e($ua));
}

/** Adminga Telegram orqali qisqa ogohlantirish. */
function admin_alert(string $html): void
{
    $adminId = (int) cfg('admin_tg_id', 0);
    if ($adminId > 0) {
        tg_api('sendMessage', ['chat_id' => $adminId, 'text' => $html, 'parse_mode' => 'HTML']);
    }
}

/* ------------------------------------------------------------------
   Parol: config'dagi bcrypt (yoki eski SHA-256) + paneldagi o'zgartirish
   ------------------------------------------------------------------ */

function admin_cred(): array
{
    return store_read('admin');
}

function admin_check(string $user, string $pass): bool
{
    global $CONFIG;
    $expectedUser = (string) ($CONFIG['admin_user'] ?? '');
    $configHash = (string) ($CONFIG['admin_pass_hash'] ?? '');

    if ($expectedUser === '' || $pass === ''
        || !hash_equals(mb_strtolower($expectedUser), mb_strtolower(trim($user)))) {
        return false;
    }

    // Panelda o'zgartirilgan parol — index.php dagi xesh o'zgarmagan bo'lsa ustun.
    $cred = admin_cred();
    if (!empty($cred['hash']) && (string) ($cred['legacy'] ?? '') === $configHash) {
        return password_verify($pass, (string) $cred['hash']);
    }

    // index.php dagi bcrypt xesh
    if (str_starts_with($configHash, '$2')) {
        return password_verify($pass, $configHash);
    }

    // Eski SHA-256 (v2) — birinchi kirishda bcrypt'ga o'tkaziladi
    if ($configHash !== '' && hash_equals($configHash, hash('sha256', ADMIN_SALT . $pass))) {
        store_write('admin', [
            'user'       => $expectedUser,
            'hash'       => password_hash($pass, PASSWORD_DEFAULT),
            'legacy'     => $configHash,
            'updated_at' => date('c'),
        ]);
        return true;
    }
    return false;
}

function csrf_token(): string
{
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(24));
    }
    return (string) $_SESSION['csrf'];
}

function csrf_ok(): bool
{
    $sent = (string) ($_POST['csrf'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');
    return $sent !== '' && hash_equals((string) ($_SESSION['csrf'] ?? ''), $sent);
}

function admin_login_session(string $how): void
{
    session_regenerate_id(true);
    $_SESSION['admin_ok'] = true;
    $_SESSION['admin_since'] = time();
    $_SESSION['admin_via'] = $how;
    unset($_SESSION['csrf']);
    login_succeeded($how);
}

/* ==================================================================
   RASM YUKLASH
   ================================================================== */

/** "8M", "2G" kabi ini qiymatlarni baytga o'giradi. */
function ini_to_bytes(string $value): int
{
    $value = trim($value);
    if ($value === '' || $value === '-1') {
        return -1;
    }
    $unit = strtolower(substr($value, -1));
    $number = (float) $value;
    switch ($unit) {
        case 'g': return (int) ($number * 1024 * 1024 * 1024);
        case 'm': return (int) ($number * 1024 * 1024);
        case 'k': return (int) ($number * 1024);
        default:  return (int) $number;
    }
}

function format_bytes(int $bytes): string
{
    if ($bytes <= 0) {
        return 'cheksiz';
    }
    if ($bytes >= 1024 * 1024 * 1024) {
        return round($bytes / (1024 * 1024 * 1024), 1) . ' GB';
    }
    return round($bytes / (1024 * 1024)) . ' MB';
}

/**
 * Yuklangan rasmni saqlaydi. Faqat haqiqiy rasm qabul qilinadi
 * (kengaytmaga emas, faylning o'ziga qaraladi).
 */
function save_upload(array $file, ?string &$error = null): ?string
{
    if (($file['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_NO_FILE) {
        return null;
    }
    if (($file['error'] ?? 1) !== UPLOAD_ERR_OK) {
        $error = upload_error_message((int) $file['error']);
        return null;
    }

    $size = (int) ($file['size'] ?? 0);
    if ($size <= 0) {
        $error = 'Fayl bo\'sh yoki noto\'g\'ri yuborildi';
        return null;
    }
    if ($size > 25 * 1024 * 1024) {
        $error = 'Rasm 25 MB dan katta. Kichikroq rasm yuklang.';
        return null;
    }

    $temp = (string) ($file['tmp_name'] ?? '');
    if (!is_uploaded_file($temp)) {
        $error = 'Fayl noto\'g\'ri yuborildi';
        return null;
    }

    @ini_set('memory_limit', '512M');
    @set_time_limit(120);

    $info = @getimagesize($temp);
    if ($info === false) {
        $error = 'Bu fayl haqiqiy rasm emas yoki buzilgan (HEIC bo\'lsa, JPG\'ga o\'tkazib yuklang)';
        return null;
    }

    $extensions = [IMAGETYPE_JPEG => 'jpg', IMAGETYPE_PNG => 'png', IMAGETYPE_GIF => 'gif', IMAGETYPE_WEBP => 'webp'];
    $type = (int) ($info[2] ?? 0);
    if (!isset($extensions[$type])) {
        $error = 'Faqat JPG, PNG, GIF yoki WEBP';
        return null;
    }

    $dir = uploads_dir();
    if ($dir === null) {
        $error = 'uploads papkasini yaratib bo\'lmadi (yozish huquqi yo\'q)';
        return null;
    }

    $optimized = image_optimize($temp, $type, (int) $info[0], (int) $info[1]);
    $ext = $optimized !== null ? $optimized['ext'] : $extensions[$type];
    $name = date('Ymd') . '-' . bin2hex(random_bytes(6)) . '.' . $ext;
    $destination = $dir . '/' . $name;

    if ($optimized !== null) {
        if (@file_put_contents($destination, $optimized['data']) === false) {
            $error = 'Faylni saqlab bo\'lmadi';
            return null;
        }
    } elseif (!@move_uploaded_file($temp, $destination)) {
        $error = 'Faylni saqlab bo\'lmadi';
        return null;
    }

    @chmod($destination, 0644);
    return $name;
}

function upload_error_message(int $code): string
{
    switch ($code) {
        case UPLOAD_ERR_INI_SIZE:
        case UPLOAD_ERR_FORM_SIZE:
            return 'Rasm serverning ruxsat etilgan hajmidan katta. Kichikroq rasm yuklang.';
        case UPLOAD_ERR_PARTIAL:
            return 'Rasm to\'liq yuklanmadi — internetni tekshirib qayta urinib ko\'ring.';
        case UPLOAD_ERR_NO_TMP_DIR:
            return 'Serverda vaqtinchalik papka topilmadi (hosting muammosi).';
        case UPLOAD_ERR_CANT_WRITE:
            return 'Serverga yozib bo\'lmadi (disk yoki ruxsat muammosi).';
        case UPLOAD_ERR_EXTENSION:
            return 'Serverdagi kengaytma yuklashni blokladi.';
        default:
            return 'Fayl yuklanmadi (kod ' . $code . ')';
    }
}

/** PNG/WEBP faylda shaffoflik bormi (alfa kanal). */
function image_has_alpha(string $path, int $type): bool
{
    if ($type === IMAGETYPE_PNG) {
        $head = (string) @file_get_contents($path, false, null, 0, 64 * 1024);
        $colorType = strlen($head) > 25 ? ord($head[25]) : 0;
        return in_array($colorType, [4, 6], true) || strpos($head, 'tRNS') !== false;
    }
    if ($type === IMAGETYPE_WEBP) {
        $head = (string) @file_get_contents($path, false, null, 0, 64);
        return strpos($head, 'VP8X') !== false && (ord($head[20] ?? "\0") & 0x10) === 0x10
            || strpos($head, 'VP8L') !== false;
    }
    return $type === IMAGETYPE_GIF;
}

/**
 * Rasmni ekranga mos holatga keltiradi: uzun tomoni 1600px dan oshmaydi.
 * Shaffof rasm (logo) PNG bo'lib qoladi — foni qora bo'lib ketmaydi.
 * Boshqalari JPEG sifatida siqiladi (shaffof joylar oq bilan to'ldiriladi).
 *
 * @return array{data:string, ext:string}|null  null — asl fayl saqlanadi
 */
function image_optimize(string $path, int $type, int $width, int $height): ?array
{
    if (!extension_loaded('gd') || $width <= 0 || $height <= 0) {
        return null;
    }

    $limitBytes = ini_to_bytes((string) ini_get('memory_limit'));
    if ($limitBytes > 0) {
        $estimated = ($width * $height * 4 * 2) + (16 * 1024 * 1024);
        if ((int) memory_get_usage(true) + $estimated > $limitBytes * 0.85) {
            return null;
        }
    }

    $maxSide = 1600;
    $needsResize = $width > $maxSide || $height > $maxSide;
    $alpha = image_has_alpha($path, $type);

    // GIF animatsiyasini buzmaslik uchun — kichik GIF'ga tegmaymiz.
    if ($type === IMAGETYPE_GIF && !$needsResize) {
        return null;
    }
    // Shaffof, o'lchami joyida — asl fayl eng yaxshisi.
    if ($alpha && !$needsResize) {
        return null;
    }

    try {
        switch ($type) {
            case IMAGETYPE_JPEG: $source = @imagecreatefromjpeg($path); break;
            case IMAGETYPE_PNG:  $source = @imagecreatefrompng($path); break;
            case IMAGETYPE_GIF:  $source = @imagecreatefromgif($path); break;
            case IMAGETYPE_WEBP: $source = function_exists('imagecreatefromwebp') ? @imagecreatefromwebp($path) : false; break;
            default:             $source = false;
        }
    } catch (Throwable $exception) {
        return null;
    }
    if (!$source) {
        return null;
    }

    $ratio = $needsResize ? min($maxSide / $width, $maxSide / $height) : 1;
    $newWidth = max(1, (int) round($width * $ratio));
    $newHeight = max(1, (int) round($height * $ratio));

    $canvas = @imagecreatetruecolor($newWidth, $newHeight);
    if (!$canvas) {
        imagedestroy($source);
        return null;
    }

    if ($alpha) {
        imagealphablending($canvas, false);
        imagesavealpha($canvas, true);
        imagefill($canvas, 0, 0, imagecolorallocatealpha($canvas, 0, 0, 0, 127));
    } else {
        imagefill($canvas, 0, 0, imagecolorallocate($canvas, 255, 255, 255));
        imagealphablending($canvas, true);
    }
    imagecopyresampled($canvas, $source, 0, 0, 0, 0, $newWidth, $newHeight, $width, $height);
    imagedestroy($source);

    ob_start();
    $ok = $alpha ? imagepng($canvas, null, 7) : imagejpeg($canvas, null, 82);
    $data = (string) ob_get_clean();
    imagedestroy($canvas);

    if (!$ok || $data === '') {
        return null;
    }
    if (!$needsResize && strlen($data) >= (int) @filesize($path)) {
        return null;
    }
    return ['data' => $data, 'ext' => $alpha ? 'png' : 'jpg'];
}

function delete_upload(string $name): void
{
    if ($name === '' || strpos($name, '/') !== false || strpos($name, '\\') !== false || $name[0] === '.') {
        return;
    }
    $dir = uploads_dir();
    if ($dir !== null && is_file($dir . '/' . $name)) {
        @unlink($dir . '/' . $name);
    }
}

/** Faqat http(s) havolalar (javascript: va boshqalar o'tmaydi). */
function clean_url(string $url): string
{
    $url = trim($url);
    return preg_match('#^https?://[^\s<>"]+$#i', $url) ? mb_substr($url, 0, 500) : '';
}

/** #RRGGBB rang yoki standart qiymat. */
function clean_color(string $value, string $default): string
{
    return preg_match('/^#[0-9a-fA-F]{6}$/', trim($value)) ? strtoupper(trim($value)) : $default;
}

/** Kalitni ekranda yashirish: "AIzaSy…f9Qk". */
function mask_secret(string $secret): string
{
    $len = strlen($secret);
    if ($len === 0) { return ''; }
    if ($len <= 10) { return str_repeat('•', $len); }
    return substr($secret, 0, 6) . '…' . substr($secret, -4);
}

/* ==================================================================
   HOLAT
   ================================================================== */

$notice = null;
$noticeKind = 'ok';
$page = (string) ($_GET['p'] ?? 'dashboard');

/* --- chiqish (faqat POST + CSRF) --- */
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && ($_POST['action'] ?? '') === 'logout' && csrf_ok()) {
    $_SESSION = [];
    session_destroy();
    header('Location: ' . basename(__FILE__));
    exit;
}

/* --- kirish --- */
if (!admin_logged_in()) {
    $loginError = null;
    $method = $_SERVER['REQUEST_METHOD'] ?? '';

    if ($method === 'POST' && (isset($_POST['login']) || isset($_POST['tg_init']))) {
        $wait = login_blocked();

        if (!csrf_ok()) {
            $loginError = 'Sahifa eskirgan. Qayta urinib ko\'ring.';
        } elseif ($wait > 0) {
            $loginError = 'Juda ko\'p urinish. ' . $wait . ' daqiqadan keyin qayta urining.';
        } elseif (isset($_POST['tg_init'])) {
            // Telegram orqali: imzo tekshiriladi va ID admin_tg_id bilan solishtiriladi.
            $verified = tg_verify((string) $_POST['tg_init']);
            $adminId = (int) cfg('admin_tg_id', 0);
            if ($verified !== null && $adminId > 0 && (int) $verified['user']['id'] === $adminId) {
                admin_login_session('Telegram');
                $want = preg_replace('/[^a-z]/', '', (string) ($_GET['p'] ?? ''));
                header('Location: ' . basename(__FILE__) . ($want !== '' ? '?p=' . $want : ''));
                exit;
            }
            login_failed();
            $loginError = 'Telegram orqali kirish faqat admin hisobi uchun. Login va parol bilan kiring.';
        } else {
            $user = trim((string) ($_POST['login'] ?? ''));
            $pass = (string) ($_POST['password'] ?? '');

            if (admin_check($user, $pass)) {
                admin_login_session('parol');
                header('Location: ' . basename(__FILE__));
                exit;
            }

            login_failed();
            usleep(random_int(300000, 700000)); // taxmin qilishni sekinlashtiradi
            $loginError = 'Login yoki parol noto\'g\'ri';
        }
    }

    render_login($loginError);
    exit;
}

/* --- seans muddati --- */
if (time() - (int) ($_SESSION['admin_since'] ?? 0) > SESSION_HOURS * 3600) {
    $_SESSION = [];
    session_destroy();
    header('Location: ' . basename(__FILE__));
    exit;
}

/* --- token/kalit/manzil o'zgargan bo'lsa — botni avtomatik qayta ulaymiz --- */
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'GET' && !isset($_GET['ajax'])) {
    if (is_https() && bot_token() !== '' && (string) settings_get('bot_connected', '') !== bot_fingerprint()
        && time() - (int) ($_SESSION['bot_autoconnect'] ?? 0) > 600) {
        $_SESSION['bot_autoconnect'] = time();
        $auto = bot_setup();
        $_SESSION['flash'] = $auto['ok']
            ? ['Telegram bot avtomatik ulandi: ' . $auto['bot'], 'ok']
            : ['Botni ulab bo\'lmadi: ' . $auto['error'] . ' — "Telegram bot" bo\'limini oching.', 'error'];
    }
}

/* --- vazifa faylini ko'rish / yuklab olish (faqat admin) --- */
if (isset($_GET['file']) && ($_SERVER['REQUEST_METHOD'] ?? '') === 'GET') {
    admin_serve_task_file((string) $_GET['file'], !empty($_GET['dl']));
    exit;
}

/* ==================================================================
   AJAX — tarqatma qadami, AI sinovi
   ================================================================== */

if (isset($_GET['ajax'])) {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST' || !csrf_ok()) {
        send_json(['ok' => false, 'error' => 'csrf'], 403);
        exit;
    }
    session_write_close(); // uzoq so'rov boshqa sahifalarni bloklamasin

    $ajax = (string) $_GET['ajax'];
    if ($ajax === 'broadcast_step') {
        send_json(broadcast_step((string) ($_POST['id'] ?? '')));
        exit;
    }
    if ($ajax === 'ai_test') {
        $question = trim((string) ($_POST['q'] ?? '')) ?: 'Yaxshi prompt qanday yoziladi?';
        $settings = ai_settings();
        $started = microtime(true);
        $result = ai_complete($settings, ai_system_prompt('uz', 'app'), [['role' => 'user', 'text' => mb_substr($question, 0, 500)]]);
        send_json([
            'ok'    => $result['ok'],
            'text'  => $result['ok'] ? ai_extract_refs($result['text'])['text'] : '',
            'error' => $result['error'] === 'not_configured' ? 'API kalit kiritilmagan' : $result['error'],
            'ms'    => (int) round((microtime(true) - $started) * 1000),
            'model' => $settings['provider'] . ' · ' . $settings['model'],
        ]);
        exit;
    }
    if ($ajax === 'task_review') {
        send_json(task_review((string) ($_POST['id'] ?? ''), (string) ($_POST['decision'] ?? ''), (string) ($_POST['note'] ?? '')));
        exit;
    }
    if ($ajax === 'cert_prepare') {
        $uid = (int) ($_POST['uid'] ?? 0);
        $name = trim((string) ($_POST['name'] ?? ''));
        if ($uid <= 0 || $name === '') {
            send_json(['ok' => false, 'error' => 'input'], 422);
            exit;
        }
        $cert = cert_create($uid, (string) ($_POST['type'] ?? 'appreciation'), $name, (string) ($_POST['reason'] ?? ''));
        send_json(['ok' => true, 'cert' => cert_public($cert)]);
        exit;
    }
    if ($ajax === 'cert_image') {
        $tmp = (string) ($_FILES['image']['tmp_name'] ?? '');
        if ($tmp === '' || !is_uploaded_file($tmp) || (int) ($_FILES['image']['size'] ?? 0) > 8 * 1048576) {
            send_json(['ok' => false, 'error' => 'no_file']);
            exit;
        }
        send_json(cert_attach_image((string) ($_POST['id'] ?? ''), $tmp));
        exit;
    }
    if ($ajax === 'cert_resend') {
        $cert = cert_find((string) ($_POST['id'] ?? ''));
        send_json(['ok' => $cert !== null && cert_send($cert)]);
        exit;
    }
    send_json(['ok' => false, 'error' => 'unknown'], 404);
    exit;
}

/* ==================================================================
   AMALLAR
   ================================================================== */

/* post_max_size oshib ketsa PHP bo'sh $_POST qaytaradi — aniq xabar beramiz. */
$contentLength = (int) ($_SERVER['CONTENT_LENGTH'] ?? 0);
$postLimit = ini_to_bytes((string) ini_get('post_max_size'));

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && empty($_POST) && empty($_FILES) && $contentLength > 0) {
    $notice = 'Yuborilgan fayllarning umumiy hajmi (' . format_bytes($contentLength) . ') serverning chegarasidan'
        . ($postLimit > 0 ? ' (' . format_bytes($postLimit) . ')' : '')
        . ' katta. Rasmlarni kamroq miqdorda yuklang.';
    $noticeKind = 'error';
}

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && isset($_POST['action'])) {
    if (!csrf_ok()) {
        $notice = 'Xavfsizlik tekshiruvi o\'tmadi. Sahifani yangilab qayta urining.';
        $noticeKind = 'error';
    } else {
        $action = (string) $_POST['action'];

        /* ---- loyiha saqlash ---- */
        if ($action === 'project_save') {
            $list = projects_all();
            $slug = (string) ($_POST['slug'] ?? '');
            $isNew = $slug === '';

            $name = trim((string) ($_POST['name'] ?? ''));
            if ($name === '') {
                $notice = 'Loyiha nomini kiriting';
                $noticeKind = 'error';
            } else {
                $index = -1;
                foreach ($list as $i => $item) {
                    if ((string) ($item['slug'] ?? '') === $slug) {
                        $index = $i;
                        break;
                    }
                }

                $project = $index >= 0 ? $list[$index] : [];

                if ($isNew) {
                    $base = slugify($name);
                    $newSlug = $base;
                    $taken = array_map(static fn ($x) => (string) ($x['slug'] ?? ''), $list);
                    for ($n = 2; in_array($newSlug, $taken, true); $n++) {
                        $newSlug = $base . '-' . $n;
                    }
                }
                $icons = array_keys(icon_paths());
                $icon = (string) ($_POST['icon'] ?? 'sparkles');

                $project['slug']     = $isNew ? $newSlug : $slug;
                $project['name']     = mb_substr($name, 0, 80);
                $project['icon']     = in_array($icon, $icons, true) ? $icon : 'sparkles';
                $project['accent']   = clean_color((string) ($_POST['accent'] ?? ''), '#1677FF');
                $project['accent_2'] = clean_color((string) ($_POST['accent_2'] ?? ''), '#83C8FF');
                $project['year']     = mb_substr(trim((string) ($_POST['year'] ?? date('Y'))), 0, 12);
                $project['link']     = clean_url((string) ($_POST['link'] ?? ''));
                $project['featured'] = !empty($_POST['featured']);
                $image = (string) ($_POST['image'] ?? '');
                $project['image']    = in_array($image, img_library('pj-'), true) ? $image : '';
                $cat = (string) ($_POST['cat'] ?? '');
                $project['cat']      = isset(PROJECT_CATS[$cat]) ? $cat : '';
                $status = (string) ($_POST['status'] ?? '');
                $project['status']   = in_array($status, PROJECT_STATUSES, true) ? $status : '';

                $project['category'] = fill_locales($_POST['category'] ?? []);
                $project['tagline']  = fill_locales($_POST['tagline'] ?? []);
                $project['summary']  = fill_locales($_POST['summary'] ?? []);

                $stack = trim((string) ($_POST['stack'] ?? ''));
                $project['stack'] = $stack === ''
                    ? []
                    : array_values(array_slice(array_filter(array_map('trim', explode(',', $stack))), 0, 12));

                // Raqamlar (masalan: "1200" — "Foydalanuvchi")
                $metrics = [];
                foreach ((array) ($_POST['metrics'] ?? []) as $row) {
                    $value = mb_substr(trim((string) ($row['value'] ?? '')), 0, 12);
                    $label = fill_locales($row['label'] ?? []);
                    if ($value !== '' && $label['uz'] !== '') {
                        $metrics[] = ['value' => $value, 'label' => $label];
                    }
                }
                $project['metrics'] = array_slice($metrics, 0, 3);

                $error = null;
                $cover = save_upload($_FILES['cover'] ?? [], $error);
                if ($error !== null) {
                    $notice = $error;
                    $noticeKind = 'error';
                } elseif ($cover !== null) {
                    if (!empty($project['cover'])) {
                        delete_upload((string) $project['cover']);
                    }
                    $project['cover'] = $cover;
                }
                if (!empty($_POST['cover_remove']) && !empty($project['cover']) && $cover === null) {
                    delete_upload((string) $project['cover']);
                    $project['cover'] = '';
                }

                $shots = (array) ($project['shots'] ?? []);
                $shotErrors = [];
                for ($i = 0; $i < 4; $i++) {
                    $error = null;
                    $saved = save_upload($_FILES['shot' . $i] ?? [], $error);
                    if ($error !== null) {
                        $shotErrors[] = ($i + 1) . '-rasm: ' . $error;
                    }
                    if ($saved !== null) {
                        if (!empty($shots[$i])) {
                            delete_upload((string) $shots[$i]);
                        }
                        $shots[$i] = $saved;
                    }
                    if (!empty($_POST['shot_remove'][$i]) && !empty($shots[$i])) {
                        delete_upload((string) $shots[$i]);
                        $shots[$i] = '';
                    }
                }
                $project['shots'] = array_values(array_map('strval', $shots));

                if ($shotErrors !== [] && $noticeKind !== 'error') {
                    $notice = implode(' | ', $shotErrors);
                    $noticeKind = 'error';
                }

                if ($index >= 0) {
                    $list[$index] = $project;
                } else {
                    array_unshift($list, $project);
                }

                if ($noticeKind !== 'error') {
                    $saved = projects_save($list);
                    $notice = $saved ? ($isNew ? 'Loyiha qo\'shildi' : 'Loyiha yangilandi') : 'Saqlab bo\'lmadi — papka yozuvchi emasmi?';
                    $noticeKind = $saved ? 'ok' : 'error';
                }

                $page = 'projects';
            }
        }

        /* ---- profil va kontent ---- */
        if ($action === 'content_save') {
            $section = (string) ($_POST['section'] ?? '');
            $result = admin_content_collect($section);
            if (isset($result['error'])) {
                $notice = (string) $result['error'];
                $noticeKind = 'error';
            } else {
                $saved = content_save($section === 'skills' ? 'competencies' : $section, $result['value']);
                if ($saved && $section === 'skills') {
                    $saved = content_save('platforms', $result['platforms']) && content_save('directions', $result['directions']);
                }
                $notice = $saved ? 'Saqlandi — Mini app’da darhol ko‘rinadi' : 'Saqlab bo‘lmadi — papka yozuvchi emasmi?';
                $noticeKind = $saved ? 'ok' : 'error';
            }
            $page = 'content';
        }

        /* ---- loyiha o'chirish ---- */
        if ($action === 'project_delete') {
            $slug = (string) ($_POST['slug'] ?? '');
            $list = [];
            foreach (projects_all() as $item) {
                if ((string) ($item['slug'] ?? '') === $slug) {
                    delete_upload((string) ($item['cover'] ?? ''));
                    foreach ((array) ($item['shots'] ?? []) as $shot) {
                        delete_upload((string) $shot);
                    }
                    continue;
                }
                $list[] = $item;
            }
            $saved = projects_save($list);
            $notice = $saved ? 'Loyiha o\'chirildi' : 'O\'chirib bo\'lmadi';
            $noticeKind = $saved ? 'ok' : 'error';
            $page = 'projects';
        }

        /* ---- xabar yuborish ---- */
        if ($action === 'message_send') {
            $title = trim((string) ($_POST['title'] ?? ''));
            $text = trim((string) ($_POST['text'] ?? ''));

            if ($title === '' || $text === '') {
                $notice = 'Sarlavha va matnni to\'ldiring';
                $noticeKind = 'error';
            } else {
                $error = null;
                $image = save_upload($_FILES['image'] ?? [], $error);

                if ($error !== null) {
                    $notice = $error;
                    $noticeKind = 'error';
                } else {
                    $message = [
                        'id'         => date('Ymd-His') . '-' . bin2hex(random_bytes(3)),
                        'title'      => mb_substr($title, 0, 120),
                        'text'       => mb_substr($text, 0, 2000),
                        'link'       => clean_url((string) ($_POST['link'] ?? '')),
                        'image'      => $image ?? '',
                        'created_at' => date('c'),
                    ];

                    $list = messages_all();
                    array_unshift($list, $message);

                    if (messages_save($list)) {
                        $notice = 'Xabar saqlandi va ilovada ko\'rinadi';
                        if (!empty($_POST['send_telegram'])) {
                            $job = broadcast_create($message);
                            $notice .= '. Telegram tarqatma boshlandi: ' . count($job['recipients']) . ' ta qabul qiluvchi';
                        }
                    } else {
                        $notice = 'Xabarni saqlab bo\'lmadi';
                        $noticeKind = 'error';
                    }
                }
            }
            $page = 'messages';
        }

        /* ---- xabar o'chirish ---- */
        if ($action === 'message_delete') {
            $id = (string) ($_POST['id'] ?? '');
            $list = [];
            foreach (messages_all() as $item) {
                if ((string) ($item['id'] ?? '') === $id) {
                    delete_upload((string) ($item['image'] ?? ''));
                    continue;
                }
                $list[] = $item;
            }
            $saved = messages_save($list);
            $notice = $saved ? 'Xabar o\'chirildi' : 'O\'chirib bo\'lmadi';
            $noticeKind = $saved ? 'ok' : 'error';
            $page = 'messages';
        }

        /* ---- tarqatmani to'xtatish ---- */
        if ($action === 'broadcast_stop') {
            $id = (string) ($_POST['id'] ?? '');
            store_update('broadcasts', static function (array $jobs) use ($id): array {
                foreach ($jobs as $i => $job) {
                    if ((string) ($job['id'] ?? '') === $id) {
                        $jobs[$i]['done'] = true;
                        $jobs[$i]['stopped'] = true;
                    }
                }
                return $jobs;
            });
            $notice = 'Tarqatma to\'xtatildi';
            $page = 'messages';
        }

        /* ---- buyurtma holati ---- */
        if ($action === 'order_status') {
            $ok = order_set_status((string) ($_POST['id'] ?? ''), (string) ($_POST['status'] ?? ''));
            $notice = $ok ? 'Holat yangilandi' : 'Yangilab bo\'lmadi';
            $noticeKind = $ok ? 'ok' : 'error';
            $page = 'orders';
        }

        /* ---- buyurtmani o'chirish ---- */
        if ($action === 'order_delete') {
            $ok = order_delete((string) ($_POST['id'] ?? ''));
            $notice = $ok ? 'Buyurtma o\'chirildi' : 'O\'chirib bo\'lmadi';
            $noticeKind = $ok ? 'ok' : 'error';
            $page = 'orders';
        }

        /* ---- video darslik saqlash ---- */
        if ($action === 'video_save') {
            $list = videos_all();
            $id = (string) ($_POST['id'] ?? '');
            $isNew = $id === '';

            $link = trim((string) ($_POST['youtube'] ?? ''));
            $ytId = youtube_id($link);

            if ($ytId === null) {
                $notice = 'YouTube havolasi noto\'g\'ri. To\'liq havolani joylashtiring.';
                $noticeKind = 'error';
            } else {
                $index = -1;
                foreach ($list as $i => $item) {
                    if ((string) ($item['id'] ?? '') === $id) {
                        $index = $i;
                        break;
                    }
                }

                $video = $index >= 0 ? $list[$index] : [];
                $video['id']          = $isNew ? (date('Ymd-His') . '-' . bin2hex(random_bytes(3))) : $id;
                $video['youtube']     = 'https://www.youtube.com/watch?v=' . $ytId;
                $video['youtube_id']  = $ytId;
                $video['title']       = fill_locales($_POST['title'] ?? []);
                $video['description'] = fill_locales($_POST['description'] ?? []);
                $level = (string) ($_POST['level'] ?? '');
                $video['level']       = in_array($level, COURSE_LEVELS, true) ? $level : '';
                $video['topic']       = mb_substr(trim((string) ($_POST['topic'] ?? '')), 0, 40);
                $video['task']        = fill_locales($_POST['task'] ?? []);
                if ($isNew) {
                    $maxPos = 0;
                    foreach ($list as $it) { $maxPos = max($maxPos, (int) ($it['pos'] ?? 0)); }
                    $video['pos'] = $maxPos > 0 ? $maxPos + 1 : count($list) + 1;
                }

                $error = null;
                $cover = save_upload($_FILES['cover'] ?? [], $error);
                if ($error !== null) {
                    $notice = $error;
                    $noticeKind = 'error';
                } elseif ($cover !== null) {
                    if (!empty($video['cover'])) {
                        delete_upload((string) $video['cover']);
                    }
                    $video['cover'] = $cover;
                } elseif (!isset($video['cover'])) {
                    $video['cover'] = '';
                }

                if (!empty($_POST['cover_remove']) && !empty($video['cover']) && $cover === null) {
                    delete_upload((string) $video['cover']);
                    $video['cover'] = '';
                }

                if ($noticeKind !== 'error') {
                    if ($index >= 0) {
                        $list[$index] = $video;
                    } else {
                        array_unshift($list, $video);
                    }
                    $saved = videos_save($list);
                    if ($saved) { course_normalize(); }
                    $notice = $saved ? ($isNew ? 'Video darslik qo\'shildi' : 'Video darslik yangilandi') : 'Saqlab bo\'lmadi — papka yozuvchi emasmi?';
                    $noticeKind = $saved ? 'ok' : 'error';
                }
            }
            $page = 'videos';
        }

        /* ---- video darslik o'chirish ---- */
        if ($action === 'video_delete') {
            $id = (string) ($_POST['id'] ?? '');
            $list = [];
            foreach (videos_all() as $item) {
                if ((string) ($item['id'] ?? '') === $id) {
                    delete_upload((string) ($item['cover'] ?? ''));
                    continue;
                }
                $list[] = $item;
            }
            $saved = videos_save($list);
            if ($saved) { course_normalize(); }
            $notice = $saved ? 'Video darslik o\'chirildi' : 'O\'chirib bo\'lmadi';
            $noticeKind = $saved ? 'ok' : 'error';
            $page = 'videos';
        }

        /* ---- vazifani o'chirish ---- */
        if ($action === 'task_delete') {
            $ok = task_delete((string) ($_POST['id'] ?? ''));
            $notice = $ok ? 'Vazifa o\'chirildi' : 'O\'chirib bo\'lmadi';
            $noticeKind = $ok ? 'ok' : 'error';
            $page = 'tasks';
        }

        /* ---- sertifikatni o'chirish ---- */
        if ($action === 'cert_delete') {
            $ok = cert_delete((string) ($_POST['id'] ?? ''));
            $notice = $ok ? 'Hujjat o\'chirildi' : 'O\'chirib bo\'lmadi';
            $noticeKind = $ok ? 'ok' : 'error';
            $page = 'certs';
        }

        /* ---- kurs nomi ---- */
        if ($action === 'course_save') {
            $ok = settings_set(['course_title' => mb_substr(trim((string) ($_POST['course_title'] ?? '')), 0, 80) ?: null]);
            $notice = $ok ? 'Kurs nomi saqlandi' : 'Saqlab bo\'lmadi';
            $noticeKind = $ok ? 'ok' : 'error';
            $page = 'certs';
        }

        /* ---- darslar tartibi (yuqoriga / pastga) ---- */
        if ($action === 'video_move') {
            $lessons = course_normalize();
            $id = (string) ($_POST['id'] ?? '');
            $dir = (string) ($_POST['dir'] ?? '') === 'up' ? -1 : 1;
            foreach ($lessons as $i => $item) {
                if ((string) ($item['id'] ?? '') === $id && isset($lessons[$i + $dir])) {
                    $lessons[$i]['pos'] = $i + 1 + $dir;
                    $lessons[$i + $dir]['pos'] = $i + 1;
                    break;
                }
            }
            $ok = videos_save($lessons);
            $notice = $ok ? 'Tartib saqlandi' : 'Saqlab bo\'lmadi';
            $noticeKind = $ok ? 'ok' : 'error';
            $page = 'videos';
        }

        /* ---- parolni o'zgartirish ---- */
        if ($action === 'password_change') {
            $current = (string) ($_POST['current'] ?? '');
            $new     = (string) ($_POST['new'] ?? '');
            $repeat  = (string) ($_POST['repeat'] ?? '');
            $login   = (string) ($CONFIG['admin_user'] ?? '');

            if (!admin_check($login, $current)) {
                $notice = 'Joriy parol noto\'g\'ri';
                $noticeKind = 'error';
            } elseif (mb_strlen($new) < 10) {
                $notice = 'Yangi parol kamida 10 belgidan iborat bo\'lsin';
                $noticeKind = 'error';
            } elseif (!hash_equals($new, $repeat)) {
                $notice = 'Yangi parollar bir xil emas';
                $noticeKind = 'error';
            } else {
                $ok = store_write('admin', [
                    'user'       => $login,
                    'hash'       => password_hash($new, PASSWORD_DEFAULT),
                    'legacy'     => (string) ($CONFIG['admin_pass_hash'] ?? ''),
                    'updated_at' => date('c'),
                ]);
                $notice = $ok ? 'Parol yangilandi' : 'Saqlab bo\'lmadi';
                $noticeKind = $ok ? 'ok' : 'error';
                if ($ok) {
                    admin_alert('🔑 <b>Admin paroli o‘zgartirildi.</b>');
                }
            }
            $page = 'settings';
        }

        /* ---- AI yordamchi sozlamalari ---- */
        if ($action === 'ai_save') {
            $provider = (string) ($_POST['ai_provider'] ?? 'gemini');
            $provider = in_array($provider, ['gemini', 'anthropic', 'openai'], true) ? $provider : 'gemini';
            $patch = [
                'ai_enabled'   => !empty($_POST['ai_enabled']),
                'ai_in_bot'    => !empty($_POST['ai_in_bot']),
                'ai_provider'  => $provider,
                'ai_model'     => mb_substr(preg_replace('/[^A-Za-z0-9._:\/\-]/', '', (string) ($_POST['ai_model'] ?? '')) ?? '', 0, 80),
                'ai_base_url'  => clean_url((string) ($_POST['ai_base_url'] ?? '')) ?: null,
                'ai_user_hour' => max(1, min(500, (int) ($_POST['ai_user_hour'] ?? 20))),
                'ai_user_day'  => max(1, min(2000, (int) ($_POST['ai_user_day'] ?? 60))),
                'ai_guest_day' => max(0, min(200, (int) ($_POST['ai_guest_day'] ?? 10))),
                'ai_daily_cap' => max(1, min(100000, (int) ($_POST['ai_daily_cap'] ?? 1500))),
            ];
            $key = trim((string) ($_POST['ai_key'] ?? ''));
            if ($key !== '') {
                $patch['ai_key'] = mb_substr(preg_replace('/\s+/', '', $key) ?? '', 0, 300);
            }
            if (!empty($_POST['ai_key_remove'])) {
                $patch['ai_key'] = null;
            }
            $ok = settings_set($patch);
            $notice = $ok ? 'AI yordamchi sozlamalari saqlandi' : 'Saqlab bo\'lmadi';
            $noticeKind = $ok ? 'ok' : 'error';
            $page = 'ai';
        }

        /* ---- AI jurnalini tozalash ---- */
        if ($action === 'ai_log_clear') {
            store_write('ai_log', []);
            $notice = 'Jurnal tozalandi';
            $page = 'ai';
        }

        /* ---- Telegram bot: token va ulash ---- */
        if ($action === 'bot_save' || $action === 'bot_connect') {
            $token = trim((string) ($_POST['bot_token'] ?? ''));
            if ($action === 'bot_save' && $token !== '') {
                if (!preg_match('/^\d{5,15}:[A-Za-z0-9_\-]{30,60}$/', $token)) {
                    $notice = 'Token formati noto\'g\'ri. @BotFather bergan tokenni to\'liq joylashtiring.';
                    $noticeKind = 'error';
                } else {
                    settings_set(['bot_token' => $token, 'bot_token_cfg' => hash('sha256', trim((string) cfg('bot_token', '')))]);
                }
            }
            if ($noticeKind !== 'error') {
                $result = bot_setup();
                $notice = $result['ok'] ? 'Bot ulandi: ' . $result['bot'] . '. Telegramda /start yozib tekshiring.' : 'Ulab bo\'lmadi: ' . $result['error'];
                $noticeKind = $result['ok'] ? 'ok' : 'error';
            }
            $page = 'bot';
        }
    }
}

/* Muvaffaqiyatli amaldan keyin — ro'yxat sahifasiga qaytamiz (PRG). */
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && isset($_POST['action']) && $notice !== null && $noticeKind === 'ok') {
    $_SESSION['flash'] = [$notice, $noticeKind];
    $back = '?p=' . rawurlencode((string) $page);
    if ($page === 'orders' && isset($_GET['status'])) {
        $back .= '&status=' . rawurlencode((string) $_GET['status']);
    }
    header('Location: ' . basename(__FILE__) . $back);
    exit;
}
if ($notice === null && !empty($_SESSION['flash']) && is_array($_SESSION['flash'])) {
    [$notice, $noticeKind] = $_SESSION['flash'];
    unset($_SESSION['flash']);
}

/**
 * Uch tildagi maydonni to'ldiradi. Bo'sh qolgan til o'zbekchadan olinadi,
 * shuning uchun ilovada hech qachon bo'sh joy ko'rinmaydi.
 */
function fill_locales($input): array
{
    $input = is_array($input) ? $input : [];

    $uz = trim((string) ($input['uz'] ?? ''));
    $en = trim((string) ($input['en'] ?? ''));
    $ru = trim((string) ($input['ru'] ?? ''));

    return [
        'uz' => $uz,
        'en' => $en !== '' ? $en : $uz,
        'ru' => $ru !== '' ? $ru : $uz,
    ];
}

/* ==================================================================
   KO'RINISH — "AKBARTECH Studio" boshqaruv paneli
   Light (ivory + terracotta) va Dark (grafit + to'q-sarg'ish),
   chap sidebar, KPI kartalar, grafiklar, AI tahlil, modal oynalar.
   ================================================================== */

function admin_logo(int $size = 34): string
{
    return '<svg width="' . $size . '" height="' . $size . '" viewBox="0 0 64 64" fill="none" aria-hidden="true">'
        . '<rect x="2" y="2" width="60" height="60" rx="18" fill="#1677FF"/>'
        . '<rect x="2" y="2" width="60" height="30" rx="18" fill="#fff" fill-opacity=".12"/>'
        . '<path d="M35.2 13 20 35.4h11.1L28.6 51 44 28.4H32.9L35.2 13Z" fill="#fff"/>'
        . '<circle cx="47" cy="17" r="2.6" fill="#fff" fill-opacity=".9"/></svg>';
}

/** Telegram SDK — mini app ichida ochilganda tepadagi joy va "Back" tugmasi uchun. */
function admin_tg_sdk(): string
{
    if (local_file('telegram-web-app.js') !== null) {
        return '<script src="' . e(asset('telegram-web-app.js')) . '"></script>';
    }
    return '<script src="https://telegram.org/js/telegram-web-app.js?58"></script>';
}

/** Sahifaning boshidagi tema skripti (miltillashsiz). */
function admin_theme_boot(): string
{
    return "<script>(function(){try{var t=localStorage.getItem('tezmind-admin-theme')||'light';"
        . "document.documentElement.setAttribute('data-theme',t);}catch(e){}})();</script>";
}

/** Kirish sahifasi. */
function render_login(?string $error): void
{
    ?><!DOCTYPE html>
<html lang="uz" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex, nofollow">
<title>AKBARTECH Studio — kirish</title>
<?= admin_theme_boot() ?>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Source+Serif+4:opsz,wght@8..60,500;8..60,600&display=swap">
<?= admin_tg_sdk() ?>
<style><?= admin_css() ?></style>
</head>
<body class="auth">

<div class="auth__art" aria-hidden="true">
    <div class="auth__glow"></div>
    <div class="auth__quote">
        <?= admin_logo(44) ?>
        <h2 class="serif">Sun’iy intellekt bilan<br>biznesni avtomatlashtiring.</h2>
        <p>Foydalanuvchilar, buyurtmalar, loyihalar va xabarlar — bitta boshqaruv panelida.</p>
        <div class="auth__chips"><span><?= icon('sparkles', 14) ?> AI tahlil</span><span><?= icon('shield-check', 14) ?> Himoyalangan</span><span><?= icon('zap', 14) ?> Tezkor</span></div>
    </div>
</div>

<main class="auth__side">
    <form class="auth__card" method="post" autocomplete="off" id="login-form">
        <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
        <div class="brand"><?= admin_logo(40) ?><div><b class="brand__name serif">AKBAR<em>TECH</em></b><span class="brand__note">Studio · Boshqaruv paneli</span></div></div>

        <h1 class="auth__title serif">Xush kelibsiz</h1>
        <p class="auth__sub">Davom etish uchun hisobingizga kiring.</p>

        <?php if ($error !== null): ?>
            <div class="alert alert--error" data-login-error><?= icon('alert-triangle', 16) ?><span><?= e($error) ?></span></div>
        <?php endif; ?>

        <div class="tglogin" id="tg-login" hidden>
            <button class="btn btn--tg btn--wide btn--lg" type="button" id="tg-login-btn"><?= icon('send', 17) ?> Telegram orqali kirish</button>
            <span class="tglogin__or"><i></i>yoki<i></i></span>
        </div>

        <label class="field">
            <span class="field__label">Login</span>
            <span class="field__box"><?= icon('user-round', 16) ?>
                <input class="input" type="text" name="login" required autofocus autocomplete="username" spellcheck="false" placeholder="admin">
            </span>
        </label>

        <label class="field">
            <span class="field__label">Parol</span>
            <span class="field__box"><?= icon('lock', 16) ?>
                <input class="input" type="password" name="password" required autocomplete="current-password" placeholder="••••••••" id="pw">
                <button type="button" class="field__eye" data-toggle-pw="#pw" aria-label="Parolni ko'rsatish"><?= icon('eye', 16) ?></button>
            </span>
        </label>

        <button class="btn btn--primary btn--wide btn--lg" type="submit">Kirish <?= icon('arrow-right', 16) ?></button>

        <p class="hint"><?= icon('shield-check', 13) ?> 5 marta xato kiritilsa — 15 daqiqaga blok. Har bir kirish haqida Telegramga xabar boradi.</p>
        <a class="btn btn--ghost btn--wide" href="<?= e(base_path()) ?>/index.php"><?= icon('arrow-left', 15) ?> Mini app'ga qaytish</a>
    </form>
</main>

<form method="post" id="tg-login-form" hidden>
    <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
    <input type="hidden" name="tg_init" value="">
</form>
<script>
/* Telegram ichida ochilgan bo'lsa — "Telegram orqali kirish" (admin_tg_id egasi uchun) */
(function () {
    var tg = window.Telegram && window.Telegram.WebApp;
    var init = tg && tg.initData;
    try {
        var handoff = sessionStorage.getItem('akbartech:admin-init');
        sessionStorage.removeItem('akbartech:admin-init');
        if (!init) {
            var saved = JSON.parse(sessionStorage.getItem('__telegram__initParams') || '{}');
            init = handoff || saved.tgWebAppData || '';
        }
    } catch (e) {
        init = init || handoff || '';
    }
    if (!init) { return; }
    var box = document.getElementById('tg-login');
    var form = document.getElementById('tg-login-form');
    form.elements.tg_init.value = init;
    box.hidden = false;
    document.getElementById('tg-login-btn').addEventListener('click', function () { this.disabled = true; form.submit(); });
    var auto = /[?&]tg=1/.test(location.search) && !document.querySelector('[data-login-error]');
    if (auto) { form.submit(); }
})();
</script>
<script><?= admin_js() ?></script>
</body>
</html><?php
}

/* ------------------------------------------------------------------ */

/** Panelning asosiy qobig'i. */
function require_view(): void
{
    global $notice, $noticeKind, $page;

    $pages = [
        'dashboard' => ['Boshqaruv',        'gauge',      'Umumiy ko‘rinish va AI tahlil',         'main'],
        'orders'    => ['Buyurtmalar',      'package',    'Mijozlardan kelgan arizalar',            'main'],
        'users'     => ['Foydalanuvchilar', 'users',      'Mini app’ga kirgan barcha foydalanuvchilar', 'main'],
        'content'   => ['Profil va kontent', 'user-round', 'Biografiya, tajriba, ko‘nikmalar, xizmatlar va havolalar', 'content'],
        'projects'  => ['Loyihalar',        'layers',     'Portfolio: kategoriya, holat, rasmlar, havolalar', 'content'],
        'messages'  => ['Xabarlar',         'bell',       'Bildirishnoma va Telegram tarqatma',     'content'],
        'ai'        => ['AI yordamchi',     'sparkles',   'AI yordamchi: kalit, limitlar, savollar', 'system'],
        'bot'       => ['Telegram bot',     'bot',        'Token, ulanish va holat',                'system'],
        'settings'  => ['Sozlamalar',       'settings',   'Tizim holati va xavfsizlik',             'system'],
    ];
    $groups = ['main' => 'Asosiy', 'content' => 'Kontent', 'system' => 'Tizim'];

    if (!isset($pages[$page])) {
        $page = 'dashboard';
    }

    $summary = stats_summary();
    $ordersNewCount = orders_new_count();
    $tasksPending = 0; // vazifalar bo'limi v5 da menyudan olingan
    $meta = $pages[$page];
    ?><!DOCTYPE html>
<html lang="uz" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex, nofollow">
<title><?= e($meta[0]) ?> — AKBARTECH Studio</title>
<?= admin_theme_boot() ?>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Source+Serif+4:opsz,wght@8..60,500;8..60,600&display=swap">
<?php if (false): ?>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Great+Vibes&family=Marck+Script&family=Oswald:wght@500;600;700&family=Montserrat:wght@400;500;600;700&display=swap">
<?php endif; ?>
<?= admin_tg_sdk() ?>
<style><?= admin_css() ?></style>
</head>
<body class="shell">

<aside class="side" id="side">
    <div class="side__brand">
        <?= admin_logo(34) ?>
        <div><b class="brand__name serif">AKBAR<em>TECH</em></b><span class="brand__note">Studio</span></div>
        <button type="button" class="iconbtn side__close" data-drawer="close" aria-label="Yopish"><?= icon('x', 18) ?></button>
    </div>

    <nav class="side__nav">
        <?php foreach ($groups as $gKey => $gLabel): ?>
            <span class="side__label"><?= e($gLabel) ?></span>
            <?php foreach ($pages as $key => $m): if ($m[3] !== $gKey) { continue; } ?>
                <a class="nav<?= $page === $key ? ' is-active' : '' ?>" href="?p=<?= e($key) ?>">
                    <?= icon($m[1], 18) ?>
                    <span><?= e($m[0]) ?></span>
                    <?php if ($key === 'orders' && $ordersNewCount > 0): ?>
                        <b class="nav__badge"><?= $ordersNewCount > 9 ? '9+' : $ordersNewCount ?></b>
                    <?php endif; ?>
                    <?php if ($key === 'tasks' && $tasksPending > 0): ?>
                        <b class="nav__badge"><?= $tasksPending > 9 ? '9+' : $tasksPending ?></b>
                    <?php endif; ?>
                </a>
            <?php endforeach; ?>
        <?php endforeach; ?>
    </nav>

    <div class="side__promo">
        <span class="side__promo-icon"><?= icon('sparkles', 16) ?></span>
        <b>Mini app’ni ochish</b>
        <p>O‘zgarishlarni foydalanuvchi ko‘zi bilan tekshiring.</p>
        <a class="btn btn--primary btn--sm btn--wide" href="<?= e(base_path()) ?>/index.php" target="_blank" rel="noopener">Ochish <?= icon('arrow-up-right', 14) ?></a>
    </div>
</aside>
<div class="scrim" data-drawer="close"></div>

<div class="main">
    <header class="top">
        <button type="button" class="iconbtn top__menu" data-drawer="open" aria-label="Menyu"><?= icon('menu', 19) ?></button>
        <div class="top__title">
            <h1 class="serif"><?= e($meta[0]) ?></h1>
            <p><?= e($meta[2]) ?></p>
        </div>
        <div class="top__actions">
            <a class="iconbtn" href="<?= e(base_path()) ?>/index.php" title="Mini app'ga qaytish" aria-label="Mini app'ga qaytish"><?= icon('house', 18) ?></a>
            <span class="chip chip--date"><?= icon('calendar', 14) ?> <?= e(date('d.m.Y')) ?></span>
            <button type="button" class="iconbtn" data-theme-toggle aria-label="Ko‘rinish">
                <span class="only-light"><?= icon('moon', 18) ?></span><span class="only-dark"><?= icon('sun', 18) ?></span>
            </button>
            <a class="iconbtn" href="?p=orders" aria-label="Buyurtmalar">
                <?= icon('bell', 18) ?>
                <?php if ($ordersNewCount > 0): ?><i class="iconbtn__dot"></i><?php endif; ?>
            </a>
            <div class="me">
                <span class="me__ava">A</span>
                <span class="me__txt"><b>Admin</b><small>AKBARTECH</small></span>
                <form method="post" data-confirm="Paneldan chiqilsinmi?" data-confirm-ok="Chiqish">
                    <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
                    <input type="hidden" name="action" value="logout">
                    <button class="iconbtn iconbtn--ghost" type="submit" title="Chiqish" aria-label="Chiqish"><?= icon('log-out', 17) ?></button>
                </form>
            </div>
        </div>
    </header>

    <main class="wrap">
        <?php if (!store_available()): ?>
            <div class="alert alert--error"><?= icon('alert-triangle', 16) ?>
                <span>Papkaga yozib bo‘lmayapti — ma’lumotlar saqlanmaydi. Hosting panelida shu papkaga yozish huquqini bering (chmod 775).</span>
            </div>
        <?php endif; ?>

        <?php
        if ($page === 'dashboard') { render_dashboard($summary); }
        if ($page === 'orders')    { render_orders(); }
        if ($page === 'users')     { render_users(); }
        if ($page === 'projects')  { render_projects(); }
        if ($page === 'content')   { render_content(); }
        if ($page === 'messages')  { render_messages(); }
        if ($page === 'settings')  { render_settings(); }
        if ($page === 'ai')        { render_ai(); }
        if ($page === 'bot')       { render_bot(); }
        ?>
    </main>
</div>

<!-- Telefon / planshet: pastki navigatsiya — barcha bo'limlar doim ko'rinadi -->
<nav class="bnav" aria-label="Bo‘limlar">
    <?php foreach (['dashboard' => ['gauge', 'Asosiy'], 'orders' => ['package', 'Buyurtma'], 'projects' => ['layers', 'Loyiha'], 'content' => ['user-round', 'Kontent']] as $key => $b): ?>
        <a class="bnav__item<?= $page === $key ? ' is-active' : '' ?>" href="?p=<?= e($key) ?>">
            <span class="bnav__icon"><?= icon($b[0], 20) ?>
                <?php if ($key === 'orders' && $ordersNewCount > 0): ?><i class="bnav__badge"><?= $ordersNewCount > 9 ? '9+' : $ordersNewCount ?></i><?php endif; ?>
                <?php if ($key === 'tasks' && $tasksPending > 0): ?><i class="bnav__badge"><?= $tasksPending > 9 ? '9+' : $tasksPending ?></i><?php endif; ?>
            </span>
            <span><?= e($b[1]) ?></span>
        </a>
    <?php endforeach; ?>
    <button type="button" class="bnav__item<?= in_array($page, ['users', 'settings', 'ai', 'bot', 'messages'], true) ? ' is-active' : '' ?>" data-drawer="open">
        <span class="bnav__icon"><?= icon('menu', 20) ?></span><span>Yana</span>
    </button>
</nav>

<!-- Tasdiqlash oynasi -->
<div class="modal modal--confirm" id="confirm" hidden>
    <div class="modal__scrim" data-close></div>
    <div class="modal__box" role="alertdialog" aria-modal="true">
        <span class="modal__icon"><?= icon('alert-triangle', 22) ?></span>
        <h3 class="modal__title" id="confirm-text">Ishonchingiz komilmi?</h3>
        <p class="modal__text">Bu amalni ortga qaytarib bo‘lmaydi.</p>
        <div class="modal__acts">
            <button type="button" class="btn btn--ghost" data-close>Bekor qilish</button>
            <button type="button" class="btn btn--danger" id="confirm-ok">O‘chirish</button>
        </div>
    </div>
</div>

<div class="toasts" id="toasts">
    <?php if ($notice !== null): ?>
        <div class="toast toast--<?= $noticeKind === 'error' ? 'error' : 'ok' ?>" role="status">
            <?= icon($noticeKind === 'error' ? 'alert-triangle' : 'circle-check', 17) ?>
            <span><?= e($notice) ?></span>
        </div>
    <?php endif; ?>
</div>

<script><?= admin_js() ?></script>
</body>
</html><?php
}

/* ==================================================================
   1. BOSHQARUV (Dashboard)
   ================================================================== */

/** Statistikadan "AI tahlil" — qisqa, amaliy xulosalar. */
function admin_insights(array $summary, array $series): array
{
    $out = [];
    $n = count($series);
    $today = $n > 0 ? (int) $series[$n - 1]['visits'] : 0;
    $yday  = $n > 1 ? (int) $series[$n - 2]['visits'] : 0;

    if ($yday > 0) {
        $diff = (int) round(($today - $yday) / $yday * 100);
        $out[] = $diff >= 0
            ? ['trending-up', "Bugungi tashriflar kechagidan <b>{$diff}%</b> ko‘p — yaxshi dinamika."]
            : ['trending-down', 'Bugun tashriflar kechagidan <b>' . abs($diff) . '%</b> kam. Kanalda yangi post yoki xabar tarqatish foydali bo‘ladi.'];
    } elseif ($today > 0) {
        $out[] = ['trending-up', "Bugun <b>{$today}</b> ta tashrif qayd etildi."];
    }

    $best = null;
    foreach ($series as $p) { if ($best === null || $p['visits'] > $best['visits']) { $best = $p; } }
    if ($best !== null && $best['visits'] > 0) {
        $out[] = ['star', 'So‘nggi 14 kunning eng faol kuni — <b>' . e($best['label']) . '</b> (' . (int) $best['visits'] . ' tashrif).'];
    }

    $newOrders = orders_new_count();
    if ($newOrders > 0) {
        $out[] = ['package', "<b>{$newOrders} ta</b> yangi buyurtma javob kutmoqda — 24 soat ichida javob berish konversiyani oshiradi."];
    }

    $locales = (array) ($summary['locales'] ?? []);
    if ($locales !== [] && $summary['users'] > 0) {
        arsort($locales);
        $top = (string) array_key_first($locales);
        $share = (int) round(reset($locales) / max(1, $summary['users']) * 100);
        $names = ['uz' => "o‘zbekcha", 'en' => 'inglizcha', 'ru' => 'ruscha'];
        $out[] = ['languages', "Auditoriyaning <b>{$share}%</b> — " . e($names[$top] ?? $top) . ' tilida. Kontentni shu tilda birinchi chiqaring.'];
    }

    if ($out === []) {
        $out[] = ['sparkles', 'Ma’lumot yig‘ilmoqda. Birinchi foydalanuvchilar kirgach, bu yerda avtomatik xulosalar paydo bo‘ladi.'];
    }
    return array_slice($out, 0, 4);
}

function pct_change(int $now, int $before): array
{
    if ($before <= 0) { return [$now > 0 ? '+100%' : '0%', $now > 0 ? 'up' : 'flat']; }
    $d = (int) round(($now - $before) / $before * 100);
    return [($d >= 0 ? '+' : '') . $d . '%', $d > 0 ? 'up' : ($d < 0 ? 'down' : 'flat')];
}

function render_dashboard(array $summary): void
{
    $series = stats_series(14);
    $recent = array_slice(users_all(), 0, 6);
    $orders = array_slice(orders_all(), 0, 4);
    $statuses = order_statuses();

    $n = count($series);
    $todayV = $n ? (int) $series[$n - 1]['visits'] : 0;
    $ydayV  = $n > 1 ? (int) $series[$n - 2]['visits'] : 0;
    $week = 0; $prevWeek = 0;
    foreach ($series as $i => $p) { if ($i >= $n - 7) { $week += $p['users']; } else { $prevWeek += $p['users']; } }
    [$tChange, $tDir] = pct_change($todayV, $ydayV);
    [$wChange, $wDir] = pct_change($week, $prevWeek);

    $spark = static function (string $key) use ($series): string {
        $vals = array_map(static fn ($p) => (int) $p[$key], array_slice($series, -10));
        $max = max(1, ...$vals);
        $pts = [];
        foreach ($vals as $i => $v) { $pts[] = round($i * (100 / max(1, count($vals) - 1)), 1) . ',' . round(28 - ($v / $max) * 24, 1); }
        return '<svg class="spark" viewBox="0 0 100 30" preserveAspectRatio="none"><polyline points="' . implode(' ', $pts) . '"/></svg>';
    };

    $leads = store_read('bot_leads');
    $leadsActive = count(array_filter($leads, static fn ($l): bool => empty($l['blocked'])));
    $aiUsage = store_read('ai_usage');
    $aiToday = ($aiUsage['day'] ?? '') === date('Y-m-d') ? (int) ($aiUsage['total'] ?? 0) : 0;

    $cards = [
        ['Ilova foydalanuvchisi', $summary['users'],     'users',    '+' . $summary['new_week'] . ' shu hafta', 'up',  $spark('users')],
        ['Bot obunachisi',        $leadsActive,          'bot',      count($leads) - $leadsActive . ' ta bloklagan', 'flat', ''],
        ['Bugungi tashrif',       $todayV,               'eye',      $tChange . ' kechagiga nisbatan',          $tDir, $spark('visits')],
        ['AI yordamchi (bugun)',    $aiToday,              'sparkles', 'savol-javob',                             'flat', ''],
    ];
    $insights = admin_insights($summary, $series);
    $quick = [
        ['?p=projects&new=1', 'layers',  'Loyiha qo‘shish',   'Portfolio’ga yangi ish',      count(projects_all()) . ' ta loyiha'],
        ['?p=videos&new=1',   'video',   'Darslik qo‘shish',  'YouTube video darslik',       count(videos_all()) . ' ta darslik'],
        ['?p=messages',       'send',    'Xabar yuborish',    'Hammaga bildirishnoma',       count(messages_all()) . ' ta yuborilgan'],
        ['?p=orders',         'package', 'Buyurtmalar',       'Mijoz arizalari',             orders_new_count() . ' ta yangi'],
    ];
    ?>

<section class="quick">
    <?php foreach ($quick as $i => $q): ?>
        <a class="quick__item reveal" href="<?= e($q[0]) ?>" style="--i: <?= $i ?>">
            <span class="quick__icon"><?= icon($q[1], 20) ?></span>
            <span class="quick__body"><b><?= e($q[2]) ?></b><small><?= e($q[3]) ?></small></span>
            <span class="quick__meta"><?= e($q[4]) ?></span>
            <span class="quick__plus"><?= icon($i < 3 ? 'plus' : 'arrow-right', 16) ?></span>
        </a>
    <?php endforeach; ?>
</section>

<section class="ai reveal">
    <div class="ai__glow" aria-hidden="true"></div>
    <div class="ai__head">
        <span class="ai__icon"><?= icon('sparkles', 18) ?></span>
        <div>
            <h2 class="serif">Tezkor xulosalar</h2>
            <p>Oxirgi 14 kunlik statistika asosida avtomatik</p>
        </div>
        <a class="ai__live" href="?p=ai"><?= icon('sparkles', 12) ?> AI yordamchi</a>
    </div>
    <ul class="ai__list">
        <?php foreach ($insights as $i => $row): ?>
            <li style="--i: <?= $i ?>"><span><?= icon($row[0], 15) ?></span><p><?= $row[1] ?></p></li>
        <?php endforeach; ?>
    </ul>
</section>

<div class="grid grid--kpi">
    <?php foreach ($cards as $i => $c): ?>
        <article class="card kpi reveal" style="--i: <?= $i ?>">
            <div class="kpi__top">
                <span class="kpi__icon"><?= icon($c[2], 18) ?></span>
                <span class="kpi__label"><?= e($c[0]) ?></span>
            </div>
            <div class="kpi__row">
                <b class="kpi__value" data-count="<?= (int) $c[1] ?>">0</b>
                <?= $c[5] ?>
            </div>
            <span class="trend trend--<?= e($c[4]) ?>"><?= icon($c[4] === 'down' ? 'trending-down' : 'trending-up', 13) ?> <?= e($c[3]) ?></span>
        </article>
    <?php endforeach; ?>
</div>

<div class="grid grid--main">
    <section class="card reveal">
        <header class="card__head">
            <div>
                <h2 class="card__title">Faollik</h2>
                <span class="card__note">Oxirgi 14 kun</span>
            </div>
            <div class="legend"><span><i class="lg lg--a"></i>Tashriflar</span><span><i class="lg lg--b"></i>Noyob foydalanuvchi</span></div>
        </header>
        <?= chart_area($series) ?>
    </section>

    <section class="card reveal">
        <header class="card__head">
            <div>
                <h2 class="card__title">Tillar</h2>
                <span class="card__note">Foydalanuvchilar bo‘yicha</span>
            </div>
        </header>
        <?= chart_donut($summary['locales'], $summary['users']) ?>
    </section>
</div>

<div class="grid grid--main">
    <section class="card reveal">
        <header class="card__head">
            <div>
                <h2 class="card__title">So‘nggi faollik</h2>
                <span class="card__note">Oxirgi kirgan foydalanuvchilar</span>
            </div>
            <a class="link" href="?p=users">Barchasi <?= icon('chevron-right', 14) ?></a>
        </header>
        <?php if ($recent === []): ?>
            <div class="empty"><?= icon('users', 22) ?><p>Hozircha hech kim kirmagan.</p></div>
        <?php else: ?>
            <div class="table-wrap">
                <table class="table">
                    <thead><tr><th>Foydalanuvchi</th><th>Til</th><th>Tashrif</th><th>Oxirgi kirish</th></tr></thead>
                    <tbody>
                    <?php foreach ($recent as $user): ?>
                        <tr>
                            <td><div class="who"><?= avatar_html($user, 32) ?><span><b><?= e(trim(($user['first_name'] ?? '') . ' ' . ($user['last_name'] ?? '')) ?: 'Nomsiz') ?></b><small><?= ($user['username'] ?? '') !== '' ? '@' . e((string) $user['username']) : 'ID ' . (int) $user['id'] ?></small></span></div></td>
                            <td><span class="tag"><?= e(strtoupper((string) ($user['locale'] ?? '—'))) ?></span></td>
                            <td class="num"><?= (int) ($user['visits'] ?? 0) ?></td>
                            <td class="muted"><?= e(time_ago((string) ($user['last_seen'] ?? ''))) ?></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>
    </section>

    <section class="card reveal">
        <header class="card__head">
            <div>
                <h2 class="card__title">Buyurtmalar</h2>
                <span class="card__note">Eng so‘nggilari</span>
            </div>
            <a class="link" href="?p=orders">Barchasi <?= icon('chevron-right', 14) ?></a>
        </header>
        <?php if ($orders === []): ?>
            <div class="empty"><?= icon('package', 22) ?><p>Hozircha buyurtma yo‘q.</p></div>
        <?php else: ?>
            <ul class="mini">
                <?php foreach ($orders as $o): $st = (string) ($o['status'] ?? 'new'); ?>
                    <li>
                        <span class="mini__icon"><?= icon('package', 16) ?></span>
                        <span class="mini__body"><b><?= e((string) $o['name']) ?></b><small><?= e((string) (($o['project_name'] ?? '') !== '' ? $o['project_name'] : mb_substr((string) $o['description'], 0, 38))) ?></small></span>
                        <span class="pill pill--<?= e($statuses[$st]['tone'] ?? 'gray') ?>"><?= e($statuses[$st]['label'] ?? $st) ?></span>
                    </li>
                <?php endforeach; ?>
            </ul>
        <?php endif; ?>
    </section>
</div>
<?php
}

/* ------------------------------------------------------------------
   Grafiklar — SVG, kutubxonasiz, rangi CSS o'zgaruvchilardan
   ------------------------------------------------------------------ */

function chart_area(array $series): string
{
    $width = 720; $height = 260; $padL = 34; $padR = 12; $padT = 16; $padB = 30;

    $max = 1;
    foreach ($series as $point) { $max = max($max, (int) $point['visits'], (int) $point['users']); }
    $max = (int) (ceil($max / 5) * 5);
    $max = max(5, $max);

    $count = max(count($series), 2);
    $stepX = ($width - $padL - $padR) / ($count - 1);
    $usable = $height - $padT - $padB;

    $pointsAt = static function (string $key) use ($series, $stepX, $padL, $padT, $usable, $max): array {
        $out = [];
        foreach ($series as $i => $p) {
            $out[] = [round($padL + $i * $stepX, 1), round($padT + $usable - ($usable * ((int) $p[$key]) / $max), 1)];
        }
        return $out;
    };

    $curve = static function (array $pts): string {
        if ($pts === []) { return ''; }
        $d = 'M' . $pts[0][0] . ' ' . $pts[0][1];
        for ($i = 1, $c = count($pts); $i < $c; $i++) {
            $mx = round(($pts[$i - 1][0] + $pts[$i][0]) / 2, 1);
            $d .= ' C' . $mx . ' ' . $pts[$i - 1][1] . ', ' . $mx . ' ' . $pts[$i][1] . ', ' . $pts[$i][0] . ' ' . $pts[$i][1];
        }
        return $d;
    };

    $visits = $pointsAt('visits');
    $users  = $pointsAt('users');
    $vPath  = $curve($visits);
    $uPath  = $curve($users);
    $area   = $vPath . ' L' . end($visits)[0] . ' ' . ($height - $padB) . ' L' . $visits[0][0] . ' ' . ($height - $padB) . ' Z';

    $data = [];
    foreach ($series as $i => $p) {
        $data[] = ['x' => $visits[$i][0], 'y' => $visits[$i][1], 'l' => $p['label'], 'v' => (int) $p['visits'], 'u' => (int) $p['users']];
    }

    ob_start();
    ?>
<div class="chart" data-chart='<?= e(json_encode($data)) ?>' data-w="<?= $width ?>" data-h="<?= $height ?>">
    <svg viewBox="0 0 <?= $width ?> <?= $height ?>" preserveAspectRatio="none" role="img" aria-label="Faollik grafigi">
        <defs>
            <linearGradient id="areaFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" style="stop-color: var(--accent); stop-opacity: .32"/>
                <stop offset="100%" style="stop-color: var(--accent); stop-opacity: 0"/>
            </linearGradient>
        </defs>
        <?php for ($i = 0; $i <= 4; $i++): $y = round($padT + ($usable / 4) * $i, 1); ?>
            <line class="chart__grid" x1="<?= $padL ?>" y1="<?= $y ?>" x2="<?= $width - $padR ?>" y2="<?= $y ?>"/>
            <text class="chart__axis" x="<?= $padL - 8 ?>" y="<?= $y + 4 ?>" text-anchor="end"><?= (int) round($max - ($max / 4) * $i) ?></text>
        <?php endfor; ?>
        <path class="chart__area" d="<?= e($area) ?>" fill="url(#areaFill)"/>
        <path class="chart__line chart__line--b" d="<?= e($uPath) ?>"/>
        <path class="chart__line" d="<?= e($vPath) ?>" pathLength="1"/>
        <?php foreach ($series as $i => $p): if ($i % 2 !== 0 && $i !== count($series) - 1) { continue; } ?>
            <text class="chart__axis" x="<?= round($padL + $i * $stepX, 1) ?>" y="<?= $height - 8 ?>" text-anchor="middle"><?= e($p['label']) ?></text>
        <?php endforeach; ?>
        <line class="chart__cursor" x1="0" y1="<?= $padT ?>" x2="0" y2="<?= $height - $padB ?>"/>
        <circle class="chart__dot" r="5" cx="-10" cy="-10"/>
    </svg>
    <div class="chart__tip" hidden><b></b><span></span><span></span></div>
</div>
    <?php
    return (string) ob_get_clean();
}

function chart_donut(array $locales, int $total): string
{
    $palette = ['uz' => 'var(--accent)', 'en' => 'var(--c2)', 'ru' => 'var(--c3)'];
    $names = ['uz' => "O‘zbekcha", 'en' => 'English', 'ru' => 'Русский'];
    $safeTotal = max($total, 1);
    $radius = 54;
    $circ = 2 * M_PI * $radius;
    $offset = 0;
    ob_start();
    ?>
<div class="donut">
    <svg viewBox="0 0 140 140" class="donut__svg">
        <circle cx="70" cy="70" r="<?= $radius ?>" fill="none" class="donut__track" stroke-width="14"/>
        <?php foreach ($palette as $code => $color):
            $value = (int) ($locales[$code] ?? 0);
            if ($value === 0) { continue; }
            $len = $circ * $value / $safeTotal; ?>
            <circle class="donut__slice" cx="70" cy="70" r="<?= $radius ?>" fill="none" style="stroke: <?= $color ?>"
                    stroke-width="14" stroke-dasharray="<?= round(max(0, $len - 3), 2) ?> <?= round($circ, 2) ?>"
                    stroke-dashoffset="<?= round(-$offset, 2) ?>" transform="rotate(-90 70 70)"/>
            <?php $offset += $len; ?>
        <?php endforeach; ?>
        <text x="70" y="68" text-anchor="middle" class="donut__num"><?= $total ?></text>
        <text x="70" y="86" text-anchor="middle" class="donut__cap">foydalanuvchi</text>
    </svg>
    <ul class="donut__legend">
        <?php foreach ($palette as $code => $color): $v = (int) ($locales[$code] ?? 0); ?>
            <li>
                <i style="background: <?= $color ?>"></i>
                <span><?= e($names[$code]) ?></span>
                <b><?= $v ?></b>
                <em><?= $total > 0 ? (int) round($v / $total * 100) : 0 ?>%</em>
            </li>
        <?php endforeach; ?>
    </ul>
</div>
    <?php
    return (string) ob_get_clean();
}

/** Foydalanuvchi rasmi yoki bosh harflari. */
function avatar_html(array $user, int $size): string
{
    // Avval serverga saqlangan rasm (bot orqali olingan), bo'lmasa Telegram bergan havola
    $photo = function_exists('user_avatar_url') ? user_avatar_url($user) : '';
    if ($photo === '') {
        $photo = (string) ($user['photo_url'] ?? '');
    }
    $name = trim(((string) ($user['first_name'] ?? '')) . ' ' . ((string) ($user['last_name'] ?? '')));
    $initials = mb_strtoupper(mb_substr($name !== '' ? $name : 'A', 0, 1));

    if ($photo !== '') {
        // Rasm ochilmasa — bosh harf ko'rsatiladi
        return sprintf(
            '<img class="ava" src="%s" alt="" loading="lazy" referrerpolicy="no-referrer" style="width:%dpx;height:%dpx" data-l="%s" data-fs="%d" '
            . 'onerror="var s=document.createElement(\'span\');s.className=\'ava ava--letter\';s.textContent=this.dataset.l;s.style.cssText=this.style.cssText+\';font-size:\'+this.dataset.fs+\'px\';this.replaceWith(s)">',
            e($photo), $size, $size, e($initials), (int) round($size * 0.4)
        );
    }
    return sprintf('<span class="ava ava--letter" style="width:%dpx;height:%dpx;font-size:%dpx">%s</span>', $size, $size, (int) round($size * 0.4), e($initials));
}

/* ==================================================================
   2. FOYDALANUVCHILAR
   ================================================================== */

/** Foydalanuvchilar sahifasidagi bo'limlar: ilova / bot. */
function users_tabs(string $active, int $appCount, int $botCount): string
{
    return '<div class="toolbar reveal"><div class="segs">'
        . '<a class="seg' . ($active === 'app' ? ' is-active' : '') . '" href="?p=users">Mini app <b>' . $appCount . '</b></a>'
        . '<a class="seg' . ($active === 'bot' ? ' is-active' : '') . '" href="?p=users&tab=bot">Bot obunachilari <b>' . $botCount . '</b></a>'
        . '</div></div>';
}

function render_leads(): void
{
    $leads = [];
    foreach (store_read('bot_leads') as $key => $lead) {
        $lead['id'] = (int) ($lead['id'] ?? $key);
        $lead['last_at'] = (string) ($lead['last_at'] ?? (is_numeric($lead['updated_at'] ?? null) ? date('c', (int) $lead['updated_at']) : ''));
        $leads[] = $lead;
    }
    usort($leads, static fn (array $a, array $b): int => strcmp((string) ($b['last_at'] ?? ''), (string) ($a['last_at'] ?? '')));
    $phones = count(array_filter($leads, static fn ($l): bool => !empty($l['phone'])));
    echo users_tabs('bot', count(store_read('users')), count($leads));
    ?>
<section class="card reveal">
    <header class="card__head card__head--tools">
        <div>
            <h2 class="card__title">Botga /start bosganlar <span class="count"><?= count($leads) ?></span></h2>
            <span class="card__note"><?= $phones ?> tasi raqamini tasdiqlagan · xabar tarqatmasiga kiradi (bloklaganlardan tashqari)</span>
        </div>
        <?php if ($leads !== []): ?>
            <label class="search"><?= icon('search', 16) ?>
                <input class="input" type="search" id="user-search" placeholder="Ism, username yoki raqam…" autocomplete="off">
            </label>
        <?php endif; ?>
    </header>
    <?php if ($leads === []): ?>
        <div class="empty"><?= icon('bot', 24) ?><p>Hali hech kim botga yozmagan. Bot ulanganini “Telegram bot” bo‘limida tekshiring.</p></div>
    <?php else: ?>
        <div class="table-wrap">
            <table class="table">
                <thead><tr><th>#</th><th>Foydalanuvchi</th><th>Telefon</th><th>Til</th><th class="num">Xabar</th><th>Birinchi</th><th>Oxirgi</th><th>Holat</th></tr></thead>
                <tbody>
                <?php foreach ($leads as $i => $lead):
                    $name = trim((string) ($lead['name'] ?? '')) ?: 'Nomsiz';
                    $username = (string) ($lead['username'] ?? '');
                    $phone = (string) ($lead['phone'] ?? ''); ?>
                    <tr class="urow" data-search="<?= e(mb_strtolower($name . ' ' . $username . ' ' . $phone . ' ' . ($lead['id'] ?? ''))) ?>">
                        <td class="muted num"><?= $i + 1 ?></td>
                        <td><div class="who"><span class="ava ava--letter" style="width:32px;height:32px;font-size:13px"><?= e(mb_strtoupper(mb_substr($name, 0, 1))) ?></span><span>
                            <b><?= e($name) ?></b>
                            <small><?= $username !== '' ? '<a href="https://t.me/' . e($username) . '" target="_blank" rel="noopener">@' . e($username) . '</a>' : 'username yo‘q' ?> · ID <?= (int) ($lead['id'] ?? 0) ?></small>
                        </span></div></td>
                        <td><?= $phone !== '' ? '<a href="tel:' . e(preg_replace('/[^0-9+]/', '', $phone)) . '">' . e($phone) . '</a>' : '<span class="muted">—</span>' ?></td>
                        <td><span class="tag"><?= e(strtoupper(substr((string) ($lead['lang'] ?? ''), 0, 2)) ?: '—') ?></span></td>
                        <td class="num"><?= (int) ($lead['msgs'] ?? 0) ?></td>
                        <td class="muted"><?= e(($lead['started_at'] ?? '') !== '' ? date('d.m.Y', (int) strtotime((string) $lead['started_at'])) : '—') ?></td>
                        <td class="muted"><?= e(time_ago((string) ($lead['last_at'] ?? ''))) ?></td>
                        <td><?= !empty($lead['blocked']) ? '<span class="pill pill--gray">Bloklagan</span>' : '<span class="pill pill--green">Faol</span>' ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            <div class="empty empty--search" id="user-empty" hidden><?= icon('search', 22) ?><p>Hech narsa topilmadi.</p></div>
        </div>
    <?php endif; ?>
</section>
<?php
}

function render_users(): void
{
    if ((string) ($_GET['tab'] ?? '') === 'bot') {
        render_leads();
        return;
    }
    $users = users_all();
    $premium = count(array_filter($users, static fn ($u) => !empty($u['is_premium'])));
    $progressAll = store_read('progress');
    $lessonTotal = count(course_lessons());
    $failAt = (int) settings_get('tg_verify_fail_at', 0);
    $okAt = (int) settings_get('tg_verify_ok_at', 0);
    echo users_tabs('app', count($users), count(store_read('bot_leads')));
    ?>
<?php if ($failAt > 0 && $failAt > $okAt && time() - $failAt < 86400): ?>
    <div class="alert alert--warn reveal"><?= icon('alert-triangle', 16) ?><span><b>Telegram imzosi tasdiqlanmayapti.</b> index.php dagi <code>bot_token</code> mini app ochiladigan bot (@<?= e(ltrim((string) cfg('bot_username', 'tezmind_bot'), '@')) ?>) tokeni ekanini tekshiring — aks holda foydalanuvchilar “mehmon” bo‘lib qoladi va bu ro‘yxatga tushmaydi.</span></div>
<?php endif; ?>
<section class="card reveal">
    <header class="card__head card__head--tools">
        <div>
            <h2 class="card__title">Barcha foydalanuvchilar <span class="count"><?= count($users) ?></span></h2>
            <span class="card__note"><?= $premium ?> ta Telegram Premium</span>
        </div>
        <?php if ($users !== []): ?>
            <label class="search"><?= icon('search', 16) ?>
                <input class="input" type="search" id="user-search" placeholder="Ism, username yoki ID…" autocomplete="off">
            </label>
        <?php endif; ?>
    </header>

    <?php if ($users === []): ?>
        <div class="empty"><?= icon('users', 24) ?><p>Hali hech kim mini app’ga kirmagan. Kimdir botni ochib ilovaga kirsa, shu yerda paydo bo‘ladi.</p></div>
    <?php else: ?>
        <div class="table-wrap">
            <table class="table table--click">
                <thead><tr><th>#</th><th>Foydalanuvchi</th><th>Kurs</th><th>Til</th><th class="num">Tashrif</th><th>Qo‘shilgan</th><th>Oxirgi kirish</th><th></th></tr></thead>
                <tbody>
                <?php foreach ($users as $index => $user):
                    $name = trim(((string) ($user['first_name'] ?? '')) . ' ' . ((string) ($user['last_name'] ?? '')));
                    $username = (string) ($user['username'] ?? '');
                    $doneCount = count((array) (($progressAll[(string) ($user['id'] ?? 0)] ?? [])['done'] ?? []));
                    $payload = json_encode([
                        'id' => (int) ($user['id'] ?? 0), 'name' => $name, 'username' => $username,
                        'photo' => (function_exists('user_avatar_url') && user_avatar_url($user) !== '') ? user_avatar_url($user) : (string) ($user['photo_url'] ?? ''), 'premium' => !empty($user['is_premium']),
                        'locale' => (string) ($user['locale'] ?? ''), 'language' => (string) ($user['language'] ?? ''),
                        'visits' => (int) ($user['visits'] ?? 0), 'first_seen' => (string) ($user['first_seen'] ?? ''),
                        'last_seen' => (string) ($user['last_seen'] ?? ''),
                        'course' => $lessonTotal > 0 ? $doneCount . ' / ' . $lessonTotal : '',
                        'platform' => (string) ($user['platform'] ?? ''),
                    ], JSON_UNESCAPED_UNICODE); ?>
                    <tr class="urow" data-user="<?= e((string) $payload) ?>" data-search="<?= e(mb_strtolower($name . ' ' . $username . ' ' . ($user['id'] ?? ''))) ?>" tabindex="0">
                        <td class="muted num"><?= $index + 1 ?></td>
                        <td><div class="who"><?= avatar_html($user, 34) ?><span>
                            <b><?= e($name !== '' ? $name : 'Nomsiz') ?><?php if (!empty($user['is_premium'])): ?> <i class="tag tag--accent"><?= icon('crown', 11) ?> Premium</i><?php endif; ?></b>
                            <small><?= $username !== '' ? '@' . e($username) : 'username yo‘q' ?> · ID <?= (int) ($user['id'] ?? 0) ?></small>
                        </span></div></td>
                        <td><span class="tag<?= $lessonTotal > 0 && $doneCount >= $lessonTotal ? ' tag--accent' : '' ?>"><?= $lessonTotal > 0 ? $doneCount . ' / ' . $lessonTotal : '—' ?></span></td>
                        <td><span class="tag"><?= e(strtoupper((string) ($user['locale'] ?? '—'))) ?></span></td>
                        <td class="num"><b><?= (int) ($user['visits'] ?? 0) ?></b></td>
                        <td class="muted"><?= e(($user['first_seen'] ?? '') !== '' ? date('d.m.Y', (int) strtotime((string) $user['first_seen'])) : '—') ?></td>
                        <td class="muted"><?= e(time_ago((string) ($user['last_seen'] ?? ''))) ?></td>
                        <td class="chev"><?= icon('chevron-right', 16) ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            <div class="empty empty--search" id="user-empty" hidden><?= icon('search', 22) ?><p>Hech narsa topilmadi.</p></div>
        </div>
    <?php endif; ?>
</section>

<div class="modal" id="user-modal" hidden>
    <div class="modal__scrim" data-close></div>
    <div class="modal__box modal__box--user" role="dialog" aria-modal="true">
        <button type="button" class="modal__x" data-close aria-label="Yopish"><?= icon('x', 18) ?></button>
        <div id="user-detail"></div>
    </div>
</div>
<?php
}

/* ==================================================================
   3. LOYIHALAR
   ================================================================== */

function render_projects(): void
{
    $projects = projects_all();
    $editing = isset($_GET['edit']) ? project_find((string) $_GET['edit']) : null;
    $isNew = isset($_GET['new']);

    if ($editing !== null || $isNew) {
        echo project_form($editing);
        return;
    }
    ?>
<div class="toolbar reveal">
    <p class="muted"><?= count($projects) ?> ta loyiha · <?= count(array_filter($projects, static fn ($p) => !empty($p['featured']))) ?> tasi tanlangan</p>
    <a class="btn btn--primary" href="?p=projects&new=1"><?= icon('plus', 16) ?> Loyiha qo‘shish</a>
</div>

<?php if ($projects === []): ?>
    <div class="card empty reveal"><?= icon('layers', 24) ?><p>Hozircha loyiha yo‘q. “Loyiha qo‘shish” tugmasini bosing.</p></div>
<?php else: ?>
    <div class="grid grid--cards">
        <?php foreach ($projects as $i => $project):
            $cover = (string) ($project['cover'] ?? '');
            $accent = (string) ($project['accent'] ?? '#1677FF'); ?>
            <article class="card pcard reveal" style="--p1: <?= e($accent) ?>; --i: <?= $i ?>">
                <div class="pcard__media<?= $cover !== '' ? ' has-img' : '' ?>">
                    <?php if ($cover !== ''): ?>
                        <img src="<?= e(upload_url($cover)) ?>" alt="" loading="lazy">
                    <?php else: ?>
                        <span class="pcard__icon"><?= icon((string) ($project['icon'] ?? 'sparkles'), 26) ?></span>
                    <?php endif; ?>
                    <?php if (!empty($project['featured'])): ?><span class="pcard__flag"><?= icon('star', 12) ?> Tanlangan</span><?php endif; ?>
                </div>
                <div class="pcard__body">
                    <div class="pcard__meta"><span><?= e(tr($project['category'] ?? '')) ?></span><span><?= e((string) ($project['year'] ?? '')) ?></span></div>
                    <h3><?= e((string) ($project['name'] ?? '')) ?></h3>
                    <p><?= e(tr($project['tagline'] ?? '')) ?></p>
                    <div class="chips">
                        <?php foreach (array_slice((array) ($project['stack'] ?? []), 0, 4) as $tech): ?><span class="chip"><?= e((string) $tech) ?></span><?php endforeach; ?>
                    </div>
                </div>
                <div class="pcard__acts">
                    <a class="btn btn--ghost btn--sm" href="?p=projects&edit=<?= e(urlencode((string) $project['slug'])) ?>"><?= icon('pencil', 14) ?> Tahrirlash</a>
                    <form method="post" data-confirm="«<?= e((string) $project['name']) ?>» o‘chirilsinmi?">
                        <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
                        <input type="hidden" name="action" value="project_delete">
                        <input type="hidden" name="slug" value="<?= e((string) $project['slug']) ?>">
                        <button class="iconbtn iconbtn--danger" type="submit" title="O‘chirish"><?= icon('trash-2', 16) ?></button>
                    </form>
                </div>
            </article>
        <?php endforeach; ?>
    </div>
<?php endif;
}

/** Uch tilli maydonlar — tab ko'rinishida (UZ / EN / RU). */
function lang_fields(string $key, string $label, string $placeholder, callable $value, bool $area = false): string
{
    ob_start();
    ?>
<div class="field">
    <span class="field__label"><?= e($label) ?></span>
    <div class="ltabs" data-ltabs>
        <div class="ltabs__bar">
            <?php foreach (['uz' => 'UZ', 'en' => 'EN', 'ru' => 'RU'] as $code => $t): ?>
                <button type="button" class="ltabs__btn<?= $code === 'uz' ? ' is-on' : '' ?>" data-lang="<?= $code ?>"><?= $t ?></button>
            <?php endforeach; ?>
        </div>
        <?php foreach (['uz', 'en', 'ru'] as $code): ?>
            <div class="ltabs__pane<?= $code === 'uz' ? ' is-on' : '' ?>" data-pane="<?= $code ?>">
                <?php if ($area): ?>
                    <textarea class="input" name="<?= e($key) ?>[<?= $code ?>]" rows="4" placeholder="<?= e($code === 'uz' ? $placeholder : 'Bo‘sh qolsa — o‘zbekchasi ishlatiladi') ?>"><?= e($value($key, $code)) ?></textarea>
                <?php else: ?>
                    <input class="input" type="text" name="<?= e($key) ?>[<?= $code ?>]" value="<?= e($value($key, $code)) ?>" placeholder="<?= e($code === 'uz' ? $placeholder : 'Bo‘sh qolsa — o‘zbekchasi ishlatiladi') ?>">
                <?php endif; ?>
            </div>
        <?php endforeach; ?>
    </div>
</div>
<?php
    return (string) ob_get_clean();
}

function project_form(?array $project): string
{
    $p = $project ?? [];
    $shots = (array) ($p['shots'] ?? []);
    $icons = ADMIN_ICONS;
    $value = static function (string $group, string $locale) use ($p): string {
        $v = $p[$group] ?? [];
        return is_array($v) ? (string) ($v[$locale] ?? '') : (string) $v;
    };
    $accent = (string) ($p['accent'] ?? '#1677FF');
    ob_start();
    ?>
<form class="editor" method="post" enctype="multipart/form-data">
    <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
    <input type="hidden" name="action" value="project_save">
    <input type="hidden" name="slug" value="<?= e((string) ($p['slug'] ?? '')) ?>">

    <div class="toolbar">
        <a class="btn btn--ghost btn--sm" href="?p=projects"><?= icon('arrow-left', 15) ?> Orqaga</a>
        <h2 class="serif"><?= $project === null ? 'Yangi loyiha' : 'Loyihani tahrirlash' ?></h2>
        <button class="btn btn--primary" type="submit"><?= icon('check', 16) ?> Saqlash</button>
    </div>

    <div class="editor__grid">
        <div class="editor__main">
            <section class="card">
                <h3 class="card__title">Asosiy</h3>
                <label class="field">
                    <span class="field__label">Loyiha nomi <i>*</i></span>
                    <input class="input" type="text" name="name" required value="<?= e((string) ($p['name'] ?? '')) ?>" placeholder="Masalan: Focus AI" data-preview="name">
                </label>
                <div class="row2">
                    <label class="field"><span class="field__label">Havola (demo, bot yoki video) <em>faqat tekshirilgan</em></span>
                        <input class="input" type="url" name="link" value="<?= e((string) ($p['link'] ?? '')) ?>" placeholder="https://..."></label>
                    <label class="field"><span class="field__label">Yil</span>
                        <input class="input" type="text" name="year" value="<?= e((string) ($p['year'] ?? date('Y'))) ?>"></label>
                </div>
                <div class="row2">
                    <label class="field"><span class="field__label">Kategoriya</span>
                        <select class="input" name="cat">
                            <option value="">— tanlanmagan —</option>
                            <?php foreach (PROJECT_CATS as $ck => $cl): ?>
                                <option value="<?= e($ck) ?>" <?= project_cat($p) === $ck ? 'selected' : '' ?>><?= e($cl) ?></option>
                            <?php endforeach; ?>
                        </select></label>
                    <label class="field"><span class="field__label">Holat</span>
                        <select class="input" name="status">
                            <?php foreach (['' => '— ko‘rsatilmaydi —', 'done' => 'Yakunlangan', 'progress' => 'Jarayonda', 'concept' => 'Konsept'] as $sk => $sl): ?>
                                <option value="<?= e($sk) ?>" <?= (string) ($p['status'] ?? '') === $sk ? 'selected' : '' ?>><?= e($sl) ?></option>
                            <?php endforeach; ?>
                        </select></label>
                </div>
                <label class="field"><span class="field__label">Tayyor muqova <em>yuklangan cover bo‘lsa — u ustun</em></span>
                    <select class="input" name="image">
                        <option value="">— yo‘q —</option>
                        <?php foreach (img_library('pj-') as $imgKey): ?>
                            <option value="<?= e($imgKey) ?>" <?= (string) ($p['image'] ?? '') === $imgKey ? 'selected' : '' ?>><?= e($imgKey) ?></option>
                        <?php endforeach; ?>
                    </select></label>
                <label class="field"><span class="field__label">Texnologiyalar <em>vergul bilan</em></span>
                    <input class="input" type="text" name="stack" value="<?= e(implode(', ', (array) ($p['stack'] ?? []))) ?>" placeholder="PHP, MySQL, Bot API"></label>
            </section>

            <section class="card">
                <h3 class="card__title">Matnlar</h3>
                <?= lang_fields('category', 'Turkum', 'AI ilova', $value) ?>
                <?= lang_fields('tagline', 'Qisqa izoh', 'AI odat kuzatuvchisi', $value) ?>
                <?= lang_fields('summary', 'To‘liq tavsif', 'Loyiha nima qiladi…', $value, true) ?>
            </section>

            <section class="card">
                <h3 class="card__title">Raqamlar <small class="muted">ixtiyoriy · faqat haqiqiy ko‘rsatkichlar</small></h3>
                <?php $metrics = array_values((array) ($p['metrics'] ?? [])); ?>
                <?php for ($m = 0; $m < 3; $m++):
                    $row = (array) ($metrics[$m] ?? []);
                    $lbl = $row['label'] ?? (isset($row['key']) ? __((string) $row['key']) : '');
                    $lbl = is_array($lbl) ? (string) ($lbl['uz'] ?? '') : (string) $lbl; ?>
                    <div class="row2">
                        <label class="field"><span class="field__label">Qiymat</span>
                            <input class="input" type="text" name="metrics[<?= $m ?>][value]" maxlength="12" value="<?= e((string) ($row['value'] ?? '')) ?>" placeholder="<?= ['1200+', '4.9', '35'][$m] ?>"></label>
                        <label class="field"><span class="field__label">Nomi</span>
                            <input class="input" type="text" name="metrics[<?= $m ?>][label][uz]" maxlength="30" value="<?= e($lbl) ?>" placeholder="<?= ['Foydalanuvchi', 'Reyting', 'Buyurtma'][$m] ?>"></label>
                    </div>
                <?php endfor; ?>
                <span class="field__hint">Bo‘sh qoldirilsa — ko‘rsatilmaydi. Mijozlar ishonchi uchun faqat tekshirilgan raqamlarni yozing.</span>
            </section>

            <section class="card">
                <h3 class="card__title">Rasmlar</h3>
                <div class="field">
                    <span class="field__label">Asosiy rasm (cover)</span>
                    <label class="drop">
                        <?php if (!empty($p['cover'])): ?><img src="<?= e(upload_url((string) $p['cover'])) ?>" alt=""><?php else: ?><?= icon('image', 22) ?><span>Rasm tanlang yoki shu yerga tashlang</span><?php endif; ?>
                        <input type="file" name="cover" accept="image/*">
                    </label>
                    <?php if (!empty($p['cover'])): ?>
                        <label class="check check--sm"><input type="checkbox" name="cover_remove" value="1"><span>Asosiy rasmni o‘chirish</span></label>
                    <?php endif; ?>
                </div>
                <div class="field">
                    <span class="field__label">Skrinshotlar (4 tagacha)</span>
                    <div class="shots">
                        <?php for ($i = 0; $i < 4; $i++): $ex = (string) ($shots[$i] ?? ''); ?>
                            <div class="shots__cell">
                                <label class="drop drop--sm">
                                    <?php if ($ex !== ''): ?><img src="<?= e(upload_url($ex)) ?>" alt=""><?php else: ?><?= icon('plus', 18) ?><?php endif; ?>
                                    <input type="file" name="shot<?= $i ?>" accept="image/*">
                                </label>
                                <?php if ($ex !== ''): ?>
                                    <label class="check check--sm"><input type="checkbox" name="shot_remove[<?= $i ?>]" value="1"><span>O‘chirish</span></label>
                                <?php endif; ?>
                            </div>
                        <?php endfor; ?>
                    </div>
                    <span class="field__hint">Katta rasmlar avtomatik siqiladi, shaffof PNG (logo) foni saqlanadi. JPG, PNG, GIF, WEBP.</span>
                </div>
            </section>
        </div>

        <aside class="editor__side">
            <section class="card">
                <h3 class="card__title">Ko‘rinish</h3>
                <div class="preview" style="--p1: <?= e($accent) ?>">
                    <span class="preview__icon" data-preview-icon><?= icon((string) ($p['icon'] ?? 'sparkles'), 24) ?></span>
                    <b data-preview-name><?= e((string) ($p['name'] ?? 'Loyiha nomi')) ?></b>
                    <small>Mini app’dagi kartochka</small>
                </div>
                <div class="row2">
                    <label class="field"><span class="field__label">Asosiy rang</span>
                        <input class="input input--color" type="color" name="accent" value="<?= e($accent) ?>" data-preview="accent"></label>
                    <label class="field"><span class="field__label">Ikkinchi rang</span>
                        <input class="input input--color" type="color" name="accent_2" value="<?= e((string) ($p['accent_2'] ?? '#83C8FF')) ?>"></label>
                </div>
                <div class="field">
                    <span class="field__label">Ikonka</span>
                    <div class="icons">
                        <?php foreach ($icons as $name): ?>
                            <label class="icons__pick"><input type="radio" name="icon" value="<?= e($name) ?>" <?= ((string) ($p['icon'] ?? 'sparkles')) === $name ? 'checked' : '' ?>><span><?= icon($name, 18) ?></span></label>
                        <?php endforeach; ?>
                    </div>
                </div>
                <label class="toggle">
                    <input type="checkbox" name="featured" value="1" <?= !empty($p['featured']) ? 'checked' : '' ?>>
                    <span class="toggle__ui"></span>
                    <span><b>Tanlangan loyiha</b><small>Ro‘yxat boshida yulduzcha bilan chiqadi</small></span>
                </label>
            </section>
        </aside>
    </div>
</form>
    <?php
    return (string) ob_get_clean();
}

/* ==================================================================
   PROFIL VA KONTENT — Mini app'dagi barcha matnlar shu yerda
   ================================================================== */

const ADMIN_ICONS = ['sparkles', 'bot', 'message-circle', 'user-round', 'workflow', 'database', 'globe', 'send', 'smartphone', 'brain-circuit', 'video',
    'bar-chart', 'code-xml', 'layers', 'rocket', 'cpu', 'zap', 'briefcase', 'package', 'shopping-cart', 'cake',
    'graduation-cap', 'megaphone', 'badge-check'];
const ADMIN_MAX_JOBS = 6;
const ADMIN_MAX_ACTIVITIES = 8;
const ADMIN_MAX_FAQ = 12;
const ADMIN_MAX_SERVICES = 12;

/** Bir qatorli matn: teglar va boshqaruv belgilarisiz, uzunligi cheklangan. */
function admin_line($value, int $max): string
{
    $text = trim(strip_tags((string) $value));
    $text = (string) preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $text);
    return mb_substr($text, 0, $max);
}

/** Ko'p qatorli matn (qator tashlanishlari saqlanadi). */
function admin_text($value, int $max): string
{
    $text = str_replace("\r\n", "\n", trim(strip_tags((string) $value)));
    $text = (string) preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]+/u', '', $text);
    return mb_substr($text, 0, $max);
}

/** uz/en/ru maydonlari; bo'sh tillar o'zbekchasi bilan to'ldiriladi. */
function admin_locales($input, int $max, bool $multiline = false): array
{
    $input = is_array($input) ? $input : [];
    $out = [];
    foreach (['uz', 'en', 'ru'] as $code) {
        $out[$code] = $multiline ? admin_text($input[$code] ?? '', $max) : admin_line($input[$code] ?? '', $max);
    }
    foreach (['en', 'ru'] as $code) {
        if ($out[$code] === '') {
            $out[$code] = $out['uz'];
        }
    }
    return $out;
}

/** Har qatorda bitta element. */
function admin_list($value, int $maxItems, int $maxLen): array
{
    $items = array_map(static fn ($l) => admin_line($l, $maxLen), preg_split('/\R/u', (string) $value) ?: []);
    return array_values(array_slice(array_unique(array_filter($items, static fn ($l) => $l !== '')), 0, $maxItems));
}

function admin_slug_id(string $value, string $fallback): string
{
    $id = trim((string) preg_replace('/[^a-z0-9-]+/', '-', strtolower($value)), '-');
    return mb_substr($id !== '' ? $id : $fallback, 0, 40);
}

/**
 * POST'dan bo'lim qiymatini yig'adi va tekshiradi.
 * @return array{value?: array, error?: string, platforms?: array, directions?: array}
 */
function admin_content_collect(string $section): array
{
    $p = $_POST;
    switch ($section) {
        case 'profile':
            $current = content_profile();
            $name = admin_line($p['name'] ?? '', 80);
            if ($name === '') {
                return ['error' => 'Ismni kiriting'];
            }
            $photo = (string) ($current['photo'] ?? '');
            $error = null;
            $upload = save_upload($_FILES['photo'] ?? [], $error);
            if ($error !== null) {
                return ['error' => 'Rasm: ' . $error];
            }
            if ($upload !== null) {
                if ($photo !== '') { delete_upload($photo); }
                $photo = $upload;
            } elseif (!empty($p['photo_remove']) && $photo !== '') {
                delete_upload($photo);
                $photo = '';
            }
            return ['value' => [
                'name'            => $name,
                'role'            => admin_line($p['role'] ?? '', 120),
                'photo'           => $photo,
                'location'        => admin_locales($p['location'] ?? [], 80),
                'headline'        => admin_locales($p['headline'] ?? [], 140),
                'subtitle'        => admin_locales($p['subtitle'] ?? [], 400, true),
                'experience'      => admin_locales($p['experience'] ?? [], 60),
                'experience_note' => admin_locales($p['experience_note'] ?? [], 200),
                'bio'             => admin_locales($p['bio'] ?? [], 3000, true),
            ]];

        case 'links':
            $channel = clean_url((string) ($p['channel'] ?? ''));
            $youtube = clean_url((string) ($p['youtube'] ?? ''));
            $support = ltrim(admin_line($p['support'] ?? '', 40), '@');
            if ($support !== '' && !preg_match('/^[A-Za-z0-9_]{4,32}$/', $support)) {
                return ['error' => 'Telegram username noto‘g‘ri (4–32 ta harf, raqam yoki _)'];
            }
            if ($channel !== '' && !preg_match('#^https://(t\.me|telegram\.me)/#i', $channel)) {
                return ['error' => 'Kanal havolasi https://t.me/... ko‘rinishida bo‘lsin'];
            }
            $phone = admin_line($p['phone'] ?? '', 30);
            if ($phone !== '' && !preg_match('/^[0-9+\s\-()]{7,30}$/', $phone)) {
                return ['error' => 'Telefon raqami noto‘g‘ri'];
            }
            return ['value' => ['channel' => $channel, 'support' => $support, 'phone' => $phone, 'youtube' => $youtube]];

        case 'skills':
            return [
                'value'      => admin_list($p['competencies'] ?? '', 30, 60),
                'platforms'  => admin_list($p['platforms'] ?? '', 30, 40),
                'directions' => admin_list($p['directions'] ?? '', 30, 40),
            ];

        case 'jobs':
            $jobs = [];
            foreach (array_slice((array) ($p['jobs'] ?? []), 0, ADMIN_MAX_JOBS) as $row) {
                $company = admin_line($row['company'] ?? '', 80);
                if ($company === '' || !empty($row['remove'])) { continue; }
                $jobs[] = [
                    'company' => $company,
                    'role'    => admin_locales($row['role'] ?? [], 120),
                    'period'  => admin_locales($row['period'] ?? [], 40),
                    'summary' => admin_locales($row['summary'] ?? [], 300),
                    'points'  => admin_locales($row['points'] ?? [], 1500, true),
                ];
            }
            return ['value' => $jobs];

        case 'activities':
            $items = [];
            foreach (array_slice((array) ($p['activities'] ?? []), 0, ADMIN_MAX_ACTIVITIES) as $row) {
                $title = admin_locales($row['title'] ?? [], 80);
                if ($title['uz'] === '' || !empty($row['remove'])) { continue; }
                $icon = (string) ($row['icon'] ?? '');
                $items[] = [
                    'icon'  => in_array($icon, ADMIN_ICONS, true) ? $icon : 'sparkles',
                    'title' => $title,
                    'text'  => admin_locales($row['text'] ?? [], 300),
                ];
            }
            return ['value' => $items];

        case 'faq':
            $items = [];
            foreach (array_slice((array) ($p['faq'] ?? []), 0, ADMIN_MAX_FAQ) as $row) {
                $q = admin_locales($row['q'] ?? [], 160);
                if ($q['uz'] === '' || !empty($row['remove'])) { continue; }
                $items[] = ['q' => $q, 'a' => admin_locales($row['a'] ?? [], 1200, true)];
            }
            return ['value' => $items];

        case 'hero':
            $mode = (string) ($p['hero_mode'] ?? 'custom');
            if (!in_array($mode, ['bundle', 'custom', 'off'], true)) {
                return ['error' => 'Video rejimi noto‘g‘ri.'];
            }
            $videos = [];
            foreach (text_lines((string) ($p['videos'] ?? '')) as $line) {
                $url = clean_url($line);
                if ($url === '' || !preg_match('#^https://#i', $url)) {
                    return ['error' => 'Video havolasi https:// bilan boshlanishi kerak: ' . mb_substr($line, 0, 80)];
                }
                if (!in_array($url, $videos, true)) { $videos[] = $url; }
            }
            if (count($videos) > HERO_VIDEOS_MAX) {
                return ['error' => 'Ko‘pi bilan ' . HERO_VIDEOS_MAX . ' ta video'];
            }
            if ($mode === 'custom' && $videos === []) {
                return ['error' => 'Kamida bitta video havolasini kiriting yoki boshqa rejimni tanlang.'];
            }
            return ['value' => ['mode' => $mode, 'videos' => $videos]];

        case 'services':
            $items = [];
            $ids = [];
            foreach (array_slice((array) ($p['services'] ?? []), 0, ADMIN_MAX_SERVICES) as $i => $row) {
                $title = admin_locales($row['title'] ?? [], 80);
                if ($title['uz'] === '' || !empty($row['remove'])) { continue; }
                $id = admin_slug_id((string) ($row['id'] ?? ''), slugify($title['uz']) ?: 'service-' . ($i + 1));
                if ($id === ORDER_SERVICE_OTHER || isset($ids[$id])) {
                    $id .= '-' . ($i + 1);
                }
                $ids[$id] = true;
                $icon = (string) ($row['icon'] ?? '');
                $image = (string) ($row['image'] ?? '');
                $items[] = [
                    'id'    => $id,
                    'image' => in_array($image, img_library('svc-'), true) ? $image : '',
                    'icon'  => in_array($icon, ADMIN_ICONS, true) ? $icon : 'sparkles',
                    'title' => $title,
                    'text'  => admin_locales($row['text'] ?? [], 300),
                ];
            }
            if ($items === []) {
                return ['error' => 'Kamida bitta xizmat qoldiring'];
            }
            return ['value' => $items];
    }
    return ['error' => 'Noma’lum bo‘lim'];
}

/** Takrorlanuvchi blok ichidagi uz/en/ru maydoni. */
function admin_lang_input(string $name, array $values, string $label, bool $area = false, string $placeholder = ''): string
{
    return lang_fields($name, $label, $placeholder, static function (string $key, string $code) use ($values): string {
        return (string) ($values[$code] ?? '');
    }, $area);
}

function admin_icon_select(string $name, string $current): string
{
    $html = '<label class="field"><span class="field__label">Ikonka</span><select class="input" name="' . e($name) . '">';
    foreach (ADMIN_ICONS as $icon) {
        $html .= '<option value="' . e($icon) . '"' . ($icon === $current ? ' selected' : '') . '>' . e($icon) . '</option>';
    }
    return $html . '</select></label>';
}

function admin_content_form_open(string $section, string $title, string $hint = '', bool $files = false): string
{
    return '<form class="card" method="post"' . ($files ? ' enctype="multipart/form-data"' : '') . ' id="c-' . e($section) . '">'
        . '<input type="hidden" name="csrf" value="' . e(csrf_token()) . '">'
        . '<input type="hidden" name="action" value="content_save">'
        . '<input type="hidden" name="section" value="' . e($section) . '">'
        . '<div style="display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:6px">'
        . '<h3 class="card__title" style="margin:0">' . e($title) . '</h3>'
        . '<button class="btn btn--primary btn--sm" type="submit" style="flex:none;width:auto">' . icon('check', 15) . ' Saqlash</button></div>'
        . ($hint !== '' ? '<p class="field__hint">' . e($hint) . '</p>' : '');
}

function render_content(): void
{
    $profile    = content_profile();
    $links      = content_links();
    $jobs       = content_jobs();
    $activities = content_activities();
    $services   = content_services();
    $faq        = content_faq();
    $photo      = (string) ($profile['photo'] ?? '');
    $loc        = static fn (string $key): array => (array) ($profile[$key] ?? []);
    ?>
<nav class="chips" style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px">
    <?php foreach (['profile' => 'Profil', 'jobs' => 'Tajriba', 'activities' => 'Faoliyat', 'skills' => 'Ko‘nikmalar', 'services' => 'Xizmatlar', 'hero' => 'Hero video', 'faq' => 'Savollar', 'links' => 'Havolalar'] as $id => $label): ?>
        <a class="chip" href="#c-<?= e($id) ?>"><?= e($label) ?></a>
    <?php endforeach; ?>
</nav>

<div class="stack" style="display:grid;gap:16px">

    <?= admin_content_form_open('profile', 'Profil', 'Bosh sahifa va “Men haqimda”. Sarlavhada *yulduzcha* orasidagi so‘zlar ko‘k gradient bilan chiqadi.', true) ?>
        <div class="row2">
            <label class="field"><span class="field__label">Ism familiya <i>*</i></span>
                <input class="input" type="text" name="name" required maxlength="80" value="<?= e((string) ($profile['name'] ?? '')) ?>"></label>
            <label class="field"><span class="field__label">Lavozim</span>
                <input class="input" type="text" name="role" maxlength="120" value="<?= e((string) ($profile['role'] ?? '')) ?>"></label>
        </div>
        <div class="field">
            <span class="field__label">Profil rasmi <em>ixtiyoriy · kvadrat rasm tavsiya etiladi</em></span>
            <label class="drop drop--sm" style="width:120px;height:120px;aspect-ratio:1;border-radius:50%;overflow:hidden">
                <?php if ($photo !== ''): ?><img src="<?= e(upload_url($photo)) ?>" alt=""><?php else: ?><?= icon('image', 20) ?><?php endif; ?>
                <input type="file" name="photo" accept="image/*">
            </label>
            <?php if ($photo !== ''): ?>
                <label class="check check--sm"><input type="checkbox" name="photo_remove" value="1"><span>Rasmni o‘chirish</span></label>
            <?php endif; ?>
        </div>
        <?= admin_lang_input('headline', $loc('headline'), 'Asosiy sarlavha', false, 'Kelajakni *sun’iy intellekt* bilan yarataman.') ?>
        <?= admin_lang_input('subtitle', $loc('subtitle'), 'Sarlavha ostidagi matn', true) ?>
        <div class="row2">
            <?= admin_lang_input('experience', $loc('experience'), 'Tajriba (qisqa)', false, '1,5+ yil AI tajribasi') ?>
            <?= admin_lang_input('location', $loc('location'), 'Joylashuv', false, 'Toshkent, O‘zbekiston') ?>
        </div>
        <?= admin_lang_input('experience_note', $loc('experience_note'), 'Tajriba (izoh)') ?>
        <?= admin_lang_input('bio', $loc('bio'), 'Biografiya — xatboshilar orasida bo‘sh qator', true) ?>
    </form>

    <?= admin_content_form_open('jobs', 'Tajriba', 'Kompaniya nomi bo‘sh qolsa — blok saqlanmaydi. “Vazifalar” maydonida har bir qator alohida band bo‘ladi.') ?>
        <?php for ($i = 0; $i < min(ADMIN_MAX_JOBS, count($jobs) + 1); $i++): $job = (array) ($jobs[$i] ?? []); ?>
            <fieldset class="card" style="display:grid;gap:10px">
                <div class="row2">
                    <label class="field"><span class="field__label">Kompaniya <?= $i + 1 ?></span>
                        <input class="input" type="text" name="jobs[<?= $i ?>][company]" maxlength="80" value="<?= e((string) ($job['company'] ?? '')) ?>" placeholder="Kompaniya nomi"></label>
                    <?php if ($job !== []): ?>
                        <label class="check check--sm" style="align-self:end"><input type="checkbox" name="jobs[<?= $i ?>][remove]" value="1"><span>O‘chirish</span></label>
                    <?php endif; ?>
                </div>
                <div class="row2">
                    <?= admin_lang_input('jobs[' . $i . '][role]', (array) ($job['role'] ?? []), 'Lavozim / yo‘nalish') ?>
                    <?= admin_lang_input('jobs[' . $i . '][period]', (array) ($job['period'] ?? []), 'Davr', false, 'Hozirda') ?>
                </div>
                <?= admin_lang_input('jobs[' . $i . '][summary]', (array) ($job['summary'] ?? []), 'Qisqa tavsif') ?>
                <?= admin_lang_input('jobs[' . $i . '][points]', (array) ($job['points'] ?? []), 'Vazifalar (har qatorda bittadan)', true) ?>
            </fieldset>
        <?php endfor; ?>
    </form>

    <?= admin_content_form_open('activities', 'Faoliyat yo‘nalishlari', 'Sarlavha bo‘sh qolsa — blok saqlanmaydi.') ?>
        <?php for ($i = 0; $i < min(ADMIN_MAX_ACTIVITIES, count($activities) + 1); $i++): $item = (array) ($activities[$i] ?? []); ?>
            <fieldset class="card" style="display:grid;gap:10px">
                <div class="row2">
                    <?= admin_icon_select('activities[' . $i . '][icon]', (string) ($item['icon'] ?? 'sparkles')) ?>
                    <?php if ($item !== []): ?>
                        <label class="check check--sm" style="align-self:end"><input type="checkbox" name="activities[<?= $i ?>][remove]" value="1"><span>O‘chirish</span></label>
                    <?php endif; ?>
                </div>
                <?= admin_lang_input('activities[' . $i . '][title]', (array) ($item['title'] ?? []), 'Sarlavha') ?>
                <?= admin_lang_input('activities[' . $i . '][text]', (array) ($item['text'] ?? []), 'Matn') ?>
            </fieldset>
        <?php endfor; ?>
    </form>

    <?= admin_content_form_open('skills', 'Texnik ko‘nikmalar', 'Har qatorda bitta element.') ?>
        <label class="field"><span class="field__label">Kompetensiyalar</span>
            <textarea class="input" name="competencies" rows="8"><?= e(implode("\n", content_competencies())) ?></textarea></label>
        <div class="row2">
            <label class="field"><span class="field__label">AI platformalar</span>
                <textarea class="input" name="platforms" rows="6"><?= e(implode("\n", content_platforms())) ?></textarea></label>
            <label class="field"><span class="field__label">Texnik yo‘nalishlar</span>
                <textarea class="input" name="directions" rows="6"><?= e(implode("\n", content_directions())) ?></textarea></label>
        </div>
    </form>

    <?= admin_content_form_open('services', 'Xizmatlar', 'Buyurtma formasidagi “Xizmat turi” ro‘yxati ham shu yerdan olinadi. ID — havola uchun qisqa nom (masalan ai-agents); eski buyurtmalar bilan bog‘liqlik uchun o‘zgartirmang.') ?>
        <?php for ($i = 0; $i < min(ADMIN_MAX_SERVICES, count($services) + 1); $i++): $item = (array) ($services[$i] ?? []); ?>
            <fieldset class="card" style="display:grid;gap:10px">
                <div class="row2">
                    <label class="field"><span class="field__label">ID</span>
                        <input class="input" type="text" name="services[<?= $i ?>][id]" maxlength="40" value="<?= e((string) ($item['id'] ?? '')) ?>" placeholder="avtomatik"></label>
                    <?= admin_icon_select('services[' . $i . '][icon]', (string) ($item['icon'] ?? 'sparkles')) ?>
                </div>
                <label class="field"><span class="field__label">Rasm <em>img/ papkasidagi tayyor rasmlar</em></span>
                    <select class="input" name="services[<?= $i ?>][image]">
                        <option value="">— avtomatik (svc-ID) —</option>
                        <?php foreach (img_library('svc-') as $imgKey): ?>
                            <option value="<?= e($imgKey) ?>" <?= (string) ($item['image'] ?? '') === $imgKey ? 'selected' : '' ?>><?= e($imgKey) ?></option>
                        <?php endforeach; ?>
                    </select></label>
                <?= admin_lang_input('services[' . $i . '][title]', (array) ($item['title'] ?? []), 'Nomi' . ($item === [] ? ' (yangi xizmat)' : '')) ?>
                <?= admin_lang_input('services[' . $i . '][text]', (array) ($item['text'] ?? []), 'Tavsif') ?>
                <?php if ($item !== []): ?>
                    <label class="check check--sm"><input type="checkbox" name="services[<?= $i ?>][remove]" value="1"><span>Xizmatni o‘chirish</span></label>
                <?php endif; ?>
            </fieldset>
        <?php endfor; ?>
    </form>

    <?= admin_content_form_open('hero', 'Bosh sahifa fon videolari', 'Videolar ketma-ket va ovozsiz ijro etiladi. O‘z videolaringizni tanlasangiz, har qatorda bittadan HTTPS MP4 havolasini kiriting.') ?>
        <label class="field"><span class="field__label">Ijro rejimi</span>
            <select class="input" name="hero_mode">
                <?php foreach (['bundle' => 'Paketdagi videolar', 'custom' => 'O‘z videolarim', 'off' => 'Faqat muqova rasmi'] as $mode => $label): ?>
                    <option value="<?= e($mode) ?>" <?= content_hero_mode() === $mode ? 'selected' : '' ?>><?= e($label) ?></option>
                <?php endforeach; ?>
            </select>
        </label>
        <label class="field"><span class="field__label">Video havolalari</span>
            <textarea class="input" name="videos" rows="5" spellcheck="false"><?= e(implode("\n", content_hero_videos(true))) ?></textarea></label>
    </form>

    <?= admin_content_form_open('faq', 'Ko‘p beriladigan savollar', 'Bosh sahifada ko‘rinadi. Savol bo‘sh qolsa — saqlanmaydi.') ?>
        <?php for ($i = 0; $i < min(ADMIN_MAX_FAQ, count($faq) + 1); $i++): $item = (array) ($faq[$i] ?? []); ?>
            <fieldset class="card" style="display:grid;gap:10px">
                <?= admin_lang_input('faq[' . $i . '][q]', (array) ($item['q'] ?? []), 'Savol' . ($item === [] ? ' (yangi)' : '')) ?>
                <?= admin_lang_input('faq[' . $i . '][a]', (array) ($item['a'] ?? []), 'Javob', true) ?>
                <?php if ($item !== []): ?>
                    <label class="check check--sm"><input type="checkbox" name="faq[<?= $i ?>][remove]" value="1"><span>O‘chirish</span></label>
                <?php endif; ?>
            </fieldset>
        <?php endfor; ?>
    </form>

    <?= admin_content_form_open('links', 'Havolalar', 'Bo‘sh qolgan havola ilovada ko‘rsatilmaydi. Bot tugmalari ham shu qiymatlardan foydalanadi.') ?>
        <div class="row2">
            <label class="field"><span class="field__label">Telegram kanal</span>
                <input class="input" type="url" name="channel" value="<?= e($links['channel']) ?>" placeholder="https://t.me/AKBARTECHuz"></label>
            <label class="field"><span class="field__label">Shaxsiy Telegram (username)</span>
                <input class="input" type="text" name="support" value="<?= e($links['support']) ?>" placeholder="bxdrvc"></label>
        </div>
        <div class="row2">
            <label class="field"><span class="field__label">Telefon <em>ixtiyoriy</em></span>
                <input class="input" type="tel" name="phone" value="<?= e($links['phone']) ?>" placeholder="+998 ..."></label>
            <label class="field"><span class="field__label">YouTube <em>ixtiyoriy</em></span>
                <input class="input" type="url" name="youtube" value="<?= e($links['youtube']) ?>" placeholder="https://youtube.com/@..."></label>
        </div>
    </form>
</div>
<?php
}

/* ==================================================================
   4. BUYURTMALAR
   ================================================================== */

function render_orders(): void
{
    $all = orders_all();
    $statuses = order_statuses();
    $filter = (string) ($_GET['status'] ?? '');
    if ($filter !== '' && !array_key_exists($filter, $statuses)) { $filter = ''; }
    $orders = $filter === '' ? $all : array_values(array_filter($all, static fn (array $o): bool => (string) ($o['status'] ?? 'new') === $filter));

    $counts = ['' => count($all)];
    foreach (array_keys($statuses) as $key) { $counts[$key] = 0; }
    foreach ($all as $o) { $s = (string) ($o['status'] ?? 'new'); if (isset($counts[$s])) { $counts[$s]++; } }
    ?>
<div class="pipeline reveal">
    <?php foreach ($statuses as $key => $meta): ?>
        <a class="stage stage--<?= e($meta['tone']) ?><?= $filter === $key ? ' is-active' : '' ?>" href="?p=orders&status=<?= e($key) ?>">
            <span><?= e($meta['label']) ?></span>
            <b><?= $counts[$key] ?></b>
            <i style="--w: <?= $counts[''] > 0 ? round($counts[$key] / $counts[''] * 100) : 0 ?>%"></i>
        </a>
    <?php endforeach; ?>
</div>

<div class="toolbar reveal">
    <div class="segs">
        <a class="seg<?= $filter === '' ? ' is-active' : '' ?>" href="?p=orders">Barchasi <b><?= $counts[''] ?></b></a>
        <?php foreach ($statuses as $key => $meta): ?>
            <a class="seg<?= $filter === $key ? ' is-active' : '' ?>" href="?p=orders&status=<?= e($key) ?>"><?= e($meta['label']) ?> <b><?= $counts[$key] ?></b></a>
        <?php endforeach; ?>
    </div>
</div>

<?php if ($orders === []): ?>
    <div class="card empty reveal"><?= icon('inbox', 24) ?><p><?= $filter === '' ? 'Hozircha buyurtma tushmagan.' : 'Bu holatda buyurtma yo‘q.' ?></p></div>
<?php else: ?>
    <div class="grid grid--orders">
        <?php foreach ($orders as $i => $order):
            $status = (string) ($order['status'] ?? 'new');
            $tone = $statuses[$status]['tone'] ?? 'blue'; ?>
            <article class="card order order--<?= e($tone) ?> reveal" style="--i: <?= $i ?>">
                <header class="order__head">
                    <span class="ava ava--letter" style="width:40px;height:40px;font-size:16px"><?= e(mb_strtoupper(mb_substr((string) $order['name'], 0, 1))) ?></span>
                    <div class="order__who">
                        <b><?= e((string) $order['name']) ?></b>
                        <small><?= e(time_ago((string) ($order['created_at'] ?? ''))) ?><?php if (!empty($order['username'])): ?> · @<?= e((string) $order['username']) ?><?php endif; ?></small>
                    </div>
                    <span class="pill pill--<?= e($tone) ?>"><?= e($statuses[$status]['label'] ?? $status) ?></span>
                </header>

                <?php if (!empty($order['service_name'])): ?>
                    <div class="order__project"><?= icon('briefcase', 14) ?> <?= e((string) $order['service_name']) ?></div>
                <?php endif; ?>
                <?php if (!empty($order['project_name'])): ?>
                    <div class="order__project"><?= icon('layers', 14) ?> <?= e((string) $order['project_name']) ?></div>
                <?php endif; ?>

                <p class="order__text"><?= nl2br(e((string) $order['description'])) ?></p>

                <div class="order__meta">
                    <?php if (!empty($order['budget'])): ?><span><?= icon('wallet', 14) ?> <?= e((string) $order['budget']) ?></span><?php endif; ?>
                    <?php if (!empty($order['deadline'])): ?><span><?= icon('clock', 14) ?> <?= e((string) $order['deadline']) ?></span><?php endif; ?>
                    <?php if (!empty($order['phone'])): ?><a href="tel:<?= e(preg_replace('/[^0-9+]/', '', (string) $order['phone'])) ?>"><?= icon('phone', 14) ?> <?= e((string) $order['phone']) ?></a>
                    <?php elseif (!empty($order['contact'])): ?><span><?= icon('at-sign', 14) ?> <?= e((string) $order['contact']) ?></span><?php endif; ?>
                </div>

                <footer class="order__acts">
                    <form method="post" class="order__status">
                        <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
                        <input type="hidden" name="action" value="order_status">
                        <input type="hidden" name="id" value="<?= e((string) $order['id']) ?>">
                        <select class="input input--sm" name="status" onchange="this.form.submit()" aria-label="Holat">
                            <?php foreach ($statuses as $key => $meta): ?>
                                <option value="<?= e($key) ?>" <?= $key === $status ? 'selected' : '' ?>><?= e($meta['label']) ?></option>
                            <?php endforeach; ?>
                        </select>
                    </form>
                    <?php if (!empty($order['username'])): ?>
                        <a class="btn btn--primary btn--sm" href="https://t.me/<?= e((string) $order['username']) ?>" target="_blank" rel="noopener"><?= icon('send', 14) ?> Yozish</a>
                    <?php endif; ?>
                    <form method="post" data-confirm="Buyurtma o‘chirilsinmi?">
                        <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
                        <input type="hidden" name="action" value="order_delete">
                        <input type="hidden" name="id" value="<?= e((string) $order['id']) ?>">
                        <button class="iconbtn iconbtn--danger" type="submit" title="O‘chirish"><?= icon('trash-2', 16) ?></button>
                    </form>
                </footer>
            </article>
        <?php endforeach; ?>
    </div>
<?php endif;
}

/* ==================================================================
   5. XABARLAR
   ================================================================== */

function render_messages(): void
{
    $messages = messages_all();
    $userCount = count(bot_recipients());
    $active = broadcast_active();
    $recent = array_slice(store_read('broadcasts'), 0, 3);
    ?>
<?php if ($active !== null): $pub = broadcast_public($active); ?>
<section class="card bcast reveal" id="bcast" data-id="<?= e($pub['id']) ?>" data-csrf="<?= e(csrf_token()) ?>">
    <header class="card__head">
        <div>
            <h2 class="card__title">Telegram tarqatma ketmoqda…</h2>
            <span class="card__note">«<?= e($pub['title']) ?>» — sahifani yopmang. Yopsangiz, qaytib kelganda davom etadi.</span>
        </div>
        <form method="post" data-confirm="Tarqatma to‘xtatilsinmi?" data-confirm-ok="To‘xtatish">
            <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
            <input type="hidden" name="action" value="broadcast_stop">
            <input type="hidden" name="id" value="<?= e($pub['id']) ?>">
            <button class="btn btn--ghost btn--sm" type="submit"><?= icon('x', 14) ?> To‘xtatish</button>
        </form>
    </header>
    <div class="meter meter--lg"><i style="--w: <?= $pub['percent'] ?>%" data-bcast-bar></i></div>
    <div class="bcast__stats">
        <span><b data-bcast="pos"><?= $pub['pos'] ?></b> / <?= $pub['total'] ?></span>
        <span class="ok">✓ <b data-bcast="sent"><?= $pub['sent'] ?></b> yetkazildi</span>
        <span class="muted">⛔ <b data-bcast="blocked"><?= $pub['blocked'] ?></b> bloklagan</span>
        <span class="muted">⚠ <b data-bcast="failed"><?= $pub['failed'] ?></b> xato</span>
    </div>
    <p class="field__hint" data-bcast="status">Yuborilmoqda…</p>
</section>
<?php endif; ?>

<div class="grid grid--compose">
    <section class="card reveal">
        <header class="card__head">
            <div><h2 class="card__title">Yangi xabar</h2><span class="card__note"><?= $userCount ?> ta foydalanuvchiga yetib boradi</span></div>
        </header>
        <form method="post" enctype="multipart/form-data" class="form">
            <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
            <input type="hidden" name="action" value="message_send">
            <label class="field"><span class="field__label">Sarlavha <i>*</i></span>
                <input class="input" type="text" name="title" required maxlength="120" placeholder="Masalan: Yangi loyiha chiqdi" data-live="title"></label>
            <label class="field"><span class="field__label">Matn <i>*</i></span>
                <textarea class="input" name="text" rows="6" required maxlength="2000" placeholder="Xabar matni…" data-live="text"></textarea></label>
            <div class="row2">
                <label class="field"><span class="field__label">Havola</span>
                    <input class="input" type="url" name="link" placeholder="https://…"></label>
                <div class="field"><span class="field__label">Rasm</span>
                    <label class="drop drop--row"><?= icon('image', 18) ?><span>Rasm tanlash</span><input type="file" name="image" accept="image/*" data-live="image"></label>
                    <span class="field__hint"></span>
                </div>
            </div>
            <label class="toggle">
                <input type="checkbox" name="send_telegram" value="1" checked>
                <span class="toggle__ui"></span>
                <span><b>Telegram orqali ham yuborish</b><small>Bot <?= $userCount ?> kishiga bosqichma-bosqich yuboradi — to‘xtab qolmaydi, bloklaganlar avtomatik chiqariladi</small></span>
            </label>
            <button class="btn btn--primary btn--wide btn--lg" type="submit"><?= icon('send', 16) ?> Yuborish</button>
        </form>
    </section>

    <aside class="card reveal">
        <header class="card__head"><div><h2 class="card__title">Oldindan ko‘rish</h2><span class="card__note">Telegram’da shunday ko‘rinadi</span></div></header>
        <div class="tgprev">
            <div class="tgprev__bubble">
                <div class="tgprev__img" data-live-img hidden></div>
                <b data-live-out="title">Sarlavha</b>
                <p data-live-out="text">Xabar matni shu yerda ko‘rinadi…</p>
                <span class="tgprev__time"><?= e(date('H:i')) ?></span>
            </div>
            <div class="tgprev__btn"><?= icon('external-link', 13) ?> Ilovani ochish</div>
        </div>
    </aside>
</div>

<?php if ($recent !== [] && $active === null): ?>
<section class="card reveal">
    <header class="card__head"><div><h2 class="card__title">So‘nggi tarqatmalar</h2><span class="card__note">Telegram orqali yetkazish natijasi</span></div></header>
    <ul class="mini">
        <?php foreach ($recent as $job): $pub = broadcast_public($job); ?>
            <li>
                <span class="mini__icon"><?= icon('send', 16) ?></span>
                <span class="mini__body"><b><?= e($pub['title']) ?></b><small><?= e(time_ago((string) ($job['created_at'] ?? ''))) ?> · ✓ <?= $pub['sent'] ?> · ⛔ <?= $pub['blocked'] ?> · ⚠ <?= $pub['failed'] ?><?= !empty($job['stopped']) ? ' · to‘xtatilgan' : '' ?></small></span>
                <span class="pill pill--<?= $pub['done'] ? 'green' : 'amber' ?>"><?= $pub['sent'] ?>/<?= $pub['total'] ?></span>
            </li>
        <?php endforeach; ?>
    </ul>
</section>
<?php endif; ?>

<section class="card reveal">
    <header class="card__head"><div><h2 class="card__title">Yuborilgan xabarlar <span class="count"><?= count($messages) ?></span></h2></div></header>
    <?php if ($messages === []): ?>
        <div class="empty"><?= icon('inbox', 22) ?><p>Hali xabar yuborilmagan.</p></div>
    <?php else: ?>
        <ul class="mlist">
            <?php foreach ($messages as $message): ?>
                <li>
                    <?php if (!empty($message['image'])): ?>
                        <img class="mlist__thumb" src="<?= e(upload_url((string) $message['image'])) ?>" alt="" loading="lazy">
                    <?php else: ?>
                        <span class="mlist__icon"><?= icon('bell', 17) ?></span>
                    <?php endif; ?>
                    <div class="mlist__body">
                        <b><?= e((string) ($message['title'] ?? '')) ?></b>
                        <p><?= e(mb_substr((string) ($message['text'] ?? ''), 0, 180)) ?></p>
                        <small><?= icon('clock', 12) ?> <?= e(date('d.m.Y H:i', strtotime((string) ($message['created_at'] ?? '')) ?: time())) ?></small>
                    </div>
                    <form method="post" data-confirm="Xabar o‘chirilsinmi?">
                        <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
                        <input type="hidden" name="action" value="message_delete">
                        <input type="hidden" name="id" value="<?= e((string) ($message['id'] ?? '')) ?>">
                        <button class="iconbtn iconbtn--danger" type="submit" title="O‘chirish"><?= icon('trash-2', 16) ?></button>
                    </form>
                </li>
            <?php endforeach; ?>
        </ul>
    <?php endif; ?>
</section>
<?php
}

/* ==================================================================
   6. VIDEO DARSLIKLAR
   ================================================================== */

function render_videos(): void
{
    $videos = course_normalize();
    $editing = null;
    if (isset($_GET['edit'])) {
        foreach ($videos as $item) {
            if ((string) ($item['id'] ?? '') === (string) $_GET['edit']) { $editing = $item; break; }
        }
    }
    if ($editing !== null || isset($_GET['new'])) {
        echo video_form($editing);
        return;
    }
    ?>
<div class="toolbar reveal">
    <p class="muted"><?= count($videos) ?> ta darslik · o‘quvchilar ularni shu tartibda, birma-bir ochadi</p>
    <a class="btn btn--primary" href="?p=videos&new=1"><?= icon('plus', 16) ?> Darslik qo‘shish</a>
</div>

<?php if ($videos === []): ?>
    <div class="card empty reveal"><?= icon('video', 24) ?><p>Hozircha darslik yo‘q. “Darslik qo‘shish” tugmasini bosing.</p></div>
<?php else: ?>
    <div class="grid grid--cards">
        <?php foreach ($videos as $i => $video): $cover = video_cover_url($video); ?>
            <article class="card pcard reveal" style="--i: <?= $i ?>">
                <div class="pcard__media pcard__media--video<?= $cover !== '' ? ' has-img' : '' ?>">
                    <?php if ($cover !== ''): ?><img src="<?= e($cover) ?>" alt="" loading="lazy"><?php endif; ?>
                    <span class="pcard__play"><?= icon('play', 16) ?></span>
                    <span class="pcard__flag"><?= str_pad((string) ($i + 1), 2, '0', STR_PAD_LEFT) ?>-dars</span>
                </div>
                <div class="pcard__body">
                    <h3><?= e(tr($video['title'] ?? '')) ?></h3>
                    <p><?= e(mb_substr(tr($video['description'] ?? ''), 0, 90)) ?></p>
                    <div class="vmeta">
                        <?php if (in_array((string) ($video['level'] ?? ''), COURSE_LEVELS, true)): ?><span><?= e(['beginner' => 'Boshlang‘ich', 'intermediate' => 'O‘rta', 'advanced' => 'Yuqori'][$video['level']]) ?></span><?php endif; ?>
                        <?php if ((string) ($video['topic'] ?? '') !== ''): ?><span><?= e((string) $video['topic']) ?></span><?php endif; ?>
                        <span><?= tr($video['task'] ?? '') !== '' ? '✓ Vazifa matni bor' : 'Vazifa: standart matn' ?></span>
                    </div>
                </div>
                <div class="pcard__acts">
                    <span class="vmove">
                        <?php foreach (['up' => 'chevron-up', 'down' => 'chevron-down'] as $dirKey => $dirIcon): ?>
                            <form method="post">
                                <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
                                <input type="hidden" name="action" value="video_move">
                                <input type="hidden" name="id" value="<?= e((string) $video['id']) ?>">
                                <input type="hidden" name="dir" value="<?= $dirKey ?>">
                                <button class="iconbtn" type="submit" title="<?= $dirKey === 'up' ? 'Yuqoriga' : 'Pastga' ?>" <?= ($dirKey === 'up' && $i === 0) || ($dirKey === 'down' && $i === count($videos) - 1) ? 'disabled' : '' ?>><?= icon($dirIcon, 16) ?></button>
                            </form>
                        <?php endforeach; ?>
                    </span>
                    <a class="btn btn--ghost btn--sm" href="?p=videos&edit=<?= e(urlencode((string) $video['id'])) ?>"><?= icon('pencil', 14) ?> Tahrirlash</a>
                    <form method="post" data-confirm="Bu darslik o‘chirilsinmi?">
                        <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
                        <input type="hidden" name="action" value="video_delete">
                        <input type="hidden" name="id" value="<?= e((string) $video['id']) ?>">
                        <button class="iconbtn iconbtn--danger" type="submit" title="O‘chirish"><?= icon('trash-2', 16) ?></button>
                    </form>
                </div>
            </article>
        <?php endforeach; ?>
    </div>
<?php endif;
}

function video_form(?array $video): string
{
    $v = $video ?? [];
    $value = static function (string $group, string $locale) use ($v): string {
        $x = $v[$group] ?? [];
        return is_array($x) ? (string) ($x[$locale] ?? '') : (string) $x;
    };
    ob_start();
    ?>
<form class="editor" method="post" enctype="multipart/form-data">
    <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
    <input type="hidden" name="action" value="video_save">
    <input type="hidden" name="id" value="<?= e((string) ($v['id'] ?? '')) ?>">

    <div class="toolbar">
        <a class="btn btn--ghost btn--sm" href="?p=videos"><?= icon('arrow-left', 15) ?> Orqaga</a>
        <h2 class="serif"><?= $video === null ? 'Yangi darslik' : 'Darslikni tahrirlash' ?></h2>
        <button class="btn btn--primary" type="submit"><?= icon('check', 16) ?> Saqlash</button>
    </div>

    <div class="editor__grid">
        <div class="editor__main">
            <section class="card">
                <label class="field">
                    <span class="field__label">YouTube havolasi <i>*</i></span>
                    <span class="field__box"><?= icon('video', 16) ?>
                        <input class="input" type="url" name="youtube" required value="<?= e((string) ($v['youtube'] ?? '')) ?>" placeholder="https://www.youtube.com/watch?v=…"></span>
                    <span class="field__hint">watch, youtu.be yoki shorts — farqi yo‘q.</span>
                </label>
                <?= lang_fields('title', 'Darslik nomi', '1-dars — Kirish', $value) ?>
                <?= lang_fields('description', 'Tavsif', 'Video haqida qisqacha…', $value, true) ?>
            </section>
            <section class="card">
                <h3 class="card__title">Vazifa (video tugagach chiqadi)</h3>
                <?= lang_fields('task', 'Vazifa matni', 'Masalan: Darsdagi promptni o‘z loyihangizga moslab yozing va natijani video qilib yuboring.', $value, true) ?>
                <span class="field__hint">Bo‘sh qoldirsangiz — standart matn: “Darsda o‘rganganingiz asosida loyiha yarating va natijani yuboring”.</span>
            </section>
        </div>
        <aside class="editor__side">
            <section class="card">
                <h3 class="card__title">Daraja va mavzu</h3>
                <label class="field">
                    <span class="field__label">Daraja</span>
                    <select class="input" name="level">
                        <option value="">— Ko‘rsatilmagan —</option>
                        <?php foreach (['beginner' => 'Boshlang‘ich', 'intermediate' => 'O‘rta', 'advanced' => 'Yuqori'] as $lk => $ll): ?>
                            <option value="<?= $lk ?>" <?= ($v['level'] ?? '') === $lk ? 'selected' : '' ?>><?= e($ll) ?></option>
                        <?php endforeach; ?>
                    </select>
                </label>
                <label class="field">
                    <span class="field__label">Mavzu</span>
                    <input class="input" type="text" name="topic" maxlength="40" value="<?= e((string) ($v['topic'] ?? '')) ?>" placeholder="Masalan: ChatGPT, Cursor, Telegram bot">
                    <span class="field__hint">Darsliklar bo‘limidagi filtrda ko‘rinadi.</span>
                </label>
            </section>
            <section class="card">
                <h3 class="card__title">Muqova</h3>
                <label class="drop">
                    <?php if (!empty($v['cover'])): ?><img src="<?= e(upload_url((string) $v['cover'])) ?>" alt=""><?php else: ?><?= icon('image', 22) ?><span>Yuklamasangiz — YouTube eskizi ishlatiladi</span><?php endif; ?>
                    <input type="file" name="cover" accept="image/*">
                </label>
                <?php if (!empty($v['cover'])): ?>
                    <label class="check check--sm"><input type="checkbox" name="cover_remove" value="1"><span>Muqovani o‘chirish</span></label>
                <?php endif; ?>
                <span class="field__hint"></span>
            </section>
        </aside>
    </div>
</form>
    <?php
    return (string) ob_get_clean();
}

/* ==================================================================
   VAZIFALAR — o'quvchilar yuborgan ishlar (qabul / qaytarish)
   ================================================================== */

/** Vazifa faylini beradi (Range qo'llab-quvvatlanadi — videoni aylantirish mumkin). */
function admin_serve_task_file(string $id, bool $download): void
{
    session_write_close();
    $task = task_find($id);
    $dir = task_files_dir();
    $file = (string) ($task['file'] ?? '');
    $path = $dir !== null ? $dir . '/' . $file : '';
    if ($task === null || $dir === null || !preg_match('/^[a-f0-9]{32}\.bin$/', $file) || !is_file($path)) {
        http_response_code(404);
        header('Content-Type: text/plain; charset=UTF-8');
        echo 'Fayl topilmadi';
        return;
    }
    $mime = (string) ($task['file_mime'] ?? 'application/octet-stream');
    $size = (int) filesize($path);
    $inline = !$download && preg_match('~^(image/(jpeg|png|gif|webp)|video/(mp4|webm|quicktime)|audio/(mpeg|mp4|ogg|wav|webm|x-wav)|application/pdf)$~', $mime);
    $name = (string) ($task['file_name'] ?? 'fayl');
    $ascii = preg_replace('/[^A-Za-z0-9._-]+/', '_', $name) ?: 'fayl';

    header('Content-Type: ' . ($inline ? $mime : 'application/octet-stream'));
    header('X-Content-Type-Options: nosniff');
    if ($mime !== 'application/pdf') {
        header("Content-Security-Policy: default-src 'none'; img-src 'self'; media-src 'self'; style-src 'unsafe-inline'; sandbox");
    }
    header('Content-Disposition: ' . ($inline ? 'inline' : 'attachment') . '; filename="' . $ascii . '"; filename*=UTF-8\'\'' . rawurlencode($name));
    header('Accept-Ranges: bytes');
    header('Cache-Control: private, max-age=3600');

    $start = 0;
    $end = $size - 1;
    if (isset($_SERVER['HTTP_RANGE']) && preg_match('/bytes=(\d*)-(\d*)/', (string) $_SERVER['HTTP_RANGE'], $m)) {
        if ($m[1] === '' && $m[2] !== '') {
            $start = max(0, $size - (int) $m[2]);
        } else {
            $start = (int) $m[1];
            if ($m[2] !== '') { $end = min($end, (int) $m[2]); }
        }
        if ($start > $end || $start >= $size) {
            http_response_code(416);
            header('Content-Range: bytes */' . $size);
            return;
        }
        http_response_code(206);
        header('Content-Range: bytes ' . $start . '-' . $end . '/' . $size);
    }
    header('Content-Length: ' . ($end - $start + 1));
    while (ob_get_level() > 0) { ob_end_clean(); }
    @set_time_limit(0);
    $fp = fopen($path, 'rb');
    if ($fp === false) { return; }
    fseek($fp, $start);
    $left = $end - $start + 1;
    while ($left > 0 && !feof($fp)) {
        $chunk = fread($fp, (int) min(262144, $left));
        if ($chunk === false || $chunk === '') { break; }
        echo $chunk;
        $left -= strlen($chunk);
        flush();
    }
    fclose($fp);
}

function render_tasks(): void
{
    $all = store_read('tasks');
    $labels = [
        'pending'  => ['Kutilmoqda', 'amber'],
        'accepted' => ['Qabul qilingan', 'green'],
        'rejected' => ['Qaytarilgan', 'red'],
        'all'      => ['Hammasi', 'blue'],
    ];
    $filter = (string) ($_GET['status'] ?? 'pending');
    if (!isset($labels[$filter])) { $filter = 'pending'; }
    $counts = ['pending' => 0, 'accepted' => 0, 'rejected' => 0, 'all' => count($all)];
    foreach ($all as $t) {
        $st = (string) ($t['status'] ?? '');
        if (isset($counts[$st])) { $counts[$st]++; }
    }
    $list = $filter === 'all' ? $all : array_values(array_filter($all, static fn (array $t): bool => ($t['status'] ?? '') === $filter));
    $total = count(course_lessons());
    ?>
<div class="toolbar reveal">
    <div class="segs">
        <?php foreach ($labels as $key => $meta): ?>
            <a class="seg<?= $filter === $key ? ' is-active' : '' ?>" href="?p=tasks&status=<?= e($key) ?>"><?= e($meta[0]) ?> <b><?= $counts[$key] ?></b></a>
        <?php endforeach; ?>
    </div>
    <p class="muted"><?= $total ?> ta dars · ketma-ket ochiladi</p>
</div>

<?php if ($list === []): ?>
    <div class="card empty reveal"><?= icon('list-checks', 24) ?><p><?= $filter === 'pending' ? 'Tekshirilishi kerak bo‘lgan vazifa yo‘q. Yangi vazifa kelsa — botga xabar keladi.' : 'Bu bo‘limda vazifa yo‘q.' ?></p></div>
<?php else: ?>
    <div class="grid grid--orders">
        <?php foreach ($list as $i => $task):
            $status = (string) ($task['status'] ?? 'pending');
            $tone = $labels[$status][1] ?? 'blue';
            $mime = (string) ($task['file_mime'] ?? '');
            $fileUrl = '?file=' . rawurlencode((string) $task['id']); ?>
            <article class="card order order--<?= e($tone) ?> task reveal" style="--i: <?= $i ?>">
                <header class="order__head">
                    <span class="ava ava--letter" style="width:40px;height:40px;font-size:16px"><?= e(mb_strtoupper(mb_substr((string) $task['name'], 0, 1)) ?: 'T') ?></span>
                    <div class="order__who">
                        <b><?= e((string) $task['name']) ?></b>
                        <small><?= e(time_ago((string) ($task['created_at'] ?? ''))) ?><?php if (!empty($task['username'])): ?> · @<?= e((string) $task['username']) ?><?php endif; ?> · ID <?= (int) $task['uid'] ?></small>
                    </div>
                    <span class="pill pill--<?= e($tone) ?>"><?= e($labels[$status][0] ?? $status) ?></span>
                </header>

                <div class="order__project"><?= icon('graduation-cap', 14) ?> <?= (int) $task['lesson'] ?>-dars — <?= e((string) $task['title']) ?></div>

                <?php if (($task['kind'] ?? '') === 'link'): ?>
                    <a class="tlink" href="<?= e((string) $task['link']) ?>" target="_blank" rel="noopener noreferrer"><?= icon('link', 15) ?><span><?= e((string) $task['link']) ?></span><?= icon('external-link', 13) ?></a>
                <?php else: ?>
                    <?php if (str_starts_with($mime, 'image/') && $mime !== 'image/svg+xml' && $mime !== 'image/vnd.adobe.photoshop'): ?>
                        <a class="tmedia" href="<?= e($fileUrl) ?>" target="_blank" rel="noopener"><img src="<?= e($fileUrl) ?>" alt="" loading="lazy"></a>
                    <?php elseif (preg_match('~^video/(mp4|webm|quicktime)$~', $mime)): ?>
                        <video class="tmedia" src="<?= e($fileUrl) ?>" controls preload="metadata" playsinline></video>
                    <?php elseif (str_starts_with($mime, 'audio/')): ?>
                        <audio class="tmedia tmedia--audio" src="<?= e($fileUrl) ?>" controls preload="none"></audio>
                    <?php endif; ?>
                    <div class="tfilebox">
                        <span class="tfilebox__icon"><?= icon(str_starts_with($mime, 'video/') ? 'video' : (str_starts_with($mime, 'image/') ? 'image' : 'file'), 18) ?></span>
                        <span class="tfilebox__meta"><b><?= e((string) $task['file_name']) ?></b><small><?= e(task_size_label((int) $task['file_size'])) ?> · <?= e($mime) ?></small></span>
                        <a class="btn btn--ghost btn--sm" href="<?= e($fileUrl) ?>&amp;dl=1"><?= icon('download', 14) ?> Yuklab olish</a>
                    </div>
                <?php endif; ?>

                <?php if ((string) ($task['comment'] ?? '') !== ''): ?>
                    <p class="order__text"><?= nl2br(e((string) $task['comment'])) ?></p>
                <?php endif; ?>
                <?php if ((string) ($task['note'] ?? '') !== ''): ?>
                    <p class="tnote"><b>Admin izohi:</b> <?= nl2br(e((string) $task['note'])) ?></p>
                <?php endif; ?>

                <footer class="order__acts">
                    <?php if ($status !== 'accepted'): ?>
                        <button type="button" class="btn btn--primary btn--sm" data-review="accept" data-id="<?= e((string) $task['id']) ?>"><?= icon('check', 14) ?> Qabul qilindi</button>
                    <?php endif; ?>
                    <?php if ($status === 'pending'): ?>
                        <button type="button" class="btn btn--ghost btn--sm" data-review="reject" data-id="<?= e((string) $task['id']) ?>"><?= icon('rotate-ccw', 14) ?> Qaytarish</button>
                    <?php endif; ?>
                    <?php if (!empty($task['username'])): ?>
                        <a class="iconbtn" href="https://t.me/<?= e((string) $task['username']) ?>" target="_blank" rel="noopener" title="Yozish"><?= icon('send', 15) ?></a>
                    <?php endif; ?>
                    <form method="post" data-confirm="Vazifa (va fayli) o‘chirilsinmi?">
                        <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
                        <input type="hidden" name="action" value="task_delete">
                        <input type="hidden" name="id" value="<?= e((string) $task['id']) ?>">
                        <button class="iconbtn iconbtn--danger" type="submit" title="O‘chirish"><?= icon('trash-2', 16) ?></button>
                    </form>
                </footer>
            </article>
        <?php endforeach; ?>
    </div>
<?php endif; ?>

<div class="modal" id="reject-modal" hidden>
    <div class="modal__scrim" data-close></div>
    <div class="modal__box" role="dialog" aria-modal="true">
        <span class="modal__icon"><?= icon('rotate-ccw', 22) ?></span>
        <h3 class="modal__title">Vazifani qaytarish</h3>
        <p class="modal__text">O‘quvchiga nima tuzatish kerakligini yozing — bot orqali yetkaziladi.</p>
        <textarea class="input input--area" id="reject-note" rows="4" maxlength="600" placeholder="Masalan: Loyihada tugmalar ishlamayapti, videoda natijani ko‘rsating…"></textarea>
        <div class="modal__acts">
            <button type="button" class="btn btn--ghost" data-close>Bekor qilish</button>
            <button type="button" class="btn btn--primary" id="reject-ok">Qaytarish</button>
        </div>
    </div>
</div>
<?php
}

/* ==================================================================
   SERTIFIKATLAR — kurs sertifikati va tashakkurnoma
   ================================================================== */

function render_certs(): void
{
    $certs = certs_all();
    $users = store_read('users');
    $leads = store_read('bot_leads');
    $progress = store_read('progress');
    $total = count(course_lessons());
    $people = [];
    foreach ($users as $key => $u) {
        $id = (int) ($u['id'] ?? $key);
        if ($id <= 0) { continue; }
        $full = trim((string) ($u['first_name'] ?? '') . ' ' . (string) ($u['last_name'] ?? ''));
        $people[$id] = ['name' => $full !== '' ? $full : ('ID ' . $id), 'username' => (string) ($u['username'] ?? '')];
    }
    foreach ($leads as $key => $l) {
        $id = (int) ($l['id'] ?? $key);
        if ($id <= 0 || isset($people[$id])) { continue; }
        $people[$id] = ['name' => trim((string) ($l['name'] ?? '')) ?: ('ID ' . $id), 'username' => (string) ($l['username'] ?? '')];
    }
    foreach ($people as $id => $p) {
        $people[$id]['done'] = count((array) ($progress[(string) $id]['done'] ?? []));
    }
    uasort($people, static fn (array $a, array $b): int => [$b['done'], $a['name']] <=> [$a['done'], $b['name']]);
    $preselect = (int) ($_GET['uid'] ?? 0);
    ?>
<div class="certgrid">
    <section class="card certform reveal">
        <h3 class="card__title"><?= icon('award', 17) ?> Hujjat berish</h3>
        <form id="cert-form" data-course="<?= e(course_title()) ?>" data-lessons="<?= $total ?>" data-next="<?= e(cert_next_number()) ?>" data-today="<?= e(date('Y-m-d')) ?>">
            <div class="segs certform__type">
                <label class="seg is-active"><input type="radio" name="type" value="appreciation" checked hidden>Tashakkurnoma</label>
                <label class="seg"><input type="radio" name="type" value="certificate" hidden>Sertifikat</label>
            </div>
            <label class="field">
                <span class="field__label">Kimga <i>*</i></span>
                <select class="input" name="uid" required>
                    <option value="">— O‘quvchini tanlang —</option>
                    <?php foreach ($people as $id => $p): ?>
                        <option value="<?= (int) $id ?>" data-name="<?= e($p['name']) ?>" <?= $preselect === (int) $id ? 'selected' : '' ?>><?= e($p['name']) ?><?= $p['username'] !== '' ? ' (@' . e($p['username']) . ')' : '' ?> — <?= (int) $p['done'] ?>/<?= $total ?> dars</option>
                    <?php endforeach; ?>
                </select>
            </label>
            <label class="field">
                <span class="field__label">Hujjatdagi ism <i>*</i></span>
                <input class="input" type="text" name="name" maxlength="60" required placeholder="Ism Familiya">
            </label>
            <label class="field" data-reason>
                <span class="field__label">Matn (nima uchun)</span>
                <textarea class="input input--area" name="reason" rows="3" maxlength="400">Darslarda faol ishtirok etgani, ijodiy loyihalari va a’lo natijalari uchun AKBARTECH jamoasi o‘z minnatdorchiligini bildiradi.</textarea>
            </label>
            <div class="certpreview"><canvas id="cert-canvas" width="2400" height="1697"></canvas></div>
            <button class="btn btn--primary btn--wide" type="submit"><?= icon('send', 16) ?> Berish va botga yuborish</button>
            <p class="field__hint">Rasm shu yerda chiziladi, o‘quvchiga bot orqali (rasm + asl fayl) yuboriladi va mini app’ga kirganda katta bo‘lib ko‘rinadi.</p>
        </form>

        <form method="post" class="certcourse">
            <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
            <input type="hidden" name="action" value="course_save">
            <label class="field">
                <span class="field__label">Kurs nomi (sertifikatda yoziladi)</span>
                <span class="certcourse__row">
                    <input class="input" type="text" name="course_title" maxlength="80" value="<?= e(course_title()) ?>">
                    <button class="btn btn--ghost" type="submit">Saqlash</button>
                </span>
            </label>
        </form>
    </section>

    <section class="certlist reveal">
        <div class="toolbar"><p class="muted"><?= count($certs) ?> ta hujjat berilgan</p></div>
        <?php if ($certs === []): ?>
            <div class="card empty"><?= icon('award', 24) ?><p>Hali hujjat berilmagan. O‘quvchi barcha darslarni tugatsa — sertifikat avtomatik beriladi.</p></div>
        <?php else: ?>
            <div class="grid grid--certs">
                <?php foreach ($certs as $cert):
                    $img = (string) ($cert['image'] ?? '');
                    $isThanks = ($cert['type'] ?? '') === 'appreciation'; ?>
                    <article class="card certitem">
                        <div class="certitem__img">
                            <?php if ($img !== ''): ?>
                                <a href="<?= e(upload_url($img)) ?>" target="_blank" rel="noopener"><img src="<?= e(upload_url($img)) ?>" alt="" loading="lazy"></a>
                            <?php else: ?>
                                <span class="certitem__none"><?= icon('image', 20) ?> Rasm yaratilmagan</span>
                            <?php endif; ?>
                        </div>
                        <div class="certitem__body">
                            <span class="pill pill--<?= $isThanks ? 'amber' : 'green' ?>"><?= $isThanks ? 'Tashakkurnoma' : 'Sertifikat' ?></span>
                            <b><?= e((string) $cert['name']) ?></b>
                            <small>№ <?= e((string) $cert['number']) ?> · <?= e(date('d.m.Y', (int) strtotime((string) ($cert['issued_at'] ?? 'now')))) ?></small>
                            <small><?= !empty($cert['sent']) ? '✓ Botga yuborildi' : '• Botga yuborilmagan' ?><?= !empty($cert['seen']) ? ' · ilovada ko‘rildi' : '' ?></small>
                        </div>
                        <div class="certitem__acts">
                            <button type="button" class="btn btn--ghost btn--sm" data-cert-regen="<?= e((string) json_encode(cert_public($cert), JSON_UNESCAPED_UNICODE)) ?>"><?= icon('refresh', 14) ?> <?= $img === '' ? 'Yaratish' : 'Qayta chizish' ?></button>
                            <?php if ($img !== ''): ?>
                                <button type="button" class="btn btn--ghost btn--sm" data-cert-resend="<?= e((string) $cert['id']) ?>"><?= icon('send', 14) ?> Qayta yuborish</button>
                            <?php endif; ?>
                            <form method="post" data-confirm="Hujjat o‘chirilsinmi?">
                                <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
                                <input type="hidden" name="action" value="cert_delete">
                                <input type="hidden" name="id" value="<?= e((string) $cert['id']) ?>">
                                <button class="iconbtn iconbtn--danger" type="submit" title="O‘chirish"><?= icon('trash-2', 16) ?></button>
                            </form>
                        </div>
                    </article>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
    </section>
</div>
<?php
}

/* ==================================================================
   7. SOZLAMALAR — tizim holati va parol
   ================================================================== */

function render_settings(): void
{
    $dir = store_dir() ?? __DIR__ . '/store';
    $dirExists = store_available();
    $writeTest = false;
    if ($dirExists) {
        $probe = $dir . '/.write_test_' . bin2hex(random_bytes(3));
        if (@file_put_contents($probe, 'ok') !== false) { $writeTest = true; @unlink($probe); }
    }
    $files = ['users' => 'Foydalanuvchilar', 'bot_leads' => 'Bot obunachilari', 'orders' => 'Buyurtmalar', 'messages' => 'Xabarlar', 'projects' => 'Loyihalar', 'videos' => 'Video darsliklar', 'tasks' => 'Vazifalar', 'certificates' => 'Sertifikatlar', 'progress' => 'Kurs progressi', 'ai_log' => 'AI savollar', 'stats' => 'Statistika'];
    $legacyJson = $dirExists ? fs_glob($dir . '/*.json') : [];
    $checks = [
        ['store/ papkasi mavjud va yoziladi', $dirExists && $writeTest],
        ['Ma’lumotlar brauzerdan yopiq (.php himoya)', $legacyJson === [] || $legacyJson === false],
        ['PHP ' . PHP_VERSION . ' (7.4+ kerak)', version_compare(PHP_VERSION, '7.4', '>=')],
        ['GD (rasm siqish)', extension_loaded('gd')],
        ['cURL (Telegram va AI API)', function_exists('curl_init')],
        ['HTTPS ulanish', is_https()],
        ['Admin parol bcrypt bilan', str_starts_with((string) cfg('admin_pass_hash', ''), '$2') || !empty(admin_cred()['hash'])],
        ['admin_tg_id sozlangan (Telegram kirish va xabarlar)', (int) cfg('admin_tg_id', 0) > 0],
        ['Telegram bot ulangan', (string) settings_get('bot_connected', '') === bot_fingerprint()],
        ['AI yordamchi kaliti kiritilgan', ai_settings()['key'] !== ''],
    ];
    $okCount = count(array_filter($checks, static fn ($c) => $c[1]));
    ?>
<div class="grid grid--main">
    <section class="card reveal">
        <header class="card__head">
            <div><h2 class="card__title">Tizim holati</h2><span class="card__note"><?= $okCount ?> / <?= count($checks) ?> tekshiruv o‘tdi</span></div>
            <span class="pill pill--<?= $okCount === count($checks) ? 'green' : 'amber' ?>"><?= $okCount === count($checks) ? 'Hammasi joyida' : 'Diqqat' ?></span>
        </header>
        <div class="meter"><i style="--w: <?= round($okCount / count($checks) * 100) ?>%"></i></div>
        <ul class="checks">
            <?php foreach ($checks as $c): ?>
                <li class="<?= $c[1] ? 'is-ok' : 'is-bad' ?>"><span><?= icon($c[1] ? 'check' : 'x', 14) ?></span><?= e($c[0]) ?></li>
            <?php endforeach; ?>
        </ul>
        <h3 class="card__sub">Ma’lumot fayllari</h3>
        <div class="files">
            <?php foreach ($files as $file => $label): $count = count(store_read($file)); ?>
                <div><?= icon('database', 15) ?><span><?= e($label) ?></span><b><?= $count ?></b></div>
            <?php endforeach; ?>
        </div>
    </section>

    <section class="card reveal">
        <header class="card__head"><div><h2 class="card__title">Parolni o‘zgartirish</h2><span class="card__note">Parol bcrypt bilan shifrlanib saqlanadi</span></div></header>
        <form method="post" class="form" autocomplete="off">
            <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
            <input type="hidden" name="action" value="password_change">
            <label class="field"><span class="field__label">Joriy parol</span>
                <span class="field__box"><?= icon('lock', 16) ?><input class="input" type="password" name="current" required autocomplete="current-password"></span></label>
            <label class="field"><span class="field__label">Yangi parol <em>kamida 10 belgi</em></span>
                <span class="field__box"><?= icon('key', 16) ?><input class="input" type="password" name="new" required minlength="10" autocomplete="new-password" data-strength></span>
                <span class="strength"><i></i><i></i><i></i><i></i></span></label>
            <label class="field"><span class="field__label">Yangi parolni takrorlang</span>
                <span class="field__box"><?= icon('key', 16) ?><input class="input" type="password" name="repeat" required minlength="10" autocomplete="new-password"></span></label>
            <button class="btn btn--primary btn--wide" type="submit"><?= icon('shield-check', 16) ?> Parolni yangilash</button>
        </form>
    </section>
</div>
<?php
}
/* ==================================================================
   8. TEZMIND AI
   ================================================================== */

function render_ai(): void
{
    $ai = ai_settings();
    $log = array_slice(store_read('ai_log'), 0, 60);
    $usage = store_read('ai_usage');
    $today = ($usage['day'] ?? '') === date('Y-m-d') ? (int) ($usage['total'] ?? 0) : 0;
    $people = ($usage['day'] ?? '') === date('Y-m-d') ? count((array) ($usage['u'] ?? [])) : 0;
    $errors = count(array_filter($log, static fn ($r): bool => empty($r['ok'])));
    $providers = [
        'gemini'    => ['Google Gemini', 'gemini-3.8-flash', 'https://aistudio.google.com/apikey', 'Bepul limit bor. Tezroq va arzonroq variant: gemini-3.5-flash-lite'],
        'anthropic' => ['Anthropic Claude', 'claude-haiku-5-5', 'https://console.anthropic.com/settings/keys', 'Pullik, sifati juda yuqori'],
        'openai'    => ['OpenAI-mos API', '', 'https://platform.openai.com/api-keys', 'OpenAI, Groq, OpenRouter, DeepSeek… — Base URL va model nomini kiriting'],
    ];
    $configured = $ai['key'] !== '';
    ?>
<div class="grid grid--kpi">
    <article class="card kpi reveal"><div class="kpi__top"><span class="kpi__icon"><?= icon('sparkles', 18) ?></span><span class="kpi__label">Holat</span></div>
        <div class="kpi__row"><b class="kpi__value kpi__value--txt"><?= !$ai['enabled'] ? 'O‘chiq' : ($configured ? 'Ishlayapti' : 'Kalit yo‘q') ?></b></div>
        <span class="trend trend--<?= $ai['enabled'] && $configured ? 'up' : 'down' ?>"><?= e($providers[$ai['provider']][0] . ' · ' . ($ai['model'] ?: '—')) ?></span></article>
    <article class="card kpi reveal"><div class="kpi__top"><span class="kpi__icon"><?= icon('message-circle', 18) ?></span><span class="kpi__label">Bugungi savollar</span></div>
        <div class="kpi__row"><b class="kpi__value" data-count="<?= $today ?>">0</b></div><span class="trend trend--flat">limit: <?= $ai['daily_cap'] ?> / kun</span></article>
    <article class="card kpi reveal"><div class="kpi__top"><span class="kpi__icon"><?= icon('users', 18) ?></span><span class="kpi__label">Bugun so‘raganlar</span></div>
        <div class="kpi__row"><b class="kpi__value" data-count="<?= $people ?>">0</b></div><span class="trend trend--flat">ilova + bot</span></article>
    <article class="card kpi reveal"><div class="kpi__top"><span class="kpi__icon"><?= icon('alert-triangle', 18) ?></span><span class="kpi__label">Xatolar (jurnalda)</span></div>
        <div class="kpi__row"><b class="kpi__value" data-count="<?= $errors ?>">0</b></div><span class="trend trend--<?= $errors ? 'down' : 'up' ?>"><?= $errors ? 'jurnalni ko‘ring' : 'hammasi joyida' ?></span></article>
</div>

<?php if (!$configured): ?>
    <div class="alert alert--warn reveal"><?= icon('key', 16) ?><span><b>API kalit kiritilmagan.</b> Hozircha AI yordamchi savolga mos darsliklarni ko‘rsatadi, lekin to‘liq javob bermaydi. Bepul kalit: <a href="https://aistudio.google.com/apikey" target="_blank" rel="noopener">aistudio.google.com/apikey</a> → “Create API key” → pastdagi maydonga joylashtiring.</span></div>
<?php endif; ?>

<div class="grid grid--main">
    <section class="card reveal">
        <header class="card__head"><div><h2 class="card__title">Sozlamalar</h2><span class="card__note">Faqat prompt engineering va AI coding bo‘yicha javob beradi — darsliklar va loyihalar asosida</span></div></header>
        <form method="post" class="form" autocomplete="off">
            <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
            <input type="hidden" name="action" value="ai_save">

            <label class="toggle">
                <input type="checkbox" name="ai_enabled" value="1" <?= $ai['enabled'] ? 'checked' : '' ?>>
                <span class="toggle__ui"></span>
                <span><b>AI yordamchi yoqilgan</b><small>Mini app markazidagi tugma va bot javoblari</small></span>
            </label>
            <label class="toggle">
                <input type="checkbox" name="ai_in_bot" value="1" <?= $ai['in_bot'] ? 'checked' : '' ?>>
                <span class="toggle__ui"></span>
                <span><b>Botda ham javob bersin</b><small>Botga yozilgan savollarga AI yordamchi javob beradi</small></span>
            </label>

            <div class="row2">
                <label class="field"><span class="field__label">Provayder</span>
                    <select class="input" name="ai_provider" data-ai-provider>
                        <?php foreach ($providers as $key => $meta): ?>
                            <option value="<?= e($key) ?>" data-model="<?= e($meta[1]) ?>" data-link="<?= e($meta[2]) ?>" data-note="<?= e($meta[3]) ?>" <?= $ai['provider'] === $key ? 'selected' : '' ?>><?= e($meta[0]) ?></option>
                        <?php endforeach; ?>
                    </select></label>
                <label class="field"><span class="field__label">Model</span>
                    <input class="input mono" type="text" name="ai_model" value="<?= e((string) settings_get('ai_model', '')) ?>" placeholder="<?= e($providers[$ai['provider']][1] ?: 'model nomi') ?>" data-ai-model></label>
            </div>
            <span class="field__hint" data-ai-note><?= e($providers[$ai['provider']][3]) ?></span>

            <label class="field"><span class="field__label">API kalit <?= $configured ? '<em>joriy: ' . e(mask_secret($ai['key'])) . '</em>' : '' ?></span>
                <span class="field__box"><?= icon('key', 16) ?><input class="input mono" type="password" name="ai_key" value="" placeholder="<?= $configured ? 'O‘zgartirish uchun yangi kalitni kiriting' : 'Kalitni shu yerga joylashtiring' ?>" autocomplete="off" spellcheck="false"></span>
                <span class="field__hint">Kalitni olish: <a href="<?= e($providers[$ai['provider']][2]) ?>" target="_blank" rel="noopener" data-ai-link><?= e($providers[$ai['provider']][2]) ?></a></span>
            </label>
            <?php if ($configured): ?>
                <label class="check check--sm"><input type="checkbox" name="ai_key_remove" value="1"><span>Kalitni o‘chirish</span></label>
            <?php endif; ?>

            <label class="field" data-ai-base <?= $ai['provider'] === 'openai' ? '' : 'hidden' ?>><span class="field__label">Base URL <em>OpenAI-mos API uchun</em></span>
                <input class="input mono" type="url" name="ai_base_url" value="<?= e((string) settings_get('ai_base_url', '')) ?>" placeholder="https://api.openai.com/v1 · https://api.groq.com/openai/v1 · https://openrouter.ai/api/v1"></label>

            <h3 class="card__sub">Limitlar (xarajat va spamdan himoya)</h3>
            <div class="row2">
                <label class="field"><span class="field__label">1 kishi / soat</span><input class="input" type="number" min="1" max="500" name="ai_user_hour" value="<?= $ai['user_hour'] ?>"></label>
                <label class="field"><span class="field__label">1 kishi / kun</span><input class="input" type="number" min="1" max="2000" name="ai_user_day" value="<?= $ai['user_day'] ?>"></label>
            </div>
            <div class="row2">
                <label class="field"><span class="field__label">Mehmon (Telegramsiz) / kun</span><input class="input" type="number" min="0" max="200" name="ai_guest_day" value="<?= $ai['guest_day'] ?>"></label>
                <label class="field"><span class="field__label">Hammasi bo‘lib / kun</span><input class="input" type="number" min="1" max="100000" name="ai_daily_cap" value="<?= $ai['daily_cap'] ?>"></label>
            </div>

            <button class="btn btn--primary btn--wide" type="submit"><?= icon('check', 16) ?> Saqlash</button>
        </form>
    </section>

    <section class="card reveal">
        <header class="card__head"><div><h2 class="card__title">Sinab ko‘rish</h2><span class="card__note">Saqlangan sozlamalar bilan haqiqiy javob</span></div></header>
        <form class="form" data-ai-test data-csrf="<?= e(csrf_token()) ?>">
            <label class="field"><span class="field__label">Savol</span>
                <textarea class="input" name="q" rows="3" maxlength="500">Yaxshi prompt qanday yoziladi?</textarea></label>
            <button class="btn btn--ghost btn--wide" type="submit"><?= icon('send', 15) ?> Yuborish</button>
        </form>
        <div class="aitest" data-ai-out hidden></div>
        <p class="field__hint">Mavzudan tashqari savol bering (masalan, ob-havo) — AI yordamchi muloyimlik bilan rad etishi kerak.</p>
    </section>
</div>

<section class="card reveal">
    <header class="card__head card__head--tools">
        <div><h2 class="card__title">So‘nggi savollar <span class="count"><?= count($log) ?></span></h2><span class="card__note">Odamlar nimani so‘rayapti — yangi darslik g‘oyalari shu yerda</span></div>
        <?php if ($log !== []): ?>
            <form method="post" data-confirm="Jurnal tozalansinmi?" data-confirm-ok="Tozalash">
                <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
                <input type="hidden" name="action" value="ai_log_clear">
                <button class="btn btn--ghost btn--sm" type="submit"><?= icon('trash-2', 14) ?> Tozalash</button>
            </form>
        <?php endif; ?>
    </header>
    <?php if ($log === []): ?>
        <div class="empty"><?= icon('message-circle', 22) ?><p>Hali savol berilmagan.</p></div>
    <?php else: ?>
        <ul class="ailog">
            <?php foreach ($log as $row): ?>
                <li class="<?= empty($row['ok']) ? 'is-bad' : '' ?>">
                    <div class="ailog__meta">
                        <span class="tag"><?= e(($row['src'] ?? '') === 'bot' ? 'BOT' : 'APP') ?></span>
                        <b><?= e((string) ($row['name'] ?? '') ?: 'Mehmon') ?></b>
                        <small><?= e(time_ago((string) ($row['t'] ?? ''))) ?><?= isset($row['ms']) ? ' · ' . round(((int) $row['ms']) / 1000, 1) . ' s' : '' ?></small>
                    </div>
                    <p class="ailog__q"><?= e((string) ($row['q'] ?? '')) ?></p>
                    <?php if (!empty($row['ok'])): ?>
                        <p class="ailog__a"><?= e(mb_substr((string) ($row['a'] ?? ''), 0, 260)) ?></p>
                    <?php else: ?>
                        <p class="ailog__a ailog__a--err"><?= e((string) ($row['err'] ?? 'xato')) ?></p>
                    <?php endif; ?>
                </li>
            <?php endforeach; ?>
        </ul>
    <?php endif; ?>
</section>
<?php
}

/* ==================================================================
   9. TELEGRAM BOT
   ================================================================== */

function render_bot(): void
{
    $token = bot_token();
    $fromPanel = trim((string) settings_get('bot_token', '')) !== '';
    $me = $token !== '' ? bot_api('getMe', [], 8) : ['ok' => false, 'description' => 'Token kiritilmagan'];
    $info = $token !== '' ? bot_webhook_info() : [];
    $expectedUrl = bot_app_url() . '?r=webhook';
    $hookOk = ($info['url'] ?? '') === $expectedUrl && empty($info['last_error_message']);
    $username = (string) ($me['result']['username'] ?? '');
    $leads = store_read('bot_leads');
    ?>
<div class="grid grid--kpi">
    <article class="card kpi reveal"><div class="kpi__top"><span class="kpi__icon"><?= icon('bot', 18) ?></span><span class="kpi__label">Bot</span></div>
        <div class="kpi__row"><b class="kpi__value kpi__value--txt"><?= !empty($me['ok']) ? '@' . e($username) : 'Ulanmagan' ?></b></div>
        <span class="trend trend--<?= !empty($me['ok']) ? 'up' : 'down' ?>"><?= !empty($me['ok']) ? 'Token to‘g‘ri' : e((string) ($me['description'] ?? 'Telegram javob bermadi')) ?></span></article>
    <article class="card kpi reveal"><div class="kpi__top"><span class="kpi__icon"><?= icon('zap', 18) ?></span><span class="kpi__label">Webhook</span></div>
        <div class="kpi__row"><b class="kpi__value kpi__value--txt"><?= $hookOk ? 'Ishlayapti' : (($info['url'] ?? '') === '' ? 'O‘rnatilmagan' : 'Muammo bor') ?></b></div>
        <span class="trend trend--<?= $hookOk ? 'up' : 'down' ?>"><?= (int) ($info['pending_update_count'] ?? 0) ?> ta kutilayotgan xabar</span></article>
    <article class="card kpi reveal"><div class="kpi__top"><span class="kpi__icon"><?= icon('users', 18) ?></span><span class="kpi__label">Obunachilar</span></div>
        <div class="kpi__row"><b class="kpi__value" data-count="<?= count($leads) ?>">0</b></div>
        <a class="trend trend--flat" href="?p=users&tab=bot">ro‘yxatni ko‘rish →</a></article>
</div>

<?php
    $okAt = (int) settings_get('tg_verify_ok_at', 0);
    $failAt = (int) settings_get('tg_verify_fail_at', 0);
    if ($failAt > $okAt && time() - $failAt < 86400): ?>
    <div class="alert alert--error reveal"><?= icon('fingerprint', 16) ?><span><b>Mini app foydalanuvchilari tasdiqlanmayapti</b> (oxirgisi: <?= e(date('d.m H:i', $failAt)) ?>). Sabab: saytdagi bot tokeni mini app ochilgan botniki emas yoki token @BotFather'da yangilangan. Yangi tokenni pastga kiriting va “Saqlash va ulash”ni bosing — shundan keyin ismlar, admin tugmasi va buyurtmalar to‘g‘ri ishlaydi.</span></div>
<?php endif; ?>
<?php if (!empty($info['last_error_message'])): ?>
    <div class="alert alert--error reveal"><?= icon('alert-triangle', 16) ?><span><b>Telegram oxirgi xato:</b> <?= e((string) $info['last_error_message']) ?> (<?= e(date('d.m.Y H:i', (int) ($info['last_error_date'] ?? time()))) ?>). “Qayta ulash” tugmasini bosing.</span></div>
<?php endif; ?>
<?php if (!is_https()): ?>
    <div class="alert alert--error reveal"><?= icon('lock', 16) ?><span>Sayt <b>https</b> orqali ochilmagan. Telegram faqat SSL sertifikatli manzilga ulanadi — hosting panelida SSL (Let’s Encrypt) ni yoqing.</span></div>
<?php endif; ?>

<div class="grid grid--main">
    <section class="card reveal">
        <header class="card__head"><div><h2 class="card__title">Bot tokeni</h2><span class="card__note">Joriy: <code><?= e(mask_secret($token)) ?: '—' ?></code> · <?= $fromPanel ? 'paneldan' : 'index.php dan' ?></span></div></header>
        <ol class="steps">
            <li>Telegramda <a href="https://t.me/BotFather" target="_blank" rel="noopener">@BotFather</a> → <code>/mybots</code> → botingiz → <b>API Token</b> → <b>Revoke current token</b>.</li>
            <li>Yangi tokenni nusxalab, pastga joylashtiring.</li>
            <li><b>Saqlash va ulash</b> — webhook, menyu tugmasi, buyruqlar va tavsif avtomatik sozlanadi.</li>
        </ol>
        <form method="post" class="form" autocomplete="off">
            <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
            <input type="hidden" name="action" value="bot_save">
            <label class="field"><span class="field__label">Yangi token</span>
                <span class="field__box"><?= icon('key', 16) ?><input class="input mono" type="password" name="bot_token" placeholder="1234567890:AA…" autocomplete="off" spellcheck="false"></span></label>
            <button class="btn btn--primary btn--wide" type="submit"><?= icon('check', 16) ?> Saqlash va ulash</button>
        </form>
        <form method="post" class="form" style="margin-top:10px">
            <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
            <input type="hidden" name="action" value="bot_connect">
            <button class="btn btn--ghost btn--wide" type="submit"><?= icon('refresh', 16) ?> Qayta ulash (joriy token bilan)</button>
        </form>
    </section>

    <section class="card reveal">
        <header class="card__head"><div><h2 class="card__title">Holat</h2><span class="card__note">Telegram serveridan olingan ma’lumot</span></div></header>
        <ul class="checks">
            <li class="<?= !empty($me['ok']) ? 'is-ok' : 'is-bad' ?>"><span><?= icon(!empty($me['ok']) ? 'check' : 'x', 14) ?></span>Token to‘g‘ri</li>
            <li class="<?= ($info['url'] ?? '') === $expectedUrl ? 'is-ok' : 'is-bad' ?>"><span><?= icon(($info['url'] ?? '') === $expectedUrl ? 'check' : 'x', 14) ?></span>Webhook shu saytga ulangan</li>
            <li class="<?= empty($info['last_error_message']) ? 'is-ok' : 'is-bad' ?>"><span><?= icon(empty($info['last_error_message']) ? 'check' : 'x', 14) ?></span>Oxirgi yetkazishda xato yo‘q</li>
            <li class="<?= is_https() ? 'is-ok' : 'is-bad' ?>"><span><?= icon(is_https() ? 'check' : 'x', 14) ?></span>HTTPS</li>
            <li class="<?= ai_settings()['in_bot'] && ai_settings()['key'] !== '' ? 'is-ok' : 'is-bad' ?>"><span><?= icon(ai_settings()['in_bot'] && ai_settings()['key'] !== '' ? 'check' : 'x', 14) ?></span>Botda AI yordamchi javob beradi</li>
        </ul>
        <div class="files">
            <div><?= icon('globe', 15) ?><span>Webhook</span><b class="mono" style="font-size:11px;word-break:break-all"><?= e((string) ($info['url'] ?? '—') ?: '—') ?></b></div>
            <div><?= icon('clock', 15) ?><span>Ulangan</span><b><?= e(($t = (string) settings_get('bot_connected_at', '')) !== '' ? date('d.m.Y H:i', (int) strtotime($t)) : '—') ?></b></div>
        </div>
        <?php if ($username !== ''): ?>
            <a class="btn btn--ghost btn--wide" href="https://t.me/<?= e($username) ?>?start=check" target="_blank" rel="noopener" style="margin-top:12px"><?= icon('send', 15) ?> Botni ochib /start bosing</a>
        <?php endif; ?>
    </section>
</div>
<?php
}

/* ==================================================================
   USLUBLAR
   ================================================================== */

function admin_css(): string
{
    return <<<'CSS'
:root{
  color-scheme:light;
  --bg:#E9EEF6;--bg-2:#F3F1EA;--surface:#FFFFFF;--surface-2:#FFFFFF;--surface-3:#ECE9DF;
  --border:#E8E5DB;--border-strong:#D8D4C7;--text:#07111F;--text-2:#3D3C37;--muted:#6F6D66;--faint:#9D9A91;
  --accent:#1677FF;--accent-2:#0F5FD6;--accent-ink:#0F5FD6;--accent-soft:#DCEAFF;--accent-softer:#EEF5FF;
  --c2:#6A9BCC;--c3:#788C5D;
  --ok:#2F9E6B;--ok-soft:#E2F2E9;--danger:#CF3F3F;--danger-soft:#FBE6E4;--info:#3F73C9;--info-soft:#E6EEFA;--warn:#C98A1B;--warn-soft:#FBF0DC;
  --ink:#0B172A;--scrim:rgba(26,25,21,.4);
  --sh-sm:0 1px 2px rgba(26,25,21,.05);--sh-md:0 1px 2px rgba(26,25,21,.04),0 10px 30px -14px rgba(26,25,21,.16);
  --sh-lg:0 30px 70px -24px rgba(26,25,21,.35);--sh-accent:0 1px 1px rgba(160,70,40,.25),0 8px 22px -8px rgba(217,119,87,.7);
  --r:18px;--side:264px;
  --e-out:cubic-bezier(.16,1,.3,1);--e-spring:cubic-bezier(.34,1.36,.64,1);--e-ios:cubic-bezier(.32,.72,0,1);
  --font:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  --serif:'Source Serif 4','Iowan Old Style',Georgia,serif;
}
[data-theme="dark"]{
  color-scheme:dark;
  --bg:#030B18;--bg-2:#090908;--surface:#171715;--surface-2:#0B172A;--surface-3:#16294A;
  --border:#262521;--border-strong:#35332E;--text:#FFFFFF;--text-2:#D9D6CC;--muted:#A29F96;--faint:#6F6C65;
  --accent:#1677FF;--accent-2:#0F5FD6;--accent-ink:#83C8FF;--accent-soft:rgba(22,119,255,.16);--accent-softer:rgba(22,119,255,.08);
  --c2:#7FAEDD;--c3:#98AE7A;
  --ok:#4CC38F;--ok-soft:rgba(76,195,143,.14);--danger:#F06A6A;--danger-soft:rgba(240,106,106,.14);--info:#6F9DF0;--info-soft:rgba(111,157,240,.14);--warn:#E6AE4C;--warn-soft:rgba(230,174,76,.14);
  --ink:#0B172A;--scrim:rgba(0,0,0,.62);
  --sh-sm:0 1px 2px rgba(0,0,0,.4);--sh-md:0 12px 30px -16px rgba(0,0,0,.8);--sh-lg:0 30px 70px -24px rgba(0,0,0,.9);
}
*,*::before,*::after{box-sizing:border-box}
*{margin:0;padding:0;-webkit-tap-highlight-color:transparent}
html{background:var(--bg)}
body{min-height:100vh;background:var(--bg);color:var(--text);font:14.5px/1.5 var(--font);letter-spacing:-.011em;-webkit-font-smoothing:antialiased;transition:background-color .3s,color .3s}
a{color:inherit;text-decoration:none}
button,input,select,textarea{font:inherit;color:inherit;letter-spacing:inherit;background:none;border:0}
button{cursor:pointer}
img,svg{display:block;max-width:100%}
ul{list-style:none}
h1,h2,h3{font-weight:650;letter-spacing:-.02em;line-height:1.2}
.serif{font-family:var(--serif);font-weight:550;letter-spacing:-.018em}
.muted{color:var(--muted)}
.icon{flex:none}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:8px}
::selection{background:var(--accent-soft)}
[data-theme="light"] .only-dark,[data-theme="dark"] .only-light{display:none}
[hidden]{display:none!important}

/* ---------- Tugmalar va maydonlar ---------- */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:7px;min-height:42px;padding:0 16px;border-radius:12px;font-weight:600;font-size:14px;white-space:nowrap;transition:transform .25s var(--e-spring),background-color .2s,box-shadow .2s,opacity .2s}
.btn:active{transform:scale(.97)}
.btn:disabled{opacity:.55;pointer-events:none}
.btn--primary{color:#fff;background:var(--accent);background-image:linear-gradient(180deg,rgba(255,255,255,.14),rgba(255,255,255,0));box-shadow:var(--sh-accent),inset 0 1px 0 rgba(255,255,255,.22)}
.btn--primary:hover{background-color:var(--accent-2)}
.btn--ghost{background:var(--surface);border:1px solid var(--border-strong);box-shadow:var(--sh-sm)}
.btn--ghost:hover{background:var(--surface-2)}
.btn--danger{color:#fff;background:var(--danger)}
.btn--sm{min-height:34px;padding:0 12px;font-size:13px;border-radius:10px}
.btn--lg{min-height:50px;font-size:15px;border-radius:14px}
.btn--wide{width:100%}
.iconbtn{position:relative;display:inline-grid;place-items:center;width:38px;height:38px;border-radius:11px;color:var(--text-2);background:var(--surface);border:1px solid var(--border);box-shadow:var(--sh-sm);transition:transform .25s var(--e-spring),background-color .2s,color .2s}
.iconbtn:hover{background:var(--surface-2)}
.iconbtn:active{transform:scale(.9)}
.iconbtn--ghost{background:none;border-color:transparent;box-shadow:none}
.iconbtn--danger{color:var(--danger)}
.iconbtn--danger:hover{background:var(--danger-soft);border-color:transparent}
.iconbtn__dot{position:absolute;top:7px;right:8px;width:8px;height:8px;border-radius:50%;background:var(--accent);box-shadow:0 0 0 2px var(--surface)}
.link{display:inline-flex;align-items:center;gap:2px;font-size:13px;font-weight:600;color:var(--accent-ink)}
.link:hover{opacity:.75}

.field{display:grid;gap:7px}
.field__label{font-size:12.5px;font-weight:600;color:var(--text-2)}
.field__label i{font-style:normal;color:var(--accent)}
.field__label em{font-style:normal;font-weight:500;color:var(--faint)}
.field__hint{font-size:12px;color:var(--faint)}
.field__hint:empty{display:none}
.field__box{position:relative;display:block}
.field__box>.icon{position:absolute;left:13px;top:50%;transform:translateY(-50%);color:var(--faint);pointer-events:none}
.field__box .input{padding-left:40px}
.field__box:focus-within>.icon{color:var(--accent)}
.field__eye{position:absolute;right:6px;top:50%;transform:translateY(-50%);display:grid;place-items:center;width:34px;height:34px;border-radius:9px;color:var(--faint)}
.field__eye:hover{color:var(--text);background:var(--surface-2)}
.input{width:100%;min-height:44px;padding:10px 13px;border-radius:12px;background:var(--surface);border:1px solid var(--border-strong);color:var(--text);font-size:14.5px;transition:border-color .2s,box-shadow .2s;-webkit-appearance:none;appearance:none}
.input::placeholder{color:var(--faint)}
.input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 4px var(--accent-softer)}
textarea.input{resize:vertical;line-height:1.5}
select.input{padding-right:34px;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='%239D9A91' stroke-width='2'%3E%3Cpath d='m6 9 6 6 6-6'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 10px center;cursor:pointer}
.input--sm{min-height:34px;padding:6px 32px 6px 11px;font-size:13px;border-radius:10px}
.input--color{padding:4px;height:44px;cursor:pointer}
.row2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.form{display:grid;gap:16px}
.alert{display:flex;gap:10px;align-items:flex-start;padding:12px 14px;border-radius:12px;font-size:13.5px;margin-bottom:16px}
.alert--error{color:var(--danger);background:var(--danger-soft)}
.check{display:inline-flex;align-items:center;gap:8px;font-size:13px;cursor:pointer}
.check input{accent-color:var(--accent);width:16px;height:16px}
.check--sm{font-size:12px;color:var(--muted)}

.toggle{display:flex;align-items:flex-start;gap:12px;padding:12px;border-radius:14px;background:var(--surface-2);cursor:pointer}
.toggle input{position:absolute;opacity:0;pointer-events:none}
.toggle__ui{position:relative;flex:none;width:44px;height:26px;border-radius:99px;background:var(--surface-3);transition:background-color .25s}
.toggle__ui::after{content:'';position:absolute;top:2px;left:2px;width:22px;height:22px;border-radius:50%;background:#fff;box-shadow:0 2px 5px rgba(0,0,0,.2);transition:transform .35s var(--e-spring)}
.toggle input:checked+.toggle__ui{background:var(--accent)}
.toggle input:checked+.toggle__ui::after{transform:translateX(18px)}
.toggle b{display:block;font-size:13.5px;font-weight:600}
.toggle small{display:block;font-size:12px;color:var(--muted)}

.chip{display:inline-flex;align-items:center;gap:5px;padding:4px 10px;border-radius:99px;font-size:12px;font-weight:550;color:var(--text-2);background:var(--surface-2);border:1px solid var(--border)}
.chips{display:flex;flex-wrap:wrap;gap:6px}
.tag{display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:7px;font-size:11px;font-weight:650;font-style:normal;color:var(--muted);background:var(--surface-2);letter-spacing:.02em;vertical-align:1px}
.tag--accent{color:var(--accent-ink);background:var(--accent-softer)}
.pill{display:inline-flex;align-items:center;padding:4px 10px;border-radius:99px;font-size:12px;font-weight:650;white-space:nowrap}
.pill--blue{color:var(--info);background:var(--info-soft)}
.pill--amber{color:var(--warn);background:var(--warn-soft)}
.pill--green{color:var(--ok);background:var(--ok-soft)}
.pill--gray{color:var(--muted);background:var(--surface-3)}
.count{display:inline-grid;place-items:center;min-width:22px;height:22px;padding:0 7px;margin-left:4px;border-radius:99px;font:650 12px/1 var(--font);color:var(--muted);background:var(--surface-3);vertical-align:2px}

/* ---------- Kirish sahifasi ---------- */
.auth{display:grid;grid-template-columns:1.05fr .95fr;min-height:100vh}
.auth__art{position:relative;display:grid;place-items:end start;padding:56px;background:var(--ink);color:#FFFFFF;overflow:hidden;isolation:isolate}
.auth__glow{position:absolute;right:-120px;top:-120px;width:560px;height:560px;border-radius:50%;background:radial-gradient(circle,rgba(22,119,255,.55),transparent 62%);z-index:-1;animation:breathe 8s ease-in-out infinite}
.auth__art::after{content:'';position:absolute;top:0; right:0; bottom:0; left:0;z-index:-1;background-image:linear-gradient(rgba(255,255,255,.05) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.05) 1px,transparent 1px);background-size:40px 40px;-webkit-mask-image:radial-gradient(ellipse at 70% 20%,#000,transparent 70%);mask-image:radial-gradient(ellipse at 70% 20%,#000,transparent 70%)}
@keyframes breathe{50%{transform:scale(1.12);opacity:.8}}
.auth__quote{display:grid;gap:18px;max-width:460px;animation:rise .8s var(--e-out) both}
.auth__quote h2{font-size:40px;line-height:1.1}
.auth__quote p{color:rgba(245,243,236,.66);font-size:15px}
.auth__chips{display:flex;flex-wrap:wrap;gap:8px}
.auth__chips span{display:inline-flex;align-items:center;gap:6px;padding:7px 12px;border-radius:99px;font-size:12.5px;background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.12)}
.auth__side{display:grid;place-items:center;padding:calc(32px + var(--tg-top,0px)) 24px calc(32px + var(--tg-bottom,0px))}
.auth__card{display:grid;gap:16px;width:min(100%,380px);animation:rise .7s var(--e-out) .08s both}
.auth__title{font-size:32px;margin-top:18px}
.auth__sub{color:var(--muted);margin-top:-8px}
.hint{display:flex;align-items:center;justify-content:center;gap:6px;font-size:12px;color:var(--faint)}
.brand{display:flex;align-items:center;gap:11px}
.brand__name{display:block;font-size:20px}
.brand__name em{font-style:normal;color:var(--accent)}
.brand__note{display:block;font-size:12px;color:var(--muted)}
@keyframes rise{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:none}}

/* ---------- Qobiq ---------- */
.side{position:fixed;top:0; right:auto; bottom:0; left:0;z-index:30;display:flex;flex-direction:column;width:var(--side);padding:calc(22px + var(--tg-top,0px)) 16px calc(18px + var(--tg-bottom,0px));background:var(--surface);border-right:1px solid var(--border);transition:transform .45s var(--e-ios)}
.side__brand{display:flex;align-items:center;gap:10px;padding:0 8px 24px}
.side__close{display:none;margin-left:auto}
.side__nav{display:grid;align-content:start;gap:3px;min-height:0;flex:0 1 auto;overflow-y:auto;overscroll-behavior:contain;scrollbar-width:thin;margin-bottom:14px}
.side__label{display:flex;align-items:center;gap:10px;padding:14px 10px 6px;font-size:11.5px;font-weight:600;color:var(--faint)}
.side__label::after{content:'';flex:1;height:1px;background:var(--border)}
.side__label:first-child{padding-top:0}
.nav{position:relative;display:flex;align-items:center;gap:11px;height:42px;padding:0 12px;border-radius:12px;font-weight:550;color:var(--muted);transition:background-color .2s,color .2s}
.nav:hover{background:var(--surface-2);color:var(--text)}
.nav.is-active{color:#fff;background:var(--accent);box-shadow:var(--sh-accent)}
.nav__badge{margin-left:auto;min-width:20px;height:20px;padding:0 6px;display:grid;place-items:center;border-radius:99px;font-size:11px;color:#fff;background:var(--accent)}
.nav.is-active .nav__badge{color:var(--accent-ink);background:#fff}
.side__promo{position:relative;flex:none;display:grid;gap:5px;margin-top:auto;padding:16px;border-radius:18px;color:#FFFFFF;background:var(--ink);overflow:hidden;isolation:isolate}
.side__promo::before{content:'';position:absolute;top:-60px;right:-50px;z-index:-1;width:160px;height:160px;border-radius:50%;background:radial-gradient(circle,rgba(22,119,255,.5),transparent 65%)}
.side__promo-icon{display:grid;place-items:center;width:32px;height:32px;border-radius:10px;background:var(--accent);margin-bottom:4px}
.side__promo b{font-size:14.5px}
.side__promo p{font-size:12px;color:rgba(245,243,236,.62);margin-bottom:6px}
.scrim{display:none}
.main{margin-left:var(--side);min-height:100vh}
.top{position:sticky;top:0;z-index:20;display:flex;align-items:center;gap:14px;padding:calc(18px + var(--tg-top,0px)) 32px 18px;background:var(--bg); background:color-mix(in srgb,var(--bg) 86%,transparent);backdrop-filter:blur(16px) saturate(170%);-webkit-backdrop-filter:blur(16px) saturate(170%);border-bottom:1px solid transparent;transition:border-color .2s}
.top.is-stuck{border-bottom-color:var(--border)}
.top__menu{display:none}
.top__title{flex:1;min-width:0}
.top__title h1{font-size:26px}
.top__title p{font-size:13px;color:var(--muted)}
.top__actions{display:flex;align-items:center;gap:8px}
.chip--date{padding:8px 12px;background:var(--surface)}
.me{display:flex;align-items:center;gap:8px;padding:4px 4px 4px 4px;margin-left:4px;border-radius:14px;background:var(--surface);border:1px solid var(--border)}
.me__ava{display:grid;place-items:center;width:32px;height:32px;border-radius:10px;font-weight:700;color:#fff;background:linear-gradient(150deg,#399BFF,#0F5FD6)}
.me__txt{display:grid;line-height:1.2;padding-right:4px}
.me__txt b{font-size:13px}
.me__txt small{font-size:11px;color:var(--muted)}
.wrap{padding:8px 32px 48px;max-width:1360px}

/* ---------- Grid va kartalar ---------- */
.grid{display:grid;gap:16px;margin-bottom:16px}
.grid>*,.main,.wrap{min-width:0}
html,body{overflow-x:clip}
.grid--kpi{grid-template-columns:repeat(4,1fr)}
.grid--main{grid-template-columns:1.7fr 1fr}
.grid--cards{grid-template-columns:repeat(auto-fill,minmax(min(100%,280px),1fr))}
.grid--orders{grid-template-columns:repeat(auto-fill,minmax(min(100%,360px),1fr))}
.grid--compose{grid-template-columns:1.4fr 1fr}
.card{position:relative;padding:20px;border-radius:var(--r);background:var(--surface);border:1px solid var(--border);box-shadow:var(--sh-sm)}
.card__head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:16px}
.card__head--tools{align-items:center;flex-wrap:wrap}
.card__title{font-size:16.5px}
.card__note{font-size:12.5px;color:var(--muted)}
.card__sub{font-size:13px;margin:18px 0 10px;color:var(--text-2)}
.card>.card__title{margin-bottom:14px}
.card+.card{margin-top:0}
.editor__main .card,.editor__side .card{display:grid;gap:16px}
.reveal{animation:rise .6s var(--e-out) both;animation-delay:calc(var(--i,0) * 60ms)}
.empty{display:grid;justify-items:center;gap:10px;padding:34px 20px;text-align:center;color:var(--muted)}
.empty .icon{width:44px;height:44px;padding:11px;border-radius:14px;color:var(--accent-ink);background:var(--accent-softer)}
.toolbar{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:16px}
.toolbar h2{flex:1;font-size:22px}

/* AI tahlil */
.ai{position:relative;margin-bottom:16px;padding:22px 24px;border-radius:22px;color:#FFFFFF;background:var(--ink);overflow:hidden;isolation:isolate}
[data-theme="dark"] .ai{border:1px solid var(--border-strong)}
.ai__glow{position:absolute;right:-100px;top:-140px;z-index:-1;width:420px;height:420px;border-radius:50%;background:radial-gradient(circle,rgba(22,119,255,.5),transparent 62%);animation:breathe 9s ease-in-out infinite}
.ai__head{display:flex;align-items:center;gap:12px;margin-bottom:16px}
.ai__head h2{font-size:20px}
.ai__head p{font-size:12.5px;color:rgba(245,243,236,.6)}
.ai__head>div{flex:1}
.ai__icon{display:grid;place-items:center;width:40px;height:40px;border-radius:12px;background:linear-gradient(150deg,#399BFF,#0F5FD6);box-shadow:0 8px 20px -8px rgba(22,119,255,.8)}
.ai__icon .icon{animation:twinkle 2.6s ease-in-out infinite}
@keyframes twinkle{50%{transform:scale(1.15) rotate(12deg)}}
.ai__live{display:inline-flex;align-items:center;gap:6px;padding:5px 10px;border-radius:99px;font-size:12px;font-weight:600;background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.12)}
.ai__live i{width:7px;height:7px;border-radius:50%;background:#4CC38F;animation:ping 2s infinite}
@keyframes ping{0%{box-shadow:0 0 0 0 rgba(76,195,143,.6)}70%{box-shadow:0 0 0 8px transparent}100%{box-shadow:0 0 0 0 transparent}}
.ai__list{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}
.ai__list li{display:flex;gap:10px;padding:12px 14px;border-radius:14px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.08);font-size:13.5px;line-height:1.45;color:rgba(245,243,236,.86);animation:rise .6s var(--e-out) both;animation-delay:calc(200ms + var(--i) * 90ms)}
.ai__list li>span{display:grid;place-items:center;flex:none;width:28px;height:28px;border-radius:9px;color:#83C8FF;background:rgba(22,119,255,.16)}
.ai__list b{color:#fff}

/* KPI */
.kpi{display:grid;gap:10px}
.kpi__top{display:flex;align-items:center;gap:10px}
.kpi__icon{display:grid;place-items:center;width:34px;height:34px;border-radius:10px;color:var(--accent-ink);background:var(--accent-softer)}
.kpi__label{font-size:13px;font-weight:550;color:var(--muted)}
.kpi__row{display:flex;align-items:flex-end;justify-content:space-between;gap:10px}
.kpi__value{font:550 34px/1 var(--serif);letter-spacing:-.02em;font-variant-numeric:tabular-nums}
.spark{width:90px;height:32px;overflow:visible}
.spark polyline{fill:none;stroke:var(--accent);stroke-width:2;stroke-linecap:round;stroke-linejoin:round;vector-effect:non-scaling-stroke;filter:drop-shadow(0 3px 5px var(--accent)); filter:drop-shadow(0 3px 5px color-mix(in srgb,var(--accent) 50%,transparent))}
.trend{display:inline-flex;align-items:center;gap:5px;font-size:12px;font-weight:600;color:var(--muted)}
.trend--up{color:var(--ok)}
.trend--down{color:var(--danger)}

/* Grafik */
.legend{display:flex;gap:14px;font-size:12px;color:var(--muted)}
.legend span{display:inline-flex;align-items:center;gap:6px}
.lg{width:10px;height:10px;border-radius:3px}
.lg--a{background:var(--accent)}
.lg--b{background:var(--c2)}
.chart{position:relative}
.chart svg{width:100%;height:260px;overflow:visible}
.chart__grid{stroke:var(--border);stroke-dasharray:4 5}
.chart__axis{fill:var(--faint);font-size:11px;font-family:var(--font)}
.chart__line{fill:none;stroke:var(--accent);stroke-width:2.6;stroke-linecap:round;vector-effect:non-scaling-stroke;stroke-dasharray:1;stroke-dashoffset:1;animation:draw 1.6s var(--e-out) .2s forwards;filter:drop-shadow(0 4px 8px var(--accent-soft)); filter:drop-shadow(0 4px 8px color-mix(in srgb,var(--accent) 45%,transparent))}
.chart__line--b{stroke:var(--c2);stroke-width:2;stroke-dasharray:5 6;animation:none;opacity:.9;filter:none}
.chart__area{opacity:0;animation:fadein 1s var(--e-out) .5s forwards}
@keyframes draw{to{stroke-dashoffset:0}}
@keyframes fadein{to{opacity:1}}
.chart__cursor{stroke:var(--border-strong);stroke-dasharray:3 4;opacity:0;vector-effect:non-scaling-stroke}
.chart__dot{fill:var(--surface);stroke:var(--accent);stroke-width:3;vector-effect:non-scaling-stroke;opacity:0}
.chart.is-hover .chart__cursor,.chart.is-hover .chart__dot{opacity:1}
.chart__tip{position:absolute;top:0;left:0;display:grid;gap:1px;padding:8px 11px;border-radius:10px;font-size:12px;color:#fff;background:#0B172A;box-shadow:var(--sh-lg);pointer-events:none;white-space:nowrap;transform:translate(-50%,calc(-100% - 12px))}
.chart__tip b{font-size:12.5px}
.chart__tip span:first-of-type::before{content:'';display:inline-block;width:7px;height:7px;margin-right:6px;border-radius:2px;background:var(--accent)}
.chart__tip span:last-of-type::before{content:'';display:inline-block;width:7px;height:7px;margin-right:6px;border-radius:2px;background:var(--c2)}

.donut{display:grid;justify-items:center;gap:18px}
.donut__svg{width:180px;height:180px}
.donut__track{stroke:var(--surface-3)}
.donut__slice{stroke-linecap:round;animation:fadein .8s var(--e-out) both}
.donut__num{font:600 28px var(--serif);fill:var(--text)}
.donut__cap{font-size:10px;fill:var(--muted)}
.donut__legend{display:grid;gap:8px;width:100%}
.donut__legend li{display:grid;grid-template-columns:auto 1fr auto auto;align-items:center;gap:10px;padding:8px 10px;border-radius:10px;background:var(--surface-2);font-size:13px}
.donut__legend i{width:10px;height:10px;border-radius:3px}
.donut__legend em{font-style:normal;color:var(--muted);font-size:12px;min-width:34px;text-align:right}

/* Jadval */
.table-wrap{overflow-x:auto;margin:0 -20px -20px;padding:0 20px 8px}
.table{width:100%;border-collapse:collapse;font-size:13.5px}
.table th{padding:10px 12px;text-align:left;font-size:12px;font-weight:600;color:var(--muted);background:var(--surface-2);white-space:nowrap}
.table th:first-child{border-radius:10px 0 0 10px}
.table th:last-child{border-radius:0 10px 10px 0}
.table td{padding:11px 12px;border-bottom:1px solid var(--border);white-space:nowrap}
.table tr:last-child td{border-bottom:0}
.table .num{text-align:right;font-variant-numeric:tabular-nums}
.table--click tbody tr{cursor:pointer;transition:background-color .15s}
.table--click tbody tr:hover{background:var(--surface-2)}
.table .chev{color:var(--faint);width:24px}
.who{display:flex;align-items:center;gap:10px}
.who span{display:grid;line-height:1.3}
.who small{font-size:12px;color:var(--muted)}
.ava{flex:none;border-radius:50%;object-fit:cover}
.ava--letter{display:grid;place-items:center;font-weight:650;color:var(--accent-ink);background:var(--accent-soft)}
.search{position:relative;display:block;width:min(100%,320px)}
.search .icon{position:absolute;left:12px;top:50%;transform:translateY(-50%);color:var(--faint)}
.search .input{padding-left:38px;min-height:40px}

.mini{display:grid;gap:4px}
.mini li{display:flex;align-items:center;gap:12px;padding:10px;border-radius:12px;transition:background-color .15s}
.mini li:hover{background:var(--surface-2)}
.mini__icon{display:grid;place-items:center;flex:none;width:36px;height:36px;border-radius:11px;color:var(--accent-ink);background:var(--accent-softer)}
.mini__body{display:grid;flex:1;min-width:0}
.mini__body small{font-size:12px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}

/* Loyiha / video kartalari */
.pcard{display:flex;flex-direction:column;padding:0;overflow:hidden;transition:box-shadow .25s,transform .35s var(--e-spring),border-color .2s}
.pcard:hover{box-shadow:var(--sh-md);border-color:var(--border-strong);transform:translateY(-2px)}
.pcard__media{position:relative;display:grid;place-items:center;aspect-ratio:16/9;background:radial-gradient(80% 90% at 30% 20%,var(--surface-2),transparent 70%),var(--surface); background:radial-gradient(80% 90% at 30% 20%,color-mix(in srgb,var(--p1,var(--accent)) 28%,transparent),transparent 70%),color-mix(in srgb,var(--p1,var(--accent)) 12%,var(--surface));border-bottom:1px solid var(--border)}
.pcard__media img{position:absolute;top:0; right:0; bottom:0; left:0;width:100%;height:100%;object-fit:cover}
.pcard__media--video{background:#0B172A}
.pcard__icon{display:grid;place-items:center;width:64px;height:64px;border-radius:20px;color:#fff;background:var(--p1,var(--accent));box-shadow:0 14px 30px -12px var(--p1,var(--accent))}
.pcard__flag{position:absolute;top:10px;left:10px;display:inline-flex;align-items:center;gap:4px;padding:4px 9px;border-radius:99px;font-size:11.5px;font-weight:650;color:var(--accent-ink);background:var(--surface);box-shadow:var(--sh-sm)}
.pcard__play{position:relative;display:grid;place-items:center;width:44px;height:44px;border-radius:50%;color:#fff;background:var(--accent);box-shadow:var(--sh-accent)}
.pcard__play .icon{fill:currentColor;margin-left:2px}
.pcard__body{display:grid;gap:4px;padding:14px 16px;flex:1}
.pcard__body h3{font-size:16px}
.pcard__body p{font-size:13px;color:var(--muted)}
.pcard__body .chips{margin-top:6px}
.pcard__meta{display:flex;justify-content:space-between;font-size:12px;color:var(--faint);font-weight:550}
.pcard__acts{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:12px 16px;border-top:1px solid var(--border)}

/* Muharrir */
.editor__grid{display:grid;grid-template-columns:1fr 340px;gap:16px;align-items:start}
.editor__main,.editor__side{display:grid;gap:16px}
.editor__side{position:sticky;top:96px}
.ltabs{border:1px solid var(--border-strong);border-radius:12px;overflow:hidden;background:var(--surface)}
.ltabs:focus-within{border-color:var(--accent);box-shadow:0 0 0 4px var(--accent-softer)}
.ltabs__bar{display:flex;gap:2px;padding:4px;background:var(--surface-2);border-bottom:1px solid var(--border)}
.ltabs__btn{padding:4px 12px;border-radius:8px;font-size:12px;font-weight:650;color:var(--muted)}
.ltabs__btn.is-on{color:var(--text);background:var(--surface);box-shadow:var(--sh-sm)}
.ltabs__btn.has-value::after{content:'';display:inline-block;width:5px;height:5px;margin-left:5px;border-radius:50%;background:var(--ok);vertical-align:2px}
.ltabs__pane{display:none}
.ltabs__pane.is-on{display:block;animation:fadein .25s}
.ltabs .input{border:0;border-radius:0;box-shadow:none}
.drop{position:relative;display:grid;place-items:center;gap:8px;min-height:150px;padding:16px;border-radius:14px;border:1.5px dashed var(--border-strong);background:var(--surface-2);color:var(--muted);font-size:13px;text-align:center;cursor:pointer;overflow:hidden;transition:border-color .2s,background-color .2s}
.drop:hover,.drop.is-over{border-color:var(--accent);background:var(--accent-softer);color:var(--accent-ink)}
.drop img{position:absolute;top:0; right:0; bottom:0; left:0;width:100%;height:100%;object-fit:cover}
.drop input{position:absolute;top:0; right:0; bottom:0; left:0;opacity:0;cursor:pointer}
.drop--sm{min-height:0;aspect-ratio:9/13}
.drop--row{display:flex;min-height:44px;padding:10px 12px;justify-content:flex-start}
.shots{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}
.shots__cell{display:grid;gap:6px}
.preview{display:grid;justify-items:center;gap:6px;padding:22px;border-radius:14px;text-align:center;background:var(--surface); background:color-mix(in srgb,var(--p1) 10%,var(--surface))}
.preview__icon{display:grid;place-items:center;width:58px;height:58px;border-radius:18px;color:#fff;background:var(--p1);box-shadow:0 14px 28px -12px var(--p1);transition:background-color .3s}
.preview b{font-size:16px}
.preview small{font-size:12px;color:var(--muted)}
.icons{display:grid;grid-template-columns:repeat(8,1fr);gap:6px}
.icons__pick input{position:absolute;opacity:0}
.icons__pick span{display:grid;place-items:center;aspect-ratio:1;border-radius:10px;color:var(--muted);background:var(--surface-2);border:1px solid transparent;cursor:pointer;transition:all .2s}
.icons__pick input:checked+span{color:var(--accent-ink);background:var(--accent-softer);border-color:var(--accent)}

/* Buyurtmalar */
.pipeline{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px}
.stage{position:relative;display:grid;gap:4px;padding:16px;border-radius:16px;background:var(--surface);border:1px solid var(--border);overflow:hidden;transition:border-color .2s,box-shadow .2s}
.stage:hover,.stage.is-active{border-color:var(--border-strong);box-shadow:var(--sh-md)}
.stage span{font-size:12.5px;font-weight:600;color:var(--muted)}
.stage b{font:550 28px/1 var(--serif)}
.stage i{display:block;height:4px;margin-top:8px;border-radius:4px;background:var(--surface-3);position:relative;overflow:hidden}
.stage i::after{content:'';position:absolute;top:0; right:auto; bottom:0; left:0;width:var(--w);border-radius:inherit;background:var(--tone);animation:grow 1s var(--e-out) both}
@keyframes grow{from{width:0}}
.stage--blue{--tone:var(--info)}.stage--amber{--tone:var(--warn)}.stage--green{--tone:var(--ok)}.stage--gray{--tone:var(--faint)}
.segs{display:flex;gap:6px;flex-wrap:wrap}
.seg{display:inline-flex;align-items:center;gap:6px;padding:7px 13px;border-radius:99px;font-size:13px;font-weight:600;color:var(--text-2);background:var(--surface);border:1px solid var(--border)}
.seg b{font-size:11.5px;color:var(--muted)}
.seg.is-active{color:var(--bg);background:var(--text);border-color:var(--text)}
.seg.is-active b{color:inherit;opacity:.7}
.order{display:grid;grid-template-columns:minmax(0,1fr);gap:12px;min-width:0;border-top:3px solid var(--tone,var(--info))}
.order--blue{--tone:var(--info)}.order--amber{--tone:var(--warn)}.order--green{--tone:var(--ok)}.order--gray{--tone:var(--faint)}
.order__head{display:flex;align-items:center;gap:12px}
.order__who{display:grid;flex:1;min-width:0}
.order__who small{font-size:12px;color:var(--muted)}
.order__project{display:inline-flex;align-items:center;gap:6px;width:max-content;padding:5px 10px;border-radius:9px;font-size:12.5px;font-weight:600;color:var(--accent-ink);background:var(--accent-softer)}
.order__text{font-size:14px;color:var(--text-2);line-height:1.55}
.order__meta{display:flex;flex-wrap:wrap;gap:6px}
.order__meta>*{display:inline-flex;align-items:center;gap:5px;padding:5px 10px;border-radius:9px;font-size:12.5px;color:var(--text-2);background:var(--surface-2)}
.order__acts{display:flex;flex-wrap:wrap;align-items:center;gap:8px;padding-top:12px;border-top:1px solid var(--border)}
.order__status{flex:1}

/* Xabarlar */
.tgprev{display:grid;gap:6px;padding:20px;border-radius:14px;background:linear-gradient(160deg,#E7DDCF,#D9CDBB);min-height:260px;align-content:end}
[data-theme="dark"] .tgprev{background:linear-gradient(160deg,#1E2A36,#141D26)}
.tgprev__bubble{position:relative;display:grid;gap:4px;max-width:92%;padding:10px 12px 18px;border-radius:14px 14px 14px 4px;background:#fff;color:#1a1a1a;box-shadow:0 1px 1px rgba(0,0,0,.1)}
[data-theme="dark"] .tgprev__bubble{background:#223040;color:#fff}
.tgprev__bubble p{font-size:13.5px;white-space:pre-wrap;word-break:break-word}
.tgprev__img{aspect-ratio:16/9;margin:-6px -8px 4px;border-radius:10px;background:center/cover no-repeat}
.tgprev__time{position:absolute;right:10px;bottom:4px;font-size:11px;opacity:.5}
.tgprev__btn{display:flex;align-items:center;justify-content:center;gap:6px;max-width:92%;padding:9px;border-radius:10px;font-size:13px;font-weight:600;color:#fff;background:rgba(0,0,0,.25)}
.mlist{display:grid}
.mlist li{display:flex;align-items:center;gap:14px;padding:12px 4px;border-bottom:1px solid var(--border)}
.mlist li:last-child{border-bottom:0}
.mlist__thumb{width:56px;height:56px;border-radius:12px;object-fit:cover;flex:none}
.mlist__icon{display:grid;place-items:center;flex:none;width:56px;height:56px;border-radius:12px;color:var(--accent-ink);background:var(--accent-softer)}
.mlist__body{display:grid;gap:2px;flex:1;min-width:0}
.mlist__body p{font-size:13px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.mlist__body small{display:inline-flex;align-items:center;gap:4px;font-size:11.5px;color:var(--faint)}

/* Sozlamalar */
.meter{height:8px;border-radius:8px;background:var(--surface-3);overflow:hidden;margin-bottom:16px}
.meter i{display:block;height:100%;width:var(--w);border-radius:inherit;background:linear-gradient(90deg,var(--accent),var(--ok));animation:grow 1.2s var(--e-out) both}
.checks{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.checks li{display:flex;align-items:center;gap:10px;padding:10px 12px;border-radius:12px;font-size:13px;background:var(--surface-2)}
.checks li>span{display:grid;place-items:center;flex:none;width:22px;height:22px;border-radius:7px}
.checks .is-ok>span{color:#fff;background:var(--ok)}
.checks .is-bad>span{color:#fff;background:var(--warn)}
.files{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:8px}
.files div{display:flex;align-items:center;gap:8px;min-width:0;padding:10px 12px;border-radius:12px;border:1px solid var(--border);font-size:13px}
.files span{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--muted)}
.strength{display:grid;grid-template-columns:repeat(4,1fr);gap:4px}
.strength i{height:4px;border-radius:4px;background:var(--surface-3);transition:background-color .25s}
.strength[data-level="1"] i:nth-child(-n+1){background:var(--danger)}
.strength[data-level="2"] i:nth-child(-n+2){background:var(--warn)}
.strength[data-level="3"] i:nth-child(-n+3){background:var(--info)}
.strength[data-level="4"] i{background:var(--ok)}

/* Modal va toast */
.modal{position:fixed;top:0; right:0; bottom:0; left:0;z-index:60;display:grid;place-items:center;padding:20px}
.modal[hidden]{display:none}
.modal__scrim{position:absolute;top:0; right:0; bottom:0; left:0;background:var(--scrim);opacity:0;transition:opacity .25s;-webkit-backdrop-filter:blur(3px);backdrop-filter:blur(3px)}
.modal__box{position:relative;display:grid;justify-items:center;gap:8px;width:min(100%,380px);padding:26px 22px 20px;border-radius:22px;text-align:center;background:var(--surface);box-shadow:var(--sh-lg);opacity:0;transform:scale(.94) translateY(10px);transition:transform .4s var(--e-spring),opacity .2s}
.modal.is-open .modal__scrim{opacity:1}
.modal.is-open .modal__box{opacity:1;transform:none}
.modal__icon{display:grid;place-items:center;width:52px;height:52px;border-radius:16px;color:var(--danger);background:var(--danger-soft);margin-bottom:4px}
.modal__title{font-size:17px}
.modal__text{font-size:13.5px;color:var(--muted)}
.modal__acts{display:grid;grid-template-columns:1fr 1fr;gap:8px;width:100%;margin-top:12px}
.modal__x{position:absolute;top:12px;right:12px;display:grid;place-items:center;width:32px;height:32px;border-radius:50%;color:var(--muted);background:var(--surface-2)}
.modal__box--user{width:min(100%,400px);padding-top:30px}
.detail{display:grid;justify-items:center;gap:6px;width:100%}
.detail .ava{box-shadow:0 0 0 4px var(--surface),0 0 0 5px var(--border)}
.detail__name{font:550 22px var(--serif);margin-top:8px}
.detail__handle{font-size:13.5px;color:var(--muted)}
.detail__rows{display:grid;width:100%;margin-top:14px;border-radius:14px;background:var(--surface-2);overflow:hidden}
.detail__row{display:flex;justify-content:space-between;gap:10px;padding:11px 14px;font-size:13.5px;border-bottom:1px solid var(--border)}
.detail__row:last-child{border-bottom:0}
.detail__row span{color:var(--muted)}
.toasts{position:fixed;top:calc(18px + var(--tg-top,0px));right:18px;z-index:70;display:grid;gap:8px}
.toast{display:flex;align-items:center;gap:10px;max-width:380px;padding:12px 16px;border-radius:14px;font-size:13.5px;font-weight:550;color:#fff;background:#0B172A;box-shadow:var(--sh-lg);animation:toastin .5s var(--e-spring) both}
.toast--ok .icon{color:#7BD8A8}
.toast--error .icon{color:#FF9A8A}
.toast.is-out{animation:toastout .3s ease forwards}
@keyframes toastin{from{opacity:0;transform:translateY(-12px) scale(.95)}}
@keyframes toastout{to{opacity:0;transform:translateY(-8px)}}

/* Tezkor amallar */
.quick{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px}
.quick__item{position:relative;display:grid;grid-template-columns:auto 1fr;grid-template-rows:auto auto;column-gap:12px;row-gap:10px;padding:16px;border-radius:18px;background:var(--surface);border:1px solid var(--border);box-shadow:var(--sh-sm);transition:transform .3s var(--e-spring),box-shadow .25s,border-color .2s}
.quick__item:hover{transform:translateY(-2px);box-shadow:var(--sh-md);border-color:var(--border-strong)}
.quick__item:active{transform:scale(.98)}
.quick__icon{grid-row:span 1;display:grid;place-items:center;width:42px;height:42px;border-radius:13px;color:#fff;background:linear-gradient(160deg,#399BFF,#0F5FD6);box-shadow:0 8px 18px -8px rgba(217,119,87,.8)}
.quick__body{display:grid;align-content:center;min-width:0}
.quick__body b{font-size:14.5px;font-weight:650}
.quick__body small{font-size:12px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.quick__meta{grid-column:1 / -1;font-size:12px;font-weight:600;color:var(--accent-ink);padding-top:10px;border-top:1px dashed var(--border)}
.quick__plus{position:absolute;right:14px;bottom:12px;display:grid;place-items:center;width:28px;height:28px;border-radius:50%;color:var(--accent-ink);background:var(--accent-softer)}

/* Pastki navigatsiya (telefon) */
.bnav{display:none}

/* ---------- Moslashuvchan ---------- */
@media (max-width:1180px){
  .quick{grid-template-columns:repeat(2,1fr)}
  .grid--kpi{grid-template-columns:repeat(2,1fr)}
  .grid--main,.grid--compose{grid-template-columns:1fr}
  .editor__grid{grid-template-columns:1fr}
  .editor__side{position:static}
}
@media (max-width:900px){
  .side{transform:translateX(-102%);box-shadow:var(--sh-lg)}
  .side__close{display:inline-grid}
  body.drawer-open .side{transform:none}
  .scrim{position:fixed;top:0; right:0; bottom:0; left:0;z-index:25;display:block;background:var(--scrim);opacity:0;pointer-events:none;transition:opacity .3s}
  body.drawer-open .scrim{opacity:1;pointer-events:auto}
  .main{margin-left:0}
  .top{padding:calc(12px + var(--tg-top,0px)) 16px 12px}
  .top__menu{display:inline-grid}
  .top__title h1{font-size:21px}
  .top__title p,.chip--date,.me__txt{display:none}
  .wrap{padding:6px 16px 40px}
  .ai__list,.checks{grid-template-columns:1fr}
  .pipeline{grid-template-columns:repeat(2,1fr)}
  .grid--orders{grid-template-columns:minmax(0,1fr)}
  .auth{grid-template-columns:1fr}
  .bnav{position:fixed;left:10px;right:10px;bottom:calc(10px + max(env(safe-area-inset-bottom,0px),var(--tg-bottom,0px)));z-index:28;display:grid;grid-template-columns:repeat(6,1fr);padding:6px;border-radius:22px;background:var(--surface); background:color-mix(in srgb,var(--surface) 90%,transparent);backdrop-filter:blur(20px) saturate(180%);-webkit-backdrop-filter:blur(20px) saturate(180%);border:1px solid var(--border);box-shadow:var(--sh-lg)}
  .bnav__item{display:grid;justify-items:center;gap:2px;padding:6px 0 4px;border-radius:16px;font-size:10.5px;font-weight:600;color:var(--faint);transition:color .2s}
  .bnav__icon{position:relative;display:grid;place-items:center;width:44px;height:28px;border-radius:14px;transition:background-color .25s,transform .3s var(--e-spring)}
  .bnav__item.is-active{color:var(--accent-ink)}
  .bnav__item.is-active .bnav__icon{background:var(--accent-soft)}
  .bnav__item:active .bnav__icon{transform:scale(.88)}
  .bnav__badge{position:absolute;top:-4px;right:4px;min-width:16px;height:16px;padding:0 4px;display:grid;place-items:center;border-radius:99px;font:700 9.5px/1 var(--font);font-style:normal;color:#fff;background:var(--accent);box-shadow:0 0 0 2px var(--surface)}
  .wrap{padding-bottom:calc(110px + var(--tg-bottom,0px))}
  .toasts{top:auto;bottom:96px}
  .toolbar .btn--primary{flex:1}
  .auth__art{display:none}
  .files{grid-template-columns:repeat(auto-fill,minmax(140px,1fr))}
  .icons{grid-template-columns:repeat(6,1fr)}
}
@media (max-width:520px){
  .top{gap:8px;padding:calc(10px + var(--tg-top,0px)) 12px 10px}
  .top__actions{gap:6px}
  .top__actions>a[aria-label="Buyurtmalar"],.me__ava{display:none}
  .me{padding:0;border:0;background:none;margin:0}
  .top__title h1{font-size:19px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .iconbtn{width:36px;height:36px}
  .quick__plus{top:12px;bottom:auto;right:12px}
  .quick__body{padding-right:30px}
  .quick{gap:10px}
  .quick__item{padding:14px;grid-template-columns:1fr}
  .quick__icon{width:38px;height:38px}
  .quick__body small{white-space:normal}
  .quick__meta{display:none}
  .pipeline{gap:8px}
  .stage{padding:12px}
  .stage b{font-size:22px}
  .editor .toolbar h2{order:-1;flex-basis:100%;font-size:20px}
  .tgprev{min-height:200px}
  .mlist li{align-items:flex-start}
  .ai{padding:18px 16px}
  .ai__head h2{font-size:18px}
  .grid--kpi{grid-template-columns:1fr 1fr;gap:10px}
  .kpi{padding:14px}
  .kpi__value{font-size:26px}
  .spark{display:none}
  .row2,.shots{grid-template-columns:1fr 1fr}
  .table td,.table th{padding:10px 8px}
  .toasts{left:12px;right:12px}
}
/* v3 — Telegram kirish, AI, bot, tarqatma */
.btn--tg{color:#fff;background:#2AABEE;box-shadow:0 8px 22px -10px rgba(42,171,238,.8)}
.tglogin{display:grid;gap:14px;margin-bottom:6px}
.tglogin[hidden]{display:none}
.tglogin__or{display:flex;align-items:center;gap:10px;font-size:12px;color:var(--faint)}
.tglogin__or i{flex:1;height:1px;background:var(--border)}
.alert--warn{color:var(--text-2);background:var(--warn-soft)}
.alert--warn .icon{color:var(--warn)}
.alert a{color:var(--accent-ink);text-decoration:underline}
.meter--lg{height:12px;margin:6px 0 12px}
.meter--lg i{transition:width .6s var(--e-out);animation:none}
.bcast{border-color:var(--accent-soft);box-shadow:0 0 0 4px var(--accent-softer),var(--sh-md)}
.bcast__stats{display:flex;flex-wrap:wrap;gap:8px 18px;font-size:13.5px}
.bcast__stats .ok{color:var(--ok)}
.kpi__value--txt{font-size:19px!important;line-height:1.3}
.ai__live{color:inherit}
code{font-family:'SF Mono',ui-monospace,Menlo,Consolas,monospace;font-size:.9em;padding:1px 5px;border-radius:6px;background:var(--surface-2);border:1px solid var(--border)}
.steps{display:grid;gap:8px;margin:2px 0 16px;padding-left:20px;font-size:13.5px;color:var(--text-2)}
.steps li{list-style:decimal}
.steps a{color:var(--accent-ink);text-decoration:underline}
.aitest{margin-top:14px;padding:14px;border-radius:14px;background:var(--surface-2);border:1px solid var(--border);font-size:14px;white-space:pre-wrap;line-height:1.55}
.aitest.is-bad{color:var(--danger);background:var(--danger-soft);border-color:transparent}
.aitest small{display:block;margin-top:8px;color:var(--muted);font-size:12px}
.ailog{display:grid}
.ailog li{display:grid;gap:4px;padding:12px 2px;border-top:1px solid var(--border)}
.ailog li:first-child{border-top:0}
.ailog__meta{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.ailog__meta small{color:var(--muted);font-size:12px}
.ailog__q{font-weight:600}
.ailog__a{color:var(--muted);font-size:13.5px}
.ailog__a--err{color:var(--danger)}
.ailog li.is-bad .ailog__q::before{content:'⚠ ';color:var(--danger)}
.me form{display:contents}
@media (prefers-reduced-motion:reduce){*{animation-duration:1ms!important;transition-duration:1ms!important}}
/* Vazifalar va sertifikatlar */
.pill--red{color:var(--danger);background:var(--danger-soft)}
.btn.is-loading{opacity:.7;pointer-events:none}
.task .order__project{margin-bottom:2px}
.tlink{display:flex;align-items:center;gap:8px;padding:11px 12px;border-radius:12px;font-size:13.5px;font-weight:600;color:var(--accent-ink);background:var(--accent-softer);border:1px solid var(--accent-soft);word-break:break-all}
.tlink span{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tmedia{display:block;width:100%;max-height:320px;border-radius:14px;overflow:hidden;background:#111;object-fit:contain}
.tmedia img{width:100%;max-height:320px;object-fit:contain;display:block;background:var(--surface-2)}
.tmedia--audio{background:none;height:44px}
.tfilebox{display:flex;align-items:center;gap:10px;padding:10px;border-radius:12px;background:var(--surface-2);border:1px solid var(--border)}
.tfilebox__icon{display:grid;place-items:center;width:38px;height:38px;flex:none;border-radius:10px;color:var(--accent-ink);background:var(--accent-softer)}
.tfilebox__meta{display:grid;flex:1;min-width:0}
.tfilebox__meta b{font-size:13.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tfilebox__meta small{font-size:11.5px;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tnote{padding:10px 12px;border-radius:12px;font-size:13px;color:var(--text-2);background:var(--danger-soft)}
#reject-modal .modal__box{width:min(100%,440px)}
#reject-modal textarea{width:100%;text-align:left}
.certgrid{display:grid;grid-template-columns:minmax(0,440px) minmax(0,1fr);gap:18px;align-items:start}
.certform{display:grid;gap:14px;position:sticky;top:calc(84px + var(--tg-top,0px))}
.certform .card__title{display:flex;align-items:center;gap:8px}
.certform form{display:grid;gap:12px}
.certform__type{display:flex}
.certform__type .seg{flex:1;justify-content:center;cursor:pointer}
.certpreview{border-radius:12px;overflow:hidden;border:1px solid var(--border);background:#E8EBEF;box-shadow:var(--sh-sm)}
.certpreview canvas{display:block;width:100%;height:auto}
.certcourse{padding-top:12px;border-top:1px dashed var(--border-strong)}
.certcourse__row{display:flex;gap:8px}
.certcourse__row .input{flex:1}
.grid--certs{grid-template-columns:repeat(auto-fill,minmax(min(100%,280px),1fr))}
.certitem{display:grid;gap:10px;padding:12px}
.certitem__img{border-radius:10px;overflow:hidden;aspect-ratio:1.414;background:var(--surface-2);display:grid;place-items:center}
.certitem__img img{width:100%;height:100%;object-fit:cover;display:block}
.certitem__none{display:inline-flex;align-items:center;gap:6px;font-size:13px;color:var(--muted)}
.certitem__body{display:grid;gap:3px}
.certitem__body .pill{justify-self:start}
.certitem__body b{font-size:15px}
.certitem__body small{font-size:12px;color:var(--muted)}
.certitem__acts{display:flex;flex-wrap:wrap;align-items:center;gap:6px}
.certitem__acts form{margin-left:auto}
.vmove{display:inline-flex;gap:4px}
.vmove form{display:inline}
.vmeta{display:flex;flex-wrap:wrap;gap:6px;margin-top:6px}
.vmeta span{display:inline-flex;align-items:center;height:22px;padding:0 8px;border-radius:99px;font-size:11px;font-weight:650;color:var(--text-2);background:var(--surface-2);border:1px solid var(--border)}
@media (max-width:980px){.certgrid{grid-template-columns:1fr}.certform{position:static}}
@media (min-width:981px) and (max-height:760px){.side__promo p,.side__promo-icon{display:none}}
@supports not (aspect-ratio:1/1){.pcard__media{height:180px}.drop--sm{height:200px}.icons__pick span{height:38px}.tgprev__img{height:150px}.certitem__img{height:190px}}

/* iPhone'da maydon bosilganda sahifa kattalashib ketmasin (16px dan kichik shrift zoom qiladi) */
@media (pointer:coarse),(max-width:980px){.input,select.input,textarea.input,.input--area{font-size:16px}}
CSS;
}

/* ==================================================================
   MIJOZ TOMONI
   ================================================================== */

function admin_js(): string
{
    return <<<'JS'
(function () {
    'use strict';
    var $ = function (s, r) { return (r || document).querySelector(s); };
    var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };

    /* ==============================================================
       TELEGRAM — mini app ichida ochilganda:
       - tepadagi soat / "Back" / "⋮" tugmalari sahifani yopmasin
       - Telegram'ning "Back" tugmasi haqiqatan orqaga qaytarsin
       ============================================================== */
    var tg = window.Telegram && window.Telegram.WebApp;
    var inTg = !!(tg && (tg.initData || (tg.platform && tg.platform !== 'unknown')));
    function safe(fn) { try { return fn(); } catch (e) { return null; } }

    function syncInsets() {
        if (!inTg) { return; }
        var d = tg.safeAreaInset || {}, c = tg.contentSafeAreaInset || {};
        var top = (d.top || 0) + (c.top || 0);
        /* Eski klientlar to'liq ekranda qiymat bermasa — xavfsiz zaxira */
        if (tg.isFullscreen && !c.top) { top = Math.max(top, (d.top || 24) + 48); }
        var bottom = (d.bottom || 0) + (c.bottom || 0);
        var root = document.documentElement.style;
        root.setProperty('--tg-top', top + 'px');
        root.setProperty('--tg-bottom', bottom + 'px');
    }

    function paintTg() {
        if (!inTg) { return; }
        var dark = document.documentElement.getAttribute('data-theme') === 'dark';
        var color = dark ? '#030B18' : '#E9EEF6';
        safe(function () { tg.setHeaderColor(color); });
        safe(function () { tg.setBackgroundColor(color); });
        safe(function () { tg.setBottomBarColor(color); });
    }

    /** "Orqaga" mantig'i: oyna → menyu → forma → bo'lim → boshqaruv → mini app */
    function goBack() {
        var modal = $('.modal.is-open');
        if (modal) { modal.classList.remove('is-open'); setTimeout(function () { modal.hidden = true; }, 250); return; }
        if (document.body.classList.contains('drawer-open')) { document.body.classList.remove('drawer-open'); return; }

        var q = new URLSearchParams(window.location.search);
        var page = q.get('p') || 'dashboard';
        var base = window.location.pathname.replace(/[^\/]*$/, '');

        if (q.has('new') || q.has('edit')) { window.location.href = '?p=' + page; return; }
        if (page !== 'dashboard' && !document.body.classList.contains('auth')) { window.location.href = '?p=dashboard'; return; }
        window.location.href = base + 'index.php';
    }
    window.__adminBack = goBack;

    if (inTg) {
        safe(function () { tg.ready(); });
        safe(function () { tg.expand(); });
        syncInsets();
        paintTg();
        safe(function () {
            tg.onEvent('safeAreaChanged', syncInsets);
            tg.onEvent('contentSafeAreaChanged', syncInsets);
            tg.onEvent('fullscreenChanged', syncInsets);
            tg.onEvent('viewportChanged', syncInsets);
        });
        safe(function () { tg.BackButton.onClick(goBack); tg.BackButton.show(); });
        document.documentElement.classList.add('in-tg');
    }

    /* Ko'rinish (light / dark) */
    $$('[data-theme-toggle]').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
            document.documentElement.setAttribute('data-theme', next);
            try { localStorage.setItem('tezmind-admin-theme', next); } catch (e) {}
            paintTg();
        });
    });

    /* Mobil menyu (drawer) */
    document.addEventListener('click', function (e) {
        var d = e.target.closest && e.target.closest('[data-drawer]');
        if (!d) { return; }
        document.body.classList.toggle('drawer-open', d.getAttribute('data-drawer') === 'open');
    });

    /* Topbar soyasi */
    var top = $('.top');
    if (top) {
        window.addEventListener('scroll', function () { top.classList.toggle('is-stuck', window.scrollY > 4); }, { passive: true });
    }

    /* Toastlar o'zi yo'qoladi */
    $$('.toast').forEach(function (t) {
        setTimeout(function () { t.classList.add('is-out'); setTimeout(function () { t.remove(); }, 320); }, 4200);
    });

    /* Parolni ko'rsatish */
    $$('[data-toggle-pw]').forEach(function (b) {
        b.addEventListener('click', function () {
            var i = $(b.getAttribute('data-toggle-pw'));
            if (i) { i.type = i.type === 'password' ? 'text' : 'password'; }
        });
    });

    /* Raqamlar noldan o'sib chiqadi */
    $$('[data-count]').forEach(function (node) {
        var target = parseInt(node.getAttribute('data-count'), 10) || 0;
        if (!target) { node.textContent = '0'; return; }
        var start = 0;
        function frame(now) {
            if (!start) { start = now; }
            var p = Math.min((now - start) / 1100, 1);
            node.textContent = Math.round(target * (1 - Math.pow(1 - p, 4))).toLocaleString('ru-RU');
            if (p < 1) { requestAnimationFrame(frame); }
        }
        requestAnimationFrame(frame);
    });

    /* Grafik: sichqoncha ostida qiymatlar */
    $$('[data-chart]').forEach(function (box) {
        var data = []; try { data = JSON.parse(box.getAttribute('data-chart')); } catch (e) { return; }
        var W = +box.getAttribute('data-w'), H = +box.getAttribute('data-h');
        var svg = $('svg', box), tip = $('.chart__tip', box), cur = $('.chart__cursor', box), dot = $('.chart__dot', box);
        function move(clientX) {
            var r = svg.getBoundingClientRect();
            var x = (clientX - r.left) / r.width * W;
            var best = data[0], dist = 1e9;
            data.forEach(function (p) { var d = Math.abs(p.x - x); if (d < dist) { dist = d; best = p; } });
            cur.setAttribute('x1', best.x); cur.setAttribute('x2', best.x);
            dot.setAttribute('cx', best.x); dot.setAttribute('cy', best.y);
            tip.hidden = false;
            tip.style.left = (best.x / W * r.width) + 'px';
            tip.style.top = (best.y / H * r.height) + 'px';
            tip.children[0].textContent = best.l;
            tip.children[1].textContent = best.v + ' tashrif';
            tip.children[2].textContent = best.u + ' foydalanuvchi';
            box.classList.add('is-hover');
        }
        svg.addEventListener('mousemove', function (e) { move(e.clientX); });
        svg.addEventListener('touchmove', function (e) { move(e.touches[0].clientX); }, { passive: true });
        svg.addEventListener('mouseleave', function () { box.classList.remove('is-hover'); tip.hidden = true; });
    });

    /* Foydalanuvchilarni qidirish */
    var search = $('#user-search');
    if (search) {
        search.addEventListener('input', function () {
            var q = search.value.trim().toLowerCase(), shown = 0;
            $$('.urow').forEach(function (row) {
                var ok = !q || (row.getAttribute('data-search') || '').indexOf(q) !== -1;
                row.style.display = ok ? '' : 'none';
                if (ok) { shown++; }
            });
            var empty = $('#user-empty'); if (empty) { empty.hidden = shown > 0; }
        });
    }

    /* Modal oynalar */
    function openModal(m) { if (!m) { return; } m.hidden = false; requestAnimationFrame(function () { requestAnimationFrame(function () { m.classList.add('is-open'); }); }); }
    function closeModal(m) { if (!m || m.hidden) { return; } m.classList.remove('is-open'); setTimeout(function () { m.hidden = true; }, 250); }

    function esc(t) { var n = document.createElement('div'); n.textContent = t == null ? '' : String(t); return n.innerHTML; }
    function fmt(iso) {
        if (!iso) { return '—'; }
        var d = new Date(iso); if (isNaN(d.getTime())) { return '—'; }
        return d.toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });
    }
    var langs = { uz: "O‘zbekcha", en: 'English', ru: 'Русский' };

    function openUser(data) {
        var modal = $('#user-modal'), box = $('#user-detail');
        if (!modal || !box) { return; }
        var letter = '<span class="ava ava--letter" style="width:84px;height:84px;font-size:32px">' + esc((data.name || 'A').charAt(0).toUpperCase()) + '</span>';
        var ava = data.photo
            ? '<img class="ava" src="' + esc(data.photo) + '" alt="" referrerpolicy="no-referrer" style="width:84px;height:84px">'
            : letter;
        var rows = [
            ['Telegram ID', data.id], ['Username', data.username ? '@' + data.username : '—'],
            ['Premium', data.premium ? 'Ha ⭐' : 'Yo‘q'], ['Til', langs[data.locale] || data.locale || '—'],
            ['Kurs (tugatgan darslar)', data.course || '—'], ['Qurilma', data.platform || '—'],
            ['Tashriflar', data.visits], ['Birinchi kirish', fmt(data.first_seen)], ['Oxirgi kirish', fmt(data.last_seen)]
        ];
        box.innerHTML = '<div class="detail">' + ava +
            '<div class="detail__name">' + esc(data.name || 'Nomsiz') + '</div>' +
            '<div class="detail__handle">' + esc(data.username ? '@' + data.username : 'username yo‘q') + '</div>' +
            '<div class="detail__rows">' + rows.map(function (r) { return '<div class="detail__row"><span>' + esc(r[0]) + '</span><b>' + esc(r[1]) + '</b></div>'; }).join('') + '</div>' +
            (data.username
                ? '<a class="btn btn--primary btn--wide" style="margin-top:16px" href="https://t.me/' + esc(data.username) + '" target="_blank" rel="noopener">Telegramda yozish</a>'
                : '<button class="btn btn--ghost btn--wide" style="margin-top:16px" disabled>Username yo‘q — yozib bo‘lmaydi</button>') +
            '</div>';
        var img = box.querySelector('img.ava');
        if (img) { img.addEventListener('error', function () { img.outerHTML = letter; }); }
        openModal(modal);
    }

    document.addEventListener('click', function (e) {
        var row = e.target.closest && e.target.closest('[data-user]');
        if (row) { try { openUser(JSON.parse(row.getAttribute('data-user'))); } catch (err) {} return; }
        var close = e.target.closest && e.target.closest('[data-close]');
        if (close) { closeModal(close.closest('.modal')); }
    });
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') { $$('.modal.is-open').forEach(closeModal); document.body.classList.remove('drawer-open'); }
        if (e.key === 'Backspace' && e.altKey) { goBack(); }
        if (e.key === 'Enter' && e.target.matches && e.target.matches('.urow')) { e.target.click(); }
    });

    /* O'chirish/chiqishdan oldin — chiroyli tasdiqlash oynasi */
    var confirmBox = $('#confirm'), pending = null;
    function ask(text, okLabel, then) {
        if (!confirmBox) { if (window.confirm(text)) { then(); } return; }
        $('#confirm-text').textContent = text;
        $('#confirm-ok').textContent = okLabel || 'O‘chirish';
        pending = then;
        openModal(confirmBox);
    }
    if (confirmBox) {
        $('#confirm-ok').addEventListener('click', function () { var f = pending; pending = null; closeModal(confirmBox); if (f) { f(); } });
    }
    $$('form[data-confirm]').forEach(function (form) {
        form.addEventListener('submit', function (e) {
            if (form.dataset.confirmed) { return; }
            e.preventDefault();
            ask(form.getAttribute('data-confirm'), form.getAttribute('data-confirm-ok'), function () { form.dataset.confirmed = '1'; form.submit(); });
        });
    });
    $$('a[data-confirm]').forEach(function (a) {
        a.addEventListener('click', function (e) {
            e.preventDefault();
            ask(a.getAttribute('data-confirm'), a.getAttribute('data-confirm-ok'), function () { window.location.href = a.href; });
        });
    });

    /* Uch tilli maydon tablari */
    $$('[data-ltabs]').forEach(function (box) {
        function mark() {
            $$('.ltabs__btn', box).forEach(function (b) {
                var f = $('[data-pane="' + b.getAttribute('data-lang') + '"] .input', box);
                b.classList.toggle('has-value', !!(f && f.value.trim()));
            });
        }
        box.addEventListener('click', function (e) {
            var b = e.target.closest('.ltabs__btn'); if (!b) { return; }
            var l = b.getAttribute('data-lang');
            $$('.ltabs__btn', box).forEach(function (x) { x.classList.toggle('is-on', x === b); });
            $$('.ltabs__pane', box).forEach(function (p) { p.classList.toggle('is-on', p.getAttribute('data-pane') === l); });
            var f = $('[data-pane="' + l + '"] .input', box); if (f) { f.focus(); }
        });
        box.addEventListener('input', mark);
        mark();
    });

    /* Loyiha kartasi — jonli ko'rinish */
    var nameIn = $('[data-preview="name"]'), accentIn = $('[data-preview="accent"]');
    if (nameIn) { nameIn.addEventListener('input', function () { var o = $('[data-preview-name]'); if (o) { o.textContent = nameIn.value || 'Loyiha nomi'; } }); }
    if (accentIn) { accentIn.addEventListener('input', function () { var p = $('.preview'); if (p) { p.style.setProperty('--p1', accentIn.value); } }); }
    $$('.icons__pick input').forEach(function (r) {
        r.addEventListener('change', function () { var o = $('[data-preview-icon]'); if (o) { o.innerHTML = r.nextElementSibling.innerHTML; } });
    });

    /* Xabar — Telegram ko'rinishida jonli oldindan ko'rish */
    $$('[data-live]').forEach(function (inp) {
        var key = inp.getAttribute('data-live');
        inp.addEventListener(key === 'image' ? 'change' : 'input', function () {
            if (key === 'image') {
                var img = $('[data-live-img]'), f = inp.files && inp.files[0];
                if (img && f) { img.style.backgroundImage = 'url(' + URL.createObjectURL(f) + ')'; img.hidden = false; }
                return;
            }
            var out = $('[data-live-out="' + key + '"]');
            if (out) { out.textContent = inp.value || (key === 'title' ? 'Sarlavha' : 'Xabar matni shu yerda ko‘rinadi…'); }
        });
    });

    /* Parol kuchi */
    $$('[data-strength]').forEach(function (inp) {
        var meter = inp.closest('.field').querySelector('.strength');
        inp.addEventListener('input', function () {
            var v = inp.value, s = 0;
            if (v.length >= 8) { s++; } if (/[A-Z]/.test(v) && /[a-z]/.test(v)) { s++; } if (/\d/.test(v)) { s++; } if (/[^A-Za-z0-9]/.test(v) && v.length >= 10) { s++; }
            if (meter) { meter.setAttribute('data-level', v ? Math.max(1, s) : 0); }
        });
    });

    /* Rasm tanlanganda — oldindan ko'rish + drag & drop */
    $$('.drop input[type="file"]').forEach(function (inp) {
        var drop = inp.closest('.drop');
        inp.addEventListener('change', function () {
            var f = inp.files && inp.files[0];
            if (!f || !drop || !/^image\//.test(f.type)) { return; }
            var img = drop.querySelector('img');
            if (!img) { img = document.createElement('img'); drop.insertBefore(img, inp); }
            img.src = URL.createObjectURL(f);
        });
        ['dragenter', 'dragover'].forEach(function (ev) { drop.addEventListener(ev, function () { drop.classList.add('is-over'); }); });
        ['dragleave', 'drop'].forEach(function (ev) { drop.addEventListener(ev, function () { drop.classList.remove('is-over'); }); });
    });

    /* --------------------------------------------------------------
       RASMNI YUKLASHDAN OLDIN BRAUZERDA SIQISH
       (upload_max_filesize chegarasiga urilmaslik uchun)
       -------------------------------------------------------------- */
    (function () {
        var MAX_SIDE = 1600, QUALITY = 0.85, pending = new Set();
        function compressible(f) { return !!f && /^image\/(jpeg|png|webp)$/i.test(f.type); }
        function compress(file) {
            return new Promise(function (resolve) {
                if (!compressible(file) || !window.createImageBitmap || !window.DataTransfer) { resolve(file); return; }
                createImageBitmap(file).then(function (bmp) {
                    var r = Math.min(1, MAX_SIDE / Math.max(bmp.width, bmp.height));
                    var c = document.createElement('canvas');
                    c.width = Math.max(1, Math.round(bmp.width * r)); c.height = Math.max(1, Math.round(bmp.height * r));
                    var ctx = c.getContext('2d');
                    ctx.drawImage(bmp, 0, 0, c.width, c.height);
                    if (bmp.close) { bmp.close(); }
                    /* Shaffof rasm (logo) — o'zgartirmaymiz, aks holda foni qora bo'lib qoladi */
                    if (file.type !== 'image/jpeg') {
                        var px = ctx.getImageData(0, 0, c.width, c.height).data;
                        for (var k = 3; k < px.length; k += 16) { if (px[k] < 250) { resolve(file); return; } }
                    }
                    ctx.globalCompositeOperation = 'destination-over';
                    ctx.fillStyle = '#ffffff';
                    ctx.fillRect(0, 0, c.width, c.height);
                    c.toBlob(function (blob) {
                        if (!blob || blob.size >= file.size) { resolve(file); return; }
                        resolve(new File([blob], file.name.replace(/\.(png|jpe?g|webp)$/i, '') + '.jpg', { type: 'image/jpeg', lastModified: Date.now() }));
                    }, 'image/jpeg', QUALITY);
                }).catch(function () { resolve(file); });
            });
        }
        $$('input[type="file"][accept*="image"]').forEach(function (input) {
            input.addEventListener('change', function () {
                var file = input.files && input.files[0]; if (!file) { return; }
                var task = compress(file).then(function (res) {
                    if (res !== file && window.DataTransfer) { var dt = new DataTransfer(); dt.items.add(res); input.files = dt.files; }
                });
                pending.add(task); task.then(function () { pending.delete(task); });
            });
        });
        $$('form').forEach(function (form) {
            if (!form.querySelector('input[type="file"][accept*="image"]')) { return; }
            form.addEventListener('submit', function (e) {
                if (pending.size === 0) { return; }
                e.preventDefault();
                var b = form.querySelector('button[type="submit"]'); if (b) { b.disabled = true; b.textContent = 'Tayyorlanmoqda…'; }
                Promise.all(Array.from(pending)).then(function () { form.submit(); });
            });
        });
    }());

    /* Telegram tarqatma — bosqichma-bosqich, sahifa ochiq turganda */
    var bcast = $('#bcast');
    if (bcast) {
        var setStat = function (k, v) { var n = $('[data-bcast="' + k + '"]', bcast); if (n) { n.textContent = v; } };
        var step = function () {
            var fd = new FormData();
            fd.append('id', bcast.getAttribute('data-id'));
            fd.append('csrf', bcast.getAttribute('data-csrf'));
            fetch('?ajax=broadcast_step', { method: 'POST', body: fd, credentials: 'same-origin' })
                .then(function (r) { return r.json(); })
                .then(function (d) {
                    if (!d || !d.ok || !d.job) { setStat('status', 'Xatolik. 5 soniyadan keyin qayta urinamiz…'); setTimeout(step, 5000); return; }
                    var j = d.job;
                    setStat('pos', j.pos); setStat('sent', j.sent); setStat('blocked', j.blocked); setStat('failed', j.failed);
                    var bar = $('[data-bcast-bar]', bcast); if (bar) { bar.style.setProperty('--w', j.percent + '%'); }
                    if (j.done) { setStat('status', '✅ Tayyor! ' + j.sent + ' kishiga yetkazildi.'); setTimeout(function () { location.href = '?p=messages'; }, 2200); return; }
                    if (d.wait) { setStat('status', 'Telegram limiti — ' + d.wait + ' soniya kutamiz…'); setTimeout(step, d.wait * 1000 + 300); return; }
                    setStat('status', d.busy ? 'Boshqa oynada yuborilmoqda…' : 'Yuborilmoqda… ' + j.percent + '%');
                    setTimeout(step, d.busy ? 3000 : 150);
                })
                .catch(function () { setStat('status', 'Internet uzildi. Qayta urinilmoqda…'); setTimeout(step, 4000); });
        };
        step();
        window.addEventListener('beforeunload', function (e) { if (!/Tayyor/.test(($('[data-bcast="status"]', bcast) || {}).textContent || '')) { e.preventDefault(); e.returnValue = ''; } });
    }

    /* AI yordamchi — provayder tanlanganda maslahatlar */
    var prov = $('[data-ai-provider]');
    if (prov) {
        prov.addEventListener('change', function () {
            var o = prov.options[prov.selectedIndex];
            var model = $('[data-ai-model]'); if (model) { model.placeholder = o.getAttribute('data-model') || 'model nomi'; }
            var note = $('[data-ai-note]'); if (note) { note.textContent = o.getAttribute('data-note') || ''; }
            var link = $('[data-ai-link]'); if (link) { link.href = link.textContent = o.getAttribute('data-link') || ''; }
            var base = $('[data-ai-base]'); if (base) { base.hidden = prov.value !== 'openai'; }
        });
    }

    /* AI yordamchi — sinov */
    var aiTest = $('[data-ai-test]');
    if (aiTest) {
        aiTest.addEventListener('submit', function (e) {
            e.preventDefault();
            var out = $('[data-ai-out]'), btn = $('button', aiTest);
            var fd = new FormData(aiTest);
            fd.append('csrf', aiTest.getAttribute('data-csrf'));
            btn.disabled = true; out.hidden = false; out.className = 'aitest'; out.textContent = 'Javob kutilmoqda…';
            fetch('?ajax=ai_test', { method: 'POST', body: fd, credentials: 'same-origin' })
                .then(function (r) { return r.json(); })
                .then(function (d) {
                    out.className = 'aitest' + (d.ok ? '' : ' is-bad');
                    out.textContent = d.ok ? d.text : ('Xato: ' + (d.error || 'noma’lum'));
                    var meta = document.createElement('small');
                    meta.textContent = (d.model || '') + ' · ' + ((d.ms || 0) / 1000).toFixed(1) + ' s';
                    out.appendChild(meta);
                })
                .catch(function () { out.className = 'aitest is-bad'; out.textContent = 'Server javob bermadi'; })
                .then(function () { btn.disabled = false; });
        });
    }


    /* ==============================================================
       SERTIFIKAT / TASHAKKURNOMA — canvas'da chiziladi (2400×1697)
       ============================================================== */
    var TMCert = (function () {
        var W = 2400, H = 1697;
        var NAVY = '#1E2A3B', GRAY = '#5B6573', LIGHT = '#8B95A3', BRAND = '#1677FF';
        var MONTHS = ['YANVAR', 'FEVRAL', 'MART', 'APREL', 'MAY', 'IYUN', 'IYUL', 'AVGUST', 'SENTABR', 'OKTABR', 'NOYABR', 'DEKABR'];
        var SCRIPT = '"Great Vibes", "Marck Script", "Brush Script MT", cursive';
        var ready = null;

        function fonts() {
            if (ready) { return ready; }
            if (!document.fonts || !document.fonts.load) { ready = Promise.resolve(); return ready; }
            var list = ['700 90px Oswald', '600 40px Oswald', '700 30px Montserrat', '600 30px Montserrat', '500 30px Montserrat', '400 30px Montserrat',
                '150px "Great Vibes"', '150px "Marck Script"'];
            ready = Promise.all(list.map(function (f) { return document.fonts.load(f, 'AaOo‘БбЖж').catch(function () {}); }))
                .then(function () { return document.fonts.ready; }).catch(function () {});
            return ready;
        }

        function rng(seed) {
            var s = seed >>> 0;
            return function () {
                s = (s + 0x6D2B79F5) >>> 0;
                var t = s;
                t = Math.imul(t ^ (t >>> 15), t | 1);
                t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
                return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
            };
        }

        function rr(g, x, y, w, h, r) {
            g.beginPath();
            g.moveTo(x + r, y);
            g.arcTo(x + w, y, x + w, y + h, r);
            g.arcTo(x + w, y + h, x, y + h, r);
            g.arcTo(x, y + h, x, y, r);
            g.arcTo(x, y, x + w, y, r);
            g.closePath();
        }

        /** Harflar orasini ochib yozish (letter-spacing). */
        function spaced(g, text, x, y, spacing, align) {
            var chars = Array.from(text);
            var widths = chars.map(function (c) { return g.measureText(c).width; });
            var total = widths.reduce(function (a, b) { return a + b; }, 0) + spacing * (chars.length - 1);
            var cx = align === 'center' ? x - total / 2 : (align === 'right' ? x - total : x);
            var prev = g.textAlign;
            g.textAlign = 'left';
            chars.forEach(function (c, i) { g.fillText(c, cx, y); cx += widths[i] + spacing; });
            g.textAlign = prev;
            return total;
        }

        function spacedWidth(g, text, spacing) {
            var chars = Array.from(text);
            return chars.reduce(function (a, c) { return a + g.measureText(c).width; }, 0) + spacing * (chars.length - 1);
        }

        function fit(g, text, weightFamily, size, maxW, min) {
            var s = size;
            do { g.font = weightFamily.replace('{s}', s); s -= 4; } while (g.measureText(text).width > maxW && s > (min || 20));
            return s + 4;
        }

        function wrap(g, text, maxW) {
            var words = String(text).split(/\s+/), lines = [], line = '';
            words.forEach(function (w) {
                var test = line ? line + ' ' + w : w;
                if (g.measureText(test).width > maxW && line) { lines.push(line); line = w; } else { line = test; }
            });
            if (line) { lines.push(line); }
            return lines;
        }

        function dateLabel(iso) {
            var p = String(iso || '').split('-');
            if (p.length < 3) { var d = new Date(); p = [d.getFullYear(), d.getMonth() + 1, d.getDate()]; }
            return parseInt(p[2], 10) + '-' + MONTHS[(parseInt(p[1], 10) || 1) - 1] + '-' + p[0];
        }

        function seal(g, x, y, thanks, year) {
            var ring = thanks ? '#B9933F' : NAVY;
            g.save();
            g.shadowColor = 'rgba(20,30,45,.28)';
            g.shadowBlur = 30;
            g.shadowOffsetY = 10;
            g.fillStyle = '#fff';
            g.beginPath(); g.arc(x, y, 168, 0, Math.PI * 2); g.fill();
            g.restore();
            var grd = g.createLinearGradient(x - 150, y - 150, x + 150, y + 150);
            grd.addColorStop(0, thanks ? '#D9B862' : '#2E3F57');
            grd.addColorStop(1, ring);
            g.fillStyle = grd;
            g.beginPath(); g.arc(x, y, 152, 0, Math.PI * 2); g.fill();
            g.strokeStyle = 'rgba(255,255,255,.95)';
            g.lineWidth = 5;
            g.beginPath(); g.arc(x, y, 130, 0, Math.PI * 2); g.stroke();
            g.setLineDash([3, 9]);
            g.lineWidth = 3;
            g.beginPath(); g.arc(x, y, 116, 0, Math.PI * 2); g.stroke();
            g.setLineDash([]);
            // Dafna barglari
            g.fillStyle = '#fff';
            [-1, 1].forEach(function (side) {
                for (var i = 0; i < 9; i++) {
                    var a = Math.PI / 2 + side * (0.55 + i * 0.2);
                    var px = x + Math.cos(a) * 92, py = y + Math.sin(a) * 92;
                    g.save();
                    g.translate(px, py);
                    g.rotate(a + side * 0.9);
                    g.beginPath(); g.ellipse(0, 0, 13, 5.5, 0, 0, Math.PI * 2); g.fill();
                    g.restore();
                }
            });
            g.textAlign = 'center';
            g.fillStyle = '#fff';
            g.font = '600 26px Oswald, sans-serif';
            spaced(g, 'TEZMIND', x, y - 30, 4, 'center');
            g.font = '700 58px Oswald, sans-serif';
            g.fillText(String(year), x, y + 30);
            // Pastda uchta yulduzcha (barglar orasiga sig'adi)
            [-30, 0, 30].forEach(function (dx, i) {
                var r = i === 1 ? 11 : 8, sx = x + dx, sy = y + 66 - (i === 1 ? 3 : 0);
                g.beginPath();
                for (var k = 0; k < 10; k++) {
                    var ang = -Math.PI / 2 + k * Math.PI / 5, rad = k % 2 ? r * 0.45 : r;
                    g[k ? 'lineTo' : 'moveTo'](sx + Math.cos(ang) * rad, sy + Math.sin(ang) * rad);
                }
                g.closePath();
                g.fill();
            });
        }

        function bolt(g, x, y, size) {
            rr(g, x, y, size, size, size * 0.24);
            g.fillStyle = NAVY;
            g.fill();
            g.save();
            g.translate(x, y);
            g.scale(size / 64, size / 64);
            g.fillStyle = '#fff';
            g.fill(new Path2D('M35.2 13 20 35.4h11.1L28.6 51 44 28.4H32.9L35.2 13Z'));
            g.fillStyle = BRAND;
            g.beginPath(); g.arc(47, 17, 3.2, 0, Math.PI * 2); g.fill();
            g.restore();
        }

        function draw(g, d) {
            var thanks = d.type === 'appreciation';
            var cx = 150, cy = 210, cw = 2100, ch = 1280;
            var year = String(d.date || '').slice(0, 4) || new Date().getFullYear();

            // Fon va to'q ko'k shakllar
            g.fillStyle = '#E8EBEF';
            g.fillRect(0, 0, W, H);
            var bg = g.createRadialGradient(W / 2, H / 2, 200, W / 2, H / 2, W * 0.75);
            bg.addColorStop(0, 'rgba(255,255,255,.75)');
            bg.addColorStop(1, 'rgba(255,255,255,0)');
            g.fillStyle = bg;
            g.fillRect(0, 0, W, H);
            g.fillStyle = thanks ? '#22304A' : NAVY;
            g.beginPath(); g.ellipse(1640, 250, 560, 320, -0.22, 0, Math.PI * 2); g.fill();
            g.beginPath(); g.ellipse(860, 1470, 600, 270, -0.12, 0, Math.PI * 2); g.fill();

            // Oq varaq
            g.save();
            g.shadowColor = 'rgba(20,30,45,.24)';
            g.shadowBlur = 80;
            g.shadowOffsetY = 26;
            g.fillStyle = '#FFFFFF';
            g.fillRect(cx, cy, cw, ch);
            g.restore();

            // Nozik uchburchak naqsh
            g.save();
            g.beginPath(); g.rect(cx, cy, cw, ch); g.clip();
            var rand = rng(20261010), size = 150;
            for (var yy = cy - size; yy < cy + ch + size; yy += size) {
                for (var xx = cx - size; xx < cx + cw + size; xx += size) {
                    for (var k = 0; k < 2; k++) {
                        g.fillStyle = 'rgba(30,42,59,' + (rand() * 0.05).toFixed(3) + ')';
                        g.beginPath();
                        if (k === 0) { g.moveTo(xx, yy); g.lineTo(xx + size, yy); g.lineTo(xx, yy + size); }
                        else { g.moveTo(xx + size, yy); g.lineTo(xx + size, yy + size); g.lineTo(xx, yy + size); }
                        g.closePath();
                        g.fill();
                    }
                }
            }
            var fade = g.createRadialGradient(W / 2, cy + ch * 0.58, 120, W / 2, cy + ch * 0.58, cw * 0.55);
            fade.addColorStop(0, 'rgba(255,255,255,.92)');
            fade.addColorStop(0.7, 'rgba(255,255,255,.55)');
            fade.addColorStop(1, 'rgba(255,255,255,0)');
            g.fillStyle = fade;
            g.fillRect(cx, cy, cw, ch);
            g.restore();
            g.strokeStyle = 'rgba(30,42,59,.13)';
            g.lineWidth = 2;
            g.strokeRect(cx + 34, cy + 34, cw - 68, ch - 68);

            // Brend
            bolt(g, cx + 110, cy + 112, 118);
            g.textAlign = 'left';
            g.textBaseline = 'alphabetic';
            g.fillStyle = NAVY;
            g.font = '700 64px Montserrat, sans-serif';
            g.fillText('TEZMIND', cx + 255, cy + 182);
            var tw = g.measureText('TEZMIND').width;
            g.fillStyle = BRAND;
            g.fillText('.UZ', cx + 255 + tw + 4, cy + 182);
            g.fillStyle = LIGHT;
            g.font = '500 25px Montserrat, sans-serif';
            spaced(g, 'www.tezmind.uz', cx + 258, cy + 224, 4, 'left');

            // Lenta + muhr
            // Lenta muhrning ostidan o'tadi; matn faqat muhrgacha bo'lgan joyga sig'diriladi
            var sealX = cx + cw - 230, sealR = 168;
            var by = cy + 112, bh = 176, bx = cx + 880;
            var tl = bx + 44, tr = sealX - sealR - 34, tcx = (tl + tr) / 2, tw = tr - tl;
            g.fillStyle = NAVY;
            rr(g, bx, by, sealX - bx + 40, bh, 20);
            g.fill();
            var title = thanks ? 'TASHAKKURNOMA' : 'SERTIFIKAT';
            g.fillStyle = '#FFFFFF';
            var tsize = 100, tsp = 10;
            g.font = '700 ' + tsize + 'px Oswald, sans-serif';
            while (spacedWidth(g, title, tsp) > tw && tsize > 48) { tsize -= 4; tsp = Math.max(4, tsp - 1); g.font = '700 ' + tsize + 'px Oswald, sans-serif'; }
            spaced(g, title, tcx, by + 108, tsp, 'center');
            var sub = thanks ? 'FAOLLIK VA A’LO NATIJALAR UCHUN' : 'KURSNI MUVAFFAQIYATLI TUGATGANI UCHUN';
            var ssize = 23, ssp = 5;
            g.font = '600 ' + ssize + 'px Montserrat, sans-serif';
            while (spacedWidth(g, sub, ssp) > tw && (ssp > 1 || ssize > 16)) {
                if (ssp > 1) { ssp -= 1; } else { ssize -= 1; g.font = '600 ' + ssize + 'px Montserrat, sans-serif'; }
            }
            g.fillStyle = 'rgba(255,255,255,.86)';
            spaced(g, sub, tcx, by + 150, ssp, 'center');
            seal(g, sealX, by + bh / 2, thanks, year);

            // Matn
            var mid = W / 2;
            g.textAlign = 'center';
            g.fillStyle = GRAY;
            g.font = '500 31px Montserrat, sans-serif';
            g.fillText(thanks ? 'Ushbu tashakkurnoma quyidagi shaxsga taqdim etiladi' : 'Ushbu sertifikat quyidagi shaxsga taqdim etiladi', mid, cy + 470);

            g.fillStyle = NAVY;
            fit(g, d.name || 'Ism Familiya', '{s}px ' + SCRIPT, 176, 1500, 80);
            g.fillText(d.name || 'Ism Familiya', mid, cy + 690);
            g.strokeStyle = '#AEB6C1';
            g.lineWidth = 2;
            g.beginPath(); g.moveTo(mid - 640, cy + 742); g.lineTo(mid + 640, cy + 742); g.stroke();

            var body = thanks
                ? (d.reason || 'Darslarda faol ishtirok etgani, ijodiy loyihalari va a’lo natijalari uchun AKBARTECH jamoasi o‘z minnatdorchiligini bildiradi.')
                : 'AKBARTECH platformasidagi «' + (d.course || 'Prompt engineering va AI coding') + '» kursining barcha ' + (d.lessons || '') + ' ta darsini ketma-ket o‘zlashtirgani va amaliy vazifalarni muvaffaqiyatli bajargani uchun taqdim etiladi.';
            var bsize = 31, lines;
            do {
                g.font = '400 ' + bsize + 'px Montserrat, sans-serif';
                lines = wrap(g, body.replace(/\s+/g, ' '), 1480);
                bsize -= 2;
            } while (lines.length > 3 && bsize > 20);
            g.fillStyle = GRAY;
            lines.forEach(function (line, i) { g.fillText(line, mid, cy + 815 + i * (bsize + 17)); });

            // Sana
            g.font = '600 40px Oswald, sans-serif';
            var dl = dateLabel(d.date);
            var dw = spacedWidth(g, dl, 6) + 120;
            g.fillStyle = NAVY;
            rr(g, mid - dw / 2, cy + 958, dw, 86, 8);
            g.fill();
            g.fillStyle = '#FFFFFF';
            spaced(g, dl, mid, cy + 1016, 6, 'center');

            // Pastki imzolar
            var lx = cx + 190, rx = cx + cw - 190;
            g.textAlign = 'left';
            g.fillStyle = NAVY;
            g.font = '700 31px Montserrat, sans-serif';
            g.fillText('Berildi:', lx, cy + 1130);
            g.fillStyle = GRAY;
            g.font = '500 29px Montserrat, sans-serif';
            g.fillText('AKBARTECH tomonidan', lx, cy + 1176);

            g.save();
            g.translate(rx - 220, cy + 1075);
            g.rotate(-0.05);
            g.textAlign = 'center';
            g.fillStyle = NAVY;
            g.font = '78px ' + SCRIPT;
            g.fillText('Akbar Abduraimov', 0, 0);
            g.restore();
            g.strokeStyle = '#AEB6C1';
            g.lineWidth = 2;
            g.beginPath(); g.moveTo(rx - 440, cy + 1096); g.lineTo(rx, cy + 1096); g.stroke();
            g.textAlign = 'right';
            g.fillStyle = NAVY;
            g.font = '700 31px Montserrat, sans-serif';
            g.fillText('Teacher:', rx, cy + 1146);
            g.fillStyle = GRAY;
            g.font = '500 29px Montserrat, sans-serif';
            g.fillText('Akbar Abduraimov', rx, cy + 1190);

            g.textAlign = 'center';
            g.fillStyle = LIGHT;
            g.font = '500 22px Montserrat, sans-serif';
            spaced(g, '№ ' + (d.number || 'TM-0000') + '   ·   TEZMIND.UZ', mid, cy + 1222, 3, 'center');
        }

        function render(data, canvas) {
            return fonts().then(function () {
                canvas = canvas || document.createElement('canvas');
                canvas.width = W;
                canvas.height = H;
                draw(canvas.getContext('2d'), data || {});
                return canvas;
            });
        }

        function toBlob(canvas, quality, scale) {
            var src = canvas;
            if (scale && scale < 1) {
                src = document.createElement('canvas');
                src.width = Math.round(W * scale);
                src.height = Math.round(H * scale);
                src.getContext('2d').drawImage(canvas, 0, 0, src.width, src.height);
            }
            return new Promise(function (resolve) { src.toBlob(resolve, 'image/jpeg', quality || 0.92); });
        }

        return { render: render, toBlob: toBlob };
    }());
    window.TMCert = TMCert;

    function csrfValue() {
        var input = $('input[name="csrf"]');
        return input ? input.value : '';
    }

    function ajax(name, data) {
        var fd = data instanceof FormData ? data : new FormData();
        if (!(data instanceof FormData)) { Object.keys(data || {}).forEach(function (k) { fd.append(k, data[k]); }); }
        fd.append('csrf', csrfValue());
        return fetch('?ajax=' + encodeURIComponent(name), { method: 'POST', body: fd, credentials: 'same-origin' })
            .then(function (r) { return r.json().catch(function () { return { ok: false, error: 'http_' + r.status }; }); });
    }

    function flash(message, kind) {
        var host = $('#toasts');
        if (!host) { return; }
        var node = document.createElement('div');
        node.className = 'toast toast--' + (kind === 'error' ? 'error' : 'ok');
        node.setAttribute('role', 'status');
        node.innerHTML = '<span></span>';
        node.firstChild.textContent = message;
        host.appendChild(node);
        setTimeout(function () { node.classList.add('is-out'); setTimeout(function () { node.remove(); }, 320); }, 3600);
    }

    /** Sertifikat rasmini chizib, serverga yuklaydi (katta bo'lsa — siqib qayta urinadi). */
    function issueImage(cert) {
        return TMCert.render(cert).then(function (canvas) {
            var attempt = function (q, scale) {
                return TMCert.toBlob(canvas, q, scale).then(function (blob) {
                    var fd = new FormData();
                    fd.append('id', cert.id);
                    fd.append('image', blob, 'certificate.jpg');
                    return ajax('cert_image', fd);
                });
            };
            return attempt(0.92, 1).then(function (res) {
                if (res && res.ok) { return res; }
                return attempt(0.8, 0.75);
            });
        });
    }

    /* --- Vazifalar: qabul qilish / qaytarish --- */
    $$('[data-review]').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var id = btn.getAttribute('data-id');
            var decision = btn.getAttribute('data-review');
            if (decision === 'reject') {
                var modal = $('#reject-modal');
                if (!modal) { return; }
                modal.hidden = false;
                requestAnimationFrame(function () { modal.classList.add('is-open'); });
                var note = $('#reject-note');
                note.value = '';
                setTimeout(function () { note.focus(); }, 120);
                var ok = $('#reject-ok');
                var fresh = ok.cloneNode(true);
                ok.parentNode.replaceChild(fresh, ok);
                fresh.addEventListener('click', function () {
                    fresh.disabled = true;
                    ajax('task_review', { id: id, decision: 'reject', note: note.value }).then(function (res) {
                        if (res && res.ok) { location.reload(); } else { fresh.disabled = false; flash('Saqlab bo‘lmadi', 'error'); }
                    });
                });
                $$('[data-close]', modal).forEach(function (c) {
                    c.onclick = function () { modal.classList.remove('is-open'); setTimeout(function () { modal.hidden = true; }, 250); };
                });
                return;
            }
            btn.disabled = true;
            btn.classList.add('is-loading');
            ajax('task_review', { id: id, decision: 'accept' }).then(function (res) {
                if (!res || !res.ok) { btn.disabled = false; btn.classList.remove('is-loading'); flash('Saqlab bo‘lmadi', 'error'); return null; }
                if (res.cert) {
                    flash('Kurs tugadi! Sertifikat chizilmoqda…');
                    return issueImage(res.cert).then(function (r) {
                        flash(r && r.ok ? (r.sent ? 'Sertifikat o‘quvchiga yuborildi 🎓' : 'Sertifikat saqlandi (bot yubora olmadi)') : 'Sertifikat rasmi yuklanmadi — “Sertifikatlar” bo‘limida qayta yarating', r && r.ok ? 'ok' : 'error');
                        setTimeout(function () { location.reload(); }, 1400);
                    });
                }
                flash('Qabul qilindi — keyingi dars ochildi ✓');
                setTimeout(function () { location.reload(); }, 700);
                return null;
            }).catch(function () { btn.disabled = false; btn.classList.remove('is-loading'); flash('Tarmoq xatosi', 'error'); });
        });
    });

    /* --- Sertifikatlar sahifasi --- */
    var certForm = $('#cert-form');
    if (certForm) {
        var canvas = $('#cert-canvas');
        var nameInput = certForm.querySelector('[name="name"]');
        var reason = certForm.querySelector('[name="reason"]');
        var select = certForm.querySelector('[name="uid"]');
        var autoName = true;
        var timer = 0;
        var type = function () { var r = certForm.querySelector('[name="type"]:checked'); return r ? r.value : 'appreciation'; };
        var data = function () {
            return {
                type: type(), name: nameInput.value.trim(), reason: reason.value.trim(),
                course: certForm.getAttribute('data-course'), lessons: certForm.getAttribute('data-lessons'),
                number: certForm.getAttribute('data-next'), date: certForm.getAttribute('data-today')
            };
        };
        var preview = function () { clearTimeout(timer); timer = setTimeout(function () { TMCert.render(data(), canvas); }, 180); };
        $$('.certform__type .seg', certForm).forEach(function (label) {
            label.addEventListener('click', function () {
                $$('.certform__type .seg', certForm).forEach(function (l) { l.classList.toggle('is-active', l === label); });
                setTimeout(function () {
                    $('[data-reason]', certForm).hidden = type() !== 'appreciation';
                    preview();
                }, 0);
            });
        });
        $('[data-reason]', certForm).hidden = type() !== 'appreciation';
        select.addEventListener('change', function () {
            var opt = select.options[select.selectedIndex];
            if (opt && (autoName || !nameInput.value.trim())) { nameInput.value = opt.getAttribute('data-name') || ''; autoName = true; }
            preview();
        });
        if (select.value) { select.dispatchEvent(new Event('change')); }
        nameInput.addEventListener('input', function () { autoName = false; preview(); });
        reason.addEventListener('input', preview);
        preview();

        certForm.addEventListener('submit', function (event) {
            event.preventDefault();
            var d = data();
            if (!select.value || !d.name) { flash('O‘quvchi va ismni kiriting', 'error'); return; }
            var btn = certForm.querySelector('button[type="submit"]');
            btn.disabled = true;
            btn.classList.add('is-loading');
            ajax('cert_prepare', { uid: select.value, type: d.type, name: d.name, reason: d.type === 'appreciation' ? d.reason : '' }).then(function (res) {
                if (!res || !res.ok) { throw new Error((res && res.error) || 'fail'); }
                return issueImage(res.cert);
            }).then(function (r) {
                if (!r || !r.ok) { throw new Error('image'); }
                flash(r.sent ? 'Hujjat o‘quvchiga yuborildi ✓' : 'Hujjat saqlandi (bot yubora olmadi — o‘quvchi botni bloklagan bo‘lishi mumkin)');
                setTimeout(function () { location.reload(); }, 1200);
            }).catch(function () {
                btn.disabled = false;
                btn.classList.remove('is-loading');
                flash('Hujjatni berib bo‘lmadi', 'error');
            });
        });
    }

    $$('[data-cert-regen]').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var cert = JSON.parse(btn.getAttribute('data-cert-regen'));
            btn.disabled = true;
            issueImage(cert).then(function (r) {
                flash(r && r.ok ? 'Rasm yaratildi va yuborildi ✓' : 'Yaratib bo‘lmadi', r && r.ok ? 'ok' : 'error');
                setTimeout(function () { location.reload(); }, 1000);
            }).catch(function () { btn.disabled = false; flash('Yaratib bo‘lmadi', 'error'); });
        });
    });
    $$('[data-cert-resend]').forEach(function (btn) {
        btn.addEventListener('click', function () {
            btn.disabled = true;
            ajax('cert_resend', { id: btn.getAttribute('data-cert-resend') }).then(function (r) {
                btn.disabled = false;
                flash(r && r.ok ? 'Botga qayta yuborildi ✓' : 'Yuborib bo‘lmadi', r && r.ok ? 'ok' : 'error');
            });
        });
    });

    /* Yuborish tugmasi ikki marta bosilmasin */
    $$('form').forEach(function (form) {
        form.addEventListener('submit', function (e) {
            if (e.defaultPrevented) { return; }
            var b = form.querySelector('button[type="submit"]');
            if (b) { setTimeout(function () { b.disabled = true; }, 10); }
        });
    });
}());
JS;
}

/* ==================================================================
   ISHGA TUSHIRISH
   ================================================================== */

require_view();