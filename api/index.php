<?php

declare(strict_types=1);

/**
 * Vercel front controller for AKBARTECH.
 *
 * Every non-static request lands here (see vercel.json). Responsibilities:
 *   1. Normalise $_SERVER behind Vercel's proxy (client IP, host, https, script name).
 *   2. Mount akbfs:// (Supabase) as storage for store/, uploads/ and admin sessions.
 *   3. Serve /uploads/* from storage; dispatch /admin.php and the app.
 */

const APP_DIR = __DIR__ . '/../app';
const UPLOAD_EXT_MIME = [
    'jpg'  => 'image/jpeg',
    'jpeg' => 'image/jpeg',
    'png'  => 'image/png',
    'gif'  => 'image/gif',
    'webp' => 'image/webp',
];
const UPLOAD_CACHE_HEADER = 'public, max-age=86400, s-maxage=31536000, immutable';

require __DIR__ . '/../lib/akbfs.php';

function fail_plain(int $status, string $message): never
{
    http_response_code($status);
    header('Content-Type: text/plain; charset=UTF-8');
    header('Cache-Control: no-store');
    echo $message;
    exit;
}

function env_required(string $name): string
{
    $value = getenv($name);
    if (!is_string($value) || trim($value) === '') {
        error_log('[bootstrap] missing env ' . $name);
        fail_plain(500, 'Server is not configured.');
    }
    return trim($value);
}

function first_header_value(string $serverKey): string
{
    $raw = (string) ($_SERVER[$serverKey] ?? '');
    return trim(explode(',', $raw)[0]);
}

function normalise_server(): void
{
    // Vercel overwrites x-real-ip / x-forwarded-for with the real client IP,
    // so they are trustworthy here. CF-Connecting-IP is NOT (client-controlled
    // on Vercel) — drop it, otherwise rate limits could be bypassed.
    unset($_SERVER['HTTP_CF_CONNECTING_IP']);
    $ip = first_header_value('HTTP_X_REAL_IP') ?: first_header_value('HTTP_X_FORWARDED_FOR');
    if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP)) {
        $_SERVER['REMOTE_ADDR'] = $ip;
    }

    $host = first_header_value('HTTP_X_FORWARDED_HOST');
    if ($host !== '' && preg_match('/^[A-Za-z0-9.\-]+(:\d+)?$/', $host)) {
        $_SERVER['HTTP_HOST'] = $host;
    }
    $_SERVER['HTTPS'] = 'on';
    $_SERVER['HTTP_X_FORWARDED_PROTO'] = 'https';
    $_SERVER['SERVER_PORT'] = '443';
}

function serve_upload(string $name): never
{
    if (!preg_match('#^(avatars/)?[A-Za-z0-9][A-Za-z0-9._-]{0,120}$#', $name)) {
        fail_plain(404, 'Not found');
    }
    $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
    $mime = UPLOAD_EXT_MIME[$ext] ?? null;
    if ($mime === null) {
        fail_plain(404, 'Not found');
    }
    try {
        $data = @file_get_contents('akbfs://uploads/' . $name);
    } catch (AkbFsException $e) {
        fail_plain(503, 'Storage unavailable');
    }
    if ($data === false) {
        fail_plain(404, 'Not found');
    }
    header('Content-Type: ' . $mime);
    header('Content-Length: ' . strlen($data));
    header('Cache-Control: ' . UPLOAD_CACHE_HEADER);
    header('X-Content-Type-Options: nosniff');
    header("Content-Security-Policy: default-src 'none'");
    echo $data;
    exit;
}

normalise_server();

AkbFs::register(
    env_required('SUPABASE_URL'),
    env_required('SUPABASE_PUBLISHABLE_KEY'),
    env_required('AKB_DB_KEY')
);
define('AKB_STORE_ROOT', 'akbfs://store');
define('AKB_UPLOADS_ROOT', 'akbfs://uploads');
session_set_save_handler(new AkbSessionHandler(), true);

$path = (string) (parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH) ?? '/');
$path = '/' . ltrim(rawurldecode($path), '/');

if (str_starts_with($path, '/uploads/')) {
    serve_upload(substr($path, strlen('/uploads/')));
}

chdir(APP_DIR);

if ($path === '/admin.php' || $path === '/admin') {
    $_SERVER['SCRIPT_NAME'] = '/admin.php';
    $_SERVER['PHP_SELF'] = '/admin.php';
    $_SERVER['SCRIPT_FILENAME'] = APP_DIR . '/admin.php';
    require APP_DIR . '/admin.php';
    exit;
}

if ($path === '/' || $path === '/index.php') {
    $_SERVER['SCRIPT_NAME'] = '/index.php';
    $_SERVER['PHP_SELF'] = '/index.php';
    $_SERVER['SCRIPT_FILENAME'] = APP_DIR . '/index.php';
    require APP_DIR . '/index.php';
    exit;
}

fail_plain(404, 'Not found');
