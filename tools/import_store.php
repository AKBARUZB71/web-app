<?php

declare(strict_types=1);

/**
 * One-time import of the old hosting's data into Supabase.
 *
 * Usage (run on your own computer, PHP 8.1+ with curl):
 *   SUPABASE_URL=https://xxx.supabase.co SUPABASE_PUBLISHABLE_KEY=sb_publishable_... AKB_DB_KEY=... \
 *     php tools/import_store.php /path/to/old/uz
 *
 * Copies <old>/store/** and <old>/uploads/** byte-for-byte. Existing remote files
 * with the same name are overwritten. Lock/tmp files are skipped.
 */

require __DIR__ . '/../lib/akbfs.php';

const SKIP_PATTERN = '/(\.lock|\.tmp|\.htaccess|index\.html)$/';
const SAFE_PATH = '#^[A-Za-z0-9._/-]{1,300}$#';

function env_or_exit(string $name): string
{
    $value = getenv($name);
    if (!is_string($value) || trim($value) === '') {
        fwrite(STDERR, "Missing env: {$name}\n");
        exit(1);
    }
    return trim($value);
}

function import_dir(string $localRoot, string $remoteRoot): array
{
    $stats = ['ok' => 0, 'skipped' => 0];
    if (!is_dir($localRoot)) {
        return $stats;
    }
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($localRoot, FilesystemIterator::SKIP_DOTS));
    foreach ($iterator as $file) {
        if (!$file->isFile()) {
            continue;
        }
        $relative = str_replace('\\', '/', substr($file->getPathname(), strlen($localRoot) + 1));
        if (preg_match(SKIP_PATTERN, $relative) || !preg_match(SAFE_PATH, $relative)) {
            echo "  skip  {$relative}\n";
            $stats['skipped']++;
            continue;
        }
        $data = file_get_contents($file->getPathname());
        if ($data === false || file_put_contents("akbfs://{$remoteRoot}/{$relative}", $data) === false) {
            fwrite(STDERR, "  FAIL  {$relative}\n");
            exit(2);
        }
        echo "  ok    {$remoteRoot}/{$relative} (" . strlen($data) . " B)\n";
        $stats['ok']++;
    }
    return $stats;
}

$source = rtrim((string) ($argv[1] ?? ''), '/\\');
if ($source === '' || !is_dir($source)) {
    fwrite(STDERR, "Usage: php tools/import_store.php /path/to/old/uz\n");
    exit(1);
}

AkbFs::register(env_or_exit('SUPABASE_URL'), env_or_exit('SUPABASE_PUBLISHABLE_KEY'), env_or_exit('AKB_DB_KEY'));

foreach (['store', 'uploads'] as $dir) {
    echo "[{$dir}]\n";
    $result = import_dir($source . '/' . $dir, $dir);
    echo "  => {$result['ok']} imported, {$result['skipped']} skipped\n";
}
