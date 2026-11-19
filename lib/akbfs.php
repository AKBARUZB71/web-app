<?php

declare(strict_types=1);

/**
 * akbfs:// — stream wrapper that maps the app's file storage (store/, uploads/)
 * onto Supabase Postgres via SECURITY DEFINER RPC functions (public.akb_fs_*).
 *
 * Why: Vercel functions have an ephemeral, per-instance filesystem. The app
 * stores everything as files, so we swap the storage root instead of rewriting
 * 20k lines. Every standard call (file_get_contents, file_put_contents, rename,
 * unlink, is_file, scandir, fopen + flock) keeps working.
 *
 * Safety rule: a failed READ throws (request aborts with 500) instead of
 * returning empty data — otherwise a read-modify-write could wipe a store.
 */

final class AkbFsException extends RuntimeException
{
}

final class AkbFs
{
    public const SCHEME = 'akbfs';

    private const CONNECT_TIMEOUT = 3;
    private const REQUEST_TIMEOUT = 12;
    private const MAX_ATTEMPTS = 2;
    private const LOCK_TTL_SECONDS = 20;
    private const LOCK_WAIT_SECONDS = 10.0;
    private const LOCK_POLL_MICROS = 60000;

    private static string $baseUrl = '';
    private static string $apiKey = '';
    private static string $dbKey = '';
    private static string $owner = '';

    /** @var array<string, array|false> per-request stat cache */
    private static array $statCache = [];
    /** @var array<string, string|null> per-request content cache */
    private static array $dataCache = [];

    /** @var resource|null required by PHP for stream wrappers */
    public $context;

    private string $path = '';
    private string $buffer = '';
    private int $position = 0;
    private bool $dirty = false;
    private bool $writable = false;
    private bool $append = false;
    private bool $virtual = false;
    private bool $locked = false;
    /** @var string[] */
    private array $dirEntries = [];
    private int $dirIndex = 0;

    public static function register(string $supabaseUrl, string $apiKey, string $dbKey): void
    {
        self::$baseUrl = rtrim($supabaseUrl, '/') . '/rest/v1/rpc/';
        self::$apiKey = $apiKey;
        self::$dbKey = $dbKey;
        self::$owner = bin2hex(random_bytes(8));
        if (!in_array(self::SCHEME, stream_get_wrappers(), true)) {
            stream_wrapper_register(self::SCHEME, self::class);
        }
    }

    /* ------------------------------------------------------------------
       RPC transport
       ------------------------------------------------------------------ */

    /** @return mixed decoded JSON result */
    public static function rpc(string $function, array $args)
    {
        $payload = json_encode(['p_key' => self::$dbKey] + $args, JSON_UNESCAPED_SLASHES);
        if ($payload === false) {
            throw new AkbFsException('akbfs: payload encode failed');
        }

        $lastError = '';
        for ($attempt = 1; $attempt <= self::MAX_ATTEMPTS; $attempt++) {
            $handle = curl_init(self::$baseUrl . $function);
            curl_setopt_array($handle, [
                CURLOPT_POST           => true,
                CURLOPT_POSTFIELDS     => $payload,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_CONNECTTIMEOUT => self::CONNECT_TIMEOUT,
                CURLOPT_TIMEOUT        => self::REQUEST_TIMEOUT,
                CURLOPT_HTTPHEADER     => [
                    'apikey: ' . self::$apiKey,
                    'Content-Type: application/json',
                    'Accept: application/json',
                ],
            ]);
            $body = curl_exec($handle);
            $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
            $curlError = curl_error($handle);
            curl_close($handle);

            if ($body !== false && $status >= 200 && $status < 300) {
                return json_decode((string) $body, true);
            }
            $lastError = $curlError !== '' ? $curlError : ('HTTP ' . $status . ' ' . substr((string) $body, 0, 300));
            // 4xx (bad key, bad path) will not succeed on retry
            if ($status >= 400 && $status < 500) {
                break;
            }
            usleep(150000);
        }

        error_log('[akbfs] ' . $function . ' failed: ' . $lastError);
        throw new AkbFsException('storage_unavailable');
    }

    private static function rel(string $url): string
    {
        $prefix = self::SCHEME . '://';
        $rel = str_starts_with($url, $prefix) ? substr($url, strlen($prefix)) : $url;
        $rel = trim(preg_replace('#/{2,}#', '/', $rel) ?? '', '/');
        if ($rel !== '' && (!preg_match('#^[A-Za-z0-9._/-]{1,300}$#', $rel) || preg_match('#(^|/)\.\.(/|$)#', $rel))) {
            throw new AkbFsException('akbfs: invalid path');
        }
        return $rel;
    }

    private static function forget(string $rel, bool $prefix = false): void
    {
        unset(self::$statCache[$rel], self::$dataCache[$rel]);
        if ($prefix) {
            foreach (array_keys(self::$statCache) as $key) {
                if (str_starts_with((string) $key, $rel . '/')) {
                    unset(self::$statCache[$key]);
                }
            }
            foreach (array_keys(self::$dataCache) as $key) {
                if (str_starts_with((string) $key, $rel . '/')) {
                    unset(self::$dataCache[$key]);
                }
            }
        }
        // parent dirs may change existence
        $parent = dirname($rel);
        while ($parent !== '.' && $parent !== '') {
            unset(self::$statCache[$parent]);
            $parent = dirname($parent);
        }
    }

    private static function flushCaches(): void
    {
        self::$statCache = [];
        self::$dataCache = [];
    }

    /** Lock files are virtual: they exist only as DB leases, never as rows. */
    private static function isLockPath(string $rel): bool
    {
        return str_ends_with($rel, '.lock');
    }

    private static function fetch(string $rel): ?string
    {
        if (array_key_exists($rel, self::$dataCache)) {
            return self::$dataCache[$rel];
        }
        $b64 = self::rpc('akb_fs_read', ['p_path' => $rel]);
        $data = is_string($b64) ? base64_decode(str_replace(["\n", "\r"], '', $b64), true) : null;
        if ($data === false) {
            throw new AkbFsException('akbfs: corrupt payload');
        }
        if ($data === null) {
            self::$statCache[$rel] = false;
        }
        return self::$dataCache[$rel] = $data;
    }

    private static function fileStat(int $size, int $mtime, bool $isDir = false): array
    {
        $mode = $isDir ? 0040777 : 0100666;
        return [
            0 => 0, 'dev' => 0, 1 => 0, 'ino' => 0, 2 => $mode, 'mode' => $mode, 3 => 1, 'nlink' => 1,
            4 => 0, 'uid' => 0, 5 => 0, 'gid' => 0, 6 => 0, 'rdev' => 0, 7 => $size, 'size' => $size,
            8 => $mtime, 'atime' => $mtime, 9 => $mtime, 'mtime' => $mtime, 10 => $mtime, 'ctime' => $mtime,
            11 => -1, 'blksize' => -1, 12 => -1, 'blocks' => -1,
        ];
    }

    private static function store(string $rel, string $data): void
    {
        self::rpc('akb_fs_write', ['p_path' => $rel, 'p_b64' => base64_encode($data), 'p_append' => false]);
        self::forget($rel);
        self::$dataCache[$rel] = $data;
    }

    private static function statOf(string $rel)
    {
        if (array_key_exists($rel, self::$statCache)) {
            return self::$statCache[$rel];
        }
        if (isset(self::$dataCache[$rel])) {
            return self::$statCache[$rel] = self::fileStat(strlen((string) self::$dataCache[$rel]), time());
        }
        // store/*.php are small JSON blobs that are read right after is_file():
        // one read RPC answers both questions.
        if (str_starts_with($rel, 'store/') && str_ends_with($rel, '.php')) {
            $data = self::fetch($rel);
            return self::$statCache[$rel] = $data === null ? false : self::fileStat(strlen($data), time());
        }
        $info = self::rpc('akb_fs_stat', ['p_path' => $rel]);
        if (!is_array($info) || empty($info['exists'])) {
            return self::$statCache[$rel] = false;
        }
        return self::$statCache[$rel] = self::fileStat(
            (int) ($info['size'] ?? 0),
            (int) ($info['mtime'] ?? time()),
            !empty($info['is_dir'])
        );
    }

    /* ------------------------------------------------------------------
       Stream wrapper: file handles
       ------------------------------------------------------------------ */

    public function stream_open(string $path, string $mode, int $options, ?string &$openedPath): bool
    {
        $this->path = self::rel($path);
        $base = str_replace(['b', 't'], '', $mode);
        $this->virtual = self::isLockPath($this->path);

        if ($this->virtual) {
            $this->writable = true;
            return true;
        }

        switch ($base[0] ?? 'r') {
            case 'r':
                $data = self::fetch($this->path);
                if ($data === null) {
                    return false;
                }
                $this->buffer = $data;
                $this->writable = str_contains($base, '+');
                break;
            case 'w':
                $this->buffer = '';
                $this->writable = true;
                $this->dirty = true;
                break;
            case 'a':
                $this->buffer = (string) self::fetch($this->path);
                $this->writable = true;
                $this->append = true;
                $this->dirty = true;
                break;
            case 'x':
                if (self::fetch($this->path) !== null) {
                    return false;
                }
                $this->buffer = '';
                $this->writable = true;
                $this->dirty = true;
                break;
            case 'c':
                $existing = self::fetch($this->path);
                $this->buffer = (string) $existing;
                $this->writable = true;
                $this->dirty = $existing === null;
                break;
            default:
                return false;
        }

        $this->position = $this->append ? strlen($this->buffer) : 0;
        return true;
    }

    public function stream_read(int $count): string
    {
        $chunk = (string) substr($this->buffer, $this->position, $count);
        $this->position += strlen($chunk);
        return $chunk;
    }

    public function stream_write(string $data): int
    {
        if (!$this->writable || $this->virtual) {
            return $this->virtual ? strlen($data) : 0;
        }
        if ($this->append) {
            $this->position = strlen($this->buffer);
        }
        $before = substr($this->buffer, 0, $this->position);
        $after = (string) substr($this->buffer, $this->position + strlen($data));
        $this->buffer = $before . $data . $after;
        $this->position += strlen($data);
        $this->dirty = true;
        return strlen($data);
    }

    public function stream_truncate(int $size): bool
    {
        if (!$this->writable) {
            return false;
        }
        $this->buffer = str_pad(substr($this->buffer, 0, $size), $size, "\0");
        $this->dirty = true;
        return true;
    }

    public function stream_eof(): bool
    {
        return $this->position >= strlen($this->buffer);
    }

    public function stream_tell(): int
    {
        return $this->position;
    }

    public function stream_seek(int $offset, int $whence = SEEK_SET): bool
    {
        $target = match ($whence) {
            SEEK_CUR => $this->position + $offset,
            SEEK_END => strlen($this->buffer) + $offset,
            default  => $offset,
        };
        if ($target < 0) {
            return false;
        }
        $this->position = $target;
        return true;
    }

    public function stream_flush(): bool
    {
        if ($this->dirty && !$this->virtual) {
            self::store($this->path, $this->buffer);
            $this->dirty = false;
        }
        return true;
    }

    public function stream_close(): void
    {
        $this->stream_flush();
        if ($this->locked) {
            $this->releaseLock();
        }
    }

    public function stream_stat()
    {
        $size = strlen($this->buffer);
        $now = time();
        return [
            'dev' => 0, 'ino' => 0, 'mode' => 0100666, 'nlink' => 1, 'uid' => 0, 'gid' => 0, 'rdev' => 0,
            'size' => $size, 'atime' => $now, 'mtime' => $now, 'ctime' => $now, 'blksize' => -1, 'blocks' => -1,
        ];
    }

    public function stream_lock(int $operation): bool
    {
        // Only *.lock files carry real cross-instance locks (store_update, broadcast).
        if (!$this->virtual) {
            return true;
        }
        if (($operation & LOCK_UN) === LOCK_UN) {
            $this->releaseLock();
            return true;
        }
        $nonBlocking = ($operation & LOCK_NB) === LOCK_NB;
        $deadline = microtime(true) + self::LOCK_WAIT_SECONDS;
        do {
            $ok = self::rpc('akb_fs_lock', [
                'p_path'  => $this->path,
                'p_owner' => self::$owner,
                'p_ttl'   => self::LOCK_TTL_SECONDS,
            ]);
            if ($ok === true) {
                $this->locked = true;
                // anything read before the lock may be stale now
                self::flushCaches();
                return true;
            }
            if ($nonBlocking) {
                return false;
            }
            usleep(self::LOCK_POLL_MICROS);
        } while (microtime(true) < $deadline);

        error_log('[akbfs] lock timeout: ' . $this->path);
        return false;
    }

    private function releaseLock(): void
    {
        if (!$this->locked) {
            return;
        }
        $this->locked = false;
        try {
            self::rpc('akb_fs_unlock', ['p_path' => $this->path, 'p_owner' => self::$owner]);
        } catch (AkbFsException $e) {
            // lease expires by TTL anyway
        }
    }

    public function stream_set_option(int $option, int $arg1, ?int $arg2): bool
    {
        return false;
    }

    public function stream_metadata(string $path, int $option, $value): bool
    {
        $rel = self::rel($path);
        if ($option === STREAM_META_TOUCH) {
            if (!self::isLockPath($rel) && self::fetch($rel) === null) {
                self::store($rel, '');
            }
        }
        // chmod/chown/chgrp are meaningless here
        return true;
    }

    /* ------------------------------------------------------------------
       Stream wrapper: paths and directories
       ------------------------------------------------------------------ */

    public function url_stat(string $path, int $flags)
    {
        $rel = self::rel($path);
        if (self::isLockPath($rel)) {
            return false;
        }
        return self::statOf($rel);
    }

    public function unlink(string $path): bool
    {
        $rel = self::rel($path);
        if (self::isLockPath($rel)) {
            return true;
        }
        $ok = self::rpc('akb_fs_unlink', ['p_path' => $rel]) === true;
        self::forget($rel);
        self::$dataCache[$rel] = null;
        self::$statCache[$rel] = false;
        return $ok;
    }

    public function rename(string $from, string $to): bool
    {
        $relFrom = self::rel($from);
        $relTo = self::rel($to);
        $cached = self::$dataCache[$relFrom] ?? null;
        $ok = self::rpc('akb_fs_rename', ['p_from' => $relFrom, 'p_to' => $relTo]) === true;
        self::forget($relFrom, true);
        self::forget($relTo, true);
        if ($ok) {
            self::$dataCache[$relFrom] = null;
            self::$statCache[$relFrom] = false;
            if ($cached !== null) {
                self::$dataCache[$relTo] = $cached;
            }
        }
        return $ok;
    }

    public function mkdir(string $path, int $mode, int $options): bool
    {
        $rel = self::rel($path);
        $ok = self::rpc('akb_fs_mkdir', ['p_path' => $rel]) === true;
        self::forget($rel);
        return $ok;
    }

    public function rmdir(string $path, int $options): bool
    {
        $rel = self::rel($path);
        $ok = self::rpc('akb_fs_rmdir', ['p_path' => $rel]) === true;
        self::forget($rel, true);
        return $ok;
    }

    public function dir_opendir(string $path, int $options): bool
    {
        $rel = self::rel($path);
        $rows = self::rpc('akb_fs_list', ['p_dir' => $rel]);
        $this->dirEntries = array_merge(['.', '..'], array_values(array_filter(
            array_map('strval', is_array($rows) ? $rows : []),
            static fn (string $name): bool => $name !== ''
        )));
        $this->dirIndex = 0;
        return true;
    }

    public function dir_readdir()
    {
        return $this->dirEntries[$this->dirIndex++] ?? false;
    }

    public function dir_rewinddir(): bool
    {
        $this->dirIndex = 0;
        return true;
    }

    public function dir_closedir(): bool
    {
        $this->dirEntries = [];
        return true;
    }

    /** Remove files under $dir older than $maxAge seconds. */
    public static function gc(string $dir, int $maxAge): int
    {
        return (int) self::rpc('akb_fs_gc', ['p_dir' => self::rel($dir), 'p_max_age' => $maxAge]);
    }
}

/**
 * PHP sessions (admin panel) stored in akbfs://sessions/ so they survive
 * across serverless instances.
 */
final class AkbSessionHandler implements SessionHandlerInterface
{
    private const DIR = 'akbfs://sessions';

    private static function file(string $id): string
    {
        return self::DIR . '/' . hash('sha256', $id) . '.sess';
    }

    public function open(string $path, string $name): bool
    {
        return true;
    }

    public function close(): bool
    {
        return true;
    }

    public function read(string $id): string|false
    {
        if (!preg_match('/^[A-Za-z0-9,-]{16,256}$/', $id)) {
            return '';
        }
        $data = @file_get_contents(self::file($id));
        return $data === false ? '' : $data;
    }

    public function write(string $id, string $data): bool
    {
        if (!preg_match('/^[A-Za-z0-9,-]{16,256}$/', $id)) {
            return false;
        }
        return file_put_contents(self::file($id), $data) !== false;
    }

    public function destroy(string $id): bool
    {
        @unlink(self::file($id));
        return true;
    }

    public function gc(int $max_lifetime): int|false
    {
        try {
            return AkbFs::gc(self::DIR, $max_lifetime);
        } catch (AkbFsException $e) {
            return 0;
        }
    }
}
