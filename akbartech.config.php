<?php

declare(strict_types=1);

/**
 * Secrets come from Vercel Environment Variables — never commit real values.
 * index.php loads this file from dirname(app/) and merges known keys only.
 * Empty env values are skipped so index.php defaults stay in effect.
 */

$env = static function (string $name): ?string {
    $value = getenv($name);
    return is_string($value) && trim($value) !== '' ? trim($value) : null;
};

$config = [
    'bot_token'       => $env('BOT_TOKEN'),
    'admin_tg_id'     => $env('ADMIN_TG_ID') !== null ? (int) $env('ADMIN_TG_ID') : null,
    'setup_key'       => $env('SETUP_KEY'),
    'admin_user'      => $env('ADMIN_USER'),
    'admin_pass_hash' => $env('ADMIN_PASS_HASH'),
    'ai_provider'     => $env('AI_PROVIDER'),
    'ai_key'          => $env('AI_KEY'),
    'ai_model'        => $env('AI_MODEL'),
    'debug'           => false,
];

return array_filter($config, static fn ($value): bool => $value !== null);
