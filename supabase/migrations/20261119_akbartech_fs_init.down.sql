-- ⚠️ DESTRUCTIVE: drops ALL AKBARTECH data (users, orders, uploads, sessions).
-- Backup first:  pg_dump "$DATABASE_URL" -n akbartech -Fc -f akbartech_backup.dump
drop function if exists public.akb_fs_gc(text, text, integer);
drop function if exists public.akb_fs_unlock(text, text, text);
drop function if exists public.akb_fs_lock(text, text, text, integer);
drop function if exists public.akb_fs_list(text, text);
drop function if exists public.akb_fs_rmdir(text, text);
drop function if exists public.akb_fs_mkdir(text, text);
drop function if exists public.akb_fs_rename(text, text, text);
drop function if exists public.akb_fs_unlink(text, text);
drop function if exists public.akb_fs_write(text, text, text, boolean);
drop function if exists public.akb_fs_read(text, text);
drop function if exists public.akb_fs_stat(text, text);
drop schema if exists akbartech cascade;
