-- AKBARTECH: isolated file-like storage for the PHP app (Vercel).
-- Applied to Supabase project nqwfchugrlorkdotyfcp as migration "akbartech_fs_init".
-- Access only through public.akb_* SECURITY DEFINER functions guarded by a shared secret
-- (AKB_DB_KEY in Vercel env; only its sha256 is stored in akbartech.secrets).
create schema if not exists akbartech;
revoke all on schema akbartech from public, anon, authenticated;

create table akbartech.files (
  id          bigint generated always as identity primary key,
  path        text not null unique check (length(path) between 1 and 300 and path ~ '^[A-Za-z0-9._/-]+$' and path !~ '(^|/)\.\.(/|$)'),
  data        bytea not null default ''::bytea,
  is_dir      boolean not null default false,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);
-- prefix searches for directory listing (text_pattern_ops supports LIKE 'dir/%')
create index files_path_prefix_idx on akbartech.files (path text_pattern_ops);

create table akbartech.locks (
  id          bigint generated always as identity primary key,
  path        text not null unique,
  owner       text not null,
  expires_at  timestamptz not null,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

create table akbartech.secrets (
  id          smallint primary key check (id = 1),
  key_hash    bytea not null,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

alter table akbartech.files   enable row level security;
alter table akbartech.locks   enable row level security;
alter table akbartech.secrets enable row level security;
revoke all on all tables in schema akbartech from public, anon, authenticated;

create or replace function akbartech.check_key(p_key text) returns void
language plpgsql security definer set search_path = '' as $$
begin
  if p_key is null or length(p_key) < 32 or not exists (
    select 1 from akbartech.secrets s where s.id = 1 and s.key_hash = sha256(convert_to(p_key, 'UTF8'))
  ) then
    raise exception 'forbidden' using errcode = '42501';
  end if;
end $$;

create or replace function akbartech.norm(p_path text) returns text
language sql immutable set search_path = '' as $$
  select trim(both '/' from regexp_replace(coalesce(p_path, ''), '/{2,}', '/', 'g'))
$$;

create or replace function public.akb_fs_stat(p_key text, p_path text) returns jsonb
language plpgsql security definer set search_path = '' as $$
declare v_path text := akbartech.norm(p_path); r record;
begin
  perform akbartech.check_key(p_key);
  if v_path = '' then
    return jsonb_build_object('exists', true, 'is_dir', true, 'size', 0, 'mtime', extract(epoch from now())::bigint);
  end if;
  select f.is_dir, octet_length(f.data) as size, f.updated_at into r from akbartech.files f where f.path = v_path;
  if found then
    return jsonb_build_object('exists', true, 'is_dir', r.is_dir, 'size', r.size, 'mtime', extract(epoch from r.updated_at)::bigint);
  end if;
  if exists (select 1 from akbartech.files f where f.path like v_path || '/%') then
    return jsonb_build_object('exists', true, 'is_dir', true, 'size', 0, 'mtime', extract(epoch from now())::bigint);
  end if;
  return jsonb_build_object('exists', false);
end $$;

create or replace function public.akb_fs_read(p_key text, p_path text) returns text
language plpgsql security definer set search_path = '' as $$
declare v text;
begin
  perform akbartech.check_key(p_key);
  select encode(f.data, 'base64') into v from akbartech.files f where f.path = akbartech.norm(p_path) and not f.is_dir;
  return v;
end $$;

create or replace function public.akb_fs_write(p_key text, p_path text, p_b64 text, p_append boolean default false) returns integer
language plpgsql security definer set search_path = '' as $$
declare v_path text := akbartech.norm(p_path); v_data bytea := decode(coalesce(p_b64, ''), 'base64'); v_size integer;
begin
  perform akbartech.check_key(p_key);
  insert into akbartech.files as f (path, data) values (v_path, v_data)
  on conflict (path) do update
    set data = case when p_append then f.data || excluded.data else excluded.data end,
        is_dir = false, updated_at = now()
  returning octet_length(f.data) into v_size;
  return v_size;
end $$;

create or replace function public.akb_fs_unlink(p_key text, p_path text) returns boolean
language plpgsql security definer set search_path = '' as $$
begin
  perform akbartech.check_key(p_key);
  delete from akbartech.files f where f.path = akbartech.norm(p_path) and not f.is_dir;
  return found;
end $$;

create or replace function public.akb_fs_rename(p_key text, p_from text, p_to text) returns boolean
language plpgsql security definer set search_path = '' as $$
declare v_from text := akbartech.norm(p_from); v_to text := akbartech.norm(p_to);
begin
  perform akbartech.check_key(p_key);
  if not exists (select 1 from akbartech.files f where f.path = v_from or f.path like v_from || '/%') then
    return false;
  end if;
  -- overwrite target atomically (POSIX rename semantics)
  delete from akbartech.files f where (f.path = v_to or f.path like v_to || '/%') and v_to <> v_from;
  update akbartech.files f
     set path = v_to || substr(f.path, length(v_from) + 1), updated_at = now()
   where f.path = v_from or f.path like v_from || '/%';
  return true;
end $$;

create or replace function public.akb_fs_mkdir(p_key text, p_path text) returns boolean
language plpgsql security definer set search_path = '' as $$
begin
  perform akbartech.check_key(p_key);
  insert into akbartech.files (path, is_dir) values (akbartech.norm(p_path), true) on conflict (path) do nothing;
  return true;
end $$;

create or replace function public.akb_fs_rmdir(p_key text, p_path text) returns boolean
language plpgsql security definer set search_path = '' as $$
declare v_path text := akbartech.norm(p_path);
begin
  perform akbartech.check_key(p_key);
  if exists (select 1 from akbartech.files f where f.path like v_path || '/%') then
    return false;
  end if;
  delete from akbartech.files f where f.path = v_path and f.is_dir;
  return true;
end $$;

create or replace function public.akb_fs_list(p_key text, p_dir text) returns setof text
language plpgsql security definer set search_path = '' as $$
declare v_dir text := akbartech.norm(p_dir); v_prefix text;
begin
  perform akbartech.check_key(p_key);
  v_prefix := case when v_dir = '' then '' else v_dir || '/' end;
  return query
    select distinct split_part(substr(f.path, length(v_prefix) + 1), '/', 1)
      from akbartech.files f
     where f.path like v_prefix || '%' and f.path <> v_dir
     order by 1;
end $$;

-- Lease lock: replaces flock() across serverless instances.
create or replace function public.akb_fs_lock(p_key text, p_path text, p_owner text, p_ttl integer default 15) returns boolean
language plpgsql security definer set search_path = '' as $$
declare v_path text := akbartech.norm(p_path); v_ok boolean;
begin
  perform akbartech.check_key(p_key);
  insert into akbartech.locks as l (path, owner, expires_at)
  values (v_path, p_owner, now() + make_interval(secs => least(greatest(p_ttl, 1), 120)))
  on conflict (path) do update
    set owner = excluded.owner, expires_at = excluded.expires_at, updated_at = now()
    where l.expires_at < now() or l.owner = excluded.owner
  returning true into v_ok;
  return coalesce(v_ok, false);
end $$;

create or replace function public.akb_fs_unlock(p_key text, p_path text, p_owner text) returns boolean
language plpgsql security definer set search_path = '' as $$
begin
  perform akbartech.check_key(p_key);
  delete from akbartech.locks l where l.path = akbartech.norm(p_path) and l.owner = p_owner;
  return found;
end $$;

-- Session / temp cleanup: delete files under a prefix older than N seconds.
create or replace function public.akb_fs_gc(p_key text, p_dir text, p_max_age integer) returns integer
language plpgsql security definer set search_path = '' as $$
declare v_count integer;
begin
  perform akbartech.check_key(p_key);
  delete from akbartech.files f
   where f.path like akbartech.norm(p_dir) || '/%' and not f.is_dir
     and f.updated_at < now() - make_interval(secs => greatest(p_max_age, 60));
  get diagnostics v_count = row_count;
  delete from akbartech.locks l where l.expires_at < now() - interval '1 hour';
  return v_count;
end $$;

do $$
declare fn text;
begin
  foreach fn in array array[
    'akb_fs_stat(text,text)', 'akb_fs_read(text,text)', 'akb_fs_write(text,text,text,boolean)',
    'akb_fs_unlink(text,text)', 'akb_fs_rename(text,text,text)', 'akb_fs_mkdir(text,text)',
    'akb_fs_rmdir(text,text)', 'akb_fs_list(text,text)', 'akb_fs_lock(text,text,text,integer)',
    'akb_fs_unlock(text,text,text)', 'akb_fs_gc(text,text,integer)'
  ] loop
    execute format('revoke all on function public.%s from public, authenticated', fn);
    execute format('grant execute on function public.%s to anon', fn);
  end loop;
end $$;
revoke all on function akbartech.check_key(text) from public, anon, authenticated;

-- Set/rotate the access key (plaintext lives only in Vercel env AKB_DB_KEY):
-- insert into akbartech.secrets (id, key_hash) values (1, sha256(convert_to('<AKB_DB_KEY>', 'UTF8')))
-- on conflict (id) do update set key_hash = excluded.key_hash, updated_at = now();
