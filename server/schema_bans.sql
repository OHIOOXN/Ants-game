-- Tablas necesarias para los bans por identidad (Supabase).
-- Ejecutar una sola vez en el SQL Editor del proyecto.

create table if not exists public.aec_bans (
    kind text not null check (kind in ('user', 'device', 'email', 'ip')),
    value_hash text not null,
    expires_at bigint not null,
    created_at bigint not null,
    reason text,
    primary key (kind, value_hash)
);

create table if not exists public.aec_identities (
    user_key text primary key,
    device_hash text,
    ip_hash text,
    email_hash text,
    updated_at bigint not null
);

create index if not exists aec_bans_expires_idx on public.aec_bans (expires_at);
