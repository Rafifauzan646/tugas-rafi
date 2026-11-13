-- =====================================================================
-- SETUP SUPABASE UNTUK WEBSITE TUGAS (jalankan SEKALI di SQL Editor)
-- Dashboard Supabase > SQL Editor > New query > tempel semua > Run
-- Aman dijalankan ulang (memakai IF NOT EXISTS / ON CONFLICT).
-- =====================================================================

-- 1) TABEL: hanya untuk data tugas (PDF / Word / Excel)
create table if not exists public.tugas (
  id           text primary key,
  title        text        not null check (char_length(title) between 1 and 120),
  description  text        not null default '' check (char_length(description) <= 400),
  file_path    text        not null,                 -- lokasi file di Storage
  file_name    text        not null,                 -- nama asli file
  file_type    text        not null check (file_type in ('pdf','doc','docx','xls','xlsx')),
  file_size    bigint      not null default 0,
  created_at   timestamptz not null default now()
);

create index if not exists tugas_created_at_idx on public.tugas (created_at desc);

-- 2) KEAMANAN: aktifkan RLS tanpa policy.
--    Artinya anon key TIDAK bisa membaca/menulis tabel secara langsung.
--    Hanya server kita (memakai service_role key) yang bisa mengakses.
alter table public.tugas enable row level security;

-- 3) STORAGE: bucket PRIVATE untuk menyimpan file, maks 25 MB per file
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'dokumen-tugas', 'dokumen-tugas', false, 26214400,
  array[
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
  ]
)
on conflict (id) do update
  set public = false,
      file_size_limit = excluded.file_size_limit,
      allowed_mime_types = excluded.allowed_mime_types;

-- 4) CEK HASIL (opsional): harus muncul 1 baris bucket dan 0 baris tugas
select id, public, file_size_limit from storage.buckets where id = 'dokumen-tugas';
select count(*) as jumlah_tugas from public.tugas;
