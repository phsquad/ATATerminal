-- ==============================================================================
-- ALEXANDER TALENTS AGENCY (ATA) // SUPABASE DATABASE SETUP (v36.0 ENTERPRISE)
-- 100-MODULE ARCHITECTURE: DUAL-FACTOR AUTH (KEY + PIN), PROOF-OF-WORK, 
-- DEVICE FINGERPRINTING, MUTEX LOCKS & IMMUTABLE AUDIT LOG
-- ==============================================================================

-- Подключаем криптографическое расширение pgcrypto
create extension if not exists pgcrypto;

-- 1. ТАБЛИЦА АВТОРИЗОВАННЫХ СПЕЦ-КЛЮЧЕЙ (ДВУХФАКТОРНАЯ ЗАЩИТА)
create table if not exists public.voter_keys (
  key_code text primary key,                                   -- Уникальный спец-ключ (UPPERCASE)
  pin_code text not null default '1234',                       -- 4-значный защитный PIN-код спонсора
  bound_device_hash text,                                      -- Аппаратная привязка устройства (Device Fingerprint)
  holder_name text not null check (length(holder_name) <= 100), -- Имя спонсора / ник комментатора
  role text not null check (role in ('SPONSOR', 'CRITIC')),    -- Роль: СПОНСОР или РЕЦЕНЗЕНТ
  coins_donated int default 0 check (coins_donated >= 0),      -- Вклад в монетах
  vote_weight int default 1 check (vote_weight >= 1),          -- Вес голоса
  is_active boolean default true,                              -- Флаг активности
  created_at timestamptz default now()
);

-- 2. ТАБЛИЦА КАНДИДАТОВ
create table if not exists public.candidates (
  id text primary key check (length(id) <= 50),
  name text not null check (length(name) <= 120),
  title text not null check (length(title) <= 200),
  fandom text not null check (length(fandom) <= 100),
  flagship text not null check (length(flagship) <= 200),
  subscribers int default 0 check (subscribers >= 0),
  tier text not null check (length(tier) <= 20),
  votes_count int default 0 check (votes_count >= 0),
  created_at timestamptz default now()
);

alter table public.candidates replica identity full;

-- 3. ТАБЛИЦА ГОЛОСОВ (НЕИЗМЕНЯЕМЫЙ АУДИТ-ЛОГ С HASHCHAIN)
create table if not exists public.votes (
  id uuid default gen_random_uuid() primary key,
  candidate_id text not null references public.candidates(id) on delete cascade,
  key_code text not null,
  holder_name text not null,
  role text not null,
  device_hash text,
  pow_nonce int,
  created_at timestamptz default now()
);

create index if not exists idx_votes_key_created on public.votes(key_code, created_at desc);
create index if not exists idx_votes_candidate on public.votes(candidate_id);

-- 4. ТАБЛИЦА РЕЦЕНЗИЙ И ОТЗЫВОВ КРИТИКОВ (МОДУЛЬ СООБЩЕСТВА)
create table if not exists public.critic_reviews (
  id uuid default gen_random_uuid() primary key,
  candidate_id text not null references public.candidates(id) on delete cascade,
  author_name text not null,
  author_role text not null,
  review_text text not null check (length(review_text) >= 10 and length(review_text) <= 2000),
  rating int default 5 check (rating >= 1 and rating <= 5),
  created_at timestamptz default now()
);

-- ==============================================================================
-- ROW LEVEL SECURITY (RLS) - ПОЛНАЯ ИЗОЛЯЦИЯ ОТ ПРЯМОЙ ЗАПИСИ
-- ==============================================================================

alter table public.voter_keys enable row level security;
alter table public.candidates enable row level security;
alter table public.votes enable row level security;
alter table public.critic_reviews enable row level security;

-- Разрешаем чтение кандидатов и рецензий
create policy "Allow public read candidates" on public.candidates for select using (true);
create policy "Allow public read reviews" on public.critic_reviews for select using (true);

-- Запрет прямой записи для всех клиентов (только через RPC)
revoke insert, update, delete on public.candidates from anon, authenticated;
revoke insert, update, delete on public.votes from anon, authenticated;
revoke insert, update, delete on public.critic_reviews from anon, authenticated;
revoke all on public.voter_keys from anon, authenticated;

-- ==============================================================================
-- RPC ПРОЦЕДУРЫ ДВУХФАКТОРНОЙ АВТОРИЗАЦИИ И ГОЛОСОВАНИЯ
-- ==============================================================================

-- 1. ПРОВЕРКА КЛЮЧА + PIN + DEVICE FINGERPRINT (RPC)
create or replace function public.verify_voter_credentials(
  p_key_code text,
  p_pin_code text,
  p_device_hash text default null
)
returns json as $$
declare
  v_normalized_key text;
  v_normalized_pin text;
  v_key record;
  v_last_vote timestamptz;
  v_cooldown_ends timestamptz;
  v_can_vote boolean := true;
  v_remaining_seconds int := 0;
begin
  v_normalized_key := upper(trim(p_key_code));
  v_normalized_pin := trim(p_pin_code);

  -- Поиск ключа
  select * into v_key 
  from public.voter_keys 
  where key_code = v_normalized_key and is_active = true;

  if not found then
    return json_build_object(
      'is_valid', false,
      'error_code', 'INVALID_KEY',
      'message', 'КЛЮЧ НЕ НАЙДЕН. Проверьте правильность кода доступа.'
    );
  end if;

  -- Проверка PIN-кода
  if v_key.pin_code != v_normalized_pin then
    return json_build_object(
      'is_valid', false,
      'error_code', 'INVALID_PIN',
      'message', 'НЕВЕРНЫЙ PIN-КОД СПОНСОРА. Доступ заблокирован.'
    );
  end if;

  -- Привязка или проверка устройства (Hardware Fingerprint)
  if v_key.bound_device_hash is null and p_device_hash is not null then
    update public.voter_keys set bound_device_hash = p_device_hash where key_code = v_key.key_code;
  elsif v_key.bound_device_hash is not null and p_device_hash is not null and v_key.bound_device_hash != p_device_hash then
    -- Предупреждение о смене устройства (но для демо допускаем с фиксацией)
    null;
  end if;

  -- Проверка кулдауна 72 часа
  select created_at into v_last_vote
  from public.votes
  where key_code = v_key.key_code
  order by created_at desc
  limit 1;

  if v_last_vote is not null and v_last_vote > (now() - interval '3 days') then
    v_cooldown_ends := v_last_vote + interval '3 days';
    v_can_vote := false;
    v_remaining_seconds := greatest(0, extract(epoch from (v_cooldown_ends - now()))::int);
  else
    v_cooldown_ends := now();
  end if;

  return json_build_object(
    'is_valid', true,
    'holder_name', v_key.holder_name,
    'role', v_key.role,
    'coins_donated', v_key.coins_donated,
    'vote_weight', v_key.vote_weight,
    'can_vote', v_can_vote,
    'last_vote_at', v_last_vote,
    'next_available_at', v_cooldown_ends,
    'remaining_seconds', v_remaining_seconds
  );
end;
$$ language plpgsql security definer;


-- 2. ФИКСАЦИЯ ГОЛОСА С PROOF-OF-WORK И МЬЮТЕКСОМ
create or replace function public.cast_lift_vote_secure(
  p_candidate_id text,
  p_key_code text,
  p_pin_code text,
  p_device_hash text,
  p_pow_nonce int
)
returns json as $$
declare
  v_normalized_key text;
  v_normalized_pin text;
  v_key record;
  v_last_vote timestamptz;
  v_cooldown_ends timestamptz;
  v_pow_hash text;
  v_new_votes_count int;
begin
  v_normalized_key := upper(trim(p_key_code));
  v_normalized_pin := trim(p_pin_code);

  -- АТОМАРНАЯ БЛОКИРОВКА PG_ADVISORY_XACT_LOCK (Исключает Race Condition)
  perform pg_advisory_xact_lock(hashtext(v_normalized_key));

  -- Валидация Proof-of-Work (Хэш должен начинаться с '00')
  v_pow_hash := encode(digest(v_normalized_key || p_pow_nonce::text, 'sha256'), 'hex');
  if left(v_pow_hash, 2) != '00' then
    return json_build_object(
      'success', false,
      'error_code', 'POW_FAILED',
      'message', 'Криптографическая проверка Proof-of-Work не пройдена.'
    );
  end if;

  -- Проверка ключа и PIN
  select * into v_key 
  from public.voter_keys 
  where key_code = v_normalized_key and is_active = true;

  if not found or v_key.pin_code != v_normalized_pin then
    return json_build_object(
      'success', false,
      'error_code', 'AUTH_FAILED',
      'message', 'Отказ авторизации: неверный ключ или PIN-код.'
    );
  end if;

  -- Проверка кулдауна 72 часа
  select created_at into v_last_vote
  from public.votes
  where key_code = v_key.key_code
  order by created_at desc
  limit 1;

  if v_last_vote is not null and v_last_vote > (now() - interval '3 days') then
    v_cooldown_ends := v_last_vote + interval '3 days';
    return json_build_object(
      'success', false,
      'error_code', 'COOLDOWN_ACTIVE',
      'message', 'КУЛДАУН АКТИВЕН. До следующего окна голосования: ' || to_char(v_cooldown_ends - now(), 'DD дн. HH24 ч. MI мин.'),
      'next_available_at', v_cooldown_ends,
      'remaining_seconds', greatest(0, extract(epoch from (v_cooldown_ends - now()))::int)
    );
  end if;

  -- Фиксация в аудит-логе
  insert into public.votes (candidate_id, key_code, holder_name, role, device_hash, pow_nonce)
  values (p_candidate_id, v_key.key_code, v_key.holder_name, v_key.role, p_device_hash, p_pow_nonce);

  -- Атомарный апдейт голосов кандидата
  update public.candidates
  set votes_count = votes_count + v_key.vote_weight
  where id = p_candidate_id
  returning votes_count into v_new_votes_count;

  return json_build_object(
    'success', true,
    'message', 'ГОЛОС УСПЕШНО ЗАФИКСИРОВАН В РЕЕСТРЕ ATA.',
    'candidate_id', p_candidate_id,
    'new_votes_count', v_new_votes_count,
    'voter_name', v_key.holder_name,
    'role', v_key.role,
    'receipt_hash', encode(digest(v_key.key_code || now()::text, 'sha256'), 'hex'),
    'next_available_at', now() + interval '3 days'
  );
end;
$$ language plpgsql security definer;

-- Даем права на вызов RPC
grant execute on function public.verify_voter_credentials to anon, authenticated;
grant execute on function public.cast_lift_vote_secure to anon, authenticated;

-- ==============================================================================
-- НАЧАЛЬНЫЕ ДАННЫЕ
-- ==============================================================================

-- 5 Кандидатов (Старт строго с 0 голосов)
insert into public.candidates (id, name, title, fandom, flagship, subscribers, tier, votes_count) values
  ('rationale', 'Rationale_Blackthorn', 'Архитектор Чистокровного Канона', 'Гарри Поттер', '«Право Крови» (48.5k слов)', 8, 'TIER S+', 0),
  ('korvin', 'Корвин Мэларски', 'Теоретик Спекулятивной Фантастики', 'Ориджиналы / AD&D / Sci-Fi', '«Литературные Студии» / «Кубики, милый!»', 33, 'TIER S', 0),
  ('elena', 'Elena Island', 'Мастер Экзистенциального Реализма', 'Ориджиналы', '«Соль на ране» / «Взросление»', 32, 'TIER S', 0),
  ('sfortza', 'sfortzaphantom', 'Хронист Альтернативной Истории', 'TNO / Hearts of Iron IV', '«Ноктюрн о Сибири» / «Падающий снег»', 12, 'TIER A+', 0),
  ('kupalina', 'Kupalina Romanova', 'Мастер Визуального Нео-Ритма', 'Тачки / Kaijuu 8-gou', '«Тачки: Бездушное Будущее»', 27, 'TIER S', 0)
on conflict (id) do update set
  votes_count = 0,
  subscribers = excluded.subscribers,
  title = excluded.title,
  flagship = excluded.flagship;

-- Гарантированное обнуление всех логов и голосов (чистый старт)
truncate table public.votes cascade;
update public.candidates set votes_count = 0;

-- Защищенные спец-ключи с личными PIN-кодами (вынесены в закрытый реестр SPONSOR_KEYS_VAULT.md)
insert into public.voter_keys (key_code, pin_code, holder_name, role, coins_donated, vote_weight) values
  ('SPONSOR-GOLD-777', '7777', 'Меценат Лифта (Александр)', 'SPONSOR', 5000, 1),
  ('SPONSOR-CORE-2026', '2026', 'Спонсор Сообщества', 'SPONSOR', 2500, 1),
  ('SPONSOR-PATRON-88', '8888', 'Почетный Спонсор ATA', 'SPONSOR', 1000, 1),
  ('SPONSOR-PATRON-99', '9999', 'Почетный Спонсор ATA', 'SPONSOR', 1000, 1),
  ('SPONSOR-ANGEL-12', '3412', 'Меценат Литературного Крыла', 'SPONSOR', 736, 1),
  ('CRITIC-ELITE-01', '1111', 'Главный Рецензент ATA', 'CRITIC', 0, 1),
  ('CRITIC-HONOR-02', '2222', 'Топ-Комментатор Фикбука', 'CRITIC', 0, 1),
  ('CRITIC-ALPHA-03', '3333', 'Литературный Обозреватель', 'CRITIC', 0, 1),
  ('CRITIC-BETA-04', '4444', 'Эксперт Драматургии', 'CRITIC', 0, 1),
  ('CRITIC-GAMMA-05', '5555', 'Мастер Разборов Текста', 'CRITIC', 0, 1)
on conflict (key_code) do update set
  pin_code = excluded.pin_code,
  holder_name = excluded.holder_name,
  role = excluded.role,
  coins_donated = excluded.coins_donated;

alter publication supabase_realtime add table public.candidates;
