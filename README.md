# AKBARTECH — Telegram bot + Mini App (Vercel + Supabase)

PHP ilova (`app/`) Vercel Functions'da ishlaydi, barcha ma'lumotlar Supabase Postgres'da saqlanadi.
Bot webhook orqali ishlaydi, shuning uchun 24/7 ishlaydi va "uxlab qolmaydi".

## Arxitektura

```
Telegram ──webhook──▶ Vercel (fra1) api/index.php ──require──▶ app/index.php | app/admin.php
                               │
                               └─ akbfs:// stream wrapper ──RPC──▶ Supabase (eu-central-1)
                                                                    schema akbartech (yopiq)
                                                                    public.akb_fs_* (SECURITY DEFINER + AKB_DB_KEY)
```

- `app/` ilova kodi kichik o'zgarishlar bilan saqlangan. `store/` va `uploads/` endi `akbfs://` orqali Supabase'ga yoziladi.
- `flock()` → Postgres'dagi lease lock (`akb_fs_lock`), shuning uchun bir nechta instansiya bir vaqtda ishlasa ham ma'lumot buzilmaydi.
- Admin seanslari ham Supabase'da saqlanadi (`AkbSessionHandler`).
- `img/`, `media/` statik fayl sifatida CDN orqali beriladi. `/uploads/*` funksiya orqali beriladi, CDN'da keshlanadi.

## Papka strukturasi

```
.
├── api/index.php                 front controller (proxy/IP/host, storage mount, dispatch)
├── lib/akbfs.php                 akbfs:// stream wrapper + session handler
├── app/
│   ├── index.php                 mini app + bot webhook + API
│   ├── admin.php                 admin panel
│   ├── img/  media/              (ilova ichidagi is_file() tekshiruvlari uchun)
├── public/img, public/media      statik fayllar (CDN)
├── akbartech.config.php          secretlar → getenv() (kodda qiymat yo'q)
├── supabase/migrations/          up/down SQL
├── tools/import_store.php        eski hostingdan ma'lumot ko'chirish
├── vercel.json
└── .env.example
```

## Environment Variables (Vercel → Settings → Environment Variables)

`.env.example`'ga qarang. Majburiy: `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY`, `AKB_DB_KEY`, `BOT_TOKEN`, `ADMIN_TG_ID`, `SETUP_KEY`.

## Deploy

1. Supabase: `supabase/migrations/*.up.sql` qo'llang, so'ng `AKB_DB_KEY` xeshini `akbartech.secrets`'ga yozing (fayl oxirida misol bor).
2. Vercel: repo'ni import qiling, env'larni kiriting, deploy qiling.
3. Botni ulash (bir marta):
   ```
   https://<domain>/index.php?r=setup&key=<SETUP_KEY>
   ```
4. Tekshirish:
   ```bash
   curl -s https://<domain>/index.php?r=health                      # {"ok":true,...}
   curl -s "https://api.telegram.org/bot<TOKEN>/getWebhookInfo"      # url = https://<domain>/index.php?r=webhook, last_error yo'q
   curl -s -o /dev/null -w "%{http_code}\n" https://<domain>/akbartech.config.php   # 404
   curl -s -o /dev/null -w "%{http_code}\n" https://<domain>/app/index.php          # 404
   ```

## Lokal ishga tushirish

```bash
cp .env.example .env   # qiymatlarni to'ldiring
set -a; . ./.env; set +a
cd public && php -S 127.0.0.1:8080 ../api/index.php
```

## Eski hostingdan ma'lumot ko'chirish

Eski hostingdan `uz/store/` va `uz/uploads/` papkalarini yuklab oling, so'ng:
```bash
SUPABASE_URL=... SUPABASE_PUBLISHABLE_KEY=... AKB_DB_KEY=... php tools/import_store.php /path/to/old/uz
```

## Rollback

`supabase/migrations/*.down.sql` **barcha AKBARTECH ma'lumotlarini o'chiradi**. Avval backup oling:
```bash
pg_dump "$DATABASE_URL" -n akbartech -Fc -f akbartech_backup.dump
```

## Cheklovlar (bepul tariflar)

- Vercel Hobby notijorat foydalanish uchun. Funksiya 60 soniyagacha ishlaydi (AI javobi va xabar tarqatish shunga sig'adi).
- Supabase Free: 500 MB DB. Faol bo'lmasa 7 kunda pauza qilinadi, lekin bot va ilova trafigi uni faol ushlab turadi.
- Yuklanadigan rasm hajmi ~4 MB'gacha (Vercel so'rov limiti 4.5 MB).
