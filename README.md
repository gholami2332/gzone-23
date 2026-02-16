# G-Zone Cafe — Production (Liara Ready)

## Deploy on Liara
1) Create App (Node)
2) Create Disk and mount to: `/data`
3) Set ENV (recommended):
   - `JWT_SECRET` = یک رشته طولانی رندوم
   - `FORCE_HTTPS` = `1`
   - `COOKIE_SECURE` = `1`
   - `ADMIN_USERNAME` و `ADMIN_PASSWORD` (فقط برای ساخت اولین ادمین)
4) Deploy این ZIP

## URLs
- Landing + Login/Register: `/`
- User Dashboard: `/dashboard`
- User Orders: `/orders`
- Admin Login: `/admin`
- Admin Dashboard: `/admin/dashboard`
- Admin Products: `/admin/products`
- Admin Users: `/admin/users`
- Admin Orders: `/admin/orders`

## Admin (Bootstrap)
برای امنیت، هیچ پسوردی داخل کد هاردکُد نشده است.

اگر دیتابیس شما هنوز ادمین ندارد، فقط برای اولین اجرا این ENV ها را ست کنید:
- `ADMIN_USERNAME`
- `ADMIN_PASSWORD`

بعد از اولین لاگین، حتماً از مسیر زیر پسورد را عوض کنید:
- `/admin/password`

## Storage
- DB: `/data/database.sqlite`
- Uploads: `/data/uploads` (served on `/uploads`)


## Health Check
- `/health` should return `{ ok: true }`


## Bilingual (FA/EN)
- Language switcher: `FA / EN` buttons in the top navbar.
- Selected language is stored in a `lang` cookie and works for all pages.
- RTL/LTR is applied automatically.

### Menu translations (Mode B)
This project supports English fields in the database:
- `categories.title_en`
- `products.title_en`
- `products.description_en`
If these are empty, the Persian fields will be shown as fallback.

## Recommended ENV on Liara
- `JWT_SECRET`: set a strong secret (do NOT keep the default).
- `COOKIE_DOMAIN`: set to `.gzonecafe.ir` so login works across `gzonecafe.ir` and `www.gzonecafe.ir`.
- `COOKIE_SECURE`: set to `1` if you force HTTPS and want secure cookies.
- `FORCE_HTTPS`: set to `1` to redirect http -> https and remove browser "Not Secure" warnings.
- `ADMIN_USERNAME` / `ADMIN_PASSWORD`: only needed for the very first bootstrapping when there is no admin user yet.


## نکته برای Liara
- نسخه Node را روی **20.x** نگه دارید. این نسخه از پروژه از **sql.js (WASM)** و **bcryptjs** استفاده می‌کند تا نصب وابستگی‌ها سریع باشد و روی سرورهایی که کامپایل ماژول‌های native مشکل/کند است، تایم‌اوت ندهد.
- فونت‌ها دیگر از Google Fonts یا npm دانلود نمی‌شوند؛ استایل از فونت‌های سیستم استفاده می‌کند (سریع‌تر و بدون محدودیت شبکه).
