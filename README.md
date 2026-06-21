# ShockNet VPN Server

Самохостинговый VPN сервер на базе **Xray-core** с VLESS+Reality и VLESS+WebSocket+TLS.  
Включает веб-сервер для подписок, панель администратора и Telegram-бота для управления.

---

## Архитектура

```
Клиент
  ├── HAPP (Android/iOS)       → VLESS+Reality   → сервер:2053
  ├── Koala Clash (Win/Mac)    → VLESS+Reality   → сервер:2053
  └── Любой клиент             → VLESS+WS+TLS    → nginx:443 → xray:8880

Сервер (Ubuntu)
  ├── xray          — ядро, обрабатывает входящие соединения
  ├── nginx         — TLS терминация, проксирует WS и веб
  ├── subserver     — HTTP сервер: подписки, лендинг, админка
  └── vpnbot        — Telegram бот для управления и выдачи конфигов
```

## Порты

| Порт  | Протокол | Назначение |
|-------|----------|------------|
| 80    | HTTP     | nginx → redirect на HTTPS |
| 443   | HTTPS    | nginx → WS→Xray + веб |
| 2053  | TCP      | Xray VLESS+Reality (основной, без flow) |
| 4443  | TCP      | Xray VLESS+Reality+Vision (альтернативный) |
| 8443  | TCP      | Xray2 standalone (Reality, SNI vk.com) |
| 8008  | TCP      | subserver (localhost only) |
| 8880  | TCP      | Xray WS inbound (localhost only) |
| 10085 | TCP      | Xray API (localhost only) |

---

## Структура репозитория

```
├── webserver/
│   └── server.py            # Subscription + admin HTTP server
├── bot/
│   └── bot.py               # Telegram bot
├── xray/
│   └── config.example.json  # Пример конфига Xray (без приватных ключей)
├── systemd/
│   ├── xray.service
│   ├── subserver.service
│   └── vpnbot.service
└── README.md
```

---

## Установка

### 1. Зависимости

```bash
apt update && apt install -y python3 python3-pip nginx certbot python3-certbot-nginx
pip3 install pyyaml python-telegram-bot
```

### 2. Xray

```bash
mkdir -p /opt/xray
# Скачать актуальный релиз с github.com/XTLS/Xray-core/releases
wget -O /tmp/xray.zip https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip
unzip /tmp/xray.zip -d /opt/xray/
chmod +x /opt/xray/xray
```

Сгенерировать ключи Reality:
```bash
/opt/xray/xray x25519
# Сохрани publicKey и privateKey
```

Скопировать `xray/config.example.json` → `/opt/xray/config.json` и заполнить:
- `privateKey` — приватный ключ Reality
- `uuid` клиентов
- `shortIds`

### 3. Веб-сервер подписок

```bash
mkdir -p /opt/subserver
cp webserver/server.py /opt/subserver/
```

Создать `/opt/vpnserver/.env`:
```env
BOT_TOKEN=telegram_bot_token
BOT_USERNAME=your_bot_username
SESSION_SECRET=random_hex_32_bytes
DOMAIN=your.domain.com
SERVER_IP=1.2.3.4
XRAY_PUBLIC_KEY=...
XRAY_SHORT_ID=...
XRAY_UUID=...
XRAY_SNI=www.microsoft.com
ADMIN_TG_ID=your_telegram_id
```

### 4. Telegram бот

```bash
mkdir -p /opt/vpnbot
cp bot/bot.py /opt/vpnbot/
```

Файл `/opt/vpnbot/users.json` создаётся автоматически при первом запуске.

### 5. nginx

Пример конфига `/etc/nginx/sites-available/shocknet`:
```nginx
server {
    listen 80;
    server_name your.domain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name your.domain.com;

    ssl_certificate     /etc/letsencrypt/live/your.domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your.domain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    # WebSocket → Xray
    location /vless {
        proxy_pass http://127.0.0.1:8880;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 300s;
    }

    # Subscription server
    location / {
        proxy_pass http://127.0.0.1:8008;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

SSL через Certbot:
```bash
certbot --nginx -d your.domain.com
```

### 6. systemd сервисы

```bash
cp systemd/*.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now xray subserver vpnbot
```

---

## Управление пользователями

Через Telegram бота (команда `/start` от admin):
- **Добавить пользователя** — генерирует UUID, добавляет в Xray и выдаёт ссылку подписки
- **Одобрить / заблокировать** — управление доступом без перезапуска Xray
- **Статистика трафика** — upload/download на каждого пользователя

Ссылки подписки:
```
https://your.domain.com/sub/{token}           # HAPP / универсальная
https://your.domain.com/sub/clash/{token}     # Koala Clash / Mihomo
```

---

## Панель администратора

Доступна по адресу `https://your.domain.com/admin`  
Авторизация через **Telegram Login Widget** (бот должен иметь настроенный домен в BotFather).

Возможности:
- Статус всех сервисов (xray, vpnbot, subserver)
- Управление пользователями (добавить, одобрить, заблокировать, сбросить трафик)
- Мониторинг сервера — CPU, RAM, диск, сетевой трафик (графики за последний час)
- QR-коды и ссылки подписок для каждого пользователя

---

## Протоколы и маскировка

### VLESS + Reality (порт 2053)
- Маскируется под TLS трафик к `www.microsoft.com`
- SNI подделывается через реальный TLS handshake с Microsoft
- Провайдер видит обычный HTTPS к Microsoft

### VLESS + WebSocket + TLS (порт 443)
- Трафик идёт через nginx как обычный HTTPS
- WS путь `/vless` выглядит как обычный API запрос
- Подходит для сетей где блокируют нестандартные порты

---

## Статистика трафика

Счётчики хранятся в Xray API и персистируются в `/opt/vpnbot/stats_persistent.json`.  
При перезапуске Xray данные не теряются — счётчик сбрасывается с `--reset` каждые 5 минут и добавляется в файл.

---

## Переменные окружения

| Переменная | Описание |
|------------|----------|
| `BOT_TOKEN` | Токен Telegram бота |
| `BOT_USERNAME` | Username бота (без @) |
| `SESSION_SECRET` | Секрет для сессий админки (hex, 32 байта) |
| `DOMAIN` | Домен сервера |
| `SERVER_IP` | IP сервера |
| `XRAY_PUBLIC_KEY` | Публичный ключ Reality |
| `XRAY_SHORT_ID` | Short ID Reality |
| `XRAY_UUID` | UUID по умолчанию |
| `XRAY_SNI` | SNI для маскировки (например `www.microsoft.com`) |
| `ADMIN_TG_ID` | Telegram ID администратора |

---

## Требования

- Ubuntu 20.04+
- Python 3.10+
- nginx
- Xray-core 24.x+
- Домен с SSL сертификатом
- Telegram бот (зарегистрировать через @BotFather)
