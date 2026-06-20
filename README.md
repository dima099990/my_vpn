# MyVPN — Self-hosted VPN Server

Личный VPN-сервер на базе **Xray VLESS+Reality** с веб-панелью, Telegram-ботом и поддержкой Koala Clash и HAPP.

## Возможности

- **VLESS + Reality** — маскировка под легитимный TLS трафик
- **Koala Clash** (порт 443, Vision flow) — для ПК (Windows/macOS/Linux)
- **HAPP** (порт 2053, без flow) — для телефона (Android/iOS)
- **Веб-панель** — личная страница для каждого пользователя с QR-кодом и статистикой трафика
- **Telegram бот** — выдача и отзыв доступа, тестовые ключи на 7 дней
- **Персистентная статистика** — счётчик трафика не сбрасывается при рестарте
- **Proxmox управление** — кнопка выключения домашнего сервера из веб-панели

## Структура

```
├── bot/
│   └── bot.py              # Telegram бот (python-telegram-bot v22)
├── webserver/
│   └── server.py           # Веб-сервер (порт 80), подписки, статистика
├── xray/
│   └── config.example.json # Шаблон конфига Xray
├── systemd/                # systemd unit файлы
├── .env.example            # Шаблон переменных окружения
└── README.md
```

## Установка

### 1. Зависимости

```bash
apt install python3-pip -y
pip3 install python-telegram-bot python-dotenv pyyaml qrcode[pil]
```

### 2. Xray

```bash
mkdir -p /opt/xray
# Скачать последний релиз с https://github.com/XTLS/Xray-core/releases
# Распаковать в /opt/xray/
cp xray/config.example.json /opt/xray/config.json
# Заполнить ключи (сгенерировать: /opt/xray/xray x25519)
```

### 3. Переменные окружения

```bash
mkdir -p /opt/vpnserver
cp .env.example /opt/vpnserver/.env
nano /opt/vpnserver/.env  # заполнить все значения
```

Генерация Xray ключей:
```bash
/opt/xray/xray x25519          # приватный и публичный ключ
openssl rand -hex 8             # short ID
cat /proc/sys/kernel/random/uuid  # UUID пользователя
```

### 4. Файлы данных

```bash
mkdir -p /opt/vpnbot
echo '{"admin_id": 0, "users": {}, "trial_keys": {}}' > /opt/vpnbot/users.json
```

### 5. Сервисы

```bash
cp systemd/*.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now xray subserver vpnbot
```

## Конфигурация

Все секреты хранятся в `/opt/vpnserver/.env` (см. `.env.example`):

| Переменная | Описание |
|---|---|
| `BOT_TOKEN` | Токен Telegram бота (@BotFather) |
| `ADMIN_USERNAME` | Username администратора в Telegram (без @) |
| `SERVER_IP` | IP-адрес сервера |
| `ADMIN_PASSWORD` | Пароль веб-панели |
| `XRAY_PRIVATE_KEY` | Приватный ключ Reality |
| `XRAY_PUBLIC_KEY` | Публичный ключ Reality |
| `XRAY_SHORT_ID` | Short ID Reality |
| `XRAY_SNI` | SNI (домен для маскировки) |
| `STATIC_UUID` | UUID администратора |
| `PROXMOX_HOST` | IP домашнего сервера Proxmox |

## Использование

### Веб-панель
- **Админка**: `http://SERVER_IP/` (логин/пароль из `.env`)
- **Личная страница**: `http://SERVER_IP/sub/TOKEN`

### Telegram бот
- `/start` — меню (для администратора) или запрос доступа (для пользователя)
- Кнопки: 👥 Пользователи | 🔑 Тест ключи | 🎁 Создать тест ключ | ❌ Убрать подписку

### Подписки
| Приложение | URL |
|---|---|
| HAPP (Android/iOS) | `http://SERVER_IP/sub/TOKEN` |
| Koala Clash | `http://SERVER_IP/sub/clash/TOKEN` |

## Порты

| Порт | Назначение |
|---|---|
| 80 | Веб-панель и подписки |
| 443 | VLESS+Reality для Koala Clash (Vision flow) |
| 2053 | VLESS+Reality для HAPP (без flow) |
| 10085 | Xray Stats API (только localhost) |
