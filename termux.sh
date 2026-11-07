#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

cd "$(dirname "$0")"

echo "=== MemoryCraft API | Termux ==="
echo "1) Установка системных пакетов..."
pkg update -y
pkg install -y python libpq

echo "2) Установка Python-зависимостей..."
python -m pip install --upgrade pip
export PSYCOPG_IMPL=python
python -m pip install "fastapi==0.115.4" "uvicorn==0.32.0" "psycopg==3.2.3"

if [ -z "${DATABASE_URL:-}" ]; then
  echo
  echo "Вставь Neon connection string (postgresql://... или postgres://...)."
  echo "Строка вводится скрыто и не отправляется в чат."
  read -r -s -p "DATABASE_URL: " DATABASE_URL
  echo
  export DATABASE_URL
fi

case "${DATABASE_URL:-}" in
  postgres://*|postgresql://*) ;;
  *)
    echo "ОШИБКА: DATABASE_URL должен начинаться с postgres:// или postgresql://"
    exit 1
    ;;
esac

if [ -z "${TOKEN_SECRET:-}" ]; then
  if [ ! -f ".termux_token_secret" ]; then
    python -c 'import secrets; print(secrets.token_urlsafe(48))' > .termux_token_secret
    chmod 600 .termux_token_secret
  fi
  export TOKEN_SECRET="$(cat .termux_token_secret)"
fi

if [ -z "${BOT_TOKEN:-}" ]; then
  echo
  read -r -s -p "BOT_TOKEN (Enter — пропустить, если тестируешь только API): " BOT_TOKEN
  echo
  export BOT_TOKEN
fi

export PORT="${PORT:-8000}"

echo
echo "3) Запуск API на http://127.0.0.1:${PORT}"
echo "Проверка: открой http://127.0.0.1:${PORT}/health"
echo "Остановка: Ctrl+C"
echo
exec python -m uvicorn main:app --host 0.0.0.0 --port "$PORT"
