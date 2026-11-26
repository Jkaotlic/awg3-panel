#!/usr/bin/env bash
# Установка awg3-panel. Идемпотентен: повторный запуск на настроенной
# системе не меняет состояние. Существующий config.yaml НЕ перетирается.
set -euo pipefail

# Разбор аргументов: --dry-run в любой позиции, путь к бинарю — первый
# позиционный. Простое ${1} здесь ошибочно: install.sh --dry-run приняло бы
# «--dry-run» за путь к бинарю и упало бы с невнятным сообщением.
BIN_SRC=""
DRY_RUN=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    -*) echo "неизвестный ключ: $arg"; exit 2 ;;
    *) [ -z "$BIN_SRC" ] && BIN_SRC="$arg" ;;
  esac
done
BIN_SRC="${BIN_SRC:-./awg3panel}"

run() {
  if [ "$DRY_RUN" = "1" ]; then
    echo "[dry-run] $*"
  else
    "$@"
  fi
}

say() { printf '%s\n' "$*"; }

ensure_dir() {
  if [ -d "$1" ]; then
    say "каталог $1 уже есть"
  else
    run install -d -m 0700 "$1"
  fi
}

[ "$(id -u)" = "0" ] || { say "нужен root"; exit 1; }
# Имя без слеша относится к текущему каталогу, а не к поиску в PATH.
[[ "$BIN_SRC" == */* ]] || BIN_SRC="./$BIN_SRC"
[ -f "$BIN_SRC" ] && [ -x "$BIN_SRC" ] || { say "бинарь недоступен для запуска: $BIN_SRC"; exit 1; }
command -v systemctl >/dev/null || { say "не найден systemctl"; exit 1; }

SCRIPT_DIR=$(dirname "$0")
EXAMPLE_SRC="$SCRIPT_DIR/config.example.yaml"
BIN_DST=/usr/local/bin/awg3panel
CONFIG_DST=/etc/awg3panel/config.yaml
STATE_ROOT=/var/lib/awg3panel
UNIT_SRC="$SCRIPT_DIR/awg3panel.service"
UNIT_DST=/etc/systemd/system/awg3panel.service
[ -f "$UNIT_SRC" ] || { say "не найден юнит: $UNIT_SRC"; exit 1; }

CONFIG_CHECK="$CONFIG_DST"
if [ ! -e "$CONFIG_DST" ] && [ ! -L "$CONFIG_DST" ]; then
  CONFIG_CHECK="$EXAMPLE_SRC"
fi
[ -f "$CONFIG_CHECK" ] && [ -r "$CONFIG_CHECK" ] || { say "конфиг недоступен для чтения: $CONFIG_CHECK"; exit 1; }

SERVICE_ACTIVE=0
if systemctl is-active --quiet awg3panel 2>/dev/null; then
  SERVICE_ACTIVE=1
fi

# Подставляем проверочный bcrypt только в поток валидации оригинального
# примера. Обычный config.yaml всегда проверяется в том виде, как он лежит
# на диске, даже если в нём где-то есть слово ЗАМЕНИТЬ.
UNCONFIGURED=0
if [ "$SERVICE_ACTIVE" = "0" ] && cmp -s "$CONFIG_CHECK" "$EXAMPLE_SRC" &&
    grep -Fxq '  bcrypt: "ЗАМЕНИТЬ"' "$CONFIG_CHECK"; then
  UNCONFIGURED=1
  CHECK_HASH=$(printf '%s' 'awg3panel installer config example check' | "$BIN_SRC" hash-password)
  IFACES=$(AWG3PANEL_SYSTEMD=0 "$BIN_SRC" -config <(sed 's|^  bcrypt: "ЗАМЕНИТЬ"$|  bcrypt: "'"$CHECK_HASH"'"|' "$CONFIG_CHECK") ifaces --ids)
elif [ "$CONFIG_CHECK" = "$CONFIG_DST" ] && [ "$SERVICE_ACTIVE" = "1" ]; then
  # Проверяем существующую активную установку с теми же ограничениями,
  # которые systemd задаст новой версии панели.
  IFACES=$(AWG3PANEL_SYSTEMD=1 "$BIN_SRC" -config "$CONFIG_CHECK" ifaces --ids)
else
  IFACES=$(AWG3PANEL_SYSTEMD=0 "$BIN_SRC" -config "$CONFIG_CHECK" ifaces --ids)
fi

# Проверяем ID перед использованием как части пути.
ids=()
while IFS= read -r id; do
  if [[ ! "$id" =~ ^[a-z0-9-]{1,32}$ ]]; then
    say "не удалось прочитать id интерфейса из вывода ifaces --ids"
    exit 1
  fi
  ids+=("$id")
done <<< "$IFACES"

# До этой точки и при --dry-run операции с установленными файлами только
# читают данные. Оба режима используют один план установки.
ensure_dir /etc/awg3panel
ensure_dir "$STATE_ROOT"

BIN_CHANGED=0
if [ -f "$BIN_DST" ] && cmp -s "$BIN_SRC" "$BIN_DST"; then
  say "бинарь не изменился"
else
  run install -m 0755 "$BIN_SRC" "$BIN_DST"
  BIN_CHANGED=1
fi

if [ "$CONFIG_CHECK" = "$CONFIG_DST" ]; then
  say "config.yaml уже есть — не трогаю"
else
  run install -m 0600 "$EXAMPLE_SRC" "$CONFIG_DST"
fi

# У старого одноинтерфейсного формата стандартное хранилище в корне.
# Для нового формата используем все ID из штатного разбора.
if grep -Eq "^(awg|\"awg\"|'awg'):([[:space:]]|$)" "$CONFIG_CHECK"; then
  ensure_dir "$STATE_ROOT/backups"
  ensure_dir "$STATE_ROOT/keys"
else
  for id in "${ids[@]}"; do
    ensure_dir "$STATE_ROOT/$id"
    ensure_dir "$STATE_ROOT/$id/backups"
    ensure_dir "$STATE_ROOT/$id/keys"
  done
fi

UNIT_CHANGED=0
if [ -f "$UNIT_DST" ] && cmp -s "$UNIT_SRC" "$UNIT_DST"; then
  say "юнит не изменился"
else
  run install -m 0644 "$UNIT_SRC" "$UNIT_DST"
  run systemctl daemon-reload
  UNIT_CHANGED=1
fi

if [ "$UNCONFIGURED" = "1" ]; then
  say "в config.yaml не задан bcrypt — сервис не запускаю"
  say "задайте bcrypt с помощью $BIN_DST hash-password"
  exit 0
fi

if [ "$SERVICE_ACTIVE" = "1" ]; then
  if [ "$BIN_CHANGED" = "0" ] && [ "$UNIT_CHANGED" = "0" ]; then
    say "сервис уже работает, ничего не менялось"
    exit 0
  fi
  run systemctl restart awg3panel
else
  run systemctl enable --now awg3panel
fi
run systemctl is-active --quiet awg3panel || { say "сервис awg3panel не активен"; exit 1; }
