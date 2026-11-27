## AWG3 Panel v0.5.2

- Исправлено восстановление MCP-сессии автоподбора Keenetic после перезапуска AWG Manager и разбор SSE-ответов без завершающей пустой строки.
- Исправлена обработка обёрнутых `context.Canceled` / `context.DeadlineExceeded`, пустых chunked-запросов, проверки границ `Best` и убран захват мьютекса на время записи HTTP-ответов в автоподборе.
- Установщик `deploy/bootstrap.sh` гарантированно удаляет временный файл профиля администратора при ошибке, `deploy/install.sh` возвращает понятную ошибку при лишнем аргументе, а фронтенд-тесты `console.test.mjs` добавлены в CI и `make test`.

## Установка

На чистом VPS выполните:

```bash
curl -fsSLo install.sh https://github.com/Jkaotlic/awg3-panel/releases/download/v0.5.2/install.sh
sudo bash install.sh --version v0.5.2
```

На действующей установке сохраните согласованный снимок конфигурации и состояния перед заменой бинарника панели. [Подготовка VPS, первый вход и откат](https://github.com/Jkaotlic/awg3-panel/blob/v0.5.2/docs/install.md)
