# Проверки SyncApp

Транспорт работает через GitHub/junk. Личная сторона создаёт подписанные зашифрованные baseline и пакеты и отправляет их по явному действию пользователя. Рабочая сторона только обновляет clone, проверяет baseline и принимает пакеты; применение меняет рабочую копию кода, а исходный коммит пользователь создаёт вручную. Рабочая сторона не создаёт транспортных коммитов, не отправляет их и не публикует подтверждения. QR- и файловый перенос не поддерживаются.

## Локальный прогон

Из корня репозитория:

```sh
dotnet build SyncApp.slnx
AGE_PATH=/path/to/age dotnet run --project tests/SyncApp.Tests.csproj --no-build
python3 tests/http_security.py
SYNCAPP_PLAYWRIGHT=/path/to/playwright \
SYNCAPP_CHROMIUM_PATH=/path/to/chrome-headless-shell \
  node tests/browser.cjs
```

Укажите локальные исполняемые файлы `age`, Playwright и Chromium. Тесты используют только временные репозитории и локальный bare remote; они не обращаются к настоящему GitHub.

## Что проверяется

Интеграционный набор создаёт две независимые исходные репозитории, два junk-clone и локальный bare remote. Он проверяет ручную привязку age recipient и fingerprint, публикацию и проверку зашифрованного baseline, последовательность личных пакетов, применение и локальное подтверждение ручного коммита. Отдельные сценарии проверяют повтор push после отказа, сохранение ciphertext при отказе fast-forward pull, блокировку посторонних staged-файлов, отказ при несовпадающем baseline и recipient, порядок пакетов, восстановление после прерываний и отсутствие plaintext исходных путей, сообщений и содержимого в объектах junk.

Проверки также убеждаются, что Work отклоняет `push: true` до вызова Git push, а его junk clone не получает транспортных коммитов: HEAD следует только fast-forward от remote, index и worktree junk остаются чистыми. Применение меняет source worktree; после него пользователь вручную создаёт source-коммит и локально подтверждает его. В junk не появляются Work-пакеты или подтверждения. Проверяются неподтверждённые локальные junk-коммиты и сообщения коммитов, переписанная очередь, дескрипторы с LF и CRLF при `core.autocrlf`, дублированные JSON-поля и `.age` symlink. HTTP-набор проверяет CSRF, Origin/Host, размер тела и удалённые QR/file-transfer маршруты. Браузерный набор проверяет отдельные действия Personal и Work, отсутствие у Work push-контрола, отсутствие загрузки файлов и QR-ресурсов, отсутствие внешних запросов и безопасный вывод недоверенных метаданных.

## Проверено в Linux

Сборки Debug (`dotnet build SyncApp.slnx`) и Release (`dotnet build SyncApp.slnx -c Release --nologo`) завершились без предупреждений и ошибок. Core integration suite прошёл 34 сценария, HTTP security suite — 8 тестов, browser suite — 3 проверки. Они использовали временные репозитории и локальный bare remote, без настоящего GitHub. Browser test запускался с локально установленными Playwright и Chromium; Core encryption использовал локальный `age` binary. Windows и WSL отдельно не проверялись.

Фактически выполненные команды и локальные пути:

```sh
dotnet clean SyncApp.slnx
dotnet build SyncApp.slnx
AGE_PATH=/tmp/syncapp-test-tools/age-v1.3.2/age/age dotnet run --project tests/SyncApp.Tests.csproj --no-build
python3 tests/http_security.py
SYNCAPP_PLAYWRIGHT=/tmp/syncapp-test-tools/browser/node_modules/playwright \
SYNCAPP_CHROMIUM_PATH=/home/alex/.cache/ms-playwright/chromium_headless_shell-1234/chrome-headless-shell-linux64/chrome-headless-shell \
  node tests/browser.cjs
dotnet build SyncApp.slnx -c Release --nologo
```

Результаты Linux-прогона не подтверждают поведение Windows или WSL. Для них нужен отдельный запуск на соответствующей платформе.
