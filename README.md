# Threat Information API

Небольшой REST API на Go, chi и PostgreSQL для создания, получения и обновления записей об угрозах. OpenAPI-контракт находится в `api.yaml`.

## Запуск

Нужен Docker Compose. Создайте локальный `.env` из примера:

```sh
cp .env.example .env
```

Значения в `.env.example` предназначены только для локальной разработки. Для общего окружения задайте собственный `DB_PASSWORD`.

```sh
docker compose up --build
```

Сервис доступен на `http://localhost:8080`. PostgreSQL доступен с хоста на порту `DB_HOST_PORT` (по умолчанию `5433`), а приложение внутри Compose подключается к `db:5432`. Если `5433` тоже занят, измените `DB_HOST_PORT` в `.env`. При запуске приложение проверяет соединение с PostgreSQL и автоматически применяет ожидающие Goose-миграции из встроенных SQL-файлов. Параметры приложения и базы задаются переменными из `.env`; `DB_HOST` внутри Compose фиксирован как `db`. Для остановки нажмите `Ctrl+C`; HTTP-сервер завершает активные запросы перед остановкой.

## Методы

- `POST /info` — создать угрозу.
- `GET /info/{md5}` — получить угрозу.
- `PUT /info/{md5}` — полностью заменить редактируемые поля угрозы.

Пример создания:

```sh
MD5=d41d8cd98f00b204e9800998ecf8427e

# Создать угрозу
curl -X POST http://localhost:8080/info \
  -H 'Content-Type: application/json' \
  -d '{"md5":"d41d8cd98f00b204e9800998ecf8427e","name":"Trojan.Win32.Generic","description":"Example threat","severity":"high","type":"malware"}'

# Получить её
curl -i "http://localhost:8080/info/$MD5"

# Обновить поля угрозы
curl -i -X PUT "http://localhost:8080/info/$MD5" \
  -H 'Content-Type: application/json' \
  -d '{"name":"Test.Trojan.Updated","description":"Updated test threat","severity":"critical","type":"malware"}'

# Получить обновлённую запись
curl -i "http://localhost:8080/info/$MD5"
```

## Тесты

```sh
go test ./...
```

Остановить Compose и удалить данные БД:

```sh
docker compose down -v
```
