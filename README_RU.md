# Анализатор HTTP-запросов для сайтов Apache

[Русский](README_RU.md) | [English](README.md)

Современный Python-скрипт для анализа конфигурационных файлов Apache с целью извлечения уникальных URL-адресов для определенных HTTP методов. Обеспечивает высокую производительность, надежность и гибкость настройки.

## ✨ Возможности

### 🚀 Производительность
- **Многопоточная обработка** - параллельная обработка файлов логов
- **Эффективное использование памяти** - потоковая обработка больших файлов
- **Компилированные регулярные выражения** - оптимизированный парсинг
- **Умная валидация** - предотвращение обработки невалидных данных

### 🛡️ Безопасность и надежность
- **Безопасная работа с файлами** - использование pathlib
- **Обработка ошибок** - comprehensive error handling
- **Валидация входных данных** - проверка доменов и URL
- **Защита от path traversal** - фильтрация вредоносных путей

### 📊 Расширенные возможности
- **Конфигурируемые параметры** - настройка через аргументы командной строки
- **Подробное логирование** - мониторинг процесса анализа
- **Статистика результатов** - детальная информация о найденных URL
- **Поддержка Unicode** - корректная обработка международных доменов

## 🔧 Системные требования

- Python 3.7+
- Права на чтение конфигурационных файлов Apache
- Права на чтение файлов логов Apache
- Права на запись в выходную директорию

## 📦 Установка

```bash
# Клонирование репозитория
git clone https://github.com/commeta/apache_url_analyzer
cd apache-url-analyzer

## 🚀 Использование

### Базовое использование

```bash
# Запуск с параметрами по умолчанию
python3 apache_url_analyzer.py

# Запуск с правами суперпользователя (если требуется)
sudo python3 apache_url_analyzer.py
```

### Расширенные опции

```bash
# Настройка путей и параметров
python3 apache_url_analyzer.py \
    --config-glob "/etc/apache2/sites-available/*.conf" \
    --output-dir "/var/log/apache2" \
    --methods POST PUT DELETE PATCH \
    --max-workers 8 \
    --log-level DEBUG

# Анализ только определенных методов
python3 apache_url_analyzer.py --methods POST DELETE

# Увеличение количества потоков для больших серверов
python3 apache_url_analyzer.py --max-workers 16
```

## 📋 Параметры командной строки

| Параметр | Описание | По умолчанию |
|----------|----------|--------------|
| `--config-glob` | Glob-паттерн для поиска конфигурационных файлов Apache | `/etc/apache2/sites-enabled/*/*.conf` |
| `--output-dir` | Директория для сохранения результатов | `/var/log/apache2` |
| `--methods` | HTTP методы для анализа | `POST DELETE PUT HEAD` |
| `--max-workers` | Максимальное количество потоков | `4` |
| `--log-level` | Уровень логирования | `INFO` |

## 📁 Структура выходных файлов

Скрипт создает отдельные файлы для каждого HTTP метода:

```
/var/log/apache2/
├── sites_post.log     # URL для POST запросов
├── sites_delete.log   # URL для DELETE запросов
├── sites_put.log      # URL для PUT запросов
└── sites_head.log     # URL для HEAD запросов
```

### Формат выходных данных

```
example.com /api/users
example.com /api/posts
subdomain.example.com /admin/settings
another-site.com /webhook/github
```

## 🔍 Примеры использования

### Анализ безопасности

```bash
# Поиск потенциально опасных POST запросов
python3 apache_url_analyzer.py --methods POST
grep -i "admin\|upload\|exec\|cmd" /var/log/apache2/sites_post.log
```

### Мониторинг API

```bash
# Анализ API endpoints
python3 apache_url_analyzer.py --methods POST PUT DELETE PATCH
```

### Отладка конфигурации

```bash
# Подробный анализ с отладочной информацией
python3 apache_url_analyzer.py --log-level DEBUG
```

## Оптимизация

```bash
# Для больших серверов
python3 apache_url_analyzer.py --max-workers 16

# Для систем с ограниченной памятью
python3 apache_url_analyzer.py --max-workers 2
```
