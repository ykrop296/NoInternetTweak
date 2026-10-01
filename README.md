# 🚫 NoInternet Tweak для LiveContainer

Dylib-твик, который полностью блокирует приложению доступ в интернет при инжекте через LiveContainer.

## 🛡️ Что блокируется

| Уровень | Функции/Классы | Метод перехвата |
|---------|---------------|-----------------|
| **BSD Sockets** | `connect()`, `sendto()`, `sendmsg()`, `socket()` | fishhook (rebind_symbols) |
| **DNS** | `getaddrinfo()`, `gethostbyname()`, `gethostbyname2()` | fishhook (rebind_symbols) |
| **NSURLSession** | `dataTaskWithURL:`, `dataTaskWithRequest:`, `downloadTaskWithURL:`, `uploadTaskWithRequest:` | ObjC Method Swizzling |
| **NSURLConnection** | `sendSynchronousRequest:` (legacy) | ObjC Method Swizzling |

## ✅ Что разрешено

- **localhost / 127.0.0.1 / ::1** — локальные соединения (нужны для WebView и IPC)
- **Unix-сокеты (AF_UNIX)** — межпроцессное взаимодействие внутри устройства

## 📦 Сборка

### На Mac с Xcode:

```bash
cd NoInternetTweak
make
```

### Если нет Mac — сборка через Theos на iPhone/iPad (jailbreak):

1. Установите Theos
2. Создайте проект `$THEOS/bin/nic.pl` → выберите `iphone/tweak`
3. Замените файлы исходным кодом из этого проекта

### Кросс-компиляция (Linux/Windows с toolchain):

```bash
# Нужен iOS SDK и clang с поддержкой arm64-apple-ios
clang -arch arm64 -target arm64-apple-ios15.0 \
      -isysroot /path/to/iPhoneOS.sdk \
      -dynamiclib -fobjc-arc -O2 \
      -framework Foundation \
      -o NoInternet.dylib \
      NoInternet.m fishhook.c
```

## 📲 Установка в LiveContainer

1. Скомпилируйте `NoInternet.dylib`
2. Откройте **LiveContainer** на устройстве
3. Перейдите в настройки нужного приложения
4. Раздел **Tweaks** → добавьте `NoInternet.dylib`
5. Перезапустите приложение через LiveContainer

## 📋 Логи

Все заблокированные запросы логируются в консоль с тегом `[NoInternet]`:

```
[NoInternet] === NoInternet Tweak Loading ===
[NoInternet] Bundle: com.example.app
[NoInternet] BSD socket & DNS hooks installed
[NoInternet] NSURLSession hooks installed
[NoInternet] NSURLConnection hooks installed
[NoInternet] === All hooks installed. Internet access is BLOCKED ===
[NoInternet] BLOCKED connect() to external address (family=2)
[NoInternet] BLOCKED getaddrinfo() for host: api.example.com
[NoInternet] BLOCKED NSURLSession dataTask for URL: https://api.example.com/data
```

Для просмотра логов используйте:
- **macOS**: Console.app → подключите устройство
- **На устройстве**: приложение вроде **oslog** или **Console** (jailbreak)

## ⚙️ Настройка

### Разрешить определённые домены

Если нужно разрешить доступ к конкретным доменам, отредактируйте `hooked_getaddrinfo()`:

```objc
static const char *allowed_hosts[] = {
    "localhost",
    "127.0.0.1",
    "::1",
    "my-allowed-api.com",  // ← добавьте сюда
    NULL
};

static int hooked_getaddrinfo(...) {
    for (int i = 0; allowed_hosts[i]; i++) {
        if (node && strcmp(node, allowed_hosts[i]) == 0) {
            return orig_getaddrinfo(node, service, hints, res);
        }
    }
    // ...блокировка
}
```

### Отключить блокировку socket()

Если приложение крашится из-за блокировки `socket()`, можно убрать этот хук из массива `rebindings[]` в функции `install_socket_hooks()`.

## 🏗️ Структура проекта

```
NoInternetTweak/
├── NoInternet.m     — основной код твика
├── fishhook.h       — заголовок fishhook (Facebook)
├── fishhook.c       — реализация fishhook
├── Makefile         — система сборки
└── README.md        — этот файл
```

## 📄 Лицензия

- **fishhook** — BSD License (Facebook, Inc.)
- **NoInternet tweak** — свободное использование
