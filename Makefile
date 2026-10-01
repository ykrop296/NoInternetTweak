# ============================================================================
# NoInternet Tweak — Makefile
# Блокирует приложению доступ в интернет через инжект в LiveContainer
# ============================================================================
#
# ТРЕБОВАНИЯ:
#   - macOS с Xcode и Command Line Tools
#   - iOS SDK (идёт с Xcode)
#
# СБОРКА:
#   make            — сборка для arm64 (реальное устройство)
#   make ARCH=arm64 — явное указание архитектуры
#   make clean      — очистка
#
# УСТАНОВКА:
#   Скопируйте NoInternet.dylib в LiveContainer → Tweaks
# ============================================================================

# Настройки
TWEAK_NAME  = NoInternet
ARCH        ?= arm64
MIN_IOS     ?= 15.0
SDK         ?= iphoneos

# Инструменты
CC          = xcrun -sdk $(SDK) clang
LDID        ?= ldid

# Файлы
SOURCES     = NoInternet.m fishhook.c
OUTPUT      = $(TWEAK_NAME).dylib

# Флаги компиляции
CFLAGS = \
	-arch $(ARCH) \
	-miphoneos-version-min=$(MIN_IOS) \
	-dynamiclib \
	-fobjc-arc \
	-O2 \
	-Wall \
	-Wextra \
	-Wno-unused-parameter

# Линковка
LDFLAGS = \
	-framework Foundation \
	-framework SystemConfiguration \
	-framework Network \
	-lSystem

# ============================================================================
# Цели
# ============================================================================

.PHONY: all clean install sign

all: $(OUTPUT)
	@echo ""
	@echo "✅ Сборка завершена: $(OUTPUT)"
	@echo "📱 Скопируйте $(OUTPUT) в LiveContainer → Tweaks"
	@echo ""

$(OUTPUT): $(SOURCES) fishhook.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SOURCES)
	@# Подпишем ad-hoc, если ldid доступен
	@if command -v $(LDID) > /dev/null 2>&1; then \
		$(LDID) -S $@; \
		echo "🔐 Подписано с помощью ldid"; \
	else \
		codesign -f -s - $@ 2>/dev/null || true; \
		echo "🔐 Подписано ad-hoc через codesign"; \
	fi

clean:
	rm -f $(OUTPUT)
	@echo "🧹 Очищено"

# Удобная цель для подписи отдельно
sign: $(OUTPUT)
	@if command -v $(LDID) > /dev/null 2>&1; then \
		$(LDID) -S $@; \
	else \
		codesign -f -s - $@; \
	fi
	@echo "🔐 Подписано"
