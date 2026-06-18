## Makefile
## Summary: Cross-compilation builder for p2p.
##
## Author:  KaisarCode
## Website: https://kaisarcode.com
## License: https://www.gnu.org/licenses/gpl-3.0.html

ANDROID_HOME  ?= $(HOME)/.local/share/android-sdk
NDK_VERSION   ?= 27.2.12479018
NDK_DIR       := $(ANDROID_HOME)/ndk/$(NDK_VERSION)
NDK_TOOLCHAIN := $(NDK_DIR)/build/cmake/android.toolchain.cmake

BUILD_DIR := .build
BIN_DIR   := bin
BUILD_VERSION ?= $(shell date +%s)

define cmake_build
	@prelog=$$(mktemp); \
	if ! cmake --build $(1) -- -n > "$$prelog" 2>&1; then \
		cat "$$prelog"; \
		rm -f "$$prelog"; \
		exit 1; \
	fi; \
	if grep -q "ninja: no work to do." "$$prelog"; then \
		rm -f "$$prelog"; \
		cmake --build $(1); \
		exit $$?; \
	fi; \
	rm -f "$$prelog"; \
	if ! cmake --build $(1); then \
		exit 1; \
	fi; \
	if [ -n "$(2)" ]; then \
		ver=$$(date +%s); \
		$(2); \
		log=$$(mktemp); \
		if ! cmake --build $(1) > "$$log" 2>&1; then \
			cat "$$log"; \
			rm -f "$$log"; \
			exit 1; \
		fi; \
		rm -f "$$log"; \
	fi; \
	:
endef

HOST_ARCH       := $(shell uname -m)
HOST_SYSTEM     := $(shell uname -s)
NATIVE_ARCH     := unsupported
NATIVE_PLATFORM := unsupported

ifneq ($(filter x86_64 amd64,$(HOST_ARCH)),)
NATIVE_ARCH := x86_64
endif

ifneq ($(filter i386 i686,$(HOST_ARCH)),)
NATIVE_ARCH := i686
endif

ifneq ($(filter aarch64 arm64,$(HOST_ARCH)),)
NATIVE_ARCH := aarch64
endif

ifneq ($(filter armv7l armv7%,$(HOST_ARCH)),)
NATIVE_ARCH := armv7
endif

ifneq ($(filter ppc64le powerpc64le,$(HOST_ARCH)),)
NATIVE_ARCH := powerpc64le
endif

ifneq ($(filter riscv64 s390x loongarch64 mips64el mipsel mips,$(HOST_ARCH)),)
NATIVE_ARCH := $(HOST_ARCH)
endif

ifeq ($(HOST_SYSTEM),Linux)
NATIVE_PLATFORM := linux
endif

ifneq ($(filter MINGW% MSYS% CYGWIN%,$(HOST_SYSTEM)),)
NATIVE_PLATFORM := windows
endif

NATIVE_TARGET := $(NATIVE_ARCH)/$(NATIVE_PLATFORM)

.DEFAULT_GOAL := native

.PHONY: native all test clean \
	x86_64/linux x86_64/windows \
	i686/linux i686/windows \
	aarch64/linux aarch64/android \
	armv7/linux armv7/android \
	armv7hf/linux \
	riscv64/linux \
	powerpc64le/linux \
	mips/linux mipsel/linux mips64el/linux \
	s390x/linux \
	loongarch64/linux

native:
	@if [ "$(NATIVE_ARCH)" = "unsupported" ] || [ "$(NATIVE_PLATFORM)" = "unsupported" ]; then \
		echo "Unsupported native target $(HOST_ARCH)/$(HOST_SYSTEM)" >&2; \
		exit 1; \
	fi
	@$(MAKE) BUILD_VERSION=$(BUILD_VERSION) $(NATIVE_TARGET)

all: \
	x86_64/linux x86_64/windows \
	i686/linux i686/windows \
	aarch64/linux aarch64/android \
	armv7/linux armv7/android \
	armv7hf/linux \
	riscv64/linux \
	powerpc64le/linux \
	mips/linux mipsel/linux mips64el/linux \
	s390x/linux \
	loongarch64/linux

## Linux

define linux_target
	@mkdir -p $(BIN_DIR)/$(1)/linux
	@if [ ! -f $(BUILD_DIR)/$(subst /,-,$(1))-linux/CMakeCache.txt ]; then \
		cmake -S . -B $(BUILD_DIR)/$(subst /,-,$(1))-linux \
			-DCMAKE_BUILD_TYPE=Release \
			-DCMAKE_SYSTEM_NAME=Linux \
			-DP2P_BUILD_VERSION=$(BUILD_VERSION) \
			-DCMAKE_C_COMPILER=$(2) \
			-DCMAKE_RUNTIME_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/linux \
			-DCMAKE_ARCHIVE_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/linux \
			-DCMAKE_LIBRARY_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/linux \
			-G Ninja -Wno-dev > /dev/null; \
	fi
	$(call cmake_build,$(BUILD_DIR)/$(subst /,-,$(1))-linux,cmake -S . -B $(BUILD_DIR)/$(subst /,-,$(1))-linux -DCMAKE_BUILD_TYPE=Release -DCMAKE_SYSTEM_NAME=Linux -DP2P_BUILD_VERSION=$$ver -DCMAKE_C_COMPILER=$(2) -DCMAKE_RUNTIME_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/linux -DCMAKE_ARCHIVE_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/linux -DCMAKE_LIBRARY_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/linux -G Ninja -Wno-dev > /dev/null)
	@echo "OK $(1)/linux"
endef

x86_64/linux:
	$(call linux_target,x86_64,gcc)

i686/linux:
	$(call linux_target,i686,i686-linux-gnu-gcc)

aarch64/linux:
	$(call linux_target,aarch64,aarch64-linux-gnu-gcc)

armv7hf/linux:
	$(call linux_target,armv7hf,arm-linux-gnueabihf-gcc)

armv7/linux:
	$(call linux_target,armv7,arm-linux-gnueabi-gcc)

riscv64/linux:
	$(call linux_target,riscv64,riscv64-linux-gnu-gcc)

powerpc64le/linux:
	$(call linux_target,powerpc64le,powerpc64le-linux-gnu-gcc)

mips/linux:
	$(call linux_target,mips,mips-linux-gnu-gcc)

mipsel/linux:
	$(call linux_target,mipsel,mipsel-linux-gnu-gcc)

mips64el/linux:
	$(call linux_target,mips64el,mips64el-linux-gnuabi64-gcc)

s390x/linux:
	$(call linux_target,s390x,s390x-linux-gnu-gcc)

loongarch64/linux:
	$(call linux_target,loongarch64,loongarch64-linux-gnu-gcc)

## Windows

define windows_target
	@mkdir -p $(BIN_DIR)/$(1)/windows
	@if [ ! -f $(BUILD_DIR)/$(1)-windows/CMakeCache.txt ]; then \
		cmake -S . -B $(BUILD_DIR)/$(1)-windows \
			-DCMAKE_BUILD_TYPE=Release \
			-DCMAKE_SYSTEM_NAME=Windows \
			-DP2P_BUILD_VERSION=$(BUILD_VERSION) \
			-DCMAKE_C_COMPILER=$(2) \
			-DCMAKE_RUNTIME_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/windows \
			-DCMAKE_ARCHIVE_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/windows \
			-DCMAKE_LIBRARY_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/windows \
			-G Ninja -Wno-dev > /dev/null; \
	fi
	$(call cmake_build,$(BUILD_DIR)/$(1)-windows,cmake -S . -B $(BUILD_DIR)/$(1)-windows -DCMAKE_BUILD_TYPE=Release -DCMAKE_SYSTEM_NAME=Windows -DP2P_BUILD_VERSION=$$ver -DCMAKE_C_COMPILER=$(2) -DCMAKE_RUNTIME_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/windows -DCMAKE_ARCHIVE_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/windows -DCMAKE_LIBRARY_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/windows -G Ninja -Wno-dev > /dev/null)
	@cp $(BUILD_DIR)/$(1)-windows/out/p2p.exe $(BIN_DIR)/$(1)/windows/p2p.exe 2>/dev/null; true
	@cp $(BUILD_DIR)/$(1)-windows/out/libkcp2p.dll $(BIN_DIR)/$(1)/windows/libkcp2p.dll 2>/dev/null; true
	@echo "OK $(1)/windows"
endef

x86_64/windows:
	$(call windows_target,x86_64,x86_64-w64-mingw32-gcc)

i686/windows:
	$(call windows_target,i686,i686-w64-mingw32-gcc)

## Android

define android_target
	@mkdir -p $(BIN_DIR)/$(1)/android
	@if [ ! -f $(BUILD_DIR)/$(1)-android/CMakeCache.txt ]; then \
		cmake -S . -B $(BUILD_DIR)/$(1)-android \
			-DCMAKE_BUILD_TYPE=Release \
			-DCMAKE_TOOLCHAIN_FILE=$(NDK_TOOLCHAIN) \
			-DP2P_BUILD_VERSION=$(BUILD_VERSION) \
			-DANDROID_ABI=$(2) \
			-DANDROID_PLATFORM=android-21 \
			-DCMAKE_RUNTIME_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/android \
			-DCMAKE_ARCHIVE_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/android \
			-DCMAKE_LIBRARY_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/android \
			-G Ninja -Wno-dev > /dev/null; \
	fi
	$(call cmake_build,$(BUILD_DIR)/$(1)-android,cmake -S . -B $(BUILD_DIR)/$(1)-android -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=$(NDK_TOOLCHAIN) -DP2P_BUILD_VERSION=$$ver -DANDROID_ABI=$(2) -DANDROID_PLATFORM=android-21 -DCMAKE_RUNTIME_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/android -DCMAKE_ARCHIVE_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/android -DCMAKE_LIBRARY_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/android -G Ninja -Wno-dev > /dev/null)
	@cp $(BUILD_DIR)/$(1)-android/out/p2p $(BIN_DIR)/$(1)/android/p2p 2>/dev/null; true
	@echo "OK $(1)/android"
endef

aarch64/android:
	$(call android_target,aarch64,arm64-v8a)

armv7/android:
	$(call android_target,armv7,armeabi-v7a)

## Utility

test:
	@sh test.sh

clean:
	@rm -rf $(BUILD_DIR)
	@echo "OK clean"
