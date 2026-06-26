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
XDG_DATA_HOME ?= $(HOME)/.local/share
OSXCROSS_ROOT ?= $(XDG_DATA_HOME)/osxcross/target
MACOSX_DEPLOYMENT_TARGET ?= 11.0
IOS_DEPLOYMENT_TARGET ?= 13.0
IPHONEOS_SDK ?= $(shell ls -d "$(OSXCROSS_ROOT)"/SDK/iPhoneOS*.sdk 2>/dev/null | sort -V | tail -n 1)
IPHONESIMULATOR_SDK ?= $(shell ls -d "$(OSXCROSS_ROOT)"/SDK/iPhoneSimulator*.sdk 2>/dev/null | sort -V | tail -n 1)
OSXCROSS_X86_64_CC := $(OSXCROSS_ROOT)/bin/o64-clang
OSXCROSS_AARCH64_CC := $(OSXCROSS_ROOT)/bin/oa64-clang
OSXCROSS_IOS_AARCH64_CC := $(OSXCROSS_ROOT)/bin/ios64-clang
OSXCROSS_IOSSIM_AARCH64_CC := $(OSXCROSS_ROOT)/bin/iossim64-clang
OSXCROSS_IOSSIM_X86_64_CC := $(OSXCROSS_ROOT)/bin/iossimx64-clang

BUILD_DIR := .build
BIN_DIR   := bin
BUILD_VERSION ?= $(shell date +%s)

define cmake_build
	@prelog=$$(mktemp); \
	if ! $(3) cmake --build $(1) -- -n > "$$prelog" 2>&1; then \
		cat "$$prelog"; \
		rm -f "$$prelog"; \
		exit 1; \
	fi; \
	if grep -q "ninja: no work to do." "$$prelog"; then \
		rm -f "$$prelog"; \
		out=$$(mktemp); \
		$(3) cmake --build $(1) 2>"$$out"; \
		r=$$?; \
		if [ -s "$$out" ]; then grep -v 'skipping incompatible' < "$$out"; fi; \
		rm -f "$$out"; \
		exit $$r; \
	fi; \
	rm -f "$$prelog"; \
	out=$$(mktemp); \
	$(3) cmake --build $(1) 2>"$$out"; \
	r=$$?; \
	if [ -s "$$out" ]; then grep -v 'skipping incompatible' < "$$out"; fi; \
	rm -f "$$out"; \
	if [ $$r -ne 0 ]; then \
		exit 1; \
	fi; \
	if [ -n "$(2)" ]; then \
		ver=$$(date +%s); \
		$(2); \
		log=$$(mktemp); \
		if ! $(3) cmake --build $(1) > "$$log" 2>&1; then \
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
	x86_64/linux x86_64/windows x86_64/macos \
	x86_64/iossim \
	i686/linux i686/windows \
	aarch64/linux aarch64/android aarch64/macos aarch64/ios aarch64/iossim \
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
	x86_64/linux x86_64/windows x86_64/macos \
	x86_64/iossim \
	i686/linux i686/windows \
	aarch64/linux aarch64/android aarch64/macos aarch64/ios aarch64/iossim \
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
			-DRP2P_BUILD_VERSION=$(BUILD_VERSION) \
			-DCMAKE_C_COMPILER=$(2) \
			-DCMAKE_RUNTIME_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/linux \
			-DCMAKE_ARCHIVE_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/linux \
			-DCMAKE_LIBRARY_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/linux \
			-G Ninja -Wno-dev > /dev/null; \
	fi
	$(call cmake_build,$(BUILD_DIR)/$(subst /,-,$(1))-linux,cmake -S . -B $(BUILD_DIR)/$(subst /,-,$(1))-linux -DCMAKE_BUILD_TYPE=Release -DCMAKE_SYSTEM_NAME=Linux -DRP2P_BUILD_VERSION=$$ver -DCMAKE_C_COMPILER=$(2) -DCMAKE_RUNTIME_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/linux -DCMAKE_ARCHIVE_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/linux -DCMAKE_LIBRARY_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/linux -G Ninja -Wno-dev > /dev/null)
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
			-DRP2P_BUILD_VERSION=$(BUILD_VERSION) \
			-DCMAKE_C_COMPILER=$(2) \
			-DCMAKE_RUNTIME_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/windows \
			-DCMAKE_ARCHIVE_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/windows \
			-DCMAKE_LIBRARY_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/windows \
			-G Ninja -Wno-dev > /dev/null; \
	fi
	$(call cmake_build,$(BUILD_DIR)/$(1)-windows,cmake -S . -B $(BUILD_DIR)/$(1)-windows -DCMAKE_BUILD_TYPE=Release -DCMAKE_SYSTEM_NAME=Windows -DRP2P_BUILD_VERSION=$$ver -DCMAKE_C_COMPILER=$(2) -DCMAKE_RUNTIME_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/windows -DCMAKE_ARCHIVE_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/windows -DCMAKE_LIBRARY_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/windows -G Ninja -Wno-dev > /dev/null)
	@cp $(BUILD_DIR)/$(1)-windows/out/rp2p.exe $(BIN_DIR)/$(1)/windows/rp2p.exe 2>/dev/null; true
	@cp $(BUILD_DIR)/$(1)-windows/out/librp2p.dll $(BIN_DIR)/$(1)/windows/librp2p.dll 2>/dev/null; true
	@echo "OK $(1)/windows"
endef

x86_64/windows:
	$(call windows_target,x86_64,x86_64-w64-mingw32-gcc)

i686/windows:
	$(call windows_target,i686,i686-w64-mingw32-gcc)

## macOS

define macos_target
	@mkdir -p $(BIN_DIR)/$(1)/macos
	@if [ ! -x $(2) ]; then \
		echo "Missing macOS cross-compiler wrapper: $(2)" >&2; \
		echo "Set OSXCROSS_ROOT to your osxcross target dir and ensure the wrappers are built." >&2; \
		exit 1; \
	fi
	@if [ ! -f $(BUILD_DIR)/$(1)-macos/build.ninja ]; then \
		PATH="$(OSXCROSS_ROOT)/bin:$$PATH" cmake -S . -B $(BUILD_DIR)/$(1)-macos \
			-DCMAKE_BUILD_TYPE=Release \
			-DCMAKE_SYSTEM_NAME=Darwin \
			-DCMAKE_OSX_DEPLOYMENT_TARGET=$(MACOSX_DEPLOYMENT_TARGET) \
			-DRP2P_BUILD_VERSION=$(BUILD_VERSION) \
			-DCMAKE_C_COMPILER=$(2) \
			-DCMAKE_RUNTIME_OUTPUT_DIRECTORY=$(CURDIR)/$(BUILD_DIR)/$(1)-macos/out \
			-DCMAKE_ARCHIVE_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/macos \
			-DCMAKE_LIBRARY_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/macos \
			-G Ninja -Wno-dev > /dev/null; \
	fi
	$(call cmake_build,$(BUILD_DIR)/$(1)-macos,PATH="$(OSXCROSS_ROOT)/bin:$$PATH" cmake -S . -B $(BUILD_DIR)/$(1)-macos -DCMAKE_BUILD_TYPE=Release -DCMAKE_SYSTEM_NAME=Darwin -DCMAKE_OSX_DEPLOYMENT_TARGET=$(MACOSX_DEPLOYMENT_TARGET) -DRP2P_BUILD_VERSION=$$ver -DCMAKE_C_COMPILER=$(2) -DCMAKE_RUNTIME_OUTPUT_DIRECTORY=$(CURDIR)/$(BUILD_DIR)/$(1)-macos/out -DCMAKE_ARCHIVE_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/macos -DCMAKE_LIBRARY_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/macos -G Ninja -Wno-dev > /dev/null,PATH="$(OSXCROSS_ROOT)/bin:$$PATH")
	@cp $(BUILD_DIR)/$(1)-macos/out/rp2p $(BIN_DIR)/$(1)/macos/rp2p
	@echo "OK $(1)/macos"
endef

x86_64/macos:
	$(call macos_target,x86_64,$(OSXCROSS_X86_64_CC))

aarch64/macos:
	$(call macos_target,aarch64,$(OSXCROSS_AARCH64_CC))

## iOS

define ios_target
	@mkdir -p $(BIN_DIR)/$(1)/$(2)
	@if [ ! -x $(3) ]; then \
		echo "Missing iOS cross-compiler wrapper: $(3)" >&2; \
		echo "Set OSXCROSS_ROOT to your osxcross target dir and ensure the wrappers are built." >&2; \
		exit 1; \
	fi
	@if [ -z "$(5)" ] || [ ! -d "$(5)" ]; then \
		echo "Missing iOS SDK sysroot: $(5)" >&2; \
		echo "Set $(4) to an installed Apple SDK directory." >&2; \
		exit 1; \
	fi
	@if [ ! -f $(BUILD_DIR)/$(1)-$(2)/build.ninja ]; then \
		PATH="$(OSXCROSS_ROOT)/bin:$$PATH" cmake -S . -B $(BUILD_DIR)/$(1)-$(2) \
			-DCMAKE_BUILD_TYPE=Release \
			-DCMAKE_SYSTEM_NAME=iOS \
			-DCMAKE_SYSTEM_VERSION=$(IOS_DEPLOYMENT_TARGET) \
			-DCMAKE_OSX_DEPLOYMENT_TARGET=$(IOS_DEPLOYMENT_TARGET) \
			-DCMAKE_OSX_SYSROOT=$(5) \
			-DCMAKE_OSX_ARCHITECTURES=$(6) \
			-DRP2P_BUILD_VERSION=$(BUILD_VERSION) \
			-DCMAKE_C_COMPILER=$(3) \
			-DCMAKE_RUNTIME_OUTPUT_DIRECTORY=$(CURDIR)/$(BUILD_DIR)/$(1)-$(2)/out \
			-DCMAKE_ARCHIVE_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/$(2) \
			-DCMAKE_LIBRARY_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/$(2) \
			-G Ninja -Wno-dev > /dev/null; \
	fi
	$(call cmake_build,$(BUILD_DIR)/$(1)-$(2),PATH="$(OSXCROSS_ROOT)/bin:$$PATH" cmake -S . -B $(BUILD_DIR)/$(1)-$(2) -DCMAKE_BUILD_TYPE=Release -DCMAKE_SYSTEM_NAME=iOS -DCMAKE_SYSTEM_VERSION=$(IOS_DEPLOYMENT_TARGET) -DCMAKE_OSX_DEPLOYMENT_TARGET=$(IOS_DEPLOYMENT_TARGET) -DCMAKE_OSX_SYSROOT=$(5) -DCMAKE_OSX_ARCHITECTURES=$(6) -DRP2P_BUILD_VERSION=$$ver -DCMAKE_C_COMPILER=$(3) -DCMAKE_RUNTIME_OUTPUT_DIRECTORY=$(CURDIR)/$(BUILD_DIR)/$(1)-$(2)/out -DCMAKE_ARCHIVE_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/$(2) -DCMAKE_LIBRARY_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/$(2) -G Ninja -Wno-dev > /dev/null,PATH="$(OSXCROSS_ROOT)/bin:$$PATH")
	@if [ -f $(BUILD_DIR)/$(1)-$(2)/out/rp2p ]; then \
		cp $(BUILD_DIR)/$(1)-$(2)/out/rp2p $(BIN_DIR)/$(1)/$(2)/rp2p; \
	elif [ -f $(BUILD_DIR)/$(1)-$(2)/out/rp2p.app/rp2p ]; then \
		cp $(BUILD_DIR)/$(1)-$(2)/out/rp2p.app/rp2p $(BIN_DIR)/$(1)/$(2)/rp2p; \
	else \
		echo "Missing built iOS executable for $(1)/$(2)" >&2; \
		exit 1; \
	fi
	@echo "OK $(1)/$(2)"
endef

aarch64/ios:
	$(call ios_target,aarch64,ios,$(OSXCROSS_IOS_AARCH64_CC),IPHONEOS_SDK,$(IPHONEOS_SDK),arm64)

aarch64/iossim:
	$(call ios_target,aarch64,iossim,$(OSXCROSS_IOSSIM_AARCH64_CC),IPHONESIMULATOR_SDK,$(IPHONESIMULATOR_SDK),arm64)

x86_64/iossim:
	$(call ios_target,x86_64,iossim,$(OSXCROSS_IOSSIM_X86_64_CC),IPHONESIMULATOR_SDK,$(IPHONESIMULATOR_SDK),x86_64)

## Android

define android_target
	@mkdir -p $(BIN_DIR)/$(1)/android
	@if [ ! -f $(BUILD_DIR)/$(1)-android/CMakeCache.txt ]; then \
		cmake -S . -B $(BUILD_DIR)/$(1)-android \
			-DCMAKE_BUILD_TYPE=Release \
			-DCMAKE_TOOLCHAIN_FILE=$(NDK_TOOLCHAIN) \
			-DRP2P_BUILD_VERSION=$(BUILD_VERSION) \
			-DANDROID_ABI=$(2) \
			-DANDROID_PLATFORM=android-21 \
			-DCMAKE_RUNTIME_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/android \
			-DCMAKE_ARCHIVE_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/android \
			-DCMAKE_LIBRARY_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/android \
			-G Ninja -Wno-dev > /dev/null; \
	fi
	$(call cmake_build,$(BUILD_DIR)/$(1)-android,cmake -S . -B $(BUILD_DIR)/$(1)-android -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=$(NDK_TOOLCHAIN) -DRP2P_BUILD_VERSION=$$ver -DANDROID_ABI=$(2) -DANDROID_PLATFORM=android-21 -DCMAKE_RUNTIME_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/android -DCMAKE_ARCHIVE_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/android -DCMAKE_LIBRARY_OUTPUT_DIRECTORY=$(CURDIR)/$(BIN_DIR)/$(1)/android -G Ninja -Wno-dev > /dev/null)
	@cp $(BUILD_DIR)/$(1)-android/out/rp2p $(BIN_DIR)/$(1)/android/rp2p 2>/dev/null; true
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
