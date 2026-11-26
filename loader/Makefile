ROOT_DIR := ..
include ../common.mk

BUILD_DIR ?= $(ROOT_DIR)/build

OBJ_ROOT = $(BUILD_DIR)/obj/$(BUILD_TYPE)/loader
OBJ_DIR = $(OBJ_ROOT)/$(ARCH)

ZKSU_VERSION ?= $(VER_NAME)-$(VER_CODE)-$(COMMIT_HASH)-$(BUILD_TYPE)

RUST_TARGET = aarch64-linux-android
RUST_MANIFEST = src/rust/Cargo.toml
RUST_TARGET_DIR = $(BUILD_DIR)/rust
RUST_LIB = $(RUST_TARGET_DIR)/$(RUST_TARGET)/release/libvrez_resource.a

ifeq ($(BUILD_TYPE),release)
	TYPE_CFLAGS = -O3 -ffast-math -flto -Wno-unused -Wno-unused-parameter       \
				  -fvisibility=hidden -fvisibility-inlines-hidden -fno-unwind-tables \
				  -fno-asynchronous-unwind-tables -DNDEBUG
	TYPE_LDFLAGS = -Wl,--exclude-libs,ALL -Wl,--strip-all -flto
else
	TYPE_CFLAGS = -g -O0
	TYPE_LDFLAGS =
endif

LOADER_CFLAGS = -std=c18 -D_GNU_SOURCE -Wall -Wextra -fno-rtti -fno-exceptions         \
				-fno-stack-protector -fomit-frame-pointer -Wno-builtin-macro-redefined \
				'-D__FILE__=__FILE_NAME__' -DZKSU_VERSION=\"$(ZKSU_VERSION)\"

COMMON_LDFLAGS = -static-libstdc++ -Wl,--build-id=sha1 -Wl,--no-rosegment           \
				 -Wl,--no-undefined-version -Wl,--fatal-warnings -Wl,--no-undefined \
				 -Qunused-arguments -Wl,--gc-sections

COMMON_SRCS = src/common/daemon.c src/common/elf_util.c src/common/mountinfo.c \\
			  src/common/misc.c src/common/socket_utils.c
INJECTOR_SRCS = src/injector/alloc.c src/injector/cpp_strings.c src/injector/entry.c \
				src/injector/hook.c src/injector/hiding.c src/injector/ptrace_clear.c
PTRACER_SRCS = src/ptracer/main.c src/ptracer/monitor.c src/ptracer/ptracer.c \
			   src/ptracer/remote_csoloader.c src/ptracer/utils.c

COMMON_OBJS = $(patsubst src/common/%.c,$(OBJ_DIR)/common/%.o,$(COMMON_SRCS))
INJECTOR_OBJS = $(patsubst src/injector/%.c,$(OBJ_DIR)/injector/%.o,$(INJECTOR_SRCS))
PTRACER_OBJS = $(patsubst src/ptracer/%.c,$(OBJ_DIR)/ptracer/%.o,$(PTRACER_SRCS))

PLTI_LIB = $(BUILD_DIR)/obj/$(BUILD_TYPE)/plti/$(ARCH)/libplti.a
CSOLOADER_LIB = $(BUILD_DIR)/obj/$(BUILD_TYPE)/csoloader/$(ARCH)/libcsoloader.a

LIBCOMMON = $(OBJ_DIR)/libcommon.a
LIBZYGISK = $(OBJ_DIR)/libzygisk.so
LIBPTRACE = $(OBJ_DIR)/libzygisk_ptrace.so
LIBZYGISK_STRIPPED = $(OBJ_DIR)/stripped/libzygisk.so
LIBPTRACE_STRIPPED = $(OBJ_DIR)/stripped/libzygisk_ptrace.so

PLTI_DIR = src/external/plti
CSOLOADER_DIR = src/external/csoloader

COMMON_INCLUDES = -Isrc/include
INJECTOR_INCLUDES = -Isrc/include -I$(PLTI_DIR)/src -I$(CSOLOADER_DIR)/include

.PHONY: all arch clean test-mountinfo

all:
	@for arch in $(ARCHS); do                                                                                  \
		$(MAKE) BUILD_TYPE=$(BUILD_TYPE) BUILD_DIR=$(BUILD_DIR) ARCH=$$arch ZKSU_VERSION=$(ZKSU_VERSION) arch; \
	done

	@mkdir -p $(OBJ_ROOT)
	@touch $(OBJ_ROOT)/.done

arch: $(LIBZYGISK_STRIPPED) $(LIBPTRACE_STRIPPED)

HOST_CC ?= cc

test-mountinfo:
	@mkdir -p $(BUILD_DIR)/tests
	$(HOST_CC) -std=c18 -D_GNU_SOURCE -Wall -Wextra -Werror -Isrc/include src/common/mountinfo.c tests/test_mountinfo.c -o $(BUILD_DIR)/tests/test_mountinfo
	$(BUILD_DIR)/tests/test_mountinfo

clean:
	rm -rf $(BUILD_DIR)/obj/$(BUILD_TYPE)/loader
	rm -rf $(BUILD_DIR)/obj/$(BUILD_TYPE)/plti
	rm -rf $(BUILD_DIR)/obj/$(BUILD_TYPE)/csoloader

$(PLTI_LIB):
	@mkdir -p $(dir $@)
	$(MAKE) -C $(PLTI_DIR) BUILD_TYPE=$(BUILD_TYPE) ARCH=$(ARCH) \
		NDK_PATH=$(NDK_PATH) API_LEVEL=$(API_LEVEL)              \
		out=$(BUILD_DIR)/obj/$(BUILD_TYPE)/plti/$(ARCH)

$(CSOLOADER_LIB):
	@mkdir -p $(dir $@)
	$(MAKE) -C $(CSOLOADER_DIR) BUILD_TYPE=$(BUILD_TYPE) ARCH=$(ARCH) \
		NDK_PATH=$(NDK_PATH) API_LEVEL=$(API_LEVEL)                   \
		out=$(BUILD_DIR)/obj/$(BUILD_TYPE)/csoloader/$(ARCH)

$(OBJ_DIR)/common/%.o: src/common/%.c
	@mkdir -p $(dir $@)
	$(CC_ARCH) $(NDK_CFLAGS) $(LOADER_CFLAGS) $(TYPE_CFLAGS) \
		$(COMMON_INCLUDES) -fPIC -c $< -o $@

$(OBJ_DIR)/injector/%.o: src/injector/%.c
	@mkdir -p $(dir $@)
	$(CC_ARCH) $(NDK_CFLAGS) $(LOADER_CFLAGS) $(TYPE_CFLAGS) \
		$(INJECTOR_INCLUDES) -Dzygisk_EXPORTS -fPIC -c $< -o $@

$(OBJ_DIR)/ptracer/%.o: src/ptracer/%.c
	@mkdir -p $(dir $@)
	$(CC_ARCH) $(NDK_CFLAGS) $(LOADER_CFLAGS) $(TYPE_CFLAGS) \
		$(COMMON_INCLUDES) -fPIE -c $< -o $@

$(RUST_LIB): $(RUST_MANIFEST) src/rust/src/lib.rs

	@cargo build --manifest-path $(RUST_MANIFEST) --target $(RUST_TARGET) --release --target-dir $(RUST_TARGET_DIR)

$(LIBCOMMON): $(COMMON_OBJS)
	@mkdir -p $(dir $@)
	$(AR) rcs $@ $^

$(LIBZYGISK): $(INJECTOR_OBJS) $(LIBCOMMON) $(PLTI_LIB) $(CSOLOADER_LIB) $(RUST_LIB)
	@mkdir -p $(dir $@)
	$(CC_ARCH) -fPIC -shared -Wl,-soname,libzygisk.so                            \
		$(COMMON_LDFLAGS) $(TYPE_LDFLAGS) -Wl,--wrap=free -Wl,--wrap=realloc     \
		-nostartfiles $(INJECTOR_OBJS) $(LIBCOMMON) $(PLTI_LIB) $(CSOLOADER_LIB) $(RUST_LIB) \
		-llog -lm -o $@

$(LIBPTRACE): $(PTRACER_OBJS) $(LIBCOMMON) $(RUST_LIB)
	@mkdir -p $(dir $@)
	$(CC_ARCH) $(COMMON_LDFLAGS) $(TYPE_LDFLAGS) \
		$(PTRACER_OBJS) $(LIBCOMMON) $(RUST_LIB) -llog -lm -o $@

$(LIBZYGISK_STRIPPED): $(LIBZYGISK)
	@mkdir -p $(dir $@)
	cp $< $@
	$(STRIP) --strip-all $@

$(LIBPTRACE_STRIPPED): $(LIBPTRACE)
	@mkdir -p $(dir $@)
	cp $< $@
	$(STRIP) --strip-all $@
