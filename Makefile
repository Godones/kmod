# Makefile for building Linux kernel loadable modules
# =====================================================
# This Makefile is a translated version of the Rust builder (builder/src/main.rs)
# 
# Features:
#   - Builds Rust kernel modules for specified architectures
#   - Extracts object files from static libraries
#   - Links them into relocatable .ko (kernel object) files
#   - Supports multiple target architectures (x86_64, RISC-V, ARM, etc.)
#   - Verifies generated kernel modules
#
# Build Flow:
#   1. Compile module crate using cargo (--release, with custom target)
#   2. Extract object files from generated .a library using rust-ar
#   3. Link object files using ld with relocation enabled (-r flag)
#   4. Verify the resulting .ko file with file/readelf commands
#   5. Clean up temporary object files

# Default values

ARCH ?= riscv64
RUSTFLAGS := -C relocation-model=static

ifeq ($(ARCH), x86_64)
  TARGET := x86_64-unknown-none
  RUSTFLAGS +=  -C code-model=large
else ifeq ($(ARCH), aarch64)
  TARGET := aarch64-unknown-none-softfloat
else ifeq ($(ARCH), riscv64)
  TARGET := riscv64gc-unknown-none-elf
else ifeq ($(ARCH), loongarch64)
  TARGET := loongarch64-unknown-none-softfloat
  RUSTFLAGS +=  -C code-model=large
else
  $(error "ARCH" must be one of "x86_64", "riscv64", "aarch64" or "loongarch64")
endif


MODULE_PATHS ?= modules
LINKER_SCRIPT ?= linker.ld

build_args := \
  -Zunstable-options \
  -Zbuild-std=core,alloc,compiler_builtins \
  -Zbuild-std-features=compiler-builtins-mem \
  --release \
  --target $(TARGET)

LINK_ARGS := \
  -C link-arg=-T$(LD_SCRIPT) \
  -C link-arg=-znostart-stop-gc \
  -C no-redzone=y

LD_COMMAND := ld.lld

# Get list of modules (directories in MODULE_PATHS)
MODULES := $(shell if [ -d $(MODULE_PATHS) ]; then ls -d $(MODULE_PATHS)/*/ 2>/dev/null | xargs -I {} basename {}; fi)

# Build output directory
BUILD_DIR := target
MODULE_BUILD_DIR := $(BUILD_DIR)/$(TARGET)/release


.PHONY: all clean modules $(MODULES) list-modules help

# Default target
all: modules

# List available modules
list-modules:
	@echo "Available modules:"
	@for module in $(MODULES); do \
		echo "  - $$module"; \
	done

# Help target
help:
	@echo "Usage: make [target] [VAR=value]"
	@echo ""
	@echo "Targets:"
	@echo "  all              Build all modules (default)"
	@echo "  modules          Build all modules"
	@echo "  <module_name>    Build specific module"
	@echo "  list-modules     List available modules"
	@echo "  clean            Clean build artifacts"
	@echo "  help             Show this help message"
	@echo ""
	@echo "Variables:"
	@echo "  TARGET           Target triple (default: x86_64-unknown-none)"
	@echo "  MODULE_PATHS     Module search path (default: modules)"
	@echo "  LINKER_SCRIPT    Linker script path (default: linker.ld)"
	@echo ""
	@echo "Examples:"
	@echo "  make                              # Build all modules"
	@echo "  make hello                        # Build hello module"
	@echo "  make TARGET=riscv64gc-unknown-none-elf  # Build for RISC-V"

# Build all modules
modules: $(MODULES)

# Individual module target
$(MODULES):
	@echo "Building module: $@"
	RUSTFLAGS="$(RUSTFLAGS)" cargo build $(build_args) -p $@
	@$(MAKE) process-module-library MODULE_NAME=$@ TARGET=$(TARGET) LD_COMMAND=$(LD_COMMAND)
	@$(MAKE) verify-kernel-module KO_PATH=$(BUILD_DIR)/$@/$@.ko

.PHONY: process-module-library
process-module-library:
	@echo "Processing module library: $(MODULE_NAME)"
	@bash build_module.sh $(MODULE_NAME) $(TARGET) $(MODULE_BUILD_DIR) $(BUILD_DIR) $(LD_COMMAND) "$(DEP_EXCLUSIONS)"

.PHONY: verify-kernel-module
verify-kernel-module:
	@echo "Verifying kernel module: $(KO_PATH)"
	@if [ ! -f "$(KO_PATH)" ]; then \
		echo "Error: Kernel module file not found: $(KO_PATH)"; \
		exit 1; \
	fi
	@if command -v readelf >/dev/null 2>&1; then \
		echo "Module sections:"; \
		readelf -S "$(KO_PATH)" | grep -E "^\s+\[|PROGBITS|NOBITS"; \
	fi


clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@echo "Clean complete"

rebuild: clean all
	@echo "Rebuild complete"

show-config:
	@echo "Build Configuration:"
	@echo "  TARGET: $(TARGET)"
	@echo "  MODULE_PATHS: $(MODULE_PATHS)"
	@echo "  LINKER_SCRIPT: $(LINKER_SCRIPT)"
	@echo "  LD_COMMAND: $(LD_COMMAND)"
	@echo "  Available modules: $(MODULES)"
