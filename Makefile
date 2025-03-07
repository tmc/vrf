# Makefile for crypto directory

SRCPATH    := $(shell pwd)
OS_TYPE    := $(shell uname | tr '[:upper:]' '[:lower:]')
ARCH       := $(shell uname -m)
LIBSODIUM_DIR := libsodium-fork

# Set up include path and library path for current architecture
INCLUDE_DIR := $(SRCPATH)/include
LIBS_DIR    := $(SRCPATH)/libs/$(OS_TYPE)/$(ARCH)

# Define the default target
default: build-libsodium

# Build libsodium and install headers
build-libsodium:
	mkdir -p copies/$(OS_TYPE)/$(ARCH)
	cp -R libsodium-fork/. copies/$(OS_TYPE)/$(ARCH)/libsodium-fork
	cd copies/$(OS_TYPE)/$(ARCH)/libsodium-fork && \
		./autogen.sh --prefix $(SRCPATH)/libs/$(OS_TYPE)/$(ARCH) && \
		./configure --disable-shared --prefix="$(SRCPATH)/libs/$(OS_TYPE)/$(ARCH)" $(EXTRA_CONFIGURE_FLAGS) && \
		$(MAKE) && \
		$(MAKE) install
	@echo "Building libsodium for $(OS_TYPE)/$(ARCH)..."
	@mkdir -p $(LIBS_DIR)
	cd $(LIBSODIUM_DIR) && \
		./autogen.sh && \
		./configure --disable-shared --enable-static --disable-dependency-tracking --with-pic --prefix="$(LIBS_DIR)" && \
		make -j$(shell nproc || echo 4) && \
		make install

# Clean the build artifacts
clean:
	cd $(LIBSODIUM_DIR) && \
		test ! -e Makefile || make clean
	rm -rf lib
	rm -rf libs
	rm -rf copies
	rm -rf $(LIBS_DIR)

.PHONY: default build-libsodium clean
