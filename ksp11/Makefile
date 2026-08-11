# ksp11 — keyless PKCS#11 module for Linux (C + cgo bridge).
#
# The PKCS#11 layer (ksp11.c) is pure C; signing requests are forwarded over
# gRPC to the cert-server through a cgo bridge (internal/kspbridge) compiled
# with -buildmode=c-shared. ksp11.so dlopens libtpmcertclient.so at
# C_Initialize (the c-archive mode is not supported for Go runtime embedded in
# a foreign-process shared library).
#
# Build:        make
# Test (e2e):   make test   (starts a local cert-server, then runs test-sign.sh)
# Dependencies: gcc, libssl-dev, libp11-kit-dev, Go toolchain, openssl 3.x +
#               pkcs11-provider package.

CC      ?= gcc
GO      ?= go
CFLAGS  ?= -O2 -Wall -Wextra -fPIC
P11_CFLAGS := $(shell pkg-config --cflags p11-kit-1 2>/dev/null || echo -I/usr/include/p11-kit-1)
LDLIBS  := -lcrypto -lpthread -ldl -lm

BRIDGE_SO := libtpmcertclient.so

all: ksp11.so $(BRIDGE_SO)

$(BRIDGE_SO): $(wildcard ../internal/kspbridge/*.go) $(wildcard ../internal/kspclient/*.go) $(wildcard ../internal/kspcommon/*.go) $(wildcard ../internal/kspmanifest/*.go) $(wildcard ../internal/tlsutil/*.go)
	cd .. && CGO_ENABLED=1 $(GO) build -buildmode=c-shared -o ksp11/$(BRIDGE_SO) ./internal/kspbridge

ksp11.so: ksp11.c
	$(CC) $(CFLAGS) $(P11_CFLAGS) -I../ksp -shared -o $@ ksp11.c $(LDLIBS)

test: ksp11.so $(BRIDGE_SO)
	./test-sign.sh

clean:
	rm -f ksp11.so $(BRIDGE_SO) ksp11.cnf msg.txt digest.bin sig*.bin server-pub.pem ec-pub.pem

.PHONY: all test clean
