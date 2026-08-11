# ksp11 — minimal PKCS#11 software token for OpenSSL signing tests.
#
# Build:        make
# Test (openssl): make test
# Dependencies: gcc, libssl-dev (OpenSSL headers), libp11-kit-dev (pkcs11.h),
#               openssl 3.x + pkcs11-provider package.

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -fPIC
P11_CFLAGS := $(shell pkg-config --cflags p11-kit-1 2>/dev/null || echo -I/usr/include/p11-kit-1)
LDLIBS  := -lcrypto

all: ksp11.so

ksp11.so: ksp11.c
	$(CC) $(CFLAGS) $(P11_CFLAGS) -shared -o $@ $< $(LDLIBS)

test: ksp11.so
	./test-sign.sh

clean:
	rm -f ksp11.so test-key.pem test-pub.pem test-ec-key.pem test-ec-pub.pem \
	      ksp11.cnf msg.txt sig.bin sig-pss.bin sig-ec.bin verify-pub.pem

.PHONY: all test clean
