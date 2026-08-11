#!/usr/bin/env bash
# Test the ksp11 PKCS#11 module with OpenSSL 3.x (pkcs11-provider):
#   - load the private key through the provider
#   - sign with RSA PKCS#1 v1.5 (dgst -sign)
#   - sign with RSA-PSS
#   - sign with ECDSA (optional, if the module is built for an EC key)
set -euo pipefail
cd "$(dirname "$0")"

PROV_MODULE=$(find /usr/lib /lib -path '*ossl-modules/pkcs11.so' 2>/dev/null | head -1)
if [ -z "$PROV_MODULE" ]; then
    echo "ERROR: pkcs11-provider not found (apt install pkcs11-provider)" >&2
    exit 1
fi
echo "pkcs11-provider: $PROV_MODULE"

# --- RSA key pair (used by default) -------------------------------------
RSA_KEY=test-key.pem
if [ ! -f "$RSA_KEY" ]; then
    echo "generating RSA test key..."
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$RSA_KEY"
fi
openssl pkey -in "$RSA_KEY" -pubout -out test-pub.pem

# --- OpenSSL config wiring pkcs11-provider to our module ----------------
cat > ksp11.cnf <<EOF
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
pkcs11 = pkcs11_sect

[pkcs11_sect]
module = $PROV_MODULE
pkcs11-module-path = $PWD/ksp11.so
pkcs11-module-token-pin = 1234
EOF
export OPENSSL_CONF="$PWD/ksp11.cnf"
export KSP11_KEY_PATH="$PWD/$RSA_KEY"

URI='pkcs11:token=ksp11-token;object=test-key;type=private'
echo "hello ksp11, sign me" > msg.txt

echo "== 1. provider loads the private key =="
openssl pkey -provider pkcs11 -provider default -in "$URI" -text -noout | head -4

echo "== 2. RSA PKCS#1 v1.5 sign via dgst -sign =="
openssl dgst -sha256 -provider pkcs11 -provider default -sign "$URI" -out sig.bin msg.txt
openssl dgst -sha256 -verify test-pub.pem -signature sig.bin msg.txt

echo "== 3. RSA-PSS sign (saltlen 32) =="
openssl dgst -sha256 -provider pkcs11 -provider default -sign "$URI" \
    -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -out sig-pss.bin msg.txt
openssl dgst -sha256 -verify test-pub.pem -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
    -signature sig-pss.bin msg.txt

echo "== 4. raw PKCS#1 via pkeyutl (DigestInfo input) =="
openssl dgst -sha256 -binary -out digest.bin msg.txt
openssl pkeyutl -sign -provider pkcs11 -provider default -inkey "$URI" -in digest.bin \
    -pkeyopt digest:sha256 -out sig-utl.bin
openssl pkeyutl -verify -pubin -inkey test-pub.pem -in digest.bin \
    -pkeyopt digest:sha256 -sigfile sig-utl.bin

# --- optional ECDSA test --------------------------------------------------
EC_KEY=test-ec-key.pem
if [ ! -f "$EC_KEY" ]; then
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$EC_KEY"
fi
openssl pkey -in "$EC_KEY" -pubout -out test-ec-pub.pem
KSP11_KEY_PATH="$PWD/$EC_KEY" openssl dgst -sha256 -provider pkcs11 -provider default \
    -sign "$URI" -out sig-ec.bin msg.txt
openssl dgst -sha256 -verify test-ec-pub.pem -signature sig-ec.bin msg.txt

echo
echo "ALL SIGNING TESTS PASSED"
