#!/usr/bin/env bash
# End-to-end test of the keyless ksp11 PKCS#11 module:
#
#   1. start a local cert-server (file store from sample-certs)
#   2. point OpenSSL's pkcs11-provider at ksp11.so
#   3. sign with RSA PKCS#1 v1.5 / RSA-PSS / raw pkeyutl / ECDSA — every
#      signature is computed by the cert-server over gRPC, never locally
set -euo pipefail
cd "$(dirname "$0")"
REPO="$(cd .. && pwd)"
CERTS="$REPO/sample-certs"
SERVER_BIN=$(mktemp /tmp/ksp11-cert-server.XXXXXX)

PROV_MODULE=$(find /usr/lib /lib -path '*ossl-modules/pkcs11.so' 2>/dev/null | head -1)
if [ -z "$PROV_MODULE" ]; then
    echo "ERROR: pkcs11-provider not found (apt install pkcs11-provider)" >&2
    exit 1
fi
echo "pkcs11-provider: $PROV_MODULE"

# Wait until a TCP port accepts connections (with timeout).
wait_port() {
    local port=$1 tries=50
    for _ in $(seq 1 "$tries"); do
        if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
            exec 3>&- 3<&- || true
            return 0
        fi
        sleep 0.1
    done
    echo "ERROR: server did not start listening on port $port" >&2
    tail -5 /tmp/ksp11-server.log 2>/dev/null || true
    exit 1
}

echo "== building ksp11.so and cert-server =="
make ksp11.so
(cd "$REPO" && go build -o "$SERVER_BIN" ./cmd/cert-server)

echo "== starting cert-server (file store: sample-certs) =="
"$SERVER_BIN" --addr 127.0.0.1:50051 --ca "$CERTS/ca.crt" --cert "$CERTS/server.crt" \
    --key "$CERTS/server.key" --cert-dir "$CERTS" --discovery=false >/tmp/ksp11-server.log 2>&1 &
SERVER_PID=$!
cleanup() {
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    rm -f "$SERVER_BIN"
}
trap cleanup EXIT
wait_port 50051

# --- OpenSSL config wiring pkcs11-provider to our module ------------------
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
# The module connects to the cert-server with mTLS using the client identity.
export KSP11_ADDR="127.0.0.1:50051"
export KSP11_CA="$CERTS/ca.crt"
export KSP11_CERT="$CERTS/client.crt"
export KSP11_KEY="$CERTS/client.key"

echo "hello keyless world" > msg.txt
TP=$(openssl x509 -in "$CERTS/server.crt" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d ':')
ID=$(echo "$TP" | sed 's/../%&/g')
URI="pkcs11:token=ksp11-token;id=$ID;type=private"
openssl x509 -in "$CERTS/server.crt" -pubkey -noout > server-pub.pem

echo "== 1. provider loads the remote key (via ListCertificates) =="
openssl pkey -provider pkcs11 -provider default -in "$URI" -text -noout | head -4

echo "== 2. RSA PKCS#1 v1.5 sign (gRPC -> cert-server) =="
openssl dgst -sha256 -provider pkcs11 -provider default -sign "$URI" -out sig.bin msg.txt
openssl dgst -sha256 -verify server-pub.pem -signature sig.bin msg.txt

echo "== 3. RSA-PSS sign (saltlen 32) =="
openssl dgst -sha256 -provider pkcs11 -provider default -sign "$URI" \
    -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -out sig-pss.bin msg.txt
openssl dgst -sha256 -verify server-pub.pem -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
    -signature sig-pss.bin msg.txt

echo "== 4. raw PKCS#1 via pkeyutl (DigestInfo input) =="
openssl dgst -sha256 -binary -out digest.bin msg.txt
openssl pkeyutl -sign -provider pkcs11 -provider default -inkey "$URI" -in digest.bin \
    -pkeyopt digest:sha256 -out sig-utl.bin
openssl pkeyutl -verify -pubin -inkey server-pub.pem -in digest.bin \
    -pkeyopt digest:sha256 -sigfile sig-utl.bin

# --- ECDSA: restart the server with an extra EC cert in the store ----------
echo "== 5. ECDSA sign =="
ECDIR=$(mktemp -d)
cp "$CERTS"/* "$ECDIR"/   # all sample pairs (ca/client/server), plus EC below
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout "$ECDIR/ec.key" -out "$ECDIR/ec.crt" -days 1 -nodes \
    -subj "/CN=ksp11-ec-test" >/dev/null 2>&1
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
sleep 0.5
"$SERVER_BIN" --addr 127.0.0.1:50051 --ca "$CERTS/ca.crt" --cert "$CERTS/server.crt" \
    --key "$CERTS/server.key" --cert-dir "$ECDIR" --discovery=false >/tmp/ksp11-server-ec.log 2>&1 &
SERVER_PID=$!
wait_port 50051

ECTP=$(openssl x509 -in "$ECDIR/ec.crt" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d ':')
ECID=$(echo "$ECTP" | sed 's/../%&/g')
ECURI="pkcs11:token=ksp11-token;id=$ECID;type=private"
openssl x509 -in "$ECDIR/ec.crt" -pubkey -noout > ec-pub.pem

openssl dgst -sha256 -provider pkcs11 -provider default -sign "$ECURI" -out sig-ec.bin msg.txt
openssl dgst -sha256 -verify ec-pub.pem -signature sig-ec.bin msg.txt
rm -rf "$ECDIR"

echo
echo "ALL KEYLESS SIGNING TESTS PASSED (signatures produced by cert-server)"
