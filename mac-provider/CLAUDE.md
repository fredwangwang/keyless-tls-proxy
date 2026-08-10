# Mac Provider Instructions

To verify that the extension is properly registered and signed correctly:

1. Build, install to /Applications, and register the app extension:
   ```bash
   ./scripts/install-app-mac.sh
   ```

2. Run the signing test to verify correct signing:
   ```bash
   go run ./cmd/local-sign-test-mac -thumbprint DAFCD3264D3A369CED2F39663CF52C3878952284E53BA6590ACD6309810A4FD2 -message "adsfadsf" -padding pkcs1
   ```
