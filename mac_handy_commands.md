codesign -dvvv --entitlements - path/to/.App

security find-certificate -c "Apple Development" -p login.keychain \
  | openssl x509 -noout -subject

# Stream extension logs in real-time
/usr/bin/log stream --predicate 'process == "MacTokenExtension"' --level debug

# View extension logs from the past 5 minutes
/usr/bin/log show --predicate 'process == "MacTokenExtension"' --last 5m
