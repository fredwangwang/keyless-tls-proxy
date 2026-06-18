Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object { $_.HasPrivateKey }

certutil -csplist

certutil -user -store My
