$KeePassUser = "REPLACE_ME_KeePassUser"
$KeePassBinaryPath = "REPLACE_ME_KeePassBinaryPath"
$DummyServiceName = "REPLACE_ME_DummyServiceName"
schtasks /create /tn "$DummyServiceName" /tr "$KeePassBinaryPath" /ru $KeePassUser /it /sc ONLOGON
taskkill /F /T /IM keepass.exe /FI "USERNAME eq $KeePassUser"
schtasks /run /tn "$DummyServiceName"
Start-Sleep -s 3
schtasks /delete /tn "$DummyServiceName" /F