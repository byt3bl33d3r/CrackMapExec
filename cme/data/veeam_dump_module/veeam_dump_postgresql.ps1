$PostgreSqlExec = "REPLACE_ME_PostgreSqlExec"
$PostgresUserForWindowsAuth = "REPLACE_ME_PostgresUserForWindowsAuth"
$SqlDatabaseName = "REPLACE_ME_SqlDatabaseName"

$SQLStatement = "SELECT user_name AS User,password AS Password FROM credentials WHERE password != '';"
$output = . $PostgreSqlExec -U $PostgresUserForWindowsAuth -w -d $SqlDatabaseName -c $SQLStatement --csv | ConvertFrom-Csv

if ($output.count -eq 0) {
	Write-Host "No passwords found!"
	exit
}

Add-Type -assembly System.Security
#Decrypting passwords using DPAPI
$output | ForEach-Object -Process {
    $EnryptedPWD = [Convert]::FromBase64String($_.password)
	$ClearPWD = [System.Security.Cryptography.ProtectedData]::Unprotect( $EnryptedPWD, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine )
	$enc = [system.text.encoding]::Default
	$_.password = $enc.GetString($ClearPWD) -replace '\s', 'WHITESPACE_ERROR'
}

Write-Output $output | Format-Table -HideTableHeaders | Out-String