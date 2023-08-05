$SqlDatabaseName = "REPLACE_ME_SqlDatabase"
$SqlServerName = "REPLACE_ME_SqlServer"
$SqlInstanceName = "REPLACE_ME_SqlInstance"

#Forming the connection string
$SQL = "SELECT [user_name] AS 'User',[password] AS 'Password' FROM [$SqlDatabaseName].[dbo].[Credentials] WHERE password <> ''" #Filter empty passwords
$auth = "Integrated Security=SSPI;" #Local user
$connectionString = "Provider=sqloledb; Data Source=$SqlServerName\$SqlInstanceName; Initial Catalog=$SqlDatabaseName; $auth;"
$connection = New-Object System.Data.OleDb.OleDbConnection $connectionString
$command = New-Object System.Data.OleDb.OleDbCommand $SQL, $connection

#Fetching encrypted credentials from the database
try {
	$connection.Open()
	$adapter = New-Object System.Data.OleDb.OleDbDataAdapter $command
	$dataset = New-Object System.Data.DataSet
	[void] $adapter.Fill($dataSet)
	$connection.Close()
}
catch {
	Write-Host "Can't connect to DB! Exiting..."
	exit -1
}

$rows=($dataset.Tables | Select-Object -Expand Rows)
if ($rows.count -eq 0) {
	Write-Host "No passwords found!"
	exit
}

Add-Type -assembly System.Security
#Decrypting passwords using DPAPI
$rows | ForEach-Object -Process {
	$EnryptedPWD = [Convert]::FromBase64String($_.password)
	$ClearPWD = [System.Security.Cryptography.ProtectedData]::Unprotect( $EnryptedPWD, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine )
	$enc = [system.text.encoding]::Default
	$_.password = $enc.GetString($ClearPWD) -replace '\s', 'WHITESPACE_ERROR'
}

Write-Output $rows | Format-Table -HideTableHeaders | Out-String
