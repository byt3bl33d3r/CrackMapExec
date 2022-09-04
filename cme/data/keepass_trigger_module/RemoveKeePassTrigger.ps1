$KeePassXMLPath = "REPLACE_ME_KeePassXMLPath"
$TriggerName = "REPLACE_ME_TriggerName"
if($KeePassXMLPath -and ($KeePassXMLPath -match '.\.xml$') -and (Test-Path -Path $KeePassXMLPath) ) {
	$KeePassXMLPath = Resolve-Path -Path $KeePassXMLPath
	$KeePassXML = [xml](Get-Content -Path $KeePassXMLPath)
	$RandomGUID = [System.GUID]::NewGuid().ToByteArray()
	if ($KeePassXML.Configuration.Application.TriggerSystem.Triggers -isnot [String]) {
		$Children = $KeePassXML.Configuration.Application.TriggerSystem.Triggers | ForEach-Object {$_.Trigger} | Where-Object {$_.Name -like $TriggerName}
		ForEach($Child in $Children) {
			$KeePassXML.Configuration.Application.TriggerSystem.Triggers.RemoveChild($Child)
		}
	}
	try {
		$KeePassXML.Save($KeePassXMLPath)
	}
	catch {
	}   
}