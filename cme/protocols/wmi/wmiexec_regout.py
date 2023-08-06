#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#
# Author: xiaolichan
# Link: https://github.com/XiaoliChan/wmiexec-RegOut/blob/main/wmiexec-regOut.py
# Note: windows version under NT6 not working with this command execution way
#       https://github.com/XiaoliChan/wmiexec-RegOut/blob/main/wmiexec-reg-sch-UnderNT6-wip.py -- WIP
# 
# Description: 
#   For more details, please check out my repository.
#   https://github.com/XiaoliChan/wmiexec-RegOut

import time
import uuid
import base64

OUTPUT_FILENAME = '__' + str(time.time())

class WMIEXEC_REGOUT:
    def __init__(self, win32Process, iWbemServices, address, logger, interval_time):
        self.logger = logger
        self.address = address
        self.interval_time = interval_time
        self.__output = '\\' + OUTPUT_FILENAME
        self.__outputBuffer = str('')
        self.__shell = 'cmd.exe /Q /c '
        #self.__pwsh = 'powershell.exe -NoP -NoL -sta -NonI -W Hidden -Exec Bypass -Enc '
        self.__pwsh = 'powershell.exe -Enc '
        self.__win32Process = win32Process
        self.iWbemServices = iWbemServices
        self.__pwd = str('C:\\')

    def encodeCommand(self, data):
        data = '$ProgressPreference="SilentlyContinue";' + data
        data = self.__pwsh + base64.b64encode(data.encode('utf-16le')).decode()
        return data

    def execute_remote(self, data):
        # Save result as txt file
        resultTXT = "C:\\windows\\temp\\" + str(uuid.uuid4()) + ".txt"
        self.logger.success("Executing command: \" %s \""%data)
        data = data + " > " + resultTXT
        command = self.__shell + self.encodeCommand(data)
        self.__win32Process.Create(command, self.__pwd, None)
        self.logger.highlight("[+] Waiting {}s for command completely executed.".format(self.interval_time))
        time.sleep(self.interval_time)
        
        # Convert result to base64 strings
        self.logger.highlight("[+] Save file to: " + resultTXT)
        keyName = str(uuid.uuid4())
        data = """[convert]::ToBase64String((Get-Content -path %s -Encoding byte)) | set-content -path C:\\windows\\temp\\%s.txt -force | Out-Null"""%(resultTXT,keyName)
        command = self.__shell + self.encodeCommand(data)
        self.__win32Process.Create(command, self.__pwd, None)
        self.logger.highlight("[+] Waiting {}s for command completely executed.".format(self.interval_time))
        time.sleep(self.interval_time)
        
        # Add base64 strings to registry
        registry_Path = "HKLM:\\Software\\Classes\\hello\\"
        self.logger.highlight("[+] Adding base64 strings to registry, path: %s, keyname: %s"%(registry_Path,keyName))
        data = """New-Item %s -Force; New-ItemProperty -Path %s -Name %s -Value (get-content -path C:\\windows\\temp\\%s.txt) -PropertyType string -Force | Out-Null"""%(registry_Path,registry_Path,keyName,keyName)
        command = self.__shell + self.encodeCommand(data)
        self.__win32Process.Create(command, self.__pwd, None)
        self.logger.highlight("[+] Waiting {}s for command completely executed.".format(self.interval_time))
        time.sleep(self.interval_time)
        
        # Remove temp file
        self.logger.highlight("[+] Remove temporary files")
        data = ("del /q /f /s C:\\windows\\temp\\*")
        command = self.__shell + data
        self.__win32Process.Create(command, self.__pwd, None)
        
        # Query result through WQL syntax
        self.queryWQL(keyName)

    def queryWQL(self, keyName):
        namespace = '//%s/root/default' % self.address
        descriptor, _ = self.iWbemServices.GetObject('StdRegProv')
        descriptor = descriptor.SpawnInstance()
        retVal = descriptor.GetStringValue(2147483650,'SOFTWARE\\classes\\hello', keyName)
        self.logger.highlight("[+] Get result:")
        result = retVal.sValue
        self.logger.highlight(base64.b64decode(result).decode('utf-16le'))
        self.logger.highlight("[+] Remove temporary registry Key")
        retVal = descriptor.DeleteKey(2147483650,'SOFTWARE\\classes\\hello')
        descriptor.RemRelease()
        self.iWbemServices.RemRelease()