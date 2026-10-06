[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Register', 'Verify', 'Unregister')]
    [string]$Action,
    [Parameter(Mandatory = $true)]
    [string]$Target,
    [Parameter()]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ExpectedShortcutSha256,
    [Parameter()]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ExpectedRegistrationSha256
)

$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

$appId = 'MiyaIF.ExternalIntelligence'
$maxShortcutBytes = 65536
$maxRecordBytes = 8192
$createdDirectories = New-Object 'System.Collections.Generic.List[string]'
$createdShortcut = $false
$createdRecord = $false
$shortcutHash = $null
$recordHash = $null
$shortcutTemp = $null
$recordTemp = $null
$shortcut = $null
$registration = $null
$targetFull = $null

function Write-Response([string]$Status, [bool]$Verified, [string]$Reason = '') {
    $response = [ordered]@{ status = $Status; verified = $Verified }
    if ($script:targetFull) { $response.target = $script:targetFull }
    if ($script:shortcutHash) { $response.shortcut_sha256 = $script:shortcutHash }
    if ($script:recordHash) { $response.registration_sha256 = $script:recordHash }
    if ($Reason) { $response.reason_code = $Reason }
    [Console]::Out.WriteLine((ConvertTo-Json -InputObject $response -Compress))
}

function Assert-NoReparseComponents([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($full)
    $cursor = $root
    $relative = $full.Substring($root.Length)
    foreach ($part in ($relative -split '[\\/]')) {
        if (-not $part) { continue }
        $cursor = Join-Path $cursor $part
        if ([IO.File]::Exists($cursor) -or [IO.Directory]::Exists($cursor)) {
            $item = Get-Item -LiteralPath $cursor -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'UNSAFE_REPARSE_POINT'
            }
        }
    }
}

function Ensure-Directory([string]$Directory) {
    $missing = New-Object 'System.Collections.Generic.List[string]'
    $cursor = [IO.Path]::GetFullPath($Directory)
    while (-not [IO.Directory]::Exists($cursor)) {
        $missing.Add($cursor)
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if (-not $parent -or $parent -eq $cursor) { throw 'DIRECTORY_ROOT_MISSING' }
        $cursor = $parent
    }
    Assert-NoReparseComponents $cursor
    for ($index = $missing.Count - 1; $index -ge 0; $index--) {
        $path = $missing[$index]
        [void][IO.Directory]::CreateDirectory($path)
        $createdDirectories.Add($path)
    }
    Assert-NoReparseComponents $Directory
}

function Test-RegularFile([string]$Path, [int]$MaximumBytes) {
    Assert-NoReparseComponents $Path
    if (-not [IO.File]::Exists($Path)) { return $false }
    $item = Get-Item -LiteralPath $Path -Force
    return (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -and -not $item.PSIsContainer -and $item.Length -le $MaximumBytes)
}

function Get-Sha256([string]$Path) {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $sha = [Security.Cryptography.SHA256]::Create()
        try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
        finally { $sha.Dispose() }
    }
    finally { $stream.Dispose() }
}

function Read-Record([string]$Path) {
    if (-not (Test-RegularFile $Path $script:maxRecordBytes)) { throw 'REGISTRATION_FILE_INVALID' }
    $raw = [IO.File]::ReadAllBytes($Path)
    $record = [Text.Encoding]::UTF8.GetString($raw) | ConvertFrom-Json
    $names = @($record.PSObject.Properties.Name | Sort-Object)
    if ($names.Count -ne 4 -or ($names -join ',') -cne 'app_id,schema_version,shortcut_sha256,target') { throw 'REGISTRATION_SCHEMA_INVALID' }
    if (($record.schema_version -isnot [int] -and $record.schema_version -isnot [long]) -or $record.schema_version -ne 1 -or $record.app_id -cne $script:appId -or $record.shortcut_sha256 -cnotmatch '^[0-9a-f]{64}$' -or $record.target -ine $script:targetFull) {
        throw 'REGISTRATION_CONTENT_INVALID'
    }
    return $record
}

function Get-EiShellLinkInteropSource {
$shellLinkInterop = @'
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace EIWinNotify {
    [StructLayout(LayoutKind.Sequential)]
    public struct PropertyKey {
        public Guid fmtid;
        public uint pid;
        public PropertyKey(Guid id, uint propertyId) { fmtid = id; pid = propertyId; }
    }

    [StructLayout(LayoutKind.Explicit, Size = 16)]
    public struct PropVariant {
        [FieldOffset(0)] public ushort vt;
        [FieldOffset(2)] public ushort wReserved1;
        [FieldOffset(4)] public ushort wReserved2;
        [FieldOffset(6)] public ushort wReserved3;
        [FieldOffset(8)] public IntPtr pointer;
        [FieldOffset(8)] public uint arrayCount;
        [FieldOffset(16)] public IntPtr arrayPointer;
    }

    [ComImport, Guid("000214F9-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IShellLinkW {
        void GetPath([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder path, int capacity, IntPtr findData, uint flags);
        void GetIDList(out IntPtr itemIdList);
        void SetIDList(IntPtr itemIdList);
        void GetDescription([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder description, int capacity);
        void SetDescription([MarshalAs(UnmanagedType.LPWStr)] string description);
        void GetWorkingDirectory([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder directory, int capacity);
        void SetWorkingDirectory([MarshalAs(UnmanagedType.LPWStr)] string directory);
        void GetArguments([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder arguments, int capacity);
        void SetArguments([MarshalAs(UnmanagedType.LPWStr)] string arguments);
        void GetHotkey(out short hotkey);
        void SetHotkey(short hotkey);
        void GetShowCmd(out int showCommand);
        void SetShowCmd(int showCommand);
        void GetIconLocation([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder iconPath, int capacity, out int iconIndex);
        void SetIconLocation([MarshalAs(UnmanagedType.LPWStr)] string iconPath, int iconIndex);
        void SetRelativePath([MarshalAs(UnmanagedType.LPWStr)] string path, uint reserved);
        void Resolve(IntPtr window, uint flags);
        void SetPath([MarshalAs(UnmanagedType.LPWStr)] string path);
    }

    [ComImport, Guid("886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IPropertyStore {
        void GetCount(out uint count);
        void GetAt(uint index, out PropertyKey key);
        void GetValue(ref PropertyKey key, out PropVariant value);
        void SetValue(ref PropertyKey key, ref PropVariant value);
        void Commit();
    }

    [ComImport, Guid("0000010B-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IPersistFile {
        void GetClassID(out Guid classId);
        [PreserveSig] int IsDirty();
        void Load([MarshalAs(UnmanagedType.LPWStr)] string fileName, uint mode);
        void Save([MarshalAs(UnmanagedType.LPWStr)] string fileName, bool remember);
        void SaveCompleted([MarshalAs(UnmanagedType.LPWStr)] string fileName);
        void GetCurFile([MarshalAs(UnmanagedType.LPWStr)] out string fileName);
    }

    public static class ShellLinkAppId {
        private static readonly Guid ClassId = new Guid("00021401-0000-0000-C000-000000000046");
        private static readonly PropertyKey AppUserModelId = new PropertyKey(new Guid("9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3"), 5);
        [DllImport("ole32.dll")]
        private static extern int PropVariantClear(ref PropVariant value);

        public static void Create(string linkPath, string targetPath, string appId) {
            object instance = Activator.CreateInstance(Type.GetTypeFromCLSID(ClassId));
            try {
                IShellLinkW link = (IShellLinkW)instance;
                link.SetPath(targetPath);
                link.SetWorkingDirectory(System.IO.Path.GetDirectoryName(targetPath));
                link.SetArguments("-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -Command exit");
                link.SetDescription("External Intelligence");
                link.SetShowCmd(1);
                IPropertyStore store = (IPropertyStore)instance;
                PropertyKey key = AppUserModelId;
                PropVariant value = new PropVariant { vt = 31, pointer = Marshal.StringToCoTaskMemUni(appId) };
                try { store.SetValue(ref key, ref value); store.Commit(); }
                finally { PropVariantClear(ref value); }
                ((IPersistFile)instance).Save(linkPath, false);
            }
            finally { if (Marshal.IsComObject(instance)) Marshal.FinalReleaseComObject(instance); }
        }

        public static bool Verify(string linkPath, string targetPath, string appId) {
            object instance = Activator.CreateInstance(Type.GetTypeFromCLSID(ClassId));
            try {
                ((IPersistFile)instance).Load(linkPath, 0);
                IShellLinkW link = (IShellLinkW)instance;
                StringBuilder actualTarget = new StringBuilder(32768);
                link.GetPath(actualTarget, actualTarget.Capacity, IntPtr.Zero, 0);
                if (!String.Equals(System.IO.Path.GetFullPath(actualTarget.ToString()), System.IO.Path.GetFullPath(targetPath), StringComparison.OrdinalIgnoreCase)) return false;
                IPropertyStore store = (IPropertyStore)instance;
                PropertyKey key = AppUserModelId;
                PropVariant value;
                store.GetValue(ref key, out value);
                try {
                    return value.vt == 31 && String.Equals(Marshal.PtrToStringUni(value.pointer), appId, StringComparison.Ordinal);
                }
                finally { PropVariantClear(ref value); }
            }
            finally { if (Marshal.IsComObject(instance)) Marshal.FinalReleaseComObject(instance); }
        }
    }
}
'@

if ([IntPtr]::Size -eq 8) {
    $propVariantSize = 24
    $propVariantArrayPointerOffset = 16
} elseif ([IntPtr]::Size -eq 4) {
    $propVariantSize = 16
    $propVariantArrayPointerOffset = 12
} else {
    throw 'UNSUPPORTED_POINTER_SIZE'
}
return $shellLinkInterop.Replace('Size = 16', "Size = $propVariantSize").Replace('FieldOffset(16)] public IntPtr arrayPointer', "FieldOffset($propVariantArrayPointerOffset)] public IntPtr arrayPointer")
}
$shellLinkInterop = Get-EiShellLinkInteropSource

try {
    if (-not $env:SystemRoot -or -not $env:APPDATA -or -not $env:LOCALAPPDATA) { Write-Response 'UNAVAILABLE' $false 'OS_ENVIRONMENT_UNAVAILABLE'; exit 0 }
    $expectedTarget = [IO.Path]::GetFullPath((Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'))
    $targetFull = [IO.Path]::GetFullPath($Target)
    if ($targetFull -ine $expectedTarget -or -not (Test-Path -LiteralPath $targetFull -PathType Leaf)) { Write-Response 'UNAVAILABLE' $false 'TARGET_UNAVAILABLE'; exit 0 }
    $shortcut = [IO.Path]::GetFullPath((Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\External Intelligence.lnk'))
    $registration = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'MiyaIF\ExternalIntelligence\notification-registration.json'))
    $targetFull = $expectedTarget
    Assert-NoReparseComponents $shortcut
    Assert-NoReparseComponents $registration

    if ($Action -eq 'Register') {
        if ([IO.File]::Exists($shortcut) -or [IO.File]::Exists($registration) -or [IO.Directory]::Exists($shortcut) -or [IO.Directory]::Exists($registration)) {
            Write-Response 'CONFLICT' $false 'PREEXISTING_UNOWNED_TARGET'; exit 0
        }
        Ensure-Directory ([IO.Path]::GetDirectoryName($shortcut))
        Ensure-Directory ([IO.Path]::GetDirectoryName($registration))
        $nonce = [Guid]::NewGuid().ToString('N')
        $shortcutTemp = Join-Path ([IO.Path]::GetDirectoryName($shortcut)) ('.ei-' + $nonce + '.lnk')
        $recordTemp = Join-Path ([IO.Path]::GetDirectoryName($registration)) ('.ei-' + $nonce + '.json')
        Add-Type -TypeDefinition $shellLinkInterop -ErrorAction Stop
        [EIWinNotify.ShellLinkAppId]::Create($shortcutTemp, $targetFull, $appId)
        if (-not (Test-RegularFile $shortcutTemp $maxShortcutBytes) -or -not [EIWinNotify.ShellLinkAppId]::Verify($shortcutTemp, $targetFull, $appId)) { throw 'SHORTCUT_VERIFICATION_FAILED' }
        $shortcutHash = Get-Sha256 $shortcutTemp
        $recordValue = [ordered]@{ schema_version = 1; app_id = $appId; shortcut_sha256 = $shortcutHash; target = $targetFull }
        $recordBytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes((ConvertTo-Json -InputObject $recordValue -Compress))
        if ($recordBytes.Length -gt $maxRecordBytes) { throw 'REGISTRATION_RECORD_TOO_LARGE' }
        $recordStream = New-Object IO.FileStream($recordTemp, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $recordStream.Write($recordBytes, 0, $recordBytes.Length); $recordStream.Flush($true) }
        finally { $recordStream.Dispose() }
        $recordHash = Get-Sha256 $recordTemp
        # File.Move without overwrite: a racing user file becomes a conflict.
        [IO.File]::Move($shortcutTemp, $shortcut)
        $shortcutTemp = $null
        $createdShortcut = $true
        [IO.File]::Move($recordTemp, $registration)
        $recordTemp = $null
        $createdRecord = $true
        if (-not (Test-RegularFile $shortcut $maxShortcutBytes) -or -not (Test-RegularFile $registration $maxRecordBytes) -or -not [EIWinNotify.ShellLinkAppId]::Verify($shortcut, $targetFull, $appId)) { throw 'FINAL_REGISTRATION_VERIFICATION_FAILED' }
        $actualRecord = Read-Record $registration
        if ((Get-Sha256 $shortcut) -cne $shortcutHash -or (Get-Sha256 $registration) -cne $recordHash -or $actualRecord.shortcut_sha256 -cne $shortcutHash) { throw 'FINAL_REGISTRATION_HASH_MISMATCH' }
        Write-Response 'REGISTERED' $true
        exit 0
    }

    if ($Action -eq 'Verify') {
        if (-not (Test-RegularFile $shortcut $maxShortcutBytes) -or -not (Test-RegularFile $registration $maxRecordBytes)) { Write-Response 'UNAVAILABLE' $false 'REGISTRATION_MISSING'; exit 0 }
        Add-Type -TypeDefinition $shellLinkInterop -ErrorAction Stop
        $actualRecord = Read-Record $registration
        $shortcutHash = Get-Sha256 $shortcut
        $recordHash = Get-Sha256 $registration
        if ($actualRecord.shortcut_sha256 -cne $shortcutHash -or ($ExpectedShortcutSha256 -and $ExpectedShortcutSha256 -cne $shortcutHash) -or ($ExpectedRegistrationSha256 -and $ExpectedRegistrationSha256 -cne $recordHash) -or -not [EIWinNotify.ShellLinkAppId]::Verify($shortcut, $targetFull, $appId)) {
            Write-Response 'CONFLICT' $false 'REGISTRATION_OWNERSHIP_MISMATCH'; exit 0
        }
        Write-Response 'CURRENT' $true
        exit 0
    }

    if (-not $ExpectedShortcutSha256 -or -not $ExpectedRegistrationSha256) { Write-Response 'DENIED' $false 'OWNERSHIP_HASHES_REQUIRED'; exit 0 }
    Add-Type -TypeDefinition $shellLinkInterop -ErrorAction Stop
    if ([IO.File]::Exists($shortcut)) {
        if (-not (Test-RegularFile $shortcut $maxShortcutBytes)) { Write-Response 'CONFLICT' $false 'SHORTCUT_NOT_REGULAR'; exit 0 }
        $shortcutHash = Get-Sha256 $shortcut
        if ($shortcutHash -cne $ExpectedShortcutSha256 -or -not [EIWinNotify.ShellLinkAppId]::Verify($shortcut, $targetFull, $appId)) { Write-Response 'CONFLICT' $false 'SHORTCUT_OWNERSHIP_MISMATCH'; exit 0 }
    }
    if ([IO.File]::Exists($registration)) {
        if (-not (Test-RegularFile $registration $maxRecordBytes) -or (Get-Sha256 $registration) -cne $ExpectedRegistrationSha256) { Write-Response 'CONFLICT' $false 'RECORD_OWNERSHIP_MISMATCH'; exit 0 }
        $actualRecord = Read-Record $registration
        if ($actualRecord.shortcut_sha256 -cne $ExpectedShortcutSha256) { Write-Response 'CONFLICT' $false 'RECORD_SHORTCUT_MISMATCH'; exit 0 }
        $recordHash = $ExpectedRegistrationSha256
    }
    if ([IO.File]::Exists($registration)) {
        Assert-NoReparseComponents $registration
        if ((Get-Sha256 $registration) -cne $ExpectedRegistrationSha256) { Write-Response 'CONFLICT' $false 'RECORD_CHANGED_BEFORE_DELETE'; exit 0 }
        [IO.File]::Delete($registration)
        $createdRecord = $true
    }
    if ([IO.File]::Exists($shortcut)) {
        Assert-NoReparseComponents $shortcut
        if ((Get-Sha256 $shortcut) -cne $ExpectedShortcutSha256) { Write-Response 'FAILED' $false 'SHORTCUT_CHANGED_BEFORE_DELETE'; exit 0 }
        [IO.File]::Delete($shortcut)
        $createdShortcut = $true
    }
    if ([IO.File]::Exists($shortcut) -or [IO.File]::Exists($registration)) { Write-Response 'FAILED' $false 'REGISTRATION_REMOVE_INCOMPLETE'; exit 0 }
    $shortcutHash = $ExpectedShortcutSha256
    $recordHash = $ExpectedRegistrationSha256
    Write-Response 'REMOVED' $true
    exit 0
}
catch {
    if ($Action -eq 'Register') {
        try {
            if ($createdRecord -and $recordHash -and [IO.File]::Exists($registration) -and (Get-Sha256 $registration) -ceq $recordHash) { [IO.File]::Delete($registration) }
            if ($createdShortcut -and $shortcutHash -and [IO.File]::Exists($shortcut) -and (Get-Sha256 $shortcut) -ceq $shortcutHash) { [IO.File]::Delete($shortcut) }
        } catch { }
        foreach ($directory in $createdDirectories.ToArray() | Sort-Object Length -Descending) {
            try { if ([IO.Directory]::Exists($directory) -and @(Get-ChildItem -LiteralPath $directory -Force).Count -eq 0) { [IO.Directory]::Delete($directory, $false) } } catch { }
        }
    }
    $code = 'OS_OPERATION_FAILED'
    if ($_.Exception.Message -match 'PSSecurityException|UnauthorizedAccessException|Access is denied') { $code = 'OS_DENIED' }
    Write-Response 'FAILED' $false $code
    exit 0
}
finally {
    foreach ($temporaryPath in @($shortcutTemp, $recordTemp)) {
        if ($temporaryPath -and [IO.File]::Exists($temporaryPath)) {
            try { [IO.File]::Delete($temporaryPath) } catch { }
        }
    }
}
