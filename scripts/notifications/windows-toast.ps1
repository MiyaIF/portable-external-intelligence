# Send only. Setup owns registration and ownership evidence; never register here.
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$registrationVerified = $false
try {
    $appId = 'MiyaIF.ExternalIntelligence'
    $shortcut = Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'Microsoft\Windows\Start Menu\Programs\External Intelligence.lnk'
    $registration = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'MiyaIF\ExternalIntelligence\notification-registration.json'
    if (-not (Test-Path -LiteralPath $shortcut -PathType Leaf) -or -not (Test-Path -LiteralPath $registration -PathType Leaf)) {
        [Console]::WriteLine('UNAVAILABLE'); exit 0
    }
    if ((Get-Item -LiteralPath $registration).Length -gt 8192 -or (Get-Item -LiteralPath $shortcut).Length -gt 65536) {
        [Console]::WriteLine('UNAVAILABLE'); exit 0
    }
    $record = Get-Content -LiteralPath $registration -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($record.schema_version -ne 1 -or $record.app_id -cne $appId -or $record.shortcut_sha256 -cnotmatch '^[0-9a-f]{64}$' -or -not [IO.Path]::IsPathRooted($record.target)) {
        [Console]::WriteLine('UNAVAILABLE'); exit 0
    }
    $actualHash = (Get-FileHash -LiteralPath $shortcut -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -cne $record.shortcut_sha256) {
        [Console]::WriteLine('UNAVAILABLE'); exit 0
    }
    $shell = New-Object -ComObject Shell.Application
    $folder = $shell.Namespace([IO.Path]::GetDirectoryName($shortcut))
    $item = $folder.ParseName([IO.Path]::GetFileName($shortcut))
    $link = (New-Object -ComObject WScript.Shell).CreateShortcut($shortcut)
    if ($item.ExtendedProperty('System.AppUserModel.ID') -cne $appId -or $link.TargetPath -ine $record.target -or -not (Test-Path -LiteralPath $record.target -PathType Leaf)) {
        [Console]::WriteLine('UNAVAILABLE'); exit 0
    }
    $registrationVerified = $true
    $raw = [Console]::In.ReadToEnd()
    if ($raw.Length -gt 16384) { [Console]::WriteLine('FAILED'); exit 0 }
    $message = $raw | ConvertFrom-Json
    foreach ($text in @($message.title, $message.body)) {
        if ($text -isnot [string] -or $text.Length -eq 0 -or $text.Length -gt 2048 -or $text.Contains([char]0)) {
            [Console]::WriteLine('FAILED'); exit 0
        }
    }
    [void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
    [void][Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
    $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
    $xml.LoadXml('<toast><visual><binding template="ToastText02"><text id="1"></text><text id="2"></text></binding></visual></toast>')
    $nodes = $xml.GetElementsByTagName('text')
    [void]$nodes.Item(0).AppendChild($xml.CreateTextNode($message.title))
    [void]$nodes.Item(1).AppendChild($xml.CreateTextNode($message.body))
    $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId)
    if ($notifier.Setting.ToString() -ne 'Enabled') { [Console]::WriteLine('DENIED'); exit 0 }
    $toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
    $notifier.Show($toast)
    # OS acceptance only; this does not establish visible display.
    [Console]::WriteLine('SENT')
} catch [System.UnauthorizedAccessException] {
    [Console]::WriteLine('DENIED')
} catch {
    if ($registrationVerified) { [Console]::WriteLine('FAILED') }
    else { [Console]::WriteLine('UNAVAILABLE') }
}
