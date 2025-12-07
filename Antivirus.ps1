# Antivirus.ps1 – FINAL FIXED & WORKING VERSION (Dec 2025)
# Safe + effective + no API key needed
# Features: CIRCL + Team Cymru MHR + smart unsigned DLL blocking

$Base       = "C:\ProgramData\Antivirus"
$Quarantine = Join-Path $Base "Quarantine"
$Backup     = Join-Path $Base "Backup"
$LogFile    = Join-Path $Base "antivirus.log"

# Optional MalwareBazaar key (leave empty if you don’t have one)
$MalwareBazaarAuthKey = ""

# Free public hash lookup endpoints (NO API KEY required)
$CirclLookupBase = "https://hashlookup.circl.lu/lookup/sha256"
$CymruMHR        = "https://api.malwarehash.cymru.com/v1/hash"

# High-risk paths where unsigned DLLs are almost never legitimate
$RiskyPaths = @(
    '\temp\','\downloads\','\appdata\local\temp\','\public\','\windows\temp\',
    '\appdata\roaming\','\desktop\'
)

# Extensions we monitor
$MonitoredExtensions = @('.exe','.dll','.sys','.ocx','.scr','.com','.cpl','.msi','.drv','.winmd',
                         '.ps1','.bat','.cmd','.vbs','.js','.hta')

# Processes we never kill
$ProtectedProcessNames = @('System','lsass','wininit','winlogon','csrss','services','smss',
                           'Registry','svchost','explorer','dwm','SearchUI','SearchIndexer')

# Create folders
New-Item -ItemType Directory -Path $Base,$Quarantine,$Backup -Force | Out-Null

# ------------------------- Logging -------------------------
function Log($msg) {
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
    $line | Out-File -FilePath $LogFile -Append -Encoding ASCII
    Write-Host $line
}

# ------------------------- Utils -------------------------
function Compute-Hash($path) {
    try { return (Get-FileHash $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower() }
    catch { return $null }
}

function Is-Locked($file) {
    try { [IO.File]::Open($file,'Open','ReadWrite','None').Close(); return $false } catch { return $true }
}

function Try-ReleaseFile($file) {
    $holders = Get-Process | Where-Object {
        try { $_.Modules.FileName -contains $file } catch { $false }
    } | Select-Object -Unique

    foreach ($p in $holders) {
        if ($ProtectedProcessNames -contains $p.Name) { continue }
        try { $p.CloseMainWindow(); Start-Sleep -Milliseconds 600 } catch {}
        if (!$p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    }
    return -not (Is-Locked $file)
}

# ------------------------- Hash Lookups (all free) -------------------------
function Query-CIRCL($sha256) {
    try {
        $resp = Invoke-RestMethod "$CirclLookupBase/$sha256" -TimeoutSec 8 -ErrorAction Stop
        return ($resp -and ($resp | ConvertTo-Json -Depth 3).Length -gt 10)
    } catch { return $false }
}

function Query-CymruMHR($sha256) {
    try {
        $resp = Invoke-RestMethod "$CymruMHR/$sha256" -TimeoutSec 8 -ErrorAction Stop
        return ($resp.detections -and $resp.detections -ge 60)   # 60%+ AV engines flag it
    } catch { return $false }
}

function Query-MalwareBazaar($sha256) {
    if (-not $sha256) { return $false }
    $body = @{ query = 'get_info'; sha256_hash = $sha256 }
    if ($MalwareBazaarAuthKey) { $body.api_key = $MalwareBazaarAuthKey }
    try {
        $resp = Invoke-RestMethod "https://mb-api.abuse.ch/api/v1/" -Method Post -Body $body -TimeoutSec 10
        return ($resp.query_status -eq 'ok' -or ($resp.data -and $resp.data.Count -gt 0))
    } catch { return $false }
}

# ------------------------- Smart Unsigned DLL Blocking -------------------------
function Is-SuspiciousUnsignedDll($file) {
    $ext = [IO.Path]::GetExtension($file).ToLower()
    if ($ext -notin @('.dll','.winmd')) { return $false }

    # Must be unsigned
    try {
        $sig = Get-AuthenticodeSignature $file -ErrorAction Stop
        if ($sig.Status -eq 'Valid') { return $false }
    } catch { return $false }

    $size = (Get-Item $file -ErrorAction SilentlyContinue).Length
    $pathLower = $file.ToLower()
    $name = [IO.Path]::GetFileName($file).ToLower()

    foreach ($rp in $RiskyPaths) {
        if ($pathLower -like "*$rp*" -and $size -lt 3MB) { return $true }
    }

    if ($pathLower -like "*\appdata\roaming\*" -and $size -lt 800KB -and $name -match '^[a-z0-9]{4,12}\.dll$') {
        return $true
    }
    return $false
}

# ------------------------- Quarantine -------------------------
function Do-Quarantine($file, $reason) {
    if (-not (Test-Path $file)) { return }
    if (Is-Locked $file) { Try-ReleaseFile $file | Out-Null }

    $name = [IO.Path]::GetFileName($file)
    $ts   = Get-Date -Format "yyyyMMdd_HHmmss"
    $bak  = Join-Path $Backup ("$name`_$ts.bak")
    $q    = Join-Path $Quarantine ("$name`_$ts")

    try {
        Copy-Item $file $bak -Force -ErrorAction Stop
        Move-Item $file $q -Force -ErrorAction Stop
        Log "QUARANTINED [$reason]: $file → $q (backup: $bak)"
    } catch {
        Log "QUARANTINE FAILED [$reason]: $file - $_"
    }
}

# ------------------------- Main Decision Engine -------------------------
function Decide-And-Act($file) {
    if (-not (Test-Path $file -PathType Leaf)) { return }
    $ext = [IO.Path]::GetExtension($file).ToLower()
    if ($ext -notin $MonitoredExtensions) { return }

    $sha256 = Compute-Hash $file
    if (-not $sha256) { return }

    # 1. CIRCL trusted list → instantly allow
    if (Query-CIRCL $sha256) {
        Log "ALLOWED (CIRCL trusted): $file"
        return
    }

    # 2. Known malware on Cymru MHR or MalwareBazaar → quarantine
    if (Query-CymruMHR $sha256) {
        Do-Quarantine $file "Cymru MHR match (≥60% AVs)"
        return
    }
    if (Query-MalwareBazaar $sha256) {
        Do-Quarantine $file "MalwareBazaar match"
        return
    }

    # 3. Smart unsigned DLL blocking
    if (Is-SuspiciousUnsignedDll $file) {
        Do-Quarantine $file "Suspicious unsigned DLL in risky location"
        return
    }

    # 4. Everything else is allowed
    Log "ALLOWED (clean): $file"
}

# ------------------------- Process + Network Scanner -------------------------
function Scan-ProcessesAndNetwork() {
    Get-Process | ForEach-Object {
        try {
            $exe = $_.MainModule.FileName
            if ($exe -and (Test-Path $exe)) { Decide-And-Act $exe }
        } catch {}
    }

    Get-NetTCPConnection | Where-Object { $_.State -in 'Established','Listen' } | ForEach-Object {
        try {
            $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            if ($p) { $exe = $p.MainModule.FileName; if ($exe) { Decide-And-Act $exe } }
        } catch {}
    }
}

# ------------------------- Startup (safe folders only) -------------------------
Log "=== Antivirus started – scanning high-risk folders only ==="
@("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:TEMP", "$env:APPDATA", "$env:LOCALAPPDATA\Temp") | ForEach-Object {
    if (Test-Path $_) {
        Get-ChildItem $_ -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            Decide-And-Act $_.FullName
        }
    }
}

# === OPTIONAL: Real-time file creation monitoring in high-risk folders ===
$WatchFolders = @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:TEMP", "$env:APPDATA", "$env:LOCALAPPDATA\Temp")

foreach ($folder in $WatchFolders) {
    if (-not (Test-Path $folder)) { continue }
    $watcher = New-Object IO.FileSystemWatcher $folder, "*.*" -Property @{IncludeSubdirectories = $true; NotifyFilter = 'FileName, LastWrite'}
    Register-ObjectEvent $watcher Created -Action {
        $path = $Event.SourceEventArgs.FullPath
        $ext  = [IO.Path]::GetExtension($path).ToLower()
        if ($MonitoredExtensions -contains $ext) {
            Start-Sleep -Milliseconds 800  # wait for file to finish writing
            Decide-And-Act $path
        }
    } | Out-Null
    $watcher.EnableRaisingEvents = $true
}
Log "Real-time file watchers active on high-risk folders"

# ------------------------- Realtime Loop -------------------------
Log "Realtime monitoring active (processes + network every 30 seconds)"
while ($true) {
    try { Scan-ProcessesAndNetwork } catch { Log "Scan loop error: $_" }
    Start-Sleep -Seconds 30
}