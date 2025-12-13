# Ultimate Antivirus by Gorstak - Merged Version
# Combines all features: hash lookups, memory scanning, real-time monitoring, smart DLL blocking

$Base       = "C:\ProgramData\Antivirus"
$Quarantine = Join-Path $Base "Quarantine"
$Backup     = Join-Path $Base "Backup"
$LogFile    = Join-Path $Base "antivirus.log"
$BlockedLog = Join-Path $Base "blocked.log"
$Database   = Join-Path $Base "scanned_files.txt"
$scannedFiles = @{}

# Task configuration
$taskName = "UltimateAntivirusStartup"
$taskDescription = "Ultimate Antivirus - Runs at user logon with admin privileges"
$scriptDir = "C:\Windows\Setup\Scripts"
$scriptPath = "$scriptDir\Antivirus.ps1"

# Check admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

# Allowed system accounts
$AllowedSIDs = @(
    'S-1-2-0',                          # Console user
    'S-1-5-20'                          # Network Service
)

# Optional MalwareBazaar API key
$MalwareBazaarAuthKey = ""

# Free public hash lookup endpoints
$CirclLookupBase = "https://hashlookup.circl.lu/lookup/sha256"
$CymruMHR        = "https://api.malwarehash.cymru.com/v1/hash"

# High-risk paths where unsigned DLLs are suspicious
$RiskyPaths = @(
    '\temp\','\downloads\','\appdata\local\temp\','\public\','\windows\temp\',
    '\appdata\roaming\','\desktop\'
)

# Comprehensive list of monitored extensions
$MonitoredExtensions = @(
    # Standard executable and script extensions
    '.exe','.dll','.sys','.ocx','.scr','.com','.cpl','.msi','.drv','.winmd',
    '.ps1','.bat','.cmd','.vbs','.js','.hta','.jse','.wsf','.wsh','.psc1',
    
    # Extended list for comprehensive coverage
    '.zoo','.zlo','.zfsendtotarget','.z','.xz','.xsl','.xps','.xpi','.xnk','.xml',
    '.xlw','.xltx','.xltm','.xlt','.xlsx','.xlsm','.xlsb','.xls','.xlm','.xll',
    '.xld','.xlc','.xlb','.xlam','.xla','.xip','.xbap','.xar','.wwl','.wsc',
    '.ws','.wll','.wiz','.website','.webpnp','.webloc','.wbk','.was','.vxd',
    '.vsw','.vst','.vss','.vsmacros','.vhdx','.vhd','.vbp','.vb','.url','.tz',
    '.txz','.tsp','.tpz','.tool','.tmp','.tlb','.theme','.tgz','.terminal',
    '.term','.tbz','.taz','.tar','.swf','.stm','.spl','.slk','.sldx',
    '.sldm','.sit','.shs','.shb','.settingcontent-ms','.search-ms','.searchconnector-ms',
    '.sea','.sct','.scf','.rtf','.rqy','.rpy','.rev','.reg','.rb',
    '.rar','.r09','.r08','.r07','.r06','.r05','.r04','.r03','.r02','.r01',
    '.r00','.pyzw','.pyz','.pyx','.pywz','.pyw','.pyt','.pyp','.pyo','.pyi',
    '.pyde','.pyd','.pyc','.py3','.py','.pxd','.pstreg','.pst','.psdm1','.psd1',
    '.prn','.printerexport','.prg','.prf','.pptx','.pptm','.ppt','.ppsx','.ppsm',
    '.pps','.ppam','.ppa','.potx','.potm','.pot','.plg','.pl','.pkg','.pif',
    '.pi','.perl','.pcd','.pa','.osd','.oqy','.ops','.one','.ods',
    '.ntfs','.nsh','.nls','.mydocs','.mui','.msu','.mst','.msp','.mshxml',
    '.msh2xml','.msh2','.msh1xml','.msh1','.msh','.mof','.mmc','.mhtml','.mht',
    '.mdz','.mdw','.mdt','.mdn','.mdf','.mde','.mdb','.mda','.mcl','.mcf',
    '.may','.maw','.mav','.mau','.mat','.mas','.mar','.maq','.mapimail',
    '.manifest','.mam','.mag','.maf','.mad','.lzh','.local','.library-ms',
    '.lha','.ldb','.laccdb','.ksh','.job','.jnlp','.jar','.its','.isp','.iso',
    '.iqy','.ins','.ini','.inf','.img','.ime','.ie','.hwp','.htt','.htm',
    '.htc','.hpj','.hlp','.hex','.gz','.grp','.glk','.gadget',
    '.fxp','.fon','.fat','.elf','.ecf','.dqy','.dotx','.dotm',
    '.dot','.docm','.docb','.doc','.dmg','.dir','.dif','.diagcab',
    '.desktop','.desklink','.der','.dcr','.db','.csv','.csh','.crx','.crt',
    '.crazy','.cpx','.command','.cnt','.cnv','.clb',
    '.class','.cla','.chm','.chi','.cfg','.cer','.cdb','.cab','.bzip2','.bzip',
    '.bz2','.bz','.bas','.ax','.asx','.aspx','.asp','.asa','.arj',
    '.arc','.appref-ms','.application','.app','.air','.adp','.adn','.ade',
    '.ad','.acm','.accdu','.accdt','.accdr','.accde','.accda','.c','.h'
)

# Protected processes we never kill
$ProtectedProcessNames = @('System','lsass','wininit','winlogon','csrss','services','smss',
                           'Registry','svchost','explorer','dwm','SearchUI','SearchIndexer')

# Create folders
New-Item -ItemType Directory -Path $Base,$Quarantine,$Backup -Force | Out-Null

# ------------------------- Logging with Rotation -------------------------
function Log($msg) {
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
    $line | Out-File -FilePath $LogFile -Append -Encoding ASCII
    Write-Host $line
    
    # Log rotation
    if ((Test-Path $LogFile) -and ((Get-Item $LogFile -ErrorAction SilentlyContinue).Length -ge 10MB)) {
        $archiveName = "$Base\antivirus_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
        Rename-Item -Path $LogFile -NewName $archiveName -ErrorAction SilentlyContinue
    }
}

Log "=== Ultimate Antivirus starting ==="
Log "Admin: $isAdmin, User: $env:USERNAME, SID: $([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"

# ------------------------- Setup & Task Registration -------------------------
if ((Get-ExecutionPolicy) -eq "Restricted") {
    Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force -ErrorAction SilentlyContinue
    Log "Set execution policy to Bypass"
}

if ($isAdmin) {
    if (-not (Test-Path $scriptDir)) {
        New-Item -Path $scriptDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    }
    if (-not (Test-Path $scriptPath) -or (Get-Item $scriptPath -ErrorAction SilentlyContinue).LastWriteTime -lt (Get-Item $MyInvocation.MyCommand.Path -ErrorAction SilentlyContinue).LastWriteTime) {
        Copy-Item -Path $MyInvocation.MyCommand.Path -Destination $scriptPath -Force -ErrorAction SilentlyContinue
        Log "Updated script to: $scriptPath"
    }
    
    $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if (-not $existingTask) {
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Description $taskDescription
        Register-ScheduledTask -TaskName $taskName -InputObject $task -Force -ErrorAction SilentlyContinue
        Log "Scheduled task registered as SYSTEM"
    }
}

# ------------------------- Database Management -------------------------
if (Test-Path $Database) {
    try {
        $scannedFiles.Clear()
        $lines = Get-Content $Database -ErrorAction Stop
        foreach ($line in $lines) {
            if ($line -match "^([0-9a-f]{64}),(true|false)$") {
                $scannedFiles[$matches[1]] = [bool]::Parse($matches[2])
            }
        }
        Log "Loaded $($scannedFiles.Count) entries from database"
    } catch {
        Log "Failed to load database: $($_.Exception.Message)"
        $scannedFiles.Clear()
    }
} else {
    New-Item -Path $Database -ItemType File -Force -ErrorAction SilentlyContinue | Out-Null
    Log "Created new database"
}

# ------------------------- File Exclusions -------------------------
function Should-ExcludeFile {
    param ([string]$filePath)
    $lowerPath = $filePath.ToLower()
    
    # Exclude Windows Assembly folders (GAC)
    if ($lowerPath -like "*\assembly\*") { return $true }
    
    # Exclude ctfmon and Input Method Editor files
    if ($lowerPath -like "*ctfmon*" -or $lowerPath -like "*msctf.dll" -or $lowerPath -like "*msutb.dll") { return $true }
    
    # Exclude Windows system config
    if ($lowerPath -like "*\windows\system32\config\*") { return $true }
    
    # Exclude WinSxS (side-by-side assemblies)
    if ($lowerPath -like "*\winsxs\*") { return $true }
    
    # Exclude .NET Framework
    if ($lowerPath -like "*\microsoft.net\*") { return $true }
    
    return $false
}

# ------------------------- Fast Signature + CIRCL Check -------------------------
function Test-FastAllow($filePath) {
    if (-not (Test-Path $filePath)) { return $false }

    # 1. Valid Authenticode signature → instant allow
    try {
        $sig = Get-AuthenticodeSignature $filePath -ErrorAction Stop
        if ($sig.Status -eq 'Valid') { return $true }
    } catch {}

    # 2. CIRCL hashlookup (known good files)
    try {
        $hash = (Get-FileHash $filePath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()
        $r = Invoke-RestMethod "https://hashlookup.circl.lu/lookup/sha256/$hash" -TimeoutSec 4 -ErrorAction SilentlyContinue
        if ($r) { return $true }
    } catch {}

    return $false
}

# ------------------------- Hash Computation -------------------------
function Compute-Hash($path) {
    try { 
        return (Get-FileHash $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower() 
    } catch { 
        return $null 
    }
}

function Calculate-FileHash {
    param ([string]$filePath)
    try {
        $signature = Get-AuthenticodeSignature -FilePath $filePath -ErrorAction Stop
        $hash = Get-FileHash -Path $filePath -Algorithm SHA256 -ErrorAction Stop
        return [PSCustomObject]@{
            Hash = $hash.Hash.ToLower()
            Status = $signature.Status
            StatusMessage = $signature.StatusMessage
        }
    } catch {
        return $null
    }
}

# ------------------------- Hash Lookup Services -------------------------
function Query-CIRCL($sha256) {
    try {
        $resp = Invoke-RestMethod "$CirclLookupBase/$sha256" -TimeoutSec 8 -ErrorAction Stop
        return ($resp -and ($resp | ConvertTo-Json -Depth 3).Length -gt 10)
    } catch { return $false }
}

function Query-CymruMHR($sha256) {
    try {
        $resp = Invoke-RestMethod "$CymruMHR/$sha256" -TimeoutSec 8 -ErrorAction Stop
        return ($resp.detections -and $resp.detections -ge 60)
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

# ------------------------- Smart Unsigned DLL/WINMD Blocking -------------------------
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

    # Check risky paths
    foreach ($rp in $RiskyPaths) {
        if ($pathLower -like "*$rp*" -and $size -lt 3MB) { return $true }
    }

    # Random-named DLLs in AppData\Roaming
    if ($pathLower -like "*\appdata\roaming\*" -and $size -lt 800KB -and $name -match '^[a-z0-9]{4,12}\.(dll|winmd)$') {
        return $true
    }
    
    return $false
}

# ------------------------- File Lock Handling -------------------------
function Is-Locked($file) {
    try { 
        [IO.File]::Open($file,'Open','ReadWrite','None').Close()
        return $false 
    } catch { 
        return $true 
    }
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

# ------------------------- Ownership & Permissions -------------------------
function Set-FileOwnershipAndPermissions {
    param ([string]$filePath)
    try {
        takeown /F $filePath /A 2>&1 | Out-Null
        icacls $filePath /reset 2>&1 | Out-Null
        icacls $filePath /grant "Administrators:F" /inheritance:d 2>&1 | Out-Null
        Log "Set ownership/permissions: $filePath"
        return $true
    } catch {
        return $false
    }
}

# ------------------------- Process Termination -------------------------
function Stop-ProcessUsingDLL {
    param ([string]$filePath)
    try {
        $processes = Get-Process | Where-Object { 
            try { ($_.Modules | Where-Object { $_.FileName -eq $filePath }) } catch { $false }
        }
        foreach ($process in $processes) {
            if ($ProtectedProcessNames -contains $process.Name) { continue }
            Stop-Process -Id $process.Id -Force -ErrorAction Stop
            Log "Stopped process $($process.Name) (PID: $($process.Id)) using $filePath"
        }
    } catch {
        try {
            taskkill /F /FI "MODULES eq $(Split-Path $filePath -Leaf)" 2>&1 | Out-Null
        } catch {}
    }
}

# ------------------------- Quarantine -------------------------
function Do-Quarantine($file, $reason) {
    if (-not (Test-Path $file)) { return }
    
    if (Is-Locked $file) { 
        Try-ReleaseFile $file | Out-Null 
    }

    $name = [IO.Path]::GetFileName($file)
    $ts   = Get-Date -Format "yyyyMMdd_HHmmss"
    $bak  = Join-Path $Backup ("$name`_$ts.bak")
    $q    = Join-Path $Quarantine ("$name`_$ts")

    try {
        Copy-Item $file $bak -Force -ErrorAction Stop
        Move-Item $file $q -Force -ErrorAction Stop
        Log "QUARANTINED [$reason]: $file → $q"
    } catch {
        Log "QUARANTINE FAILED [$reason]: $file - $_"
        if (Set-FileOwnershipAndPermissions $file) {
            try {
                Copy-Item $file $bak -Force -ErrorAction Stop
                Move-Item $file $q -Force -ErrorAction Stop
                Log "QUARANTINED (after permission fix) [$reason]: $file"
            } catch {
                Log "QUARANTINE STILL FAILED: $_"
            }
        }
    }
}

function Deny-Execution($file,$pid,$type) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$ts | BLOCKED $type | $file | PID $pid" | Out-File $BlockedLog -Append
    Log "BLOCKED $type | $file | PID $pid"
    
    try {
        $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
        if ($proc -and ($ProtectedProcessNames -notcontains $proc.ProcessName)) {
            Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
        }
    } catch {}
    
    if (Test-Path $file) {
        Do-Quarantine $file "Real-time $type block"
    }
}

# ------------------------- Main Decision Engine -------------------------
function Decide-And-Act($file) {
    if (-not (Test-Path $file -PathType Leaf)) { return }
    if (Should-ExcludeFile $file) { return }
    
    $ext = [IO.Path]::GetExtension($file).ToLower()
    if ($ext -notin $MonitoredExtensions) { return }

    $sha256 = Compute-Hash $file
    if (-not $sha256) { return }

    # Check database first
    if ($scannedFiles.ContainsKey($sha256)) {
        if (-not $scannedFiles[$sha256]) {
            Do-Quarantine $file "Previously identified threat"
        }
        return
    }

    # 1. CIRCL trusted list → allow
    if (Query-CIRCL $sha256) {
        $scannedFiles[$sha256] = $true
        "$sha256,true" | Out-File -FilePath $Database -Append -Encoding UTF8
        Log "ALLOWED (CIRCL trusted): $file"
        return
    }

    # 2. Known malware → quarantine
    if (Query-CymruMHR $sha256) {
        $scannedFiles[$sha256] = $false
        "$sha256,false" | Out-File -FilePath $Database -Append -Encoding UTF8
        Do-Quarantine $file "Cymru MHR match (≥60% AVs)"
        return
    }
    
    if (Query-MalwareBazaar $sha256) {
        $scannedFiles[$sha256] = $false
        "$sha256,false" | Out-File -FilePath $Database -Append -Encoding UTF8
        Do-Quarantine $file "MalwareBazaar match"
        return
    }

    # 3. Smart unsigned DLL/WINMD blocking
    if (Is-SuspiciousUnsignedDll $file) {
        $scannedFiles[$sha256] = $false
        "$sha256,false" | Out-File -FilePath $Database -Append -Encoding UTF8
        Do-Quarantine $file "Suspicious unsigned DLL/WINMD in risky location"
        return
    }

    # 4. Check signature status
    $fileHash = Calculate-FileHash $file
    if ($fileHash) {
        $isValid = $fileHash.Status -eq "Valid"
        $scannedFiles[$sha256] = $isValid
        "$sha256,$isValid" | Out-File -FilePath $Database -Append -Encoding UTF8
        
        if ($isValid) {
            Log "ALLOWED (signed): $file"
        } else {
            Log "ALLOWED (clean but unsigned): $file"
        }
    }
}

# ------------------------- Memory Scanner -------------------------
function Start-MemoryScanner {
    $yaraExe  = "$Base\yara64.exe"
    $yaraRule = "$Base\mem.yar"

    # Check if YARA is available
    if (Test-Path $yaraExe) {
        if (-not (Test-Path $yaraRule)) {
            try {
                Invoke-WebRequest "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/memory.yar" -OutFile $yaraRule -UseBasicParsing -TimeoutSec 10
            } catch {}
        }
        Log "[+] Full YARA memory scanner active"
        Start-Job -ScriptBlock {
            $exe = $using:yaraExe; $rule = $using:yaraRule; $log = "$using:Base\memory_hits.log"
            while ($true) {
                Start-Sleep -Seconds 10
                Get-Process | Where-Object {
                    $_.WorkingSet64 -gt 150MB -or $_.Name -match 'powershell|wscript|cscript|mshta|rundll32|regsvr32|msbuild|cmstp'
                } | ForEach-Object {
                    & $exe -w $rule -p $_.Id 2>$null
                    if ($LASTEXITCODE -eq 0) {
                        "$(Get-Date) | YARA HIT → $($_.Name) ($($_.Id))" | Out-File $log -Append
                        Stop-Process $_.Id -Force -ErrorAction SilentlyContinue
                    }
                }
            }
        } | Out-Null
        return
    }

    # PowerShell memory scanner fallback
    Log "[+] PowerShell memory scanner active"
    Start-Job -ScriptBlock {
        $log = "$using:Base\ps_memory_hits.log"
        $EvilStrings = @(
            'mimikatz','sekurlsa::','kerberos::','lsadump::','wdigest','tspkg',
            'http-beacon','https-beacon','cobaltstrike','sleepmask','reflective',
            'amsi.dll','AmsiScanBuffer','EtwEventWrite','MiniDumpWriteDump',
            'VirtualAllocEx','WriteProcessMemory','CreateRemoteThread',
            'ReflectiveLoader','sharpchrome','rubeus','safetykatz','sharphound'
        )
        while ($true) {
            Start-Sleep -Seconds 10
            Get-Process | Where-Object {
                $_.WorkingSet64 -gt 100MB -or $_.Name -match 'powershell|wscript|cscript|mshta|rundll32|regsvr32|msbuild|cmstp|excel|word|outlook'
            } | ForEach-Object {
                $hit = $false
                try {
                    $_.Modules | ForEach-Object {
                        if ($EvilStrings | Where-Object { $_.ModuleName -match $_ -or $_.FileName -match $_ }) {
                            $hit = $true
                        }
                    }
                } catch {}
                if ($hit) {
                    "$(Get-Date) | PS MEMORY HIT → $($_.Name) ($($_.Id))" | Out-File $log -Append
                    Stop-Process $_.Id -Force -ErrorAction SilentlyContinue
                }
            }
        }
    } | Out-Null
}

# Reflective/manual-map memory scanner
Log "[+] Starting reflective payload detector"
Start-Job -ScriptBlock {
    $log = "$using:Base\manual_map_hits.log"
    while ($true) {
        Start-Sleep -Seconds 10
        Get-Process | Where-Object { $_.WorkingSet64 -gt 40MB } | ForEach-Object {
            $p = $_
            $sus = $false
            if (-not $p.Path -or $p.Path -eq '' -or $p.Path -match '$$Unknown$$') { $sus = $true }
            if ($p.Modules | Where-Object { $_.FileName -eq '' -or $_.ModuleName -eq '' }) { $sus = $true }
            if ($sus) {
                "$([DateTime]::Now) | REFLECTIVE PAYLOAD → $($p.Name) ($($p.Id)) Path='$($p.Path)'" | Out-File $log -Append
                Stop-Process $p.Id -Force -ErrorAction SilentlyContinue
            }
        }
    }
} | Out-Null

# ------------------------- Process + Network Scanner -------------------------
function Scan-ProcessesAndNetwork() {
    Get-Process | ForEach-Object {
        try {
            $exe = $_.MainModule.FileName
            if ($exe -and (Test-Path $exe)) { Decide-And-Act $exe }
        } catch {}
    }

    Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $_.State -in 'Established','Listen' } | ForEach-Object {
        try {
            $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            if ($p) { 
                $exe = $p.MainModule.FileName
                if ($exe) { Decide-And-Act $exe }
            }
        } catch {}
    }
}

# ------------------------- Initial Scan -------------------------
Log "Performing initial scan of high-risk folders"
@("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:TEMP", "$env:APPDATA", "$env:LOCALAPPDATA\Temp") | ForEach-Object {
    if (Test-Path $_) {
        Get-ChildItem $_ -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            Decide-And-Act $_.FullName
        }
    }
}

# ------------------------- Real-time File Watchers -------------------------
$WatchFolders = @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:TEMP", "$env:APPDATA", "$env:LOCALAPPDATA\Temp")
foreach ($folder in $WatchFolders) {
    if (-not (Test-Path $folder)) { continue }
    $watcher = New-Object IO.FileSystemWatcher $folder, "*.*" -Property @{
        IncludeSubdirectories = $true
        NotifyFilter = 'FileName, LastWrite'
    }
    Register-ObjectEvent $watcher Created -Action {
        $path = $Event.SourceEventArgs.FullPath
        $ext  = [IO.Path]::GetExtension($path).ToLower()
        if ($MonitoredExtensions -contains $ext) {
            Start-Sleep -Milliseconds 800
            Decide-And-Act $path
        }
    } | Out-Null
    $watcher.EnableRaisingEvents = $true
}
Log "Real-time file watchers active"

# ------------------------- WMI Real-time Execution Hooks -------------------------
Log "Registering WMI real-time execution monitors"

# Process creation monitoring
Register-WmiEvent -Query "SELECT * FROM Win32_ProcessStartTrace" -Action {
    $e = $Event.SourceEventArgs.NewEvent
    $Path = $e.ProcessName
    $PID = $e.ProcessId

    try {
        $OwnerSID = (Get-CimInstance Win32_Process -Filter "ProcessId=$PID" | Invoke-CimMethod -MethodName GetOwnerSid).Sid
    } catch { $OwnerSID = "Unknown" }

    if ($AllowedSIDs -contains $OwnerSID) {
        if (Test-FastAllow $Path) { return }
    }

    Deny-Execution $Path $PID "EXE"
} | Out-Null

# DLL/Module load monitoring
Register-WmiEvent -Query "SELECT * FROM Win32_ModuleLoadTrace" -Action {
    $e = $Event.SourceEventArgs.NewEvent
    $Path = $e.ImageName
    $PID = $e.ProcessId

    if (-not (Test-Path $Path)) { return }

    try {
        $OwnerSID = (Get-CimInstance Win32_Process -Filter "ProcessId=$PID" | Invoke-CimMethod -MethodName GetOwnerSid).Sid
    } catch { $OwnerSID = "Unknown" }

    if ($AllowedSIDs -contains $OwnerSID) {
        if (Test-FastAllow $Path) { return }
    }

    Deny-Execution $Path $PID "DLL"
} | Out-Null

# ------------------------- Start Memory Scanners -------------------------
Start-MemoryScanner

# ------------------------- Main Monitoring Loop -------------------------
Log "All monitoring systems active. Starting main loop..."
Write-Host "Ultimate Antivirus running. Press [Ctrl] + [C] to stop."

try {
    while ($true) {
        try { 
            Scan-ProcessesAndNetwork 
            Log "Periodic scan completed"
        } catch { 
            Log "Scan loop error: $_" 
        }
        Start-Sleep -Seconds 30
    }
} catch {
    Log "Main loop crashed: $($_.Exception.Message)"
    Write-Host "Script crashed. Check $LogFile for details."
}
