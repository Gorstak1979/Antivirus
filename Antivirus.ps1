# Antivirus.ps1
# Author: Gorstak

$Base       = "C:\ProgramData\Antivirus"
$Quarantine = Join-Path $Base "Quarantine"
$Backup     = Join-Path $Base "Backup"
$LogFile    = Join-Path $Base "antivirus.log"
$BlockedLog = Join-Path $Base "blocked.log"

# Allowed system accounts
$AllowedSIDs = @(
    'S-1-2-0',                          # Console user
    'S-1-5-20'                          # Network Service
)

# Free public hash lookup endpoints
$CirclLookupBase = "https://hashlookup.circl.lu/lookup/sha256"
$CymruMHR        = "https://api.malwarehash.cymru.com/v1/hash"

# Optional MalwareBazaar key
$MalwareBazaarAuthKey = ""

# High-risk paths
$RiskyPaths = @(
    '\temp\','\downloads\','\appdata\local\temp\','\public\','\windows\temp\',
    '\appdata\roaming\','\desktop\'
)

# Comprehensive list of monitored extensions (including all provided ones)
$MonitoredExtensions = @(
    # Standard executable and script extensions
    '.exe','.dll','.sys','.ocx','.scr','.com','.cpl','.msi','.drv','.winmd',
    '.ps1','.bat','.cmd','.vbs','.js','.hta','.jse','.wsf','.wsh','.psc1',
    
    # New extensions from your list
    '.zoo','.zlo','.zfsendtotarget','.z','.xz','.xsl','.xps','.xpi','.xnk','.xml',
    '.xlw','.xltx','.xltm','.xlt','.xlsx','.xlsm','.xlsb','.xls','.xlm','.xll',
    '.xld','.xlc','.xlb','.xlam','.xla','.xip','.xbap','.xar','.wwl','.wsc',
    '.ws','.wll','.wiz','.website','.webpnp','.webloc','.wbk','.was','.vxd',
    '.vsw','.vst','.vss','.vsmacros','.vhdx','.vhd','.vbp','.vb','.url','.tz',
    '.txz','.tsp','.tpz','.tool','.tmp','.tlb','.theme','.tgz','.terminal',
    '.term','.tbz','.taz','.tar','.sys','.swf','.stm','.spl','.slk','.sldx',
    '.sldm','.sit','.shs','.shb','.settingcontent-ms','.search-ms','.searchconnector-ms',
    '.sea','.sct','.scr','.scf','.rtf','.rqy','.rpy','.rev','.reg','.rb',
    '.rar','.r09','.r08','.r07','.r06','.r05','.r04','.r03','.r02','.r01',
    '.r00','.pyzw','.pyz','.pyx','.pywz','.pyw','.pyt','.pyp','.pyo','.pyi',
    '.pyde','.pyd','.pyc','.py3','.py','.pxd','.pstreg','.pst','.psdm1','.psd1',
    '.prn','.printerexport','.prg','.prf','.pptx','.pptm','.ppt','.ppsx','.ppsm',
    '.pps','.ppam','.ppa','.potx','.potm','.pot','.plg','.pl','.pkg','.pif',
    '.pi','.perl','.pcd','.pa','.osd','.oqy','.ops','.one','.ods','.ocx',
    '.ntfs','.nsh','.nls','.mydocs','.mui','.msu','.mst','.msp','.mshxml',
    '.msh2xml','.msh2','.msh1xml','.msh1','.msh','.mof','.mmc','.mhtml','.mht',
    '.mdz','.mdw','.mdt','.mdn','.mdf','.mde','.mdb','.mda','.mcl','.mcf',
    '.may','.maw','.mav','.mau','.mat','.mas','.mar','.maq','.mapimail',
    '.manifest','.mam','.mag','.maf','.mad','.lzh','.local','.library-ms',
    '.lha','.ldb','.laccdb','.ksh','.job','.jnlp','.jar','.its','.isp','.iso',
    '.iqy','.ins','.ini','.inf','.img','.ime','.ie','.hwp','.htt','.htm',
    '.htc','.hta','.hqx','.hpj','.hlp','.hex','.gz','.grp','.glk','.gadget',
    '.fxp','.fon','.fat','.exe','.elf','.ecf','.drv','.dqy','.dotx','.dotm',
    '.dot','.docm','.docb','.doc','.dmg','.dll','.dir','.dif','.diagcab',
    '.desktop','.desklink','.der','.dcr','.db','.csv','.csh','.crx','.crt',
    '.crazy','.cpx','.cpl','.command','.com','.cnv','.cnt','.cmd','.clb',
    '.class','.cla','.chm','.chi','.cfg','.cer','.cdb','.cab','.bzip2','.bzip',
    '.bz2','.bz','.bat','.bas','.ax','.asx','.aspx','.asp','.asa','.arj',
    '.arc','.appref-ms','.application','.app','.air','.adp','.adn','.ade',
    '.ad','.acm','.accdu','.accdt','.accdr','.accde','.accda','.c','.h'
)

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

function Deny-Execution($file,$pid,$type) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$ts | BLOCKED $type | $file | PID $pid | SID $OwnerSID" | Out-File $BlockedLog -Append
    Log "BLOCKED $type | $file | PID $pid"
    
    # Don't kill protected processes
    try {
        $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
        if ($proc -and ($ProtectedProcessNames -contains $proc.ProcessName)) {
            Log "Skipping termination of protected process: $($proc.ProcessName)"
            return
        }
        Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
    } catch {}
}

# ------------------------- Fast Signature + CIRCL Check -------------------------
function Test-FastAllow($filePath) {
    if (-not (Test-Path $filePath)) { return $false }

    # 1. Any valid Authenticode signature → instant allow
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

# ------------------------- Memory Scanner -------------------------
function Start-MemoryScanner {
    $yaraExe  = "$Base\yara64.exe"
    $yaraRule = "$Base\mem.yar"

    # If real yara64.exe exists → use it
    if (Test-Path $yaraExe) {
        if (-not (Test-Path $yaraRule)) {
            try {
                Invoke-WebRequest "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/memory.yar" -OutFile $yaraRule -UseBasicParsing -TimeoutSec 10
            } catch {}
        }
        Log "[+] Full YARA memory scanner active (yara64.exe found)"
        Start-Job -ScriptBlock {
            $exe = $using:yaraExe; $rule = $using:yaraRule; $log = "$using:Base\memory_hits.log"
            while ($true) {
                Start-Sleep -Seconds 240
                Get-Process | Where-Object {
                    $_.WorkingSet64 -gt 150MB -or $_.Name -match 'powershell|wscript|cscript|mshta|rundll32|regsvr32|msbuild|cmstp'
                } | ForEach-Object {
                    & $exe -w $rule -p $_.Id 2>$null
                    if ($LASTEXITCODE -eq 0) {
                        "$(Get-Date) | YARA MEMORY HIT → $($_.Name) ($($_.Id))" | Out-File $log -Append
                        Stop-Process $_.Id -Force
                    }
                }
            }
        } | Out-Null
        return
    }

    # Pure-PowerShell memory scanner fallback
    Log "[+] Embedded PowerShell memory scanner active"
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
            Start-Sleep -Seconds 240
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

# ------------------------- Hash Lookup Functions -------------------------
function Compute-Hash($path) {
    try { return (Get-FileHash $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower() }
    catch { return $null }
}

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

# ------------------------- Quarantine Functions -------------------------
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

# ------------------------- Main Execution -------------------------
Log "=== Combined Antivirus starting ==="

# Start memory scanner
Start-MemoryScanner

# Initial scan of high-risk folders
Log "Performing initial scan of high-risk folders"
@("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:TEMP", "$env:APPDATA", "$env:LOCALAPPDATA\Temp") | ForEach-Object {
    if (Test-Path $_) {
        Get-ChildItem $_ -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            Decide-And-Act $_.FullName
        }
    }
}

# Real-time file creation monitoring
$WatchFolders = @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:TEMP", "$env:APPDATA", "$env:LOCALAPPDATA\Temp")
foreach ($folder in $WatchFolders) {
    if (-not (Test-Path $folder)) { continue }
    $watcher = New-Object IO.FileSystemWatcher $folder, "*.*" -Property @{IncludeSubdirectories = $true; NotifyFilter = 'FileName, LastWrite'}
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
Log "Real-time file watchers active on high-risk folders"

# WMI Real-time execution hooks
Log "Registering WMI real-time execution monitors"

# Process creation monitoring
Register-WmiEvent -Query "SELECT * FROM Win32_ProcessStartTrace" -Action {
    $e   = $Event.SourceEventArgs.NewEvent
    $Path = $e.ProcessName
    $PID  = $e.ProcessId

    try {
        $OwnerSID = (Get-CimInstance Win32_Process -Filter "ProcessId=$PID" | Invoke-CimMethod -MethodName GetOwnerSid).Sid
    } catch { $OwnerSID = "Unknown" }

    if ($AllowedSIDs -contains $OwnerSID) {
        if (Test-FastAllow $Path) { return }
    }

    Deny-Execution $Path $PID "EXE"
    Decide-And-Act $Path
} | Out-Null

# DLL/Module load monitoring
Register-WmiEvent -Query "SELECT * FROM Win32_ModuleLoadTrace" -Action {
    $e    = $Event.SourceEventArgs.NewEvent
    $Path = $e.ImageName
    $PID  = $e.ProcessId

    if (-not (Test-Path $Path)) { return }

    try {
        $OwnerSID = (Get-CimInstance Win32_Process -Filter "ProcessId=$PID" | Invoke-CimMethod -MethodName GetOwnerSid).Sid
    } catch { $OwnerSID = "Unknown" }

    if ($AllowedSIDs -contains $OwnerSID) {
        if (Test-FastAllow $Path) { return }
    }

    Deny-Execution $Path $PID "DLL"
    Decide-And-Act $Path
} | Out-Null

Log "[+] Adding reflective/manual-map memory scanner (2025 bypass protection)"
Start-Job -ScriptBlock {
    $log = "$using:Base\manual_map_hits.log"
    while ($true) {
        Start-Sleep -Seconds 12
        Get-Process | Where-Object { $_.WorkingSet64 -gt 40MB } | ForEach-Object {
            $p = $_
            $sus = $false
            if (-not $p.Path -or $p.Path -eq '' -or $p.Path -match '\(Unknown\)') { $sus = $true }
            if ($p.Modules | Where-Object { $_.FileName -eq '' -or $_.ModuleName -eq '' }) { $sus = $true }
            if ($sus) {
                "$([DateTime]::Now) | MANUAL/REFLECTIVE PAYLOAD → $($p.Name) ($($p.Id)) Path='$($p.Path)'" | Out-File $log -Append
                Stop-Process $p.Id -Force -ErrorAction SilentlyContinue
            }
        }
    }
} | Out-Null

# ------------------------- Main Monitoring Loop -------------------------
Log "All monitoring systems active. Starting main loop..."
while ($true) {
    try { 
        Scan-ProcessesAndNetwork 
        Log "Periodic scan completed"
    } catch { Log "Scan loop error: $_" }
    Start-Sleep -Seconds 30
}