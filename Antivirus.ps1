# Antivirus.ps1
# Author: Gorstak

$Base       = "C:\ProgramData\Antivirus"
$Log        = "$Base\blocked.log"
$Quarantine = "$Base\Quarantine"
$null = New-Item -ItemType Directory $Base, $Quarantine -Force

# Allow these system accounts too (Windows Update, Defender, drivers, etc.)
$AllowedSIDs = @(
    'S-1-2-0',                          # You, the console user
    'S-1-5-20'                          # Network Service
)

# --------------------- 2. Fast signature + CIRCL check ---------------------
function Test-FastAllow($filePath) {
    if (-not (Test-Path $filePath)) { return $false }

    # 1. Any valid Authenticode signature → instant allow
    try {
        $sig = Get-AuthenticodeSignature $filePath -ErrorAction Stop
        if ($sig.Status -eq 'Valid') { return $true }
    } catch {}

    # 2. CIRCL hashlookup (known good files – covers tons of old unsigned legit tools)
    try {
        $hash = (Get-FileHash $filePath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()
        $r = Invoke-RestMethod "https://hashlookup.circl.lu/lookup/sha256/$hash" -TimeoutSec 4 -ErrorAction SilentlyContinue
        if ($r) { return $true }
    } catch {}

    return $false
}

# --------------------- 3. Log + Kill + Quarantine ---------------------
function Deny-Execution($file,$pid,$type) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$ts | BLOCKED $type | $file | PID $pid | SID $OwnerSID" | Out-File $Log -Append
    Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue

    if (Test-Path $file) {
        $dest = Join-Path $Quarantine ("$(Split-Path $file -Leaf)_$(Get-Random).blocked")
        Move-Item $file $dest -Force -ErrorAction SilentlyContinue
    }
}

# --------------------- 4. Memory scanner – automatically uses yara64.exe OR pure-PowerShell fallback ---------------------
function Start-MemoryScanner {
    $yaraExe  = "$Base\yara64.exe"
    $yaraRule = "$Base\mem.yar"

    # If real yara64.exe exists → use it (best detection)
    if (Test-Path $yaraExe) {
        if (-not (Test-Path $yaraRule)) {
            try {
                Invoke-WebRequest "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/memory.yar" -OutFile $yaraRule -UseBasicParsing -TimeoutSec 10
            } catch {}
        }
        Write-Host "[+] Full YARA memory scanner active (yara64.exe found)"
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

    # ===============================================
    # EMBEDDED PURE-POWERSHELL MEMORY SCANNER (no binary needed)
    # ===============================================
    Write-Host "[+] Embedded PowerShell memory scanner active (yara64.exe not found – still very deadly)"
    Start-Job -ScriptBlock {
        $log = "$using:Base\ps_memory_hits.log"
        # Most common malicious strings seen in memory 2024–2025
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

# --------------------- Start the memory scanner (auto-detects which version to use) ---------------------
Start-MemoryScanner

# --------------------- 5. Main WMI real-time execution hooks ---------------------
Write-Host "[+] Starting Gorstak's Antivirus – press Ctrl+C to stop (but it will restart itself)"

# Process creation
Register-WmiEvent -Query "SELECT * FROM Win32_ProcessStartTrace" -Action {
    $e   = $Event.SourceEventArgs.NewEvent
    $Path = $e.ProcessName
    $PID  = $e.ProcessId

    try {
        $OwnerSID = (Get-CimInstance Win32_Process -Filter "ProcessId=$PID" | Invoke-CimMethod -MethodName GetOwnerSid).Sid
    } catch { $OwnerSID = "Unknown" }

    if ($AllowedSIDs -contains $OwnerSID) {
        # Trusted logon → still do fast signature check (catches user-launched malware)
        if (Test-FastAllow $Path) { return }
    }

    Deny-Execution $Path $PID "EXE"
} | Out-Null

# DLL / module load
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
} | Out-Null

# Optional memory YARA scanner
# Download yara64.exe from https://github.com/VirusTotal/yara/releases and drop it in $Base
if (Test-Path "$Base\yara64.exe") { Start-MemoryYara }

# Keep alive forever
while ($true) { Start-Sleep -Seconds 3600 }