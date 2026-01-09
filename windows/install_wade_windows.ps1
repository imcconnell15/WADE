[CmdletBinding()]
param()

############################################################
# Helpers: prompts, logging, admin check
############################################################

function Prompt-Default {
    param(
        [string]$Question,
        [string]$Default = ""
    )

    if ($Default) {
        $prompt = "$Question [$Default]"
    } else {
        $prompt = $Question
    }

    $ans = Read-Host -Prompt $prompt
    if ([string]::IsNullOrWhiteSpace($ans)) {
        return $Default
    }
    return $ans
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

$script:LogFile = $null
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR")]
        [string]$Level = "INFO"
    )

    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "[{0}] [{1}] {2}" -f $ts, $Level, $Message

    Write-Host $line
    if ($script:LogFile) {
        Add-Content -Path $script:LogFile -Value $line
    }
}

############################################################
# Pre-flight
############################################################

if (-not (Test-IsAdmin)) {
    Write-Error "Please run this script from an elevated PowerShell session (Run as administrator)."
    exit 1
}

$installRoot = "C:\WADE"
if (-not (Test-Path $installRoot)) {
    New-Item -Path $installRoot -ItemType Directory -Force | Out-Null
}

$logDir = Join-Path $installRoot "logs"
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}
$script:LogFile = Join-Path $logDir ("install_wade_windows_{0}.log" -f (Get-Date).ToString("yyyyMMdd_HHmmss"))

Write-Log "===== WADE Windows installer starting ====="

############################################################
# Prompts (all up front)
############################################################

$defaultWadeServer = "10.83.20.117"

$WadeServer    = Prompt-Default "WADE server hostname or IP" $defaultWadeServer
$DataShareName = Prompt-Default "DataSources share name" "DataSources"
$CaseShareName = Prompt-Default "Cases share name" "Cases"

# Optional config and offline kit roots
$ConfigSharePath = Prompt-Default "Config share UNC path (e.g. \\$WadeServer\Config, empty to skip)" ""
$OfflineKitsRoot = Prompt-Default "Offline kits UNC root (e.g. \\$WadeServer\Cases\WADE_kits_windows, empty if none)" ""

Write-Log "WADE server      : $WadeServer"
Write-Log "DataSources share: $DataShareName"
Write-Log "Cases share      : $CaseShareName"
if ($ConfigSharePath) { Write-Log "Config share     : $ConfigSharePath" }
if ($OfflineKitsRoot) { Write-Log "Offline kits root: $OfflineKitsRoot" }

$DataRoot = "\\$WadeServer\$DataShareName"
$CaseRoot = "\\$WadeServer\$CaseShareName"

# Quick sanity check on DataSources\Hosts
$hostsPath = Join-Path $DataRoot "Hosts"
if (-not (Test-Path $hostsPath)) {
    Write-Log "WARNING: Could not reach $hostsPath. Check Samba share names / WADE server IP." "WARN"
} else {
    Write-Log "Confirmed access to $hostsPath"
}

############################################################
# Path configuration
############################################################

$WadeWinConfig = [PSCustomObject]@{
    InstallRoot   = $installRoot
    LogsDir       = $logDir
    ScriptsDir    = (Join-Path $installRoot "scripts")
    DataRoot      = $DataRoot
    CaseRoot      = $CaseRoot
    ConfigShare   = $ConfigSharePath
    OfflineKits   = $OfflineKitsRoot

    KapeDir       = "C:\Tools\KAPE"
    EZToolsDir    = "C:\Tools\EZTools"
    AimCliPath    = "C:\Program Files\Arsenal Image Mounter\Command line applications\aim_cli.exe"
    AutopsyDir    = "C:\Program Files\Autopsy"
    EnvFile       = (Join-Path $installRoot "wade-win.env")
}

foreach ($dir in @($WadeWinConfig.ScriptsDir, $WadeWinConfig.KapeDir, $WadeWinConfig.EZToolsDir)) {
    if (-not (Test-Path $dir)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }
}

############################################################
# Tool install helpers
############################################################

function Install-Kape {
    param(
        [Parameter(Mandatory = $true)]
        [string]$KapeDir,
        [string]$OfflineRoot
    )

    $kapeExe = Join-Path $KapeDir "kape.exe"
    if (Test-Path $kapeExe) {
        Write-Log "KAPE already present at $kapeExe, skipping."
        return
    }

    if ($OfflineRoot) {
        $offlineZip = Join-Path $OfflineRoot "KAPE.zip"
        if (Test-Path $offlineZip) {
            Write-Log "Found offline KAPE kit at $offlineZip. Extracting to $KapeDir"
            try {
                Expand-Archive -Path $offlineZip -DestinationPath $KapeDir -Force
                if (Test-Path $kapeExe) {
                    Write-Log "KAPE extracted successfully to $KapeDir"
                    return
                } else {
                    Write-Log "KAPE.exe not found after extraction; check zip layout." "WARN"
                }
            } catch {
                Write-Log "Failed to extract KAPE from offline kit: $($_.Exception.Message)" "ERROR"
            }
        } else {
            Write-Log "No KAPE.zip found under offline kits root $OfflineRoot" "WARN"
        }
    }

    Write-Log "KAPE is not installed and no usable offline kit found." "WARN"
    Write-Log "Please download KAPE from the official Kroll/SANS site and place a KAPE.zip in:"
    Write-Host "  $OfflineRoot"
    Write-Log "Or manually extract it into: $KapeDir"
}

function Install-EZTools {
    param(
        [Parameter(Mandatory = $true)]
        [string]$EZToolsDir,
        [string]$OfflineRoot
    )

    if (Test-Path $EZToolsDir -and (Get-ChildItem $EZToolsDir -Filter '*.exe' -ErrorAction SilentlyContinue)) {
        Write-Log "EZ Tools already present in $EZToolsDir, skipping."
        return
    }

    # Offline kit option: EZTools.zip under offline root
    if ($OfflineRoot) {
        $offlineZip = Join-Path $OfflineRoot "EZTools.zip"
        if (Test-Path $offlineZip) {
            Write-Log "Found offline EZ Tools kit at $offlineZip. Extracting to $EZToolsDir"
            try {
                Expand-Archive -Path $offlineZip -DestinationPath $EZToolsDir -Force
                Write-Log "EZ Tools extracted successfully to $EZToolsDir"
                return
            } catch {
                Write-Log "Failed to extract EZ Tools from offline kit: $($_.Exception.Message)" "ERROR"
            }
        } else {
            Write-Log "No EZTools.zip found under offline kits root $OfflineRoot" "WARN"
        }
    }

    # Online option: Get-ZimmermanTools
    Write-Log "Attempting to download EZ Tools using Get-ZimmermanTools.ps1"

    $gztUrl  = "https://github.com/EricZimmerman/Get-ZimmermanTools/raw/master/Get-ZimmermanTools.ps1"
    $gztPath = Join-Path $env:TEMP "Get-ZimmermanTools.ps1"

    try {
        Write-Log "Downloading Get-ZimmermanTools.ps1 from $gztUrl"
        Invoke-WebRequest -Uri $gztUrl -OutFile $gztPath -UseBasicParsing
        Write-Log "Running Get-ZimmermanTools.ps1 to populate $EZToolsDir"
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $gztPath -Dest $EZToolsDir
        Write-Log "EZ Tools installation finished (check $EZToolsDir)."
    } catch {
        Write-Log "Failed to download or run Get-ZimmermanTools: $($_.Exception.Message)" "ERROR"
        Write-Log "You can manually fetch EZ Tools using Get-ZimmermanTools as described on Eric Zimmerman's site."
    }
}

function Install-AIM {
    param(
        [string]$OfflineRoot
    )

    $aimCli = $WadeWinConfig.AimCliPath
    if (Test-Path $aimCli) {
        Write-Log "Arsenal Image Mounter CLI already present at $aimCli, skipping."
        return
    }

    if ($OfflineRoot) {
        $aimMsi = Get-ChildItem -Path $OfflineRoot -Filter "ArsenalImageMounter*.msi" -ErrorAction SilentlyContinue |
                  Select-Object -First 1

        if ($aimMsi) {
            Write-Log "Found Arsenal Image Mounter MSI at $($aimMsi.FullName). Installing silently."
            try {
                $args = "/i `"$($aimMsi.FullName)`" /qn /norestart"
                Start-Process -FilePath "msiexec.exe" -ArgumentList $args -Wait
                if (Test-Path $aimCli) {
                    Write-Log "Arsenal Image Mounter installed successfully."
                    return
                } else {
                    Write-Log "AIM CLI still not found after MSI install; verify install path." "WARN"
                }
            } catch {
                Write-Log "Failed to install Arsenal Image Mounter: $($_.Exception.Message)" "ERROR"
            }
        } else {
            Write-Log "No ArsenalImageMounter*.msi found under offline kits root $OfflineRoot" "WARN"
        }
    }

    Write-Log "Arsenal Image Mounter is not installed and no offline MSI found." "WARN"
    Write-Log "Please download the installer from the official Arsenal Recon site and place it under:"
    Write-Host "  $OfflineRoot"
    Write-Log "Then re-run this installer."
}

function Install-Autopsy {
    param(
        [string]$OfflineRoot
    )

    if (Test-Path $WadeWinConfig.AutopsyDir) {
        Write-Log "Autopsy appears to be installed at $($WadeWinConfig.AutopsyDir), skipping."
        return
    }

    if ($OfflineRoot) {
        $autopsyMsi = Get-ChildItem -Path $OfflineRoot -Filter "autopsy-*-64bit.msi" -ErrorAction SilentlyContinue |
                      Select-Object -First 1
        if ($autopsyMsi) {
            Write-Log "Found Autopsy MSI at $($autopsyMsi.FullName). Installing silently."
            try {
                $args = "/i `"$($autopsyMsi.FullName)`" /qn /norestart"
                Start-Process -FilePath "msiexec.exe" -ArgumentList $args -Wait
                if (Test-Path $WadeWinConfig.AutopsyDir) {
                    Write-Log "Autopsy installed successfully."
                    return
                } else {
                    Write-Log "Autopsy path not found after MSI install; verify install location." "WARN"
                }
            } catch {
                Write-Log "Failed to install Autopsy: $($_.Exception.Message)" "ERROR"
            }
        } else {
            Write-Log "No autopsy-*-64bit.msi found under offline kits root $OfflineRoot" "WARN"
        }
    }

    Write-Log "Autopsy is not installed and no offline MSI found." "WARN"
    Write-Log "Please download Autopsy for Windows from the official site and place the 64-bit MSI under:"
    Write-Host "  $OfflineRoot"
    Write-Log "Then re-run this installer."
}

############################################################
# (Optional) Pull Linux wade.env from config share
############################################################

if ($WadeWinConfig.ConfigShare) {
    $remoteEnv = Join-Path $WadeWinConfig.ConfigShare "wade.env"
    if (Test-Path $remoteEnv) {
        $localEnv = Join-Path $WadeWinConfig.InstallRoot "wade.env"
        Write-Log "Copying shared wade.env from $remoteEnv to $localEnv"
        try {
            Copy-Item -Path $remoteEnv -Destination $localEnv -Force
        } catch {
            Write-Log "Failed to copy wade.env: $($_.Exception.Message)" "WARN"
        }
    } else {
        Write-Log "Config share specified but wade.env not found at $remoteEnv" "WARN"
    }
}

############################################################
# Install tools
############################################################

Install-Kape    -KapeDir    $WadeWinConfig.KapeDir   -OfflineRoot $WadeWinConfig.OfflineKits
Install-EZTools -EZToolsDir $WadeWinConfig.EZToolsDir -OfflineRoot $WadeWinConfig.OfflineKits
Install-AIM     -OfflineRoot $WadeWinConfig.OfflineKits
Install-Autopsy -OfflineRoot $WadeWinConfig.OfflineKits

############################################################
# Write local env file for WADE Windows
############################################################

$envLines = @(
    "WADE_SERVER=$WadeServer"
    "WADE_DATASOURCES=$($WadeWinConfig.DataRoot)"
    "WADE_CASES=$($WadeWinConfig.CaseRoot)"
    "WADE_CONFIG=$($WadeWinConfig.ConfigShare)"
    "KAPE_DIR=$($WadeWinConfig.KapeDir)"
    "EZTOOLS_DIR=$($WadeWinConfig.EZToolsDir)"
    "AIM_CLI_PATH=$($WadeWinConfig.AimCliPath)"
    "AUTOPSY_DIR=$($WadeWinConfig.AutopsyDir)"
)

Write-Log "Writing WADE Windows env file to $($WadeWinConfig.EnvFile)"
$envLines | Set-Content -Path $WadeWinConfig.EnvFile -Encoding ASCII

Write-Log "===== WADE Windows installer finished ====="
Write-Host ""
Write-Host "Summary:"
Write-Host "  WADE Windows root : $($WadeWinConfig.InstallRoot)"
Write-Host "  Env file          : $($WadeWinConfig.EnvFile)"
Write-Host "  KAPE dir          : $($WadeWinConfig.KapeDir)"
Write-Host "  EZ Tools dir      : $($WadeWinConfig.EZToolsDir)"
Write-Host "  AIM CLI path      : $($WadeWinConfig.AimCliPath)"
Write-Host "  Autopsy dir       : $($WadeWinConfig.AutopsyDir)"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  - Make sure KAPE, EZ Tools, AIM, and Autopsy installed correctly."
Write-Host "  - Stage offline installers under: $OfflineKitsRoot (KAPE.zip, EZTools.zip, ArsenalImageMounter*.msi, autopsy-*-64bit.msi)."
Write-Host "  - We'll then drop in the WADE Windows pipeline worker that uses these paths."
