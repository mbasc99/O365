<#
.SYNOPSIS
Teams-Posh installs or uninstalls Microsoft Teams.

.DESCRIPTION
This script allows for the installation or uninstallation of Microsoft Teams. 
When installing, it downloads the bootstrapper and Teams package if not provided, 
and then installs Microsoft Teams.
When uninstalling, it removes the installed Microsoft Teams application, 
this includes Teams Classic uninstallation querying related registry keys thus 
avoiding use of very slow call to "Get-WmiObject -Class Win32_Product".

.PARAMETER Action
Specifies the action to perform. Valid values are 'Install' or 'Uninstall'.

.PARAMETER BootstrapperPath
Specifies the path to the bootstrapper executable. 
If not provided, it will be downloaded by Microsoft website.

.PARAMETER TeamsPackagePath
Specifies the path to the Microsoft Teams package. 
If not provided (required for installation), it will be downloaded.

.EXAMPLE
.\Teams-Posh.ps1 -Action Install
Installs Microsoft Teams.

.EXAMPLE
.\Teams-Posh.ps1 -Action Uninstall
Uninstalls Microsoft Teams.

.NOTES
Author:[lestoilfante](https://github.com/lestoilfante)
#>



    
    
    [string]$Action = 'Install'
    [string]$BootstrapperPath = ''
    [string]$TeamsPackagePath = ''




function Teams-Posh {
    # Check running with elevated privileges
    if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Log "This script requires elevation. Please run as administrator"
        exit 1
    }

    if ($BootstrapperPath -eq '') {
        $BootstrapperPath = DownloadFile "https://go.microsoft.com/fwlink/?linkid=2243204&clcid=0x409" "bootstrapper.exe"
        if ($BootstrapperPath -eq $null) { exit 1 }
    }

    if ($Action -eq 'Install') {
        $install = InstallTeams -BootstrapperPath $BootstrapperPath -TeamsPackagePath $TeamsPackagePath
        if ($install -eq $true) { 
        RemoveTeamsClassicWide
        RemoveTeamsClassic
        exit 0 }
        exit 1
    }

    if ($Action -eq 'Uninstall') {
        RemoveTeamsClassicWide
        RemoveTeamsClassic
        RemoveTeams $BootstrapperPath
        exit 0
    }
}


function InstallTeams {
    param(
        [Parameter(Mandatory=$true)]
        [string]$bootstrapperPath,
        [string]$teamsPackagePath = ''
    )
    try {
        # Using the teamsbootstrapper.exe -p command always guarantees the latest Teams client is installed.
        # Use -o with path to Teams's MSIX package minimizing the amount of bandwidth used for the initial installation.
        # The MSIX can exist in a local path or UNC.
        if ($teamsPackagePath -ne '') {
            $arg = "-o $teamsPackagePath"
        } else { Log 'Downloading Teams' }
        $r = & $bootstrapperPath -p $arg
        $resultObj = try { $r | ConvertFrom-Json } catch { $null }
        if ($resultObj -eq $null -or $resultObj.success -eq $false) {
            throw ''
        }
        Log 'Teams installation done'
        return $true
    }
    catch {
        Log 'ERROR: Teams installation failed'
        return $false
    }
}

function RemoveTeamsClassicWide {
    # Known Guid
    $msiPkg32Guid = "{39AF0813-FA7B-4860-ADBE-93B9B214B914}"
    $msiPkg64Guid = "{731F6BAA-A986-45A4-8936-7C3AAAAA760B}"
    $uninstallReg64 = Get-Item -Path HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue | Get-ItemProperty | Where-Object { $_.DisplayName -match 'Teams Machine-Wide Installer' }
    $uninstallReg32 = Get-Item -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue | Get-ItemProperty | Where-Object { $_.DisplayName -match 'Teams Machine-Wide Installer' }
    if ($uninstallReg64) {
        $msiExecUninstallArgs = "/X $msiPkg64Guid /quiet"
        Log "Teams Classic Machine-Wide Installer x64 found."
    } elseif ($uninstallReg32) {
        $msiExecUninstallArgs = "/X $msiPkg32Guid /quiet"
        Log "Teams Machine-Wide Installer x86 found."
    } else {
        return
    }
    $p = Start-Process "msiexec.exe" -ArgumentList $msiExecUninstallArgs -Wait -PassThru -WindowStyle Hidden
    if ($p.ExitCode -eq 0) {
        Log "Teams Classic Machine-Wide uninstalled."
    } else {
        Log "ERROR: Teams Classic Machine-Wide uninstall failed with exit code $($p.ExitCode)"
    }
}

function RemoveTeamsClassic {
    # Specify the registry path
    $reg = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Teams"
    # Get Teams uninstall information for each user
    $userSids = Get-WmiObject Win32_UserProfile | Where-Object { $_.Special -eq $false } | Select-Object -ExpandProperty SID
    foreach ($userSid in $userSids) {
        $userReg= "Registry::HKEY_USERS\$userSid\$reg"
        $teamsUninstallInfo = Get-ItemProperty -LiteralPath $userReg -ErrorAction SilentlyContinue
        # Display the Teams uninstall information for each user
        if ($teamsUninstallInfo) {
            $sid = New-Object System.Security.Principal.SecurityIdentifier($userSid)
            # Use Translate to find user from sid
            $objUser = $sid.Translate([System.Security.Principal.NTAccount])
            if ($teamsUninstallInfo.QuietUninstallString) {
                Start-Process -FilePath "cmd" -ArgumentList "/c", $teamsUninstallInfo.QuietUninstallString -Wait
                Log "Teams Classic Removed for user $($objUser.Value)"
            }
            # Cleanup registry
            if (Test-Path -path $userReg) {
                Remove-Item $userReg -Recurse -Force
            }
        }
    }
}

function RemoveTeams {
    param(
        [string]$bootstrapper = ''
    )
    try{
        $appx = Get-AppxPackage -AllUsers | Where-Object { $PSItem.Name -eq "MSTeams" }
        if ($appx) {
            Log "Teams $($appx.Version) package found"
            $appx | Remove-AppxPackage -AllUsers
        } else { Log "No Teams package found" }
        if($bootstrapper -ne '') {
            Log "Deprovisioning Teams using $bootstrapper"
            $r = & $bootstrapper -x
            $resultObj = try { $r | ConvertFrom-Json } catch { $null }
            if ($resultObj -eq $null) {
                throw ''
            }
            Log "Deprovisioning Teams using $bootstrapper done"
        }
    }
    catch {
        Log "ERROR: Teams package remove error"
    }
}

function DownloadFile {
    param(
        [Parameter(Mandatory=$true)]
        [string]$url,
        [Parameter(Mandatory=$true)]
        [string]$fileName,
        [string]$path = [System.Environment]::GetEnvironmentVariable('TEMP','Machine')
    )
    # Construct WebClient object
    $webClient = New-Object -TypeName System.Net.WebClient
    $file = $null
    # Create path if it doesn't exist
    if (-not(Test-Path -Path $path)) {
        New-Item -Path $path -ItemType Directory -Force | Out-Null
    }
    # Download
    try {
        Log "Download of $fileName start"
        $outputPath = Join-Path -Path $path -ChildPath $fileName
        $webClient.DownloadFile($url, $outputPath)
        Log "Download of $fileName done"
        $file = $outputPath
    }
    catch {
        Log "ERROR: Download of $fileName failed"
    }
    # Dispose of the WebClient object
    $webClient.Dispose()
    return $file
}

function Log {
    param (
        [string]$Text,
        [string]$LogFile = "C:\Pkglocalcache\LogFile.log"
    )
    $timestamp = "{0:yyyy-MM-dd HH:mm:ss}" -f [DateTime]::Now
    $logMessage = "$timestamp - $($Text)"
    
    # Write the log message to the log file
    Add-Content -Path $LogFile -Value $logMessage
}




Teams-Posh