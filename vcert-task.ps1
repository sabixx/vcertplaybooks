# Running vcert as sheduled taks, downloads latest vcert
# downloads and runs a playbook 
# 
# Env variables required according to the playbook e.g. "TLSPC_APIKEY" 
# 

param (
    [Parameter(Mandatory=$true)][string]$playbook_url
) 

$tempPath = [System.IO.Path]::GetTempPath()
$logFilePathDownload = Join-Path -Path  "$tempPath" "vcert_download_log.txt"
$logFilePathRun = Join-Path -Path  "$tempPath" "vcert_run_log.txt"
$playBookPath = Join-Path -Path $tempPath -ChildPath $playbook_url.Split('/')[-1]
$playBook = $playbook_url.Split('/')[-1]

# Function to append log messages with timestamps
function Log-Message {
    param (
        [string]$Message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logFilePathDownload -Value "[$timestamp] $Message"
    Write-Host $Message
}

Log-Message "==== Start ===="

Log-Message "playbook_url  = $playbook_url"
Log-Message "playbook      = $playBook"
Log-Message "playbook path = $playBookPath"
Log-Message "tempPath      = $tempPath"
Log-Message "vcert log file= $logFilePathRun"

 # Check if the script is running with admin privileges
 if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Log-Message "This script requires administrator privileges. Please run it with administrator privileges."
    exit
}

# check is playbook_url was provided
if (-not $playbook_url) {
    Log-Message "no playbook_url provided, exiting."
    exit
} else {
    Log-Message "using playbook_url = $playbook_url"
}

# Set $TLSPC_Hostname as an environment variable for the current process only
if (-not [Environment]::GetEnvironmentVariable("TLSPC_Hostname_$playBook", "Machine")) {
    Log-Message "no TLSPC_hostname set, using ::GetHostName."
    [Environment]::SetEnvironmentVariable("TLSPC_Hostname_$playBook", [System.Net.Dns]::GetHostName(), "Machine")
} else {
    $Env:TLSPC_Hostname = [System.Environment]::GetEnvironmentVariable("TLSPC_Hostname_$playBook",'Machine')
    Log-Message "retrieved TLSPC_hostname = $Env:TLSPC_Hostname"
}

#####################################################################################################################
################################### This is for demo/testing purposes only ##########################################
################################### replace this with a secure option      ##########################################
#####################################################################################################################
 
if ([Environment]::GetEnvironmentVariable("TLSPC_APIKEY_$playBook", "Machine")) {
    $TLSPC_APIKEY_ENRYPTED = [Environment]::GetEnvironmentVariable("TLSPC_APIKEY_$playBook", "Machine")
    $TLSPC_APIKEY_SecureString = ConvertTo-SecureString -String $TLSPC_APIKEY_ENRYPTED   
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($TLSPC_APIKEY_SecureString)
    $Env:TLSPC_APIKEY = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    Log-Message "retrieved TLSPC_APIKEY."
}

#####################################################################################################################
################################### /END  demo/testing purposes only       ##########################################
#####################################################################################################################

 # check if API key is availbale in the current process
 if (-not [Environment]::GetEnvironmentVariable("TLSPC_APIKEY", "Process")) {
    Log-Message "no TLSPC_APIKEY set, exiting."
    exit
}

# Download the Playbook
Invoke-WebRequest -Uri $playbook_url -OutFile $playBookPath
Log-Message "Playbook downloaded to $playBookPath"

# GitHub API URL for the latest release of vcert
$apiUrl = "https://api.github.com/repos/Venafi/vcert/releases/latest"
Log-Message "Fetching the latest release from $apiUrl"

# Use Invoke-RestMethod to call the GitHub API
$latestRelease = Invoke-RestMethod -Uri $apiUrl
Log-Message "Latest release information retrieved."

# Attempt to find the Windows ZIP asset
$windowsZipAsset = $latestRelease.assets | Where-Object { $_.name -match "windows.*\.zip$" } | Select-Object -First 1

if ($null -eq $windowsZipAsset) {
    Log-Message "Windows ZIP file not found in the latest release."
    exit
}

# Extract the download URL
$windowsZipUrl = $windowsZipAsset.browser_download_url
Log-Message "vcert ZIP download URL: $windowsZipUrl"

# Define the path for the downloaded ZIP file
$zipFilePath = Join-Path -Path $tempPath -ChildPath "vcert_latest_windows.zip"

# Download the ZIP file
Invoke-WebRequest -Uri $windowsZipUrl -OutFile $zipFilePath
Log-Message "ZIP file downloaded to $zipFilePath"

# Extract the ZIP file directly to the temp directory, without subfolders
# Using -Force to overwrite existing files
Expand-Archive -LiteralPath $zipFilePath -DestinationPath $tempPath -Force
Log-Message "vcert extracted to $tempPath"

$vcertExePath = Join-Path -Path $tempPath -ChildPath "vcert.exe"

Log-Message "==== Vcert ===="

#write the version to the log file
$command = '& ' + "$vcertExePath" + ' -version'  + ' 2>&1 | %{ "$_" } | Tee-Object -FilePath ' + "$logFilePathRun" + ' -Append'

Invoke-Expression $command

#Run vcert with playbook
$command = '& ' + "$vcertExePath" + ' run -f ' + "$playBookPath" + ' 2>&1 | %{ "$_" } | Tee-Object -FilePath ' + "$logFilePathRun" + ' -Append'   

# Step 3: Execute the command
Invoke-Expression $command