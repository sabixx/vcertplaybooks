# Running vcert as sheduled taks, downloads latest vcert
# downloads and runs a playbook 
# 
# Env variables required according to the playbook e.g. "TLSPC_APIKEY" 
# 

param (
    [Parameter(Mandatory=$true)][string]$playbook_url
) 

$playBook = $playbook_url.Split('/')[-1]
$tempPath = [System.IO.Path]::GetTempPath()
$logFilePathDownload = Join-Path -Path  "$tempPath" "vcert_download_log.txt"
$logFilePathRun = Join-Path -Path  "$tempPath" "vcert_run_log.txt"
$playBookPath = Join-Path -Path $tempPath -ChildPath $playBook

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
Log-Message "task log file = $logFilePathDownload"
Log-Message "vcert log file= $logFilePathRun"

 # Check if the script is running with admin privileges
 if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Log-Message "Not running as Administrator. Some use cases require administrator privileges."
    #exit #do not exit out, some use cases may not require admin permissions.
 }

# check is playbook_url was provided
if (-not $playbook_url) {
    Log-Message "no playbook_url provided, exiting."
    exit
} else {
    Log-Message "using playbook_url = $playbook_url"
}

# Download the Playbook
Invoke-WebRequest -Uri $playbook_url -OutFile $playBookPath
Log-Message "Playbook downloaded to $playBookPath"

# Determine the platform (vaas or tpp)
try {
    $platform = switch -regex -file "$playBookPath" {'platform:'{"$_"} }
    $platform = $platform -replace 'platform:',''
    $platform = ($platform.Split("#"))[0].Trim()
    $platform = $platform -replace '[^a-zA-Z0-9]', '' 
    Log-Message "Platform = $platform"  
}  
catch {
    Log-Message "could not determine platform."
}

# Set $TLSPC_Hostname as an environment variable for the current process only
if (-not [Environment]::GetEnvironmentVariable("TLSPC_Hostname_$playBook", "Machine")) {
Log-Message "no TLSPC_hostname_$playBook set, using ::GetHostName."
[Environment]::SetEnvironmentVariable("TLSPC_Hostname", [System.Net.Dns]::GetHostName(), "Process")
} else {
$Env:TLSPC_Hostname = [System.Environment]::GetEnvironmentVariable("TLSPC_Hostname_$playBook",'Machine')
Log-Message "retrieved TLSPC_hostname = $Env:TLSPC_Hostname"
}

switch ($platform) {
#####################################################################################################################
################################ # TLSDC with windows Integrated Auth ###############################################
#####################################################################################################################
    'tpp' {
        try {
            $TPPurl = switch -regex (Get-Content "$playBookPath") {'url:'{"$_"} }
            $TPPurl = $TPPurl -replace 'url:', ''
            $TPPurl = ($TPPurl.Split("#"))[0].Trim()
            Log-Message "TPPurl = $TPPurl"  

            $client_id = switch -regex (Get-Content "$playBookPath") {'clientId:'{"$_"} }
            if ($client_id -eq $null -or $client_id -eq "") {
                $client_id = "vcert-cli"
            } else {
                $client_id = $client_id -replace 'clientId:', ''
                $client_id = ($client_id.Split("#"))[0].Trim()
            }
            Log-Message "client_id = $client_id" 

            $response = Invoke-RestMethod "$TPPUrl/vedauth/authorize/integrated" -UseDefaultCredentials -Method POST -Body (@{"client_id"="$client_id"; "scope"="certificate:manage"} | ConvertTo-Json) -ContentType "application/json"
            $env:TPP_ACCESS_TOKEN = $response.access_token
            $env:TPP_REFRESH_TOKEN = $response.refresh_token

            Log-Message "retrieved oAuth bearer token."  
        }
        catch {
            Log-Message "An error occurred retrieving oAuth bearer token: $($_.Exception.Message)"
            Log-Message $response
        }

        if (-not $Env:TPP_ACCESS_TOKEN) {
            Log-Message "no TPP_ACCESS_TOKEN set, exiting."
            exit
        }
    }

#####################################################################################################################
################################ Replace with function determine API Key at runtime #################################
#####################################################################################################################

    'vaas' {
        if ([Environment]::GetEnvironmentVariable("TLSPC_APIKEY_$playBook", "Machine")) {
            try {
                Add-Type -AssemblyName System.Security
                $encryptedBase64 = ([Environment]::GetEnvironmentVariable("TLSPC_APIKEY_$playBook", "Machine"))
                $SecureStr = [System.Convert]::FromBase64String($encryptedBase64) 
                $bytes = [Security.Cryptography.ProtectedData]::Unprotect($SecureStr, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
                $Env:TLSPC_APIKEY = [System.Text.Encoding]::Unicode.GetString($bytes) 
                Log-Message "retrieved TLSPC_APIKEY."  
            }
            catch {
                Log-Message "An error occurred retrieving TLSPC_APIKEY: $($_.Exception.Message)"
            }
        }

        if (-not $Env:TLSPC_APIKEY) {
            Log-Message "no TLSPC_APIKEY set, exiting."
            exit
        }
    }

    default {
        Log-Message "Unsupported platform: $platform"
        exit
    }
}

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

Log-Message $command

Invoke-Expression $command

#Run vcert with playbook
$command = '& ' + "$vcertExePath" + ' run -f ' + "$playBookPath" + ' 2>&1 | %{ "$_" } | Tee-Object -FilePath ' + "$logFilePathRun" + ' -Append'   

Log-Message $command

# Step 3: Execute the command
Invoke-Expression $command