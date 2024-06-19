# This demo shows some options how vcert can be run. 
# The script performs several taks such downloading the 
# latest version of vcert and playbook. It's performing
# authentication based on the platform of the playbook.
#
# Depening on the use case it's requiered to add, remove
# parts of this script. It's intended as a starting point
# making it easier to deploy vcert for the coresponding
# use case.
#
# For each of the part there's is a - RECOMMENDATION IF
# CERTAIN PARTS SHOULD BE USED OR IF THEY ARE OPTIONAL
# 
# (C) 2024 Jens Sabitzer jens.sabitzer@venafi.com
#

param (
    [Parameter(Mandatory=$true)][string]$playbook_url
) 

# Function to append log messages with timestamps - RECOMMENDED
function Log-Message {
    param (
        [string]$Message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logFilePathDownload -Value "[$timestamp] $Message"
    Write-Host $Message
}

$playBook = $playbook_url.Split('/')[-1] 
$tempPath = [System.IO.Path]::GettempPath()
$logFilePathDownload = Join-Path -Path  "$tempPath" "vcert_download_log.txt"
$logFilePathRun = Join-Path -Path  "$tempPath" "vcert_run_log.txt"
$playBookPath = Join-Path -Path $tempPath -ChildPath $playBook

Log-Message "==== Start ===="

Log-Message "playbook_url  = $playbook_url"
Log-Message "playbook      = $playBook"
Log-Message "playbook path = $playBookPath"
Log-Message "tempPath      = $tempPath"
Log-Message "task log file = $logFilePathDownload"
Log-Message "vcert log file= $logFilePathRun"

 # Check if the script is running with admin privileges - OPTINAL DEPENDS ON USE CASE
 if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Log-Message "Not running as Administrator. Some use cases require administrator privileges."
    #exit #do not exit out, some use cases may not require admin permissions.
 }

# check is playbook_url was provided - RECOMMENDED
if (-not $playbook_url) {
    Log-Message "no playbook_url provided, exiting."
    exit
}

# Download the Playbook - RECOMMENDED
Invoke-WebRequest -Uri $playbook_url -OutFile $playBookPath
Log-Message "Playbook downloaded to $playBookPath"

# Determine the platform (vaas or tpp) - CHANGE, BEST TO MAKE IT FIT FOR PURPOOSE
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

# Set $TLSPC_Hostname as an environment variable for the current process only - OPTIONAL
if (-not [Environment]::GetEnvironmentVariable("TLSPC_Hostname_$playBook", "Machine")) {
Log-Message "no TLSPC_hostname_$playBook set, using ::GetHostName."
[Environment]::SetEnvironmentVariable("TLSPC_Hostname", [System.Net.Dns]::GetHostName(), "Process")
} else {
$Env:TLSPC_Hostname = [System.Environment]::GetEnvironmentVariable("TLSPC_Hostname_$playBook",'Machine')
Log-Message "retrieved TLSPC_hostname = $Env:TLSPC_Hostname"
}
    

# Perform authentication based on Platorm - CHANGE, BEST TO MAKE IT FIT FOR PURPOOSE
switch ($platform) {
#####################################################################################################################
################################ # TLSDC with windows Integrated Auth ###############################################
#####################################################################################################################
    'tpp', 'tlsdc' {
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

            $response_grant = Invoke-RestMethod "$TPPUrl/vedauth/authorize/integrated" -UseDefaultCredentials -Method POST -Body (@{"client_id"="$client_id"; "scope"="certificate:manage"} | ConvertTo-Json) -ContentType "application/json" -UseBasicParsing
            $env:TPP_ACCESS_TOKEN = $response_grant.access_token
            $env:TPP_REFRESH_TOKEN = $response_grant.refresh_token

            Log-Message "retrieved oAuth bearer token."  
        }
        catch {
            Log-Message "An error occurred retrieving oAuth bearer token: $($_.Exception.Message)"
            Log-Message $response_grant
        }

        if (-not $Env:TPP_ACCESS_TOKEN) {
            Log-Message "no TPP_ACCESS_TOKEN set, exiting."
            exit
        }
    }

#####################################################################################################################
################################## TLS PC with ServiceAccount JWT authentication  ###################################
#####################################################################################################################

    'vaas', 'tlspc' {  
        
        # Set $TLSPC_CLIENTID as an environment variable for the current process only - OPTIONAL
        if ( [Environment]::GetEnvironmentVariable("TLSPC_CLIENTID_$playBook", "Machine")) {
            $TLSPC_CLIENTID = [System.Environment]::GetEnvironmentVariable("TLSPC_CLIENTID_$playBook",'Machine')
            Log-Message "retrieved TLSPC_CLIENTID = $TLSPC_CLIENTID"
        } else { Log-Message "No TLSPC_CLIENTID" }

        # Set $TLSPC_tokenURL as an environment variable for the current process only - OPTIONAL
        if ( [Environment]::GetEnvironmentVariable("TLSPC_TOKENURL_$playBook", "Machine")) {
            $TLSPC_tokenURL = [System.Environment]::GetEnvironmentVariable("TLSPC_TOKENURL_$playBook",'Machine')
            Log-Message "retrieved TLSPC_TOKENURL_ = $TLSPC_tokenURL"
        } else { Log-Message "No TLSPC_TOKENURL" }

        # Set $TLSPC_OAuthIdpURL as an environment variable for the current process only - OPTIONAL
        if ( [Environment]::GetEnvironmentVariable("TLSPC_OAUTHIDPURL_$playBook", "Machine")) {
            $TLSPC_OAuthIdpURL = [System.Environment]::GetEnvironmentVariable("TLSPC_OAUTHIDPURL_$playBook",'Machine')
            Log-Message "retrieved TLSPC_OAUTHIDPURL_ = $TLSPC_OAuthIdpURL"
        } else { Log-Message "No TLSPC_OAuthIdpURL" }

        if (-not [string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable("TLSPC_CLIENTSECRET", "User")) -and -not [string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable("TLSPC_CLIENTSECRET", "Process"))) {
        if ([Environment]::GetEnvironmentVariable("TLSPC_CLIENTSECRET_$playBook", "Machine")) {
                try {
                    Add-Type -AssemblyName System.Security
                    $encryptedBase64 = ([Environment]::GetEnvironmentVariable("TLSPC_CLIENTSECRET_$playBook", "Machine"))
                    $SecureStr = [System.Convert]::FromBase64String($encryptedBase64) 
                    $bytes = [Security.Cryptography.ProtectedData]::Unprotect($SecureStr, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
                    $TLSPC_ClientSecret = [System.Text.Encoding]::Unicode.GetString($bytes) 
                    Log-Message "retrieved TLSPC_CLIENTSECRET."  
                }
                catch {
                    Log-Message "An error occurred retrieving TLSPC_CLIENTSECRET: $($_.Exception.Message)"
                }
            }
        }

        if (-not $TLSPC_ClientSecret) {
            Log-Message "no TLSPC_CLIENTSECRET set, exiting."
            exit
        }

        # Create the JSON payload
        $jsonPayload = @{
            client_id     = $TLSPC_CLIENTID
            client_secret = $TLSPC_ClientSecret
            audience      = $audience
            grant_type    = $grant_type
        } | ConvertTo-Json

        $response = Invoke-RestMethod -Method Post -Uri $TLSPC_OAuthIdpURL -ContentType "application/json" -Body $jsonPayload

        $access_token = $response.access_token

        $env:TLSPC_ExternalJWT = $response.access_token

        $output = @{
            external_jwt = $access_token
        } | ConvertTo-Json

        Log-Message $output


        #### it's not recommneded using API Keys... use IDP oAuth instead
        ### this only exists for older clients.. 
        if ([Environment]::GetEnvironmentVariable("TLSPC_APIKEY", "User")) { Log-Message "APIKEY found in user world" }
        if ([Environment]::GetEnvironmentVariable("TLSPC_APIKEY", "Proces")){ Log-Message "APIKEY found in process world" }
        if (-not [string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable("TLSPC_APIKEY", "User")) -and -not [string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable("TLSPC_APIKEY", "Process"))) {
        if ([Environment]::GetEnvironmentVariable("TLSPC_APIKEY_$playBook", "Machine")) {
                try {
                    Add-Type -AssemblyName System.Security
                    $encryptedBase64 = ([Environment]::GetEnvironmentVariable("TLSPC_APIKEY_$playBook", "Machine"))
                    $SecureStr = [System.Convert]::FromBase64String($encryptedBase64) 
                    $bytes = [Security.Cryptography.ProtectedData]::Unprotect($SecureStr, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
                    $Env:TLSPC_APIKEY = [System.Text.Encoding]::Unicode.GetString($bytes) 
                    Log-Message "retrieved TLSPC_APIKEY, IT's NOT RECOMMENDED TO USE API KEYS, USE SERVICE ACCOUNTS INSTEAD"  
                }
                catch {
                    Log-Message "An error occurred retrieving TLSPC_APIKEY: $($_.Exception.Message)"
                }
            }
        }

        if (-not $Env:TLSPC_APIKEY) {
            Log-Message "no TLSPC_APIKEY set, recommended"
        }

    default {
        Log-Message "Unsupported platform: $platform"
        exit
    }
}

# Downloads the latest release of vcert - OPTIONAL, YOU MIGHT HOST VCERT ELSEWHERE
$apiUrl = "https://api.github.com/repos/Venafi/vcert/releases/latest"
Log-Message "Fetching the latest release from $apiUrl"

# Use Invoke-RestMethod to call the GitHub API - OPTIONAL, YOU MIGHT HOST VCERT ELSEWHERE
$latestRelease = Invoke-RestMethod -Uri $apiUrl
Log-Message "Latest release information retrieved."

# Attempt to find the Windows ZIP asset - OPTIONAL, YOU MIGHT HOST VCERT ELSEWHERE
$windowsZipAsset = $latestRelease.assets | Where-Object { $_.name -match "windows.*\.zip$" } | Select-Object -First 1
if ($null -eq $windowsZipAsset) {
    Log-Message "Windows ZIP file not found in the latest release."
    exit
}

# Extract the download URL - OPTIONAL, YOU MIGHT HOST VCERT ELSEWHERE
$windowsZipUrl = $windowsZipAsset.browser_download_url
Log-Message "vcert ZIP download URL: $windowsZipUrl"

# Define the path for the downloaded ZIP file - OPTIONAL, YOU MIGHT HOST VCERT ELSEWHERE
$zipFilePath = Join-Path -Path $tempPath -ChildPath "vcert_latest_windows.zip"

# Download the ZIP file - OPTIONAL, YOU MIGHT HOST VCERT ELSEWHERE
Invoke-WebRequest -Uri $windowsZipUrl -OutFile $zipFilePath
Log-Message "ZIP file downloaded to $zipFilePath"

# Extract the ZIP file directly to the temp directory, without subfolders - OPTIONAL, YOU MIGHT HOST VCERT ELSEWHERE
Expand-Archive -LiteralPath $zipFilePath -DestinationPath $tempPath -Force
Log-Message "vcert extracted to $tempPath"

# prepare the vcert execution  - REQUIRED
$vcertExePath = Join-Path -Path $tempPath -ChildPath "vcert.exe"
Log-Message "==== Vcert ===="

# write the version to the log file - RECOMMENDED
$command = '& ' + "$vcertExePath" + ' -version'  + ' 2>&1 | %{ "$_" } | Tee-Object -FilePath ' + "$logFilePathRun" + ' -Append'
Log-Message $command
Invoke-Expression $command

# Define command run vcert with playbook - REQUIRED 
$command = '& ' + "$vcertExePath" + ' run -d -f ' + "$playBookPath" + ' 2>&1 | %{ "$_" } | Tee-Object -FilePath ' + "$logFilePathRun" + ' -Append'   
Log-Message $command

# Execute vcert
Invoke-Expression $command

# Revoke Grant - HIGHLY RECOMMENDED
switch ($platform) {
        'tpp' { 
            $token = $response_grant.access_token
            $headers = @{
                Authorization = "Bearer $token"
            }
            $response_revoke = Invoke-WebRequest -Uri "$TPPUrl/vedauth/Revoke/token" -Method 'GET' -Headers $headers -UseBasicParsing
            
            if ($response_revoke.StatusCode -eq 200) {
                Log-Message "Status Description: $($response_revoke.StatusDescription)"                
            } else {
                Log-Message "Request failed."
                Log-Message "Status Code: $($response_revoke.StatusCode)"
                Log-Message "Status Description: $($response_revoke.StatusDescription)"
                #Log-Message "Headers: $($response_revoke.Headers | ConvertTo-Json -Depth 10)"
                #Log-Message "Content: $($response_revoke.Content)"
            } 
        }
    }


