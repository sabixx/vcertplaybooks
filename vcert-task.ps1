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
    [Parameter(Mandatory=$true)][string]$playbook_url,
    [Parameter(Mandatory=$false)][string]$TLSPC_APIKEY,
    [Parameter(Mandatory=$false)][string]$TLSPC_OAuthIdpURL,
    [Parameter(Mandatory=$false)][string]$TLSPC_tokenURL,
    [Parameter(Mandatory=$false)][string]$TLSPC_ClientID,
    [Parameter(Mandatory=$false)][string]$TLSPC_ClientSecret,
    [Parameter(Mandatory=$false)][string]$TLSPC_SyslogServer,
    [Parameter(Mandatory=$false)][string]$TLSPC_SyslogPort
)

# Function to determine the Syslog severity based on the log message
function Get-SyslogSeverity {
    param (
        [string]$Message
    )

    if ($Message -match "DEBUG") {
        return "debug"
    } elseif ($Message -match "INFO") {
        return "info"
    } elseif ($Message -match "WARN" -or $Message -match "WARNING") {
        return "warning"
    } elseif ($Message -match "ERROR" -or $Message -match "ERR") {
        return "error"
    } elseif ($Message -match "CRITICAL" -or $Message -match "CRIT") {
        return "critical"
    } else {
        return "info"  # Default to "info" if no severity level is detected
    }
}

# Function to send the captured output to Graylog over UDP
function Send-SyslogMessageUDP {
    param (
        [string]$TLSPC_SyslogServer,
        [int]$TLSPC_SyslogPort = 514,
        [string]$Message,
        [string]$Hostname,
        [string]$Category = 'Venafi/vcert'
    )

    # Determine the severity based on the message content
    $Severity = Get-SyslogSeverity -Message $Message

    # Determine Syslog priority based on facility (1 for user-level messages) and severity
    $facility = 1
    $severityValue = switch ($Severity) {
        "emergency" { 0 }
        "alert" { 1 }
        "critical" { 2 }
        "error" { 3 }
        "warning" { 4 }
        "notice" { 5 }
        "info" { 6 }
        "debug" { 7 }
        default { 6 }  # Default to "info" if severity is unrecognized
    }
    $priority = ($facility * 8) + $severityValue

    # Construct the Syslog message with category
    $syslogMsg = "<$priority>$([datetime]::Now.ToString('yyyy-MM-ddTHH:mm:ss')) $Hostname $Message [Category=$Category]"

    # Send the message over UDP
    try {
        $udpClient = New-Object System.Net.Sockets.UdpClient
        $udpClient.Connect($TLSPC_SyslogServer, $TLSPC_SyslogPort)
        $encodedMsg = [System.Text.Encoding]::ASCII.GetBytes($syslogMsg + "`n")
        $udpClient.Send($encodedMsg, $encodedMsg.Length)
        $udpClient.Close()
    } catch {
        Log-Message "Failed to send Syslog message: $_", false
    }
}

 Log-Message "Failed to send Syslog message: $_"

# Function to send the captured output to Graylog over TCP
function Send-SyslogMessageTCP {
    param (
        [string]$TLSPC_SyslogServer,
        [int]$TLSPC_SyslogPort = 514,
        [string]$Message,
        [string]$Hostname,
        [string]$Category = 'Venafi/vcert'
    )

    # Determine the severity based on the message content
    $Severity = Get-SyslogSeverity -Message $Message

    # Determine Syslog priority based on facility (1 for user-level messages) and severity
    $facility = 1
    $severityValue = switch ($Severity) {
        "emergency" { 0 }
        "alert" { 1 }
        "critical" { 2 }
        "error" { 3 }
        "warning" { 4 }
        "notice" { 5 }
        "info" { 6 }
        "debug" { 7 }
        default { 6 }  # Default to "info" if severity is unrecognized
    }
    $priority = ($facility * 8) + $severityValue

    # Construct the Syslog message with category
    $syslogMsg = "<$priority>$([datetime]::Now.ToString('yyyy-MM-ddTHH:mm:ss')) $Hostname $Message [Category=$Category]"

    # Send the message over TCP
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient($TLSPC_SyslogServer, $TLSPC_SyslogPort)
        $stream = $tcpClient.GetStream()
        $encodedMsg = [System.Text.Encoding]::ASCII.GetBytes($syslogMsg + "`n")
        $stream.Write($encodedMsg, 0, $encodedMsg.Length)
        $stream.Flush()
        $stream.Close()
        $tcpClient.Close()
    } catch {
        Log-Message "Failed to send Syslog message: $_", false
    } finally {
        # write-host "send message: $Message"    
    }
}

# Function to append log messages with timestamps - RECOMMENDED
function Log-Message {
    param (
        [string]$Message,
        [bool]$Syslog = $true
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logFilePath -Value "[$timestamp] $Message"
    Write-Host $Message

    if ($Syslog -and $TLSPC_SyslogServer) {
        Send-SyslogMessageTCP -Message $Message -Hostname "$Env:Computername" -TLSPC_SyslogServer $TLSPC_SyslogServer -TLSPC_SyslogPort $TLSPC_SyslogPort 
        # Send-SyslogMessageUDP -Message $Message -Hostname "$Env:Computername" -TLSPC_SyslogServer $TLSPC_SyslogServer -TLSPC_SyslogPort $TLSPC_SyslogPort 
    }
}


$playBook = $playbook_url.Split('/')[-1] 
$tempPath = [System.IO.Path]::GettempPath()
$logFilePath = Join-Path -Path  "$tempPath" "vcert_log.txt"
#$logFilePathRun = Join-Path -Path  "$tempPath" "vcert_run_log.txt"
$playBookPath = Join-Path -Path $tempPath -ChildPath $playBook

Log-Message "==== Start ===="

# Retrieve SyslogServer - OPTIONAL
if ( [Environment]::GetEnvironmentVariable("TLSPC_SyslogServer_$playBook", "Machine")) {
    $TLSPC_SyslogServer = [System.Environment]::GetEnvironmentVariable("TLSPC_SyslogServer_$playBook",'Machine')
}

# Retrieve SyslogServer - OPTIONAL
if ( [Environment]::GetEnvironmentVariable("TLSPC_SyslogPort_$playBook", "Machine")) {
    Log-Message "retrieved TLSPC_SyslogPort = $TLSPC_SyslogPort"
}

Log-Message "playbook_url       = $playbook_url"
Log-Message "playbook           = $playBook"
Log-Message "playbook path      = $playBookPath"
Log-Message "tempPath           = $tempPath"
Log-Message "log file           = $logFilePath"
#Log-Message "vcert log file     = $logFilePathRun"
Log-Message "TLSPC_OAuthIdpURL  = $TLSPC_OAuthIdpURL"
Log-Message "TLSPC_tokenURL     = $TLSPC_tokenURL"
Log-Message "TLSPC_ClientID     = $TLSPC_ClientID"
#Log-Message "TLSPC_SyslogServer = $TLSPC_SyslogServer"
#Log-Message "TLSPC_SyslogPort   = $TLSPC_SyslogPort"

if ($TLSPC_APIKEY)       { Log-Message "TLSPC_APIKEY      = API key used, not recommended" }

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
} catch {
    Log-Message "could not determine platform."
}

# Set $TLSPC_Hostname as an environment variable for the current process only - OPTIONAL
if (-not [Environment]::GetEnvironmentVariable("TLSPC_Hostname_$playBook", "Machine")) {
    [Environment]::SetEnvironmentVariable("TLSPC_Hostname", [System.Net.Dns]::GetHostName(), "Process")
    Log-Message "no TLSPC_hostname_$playBook set, using ::GetHostName = $Env:TLSPC_Hostname"
} else {
    $Env:TLSPC_Hostname = [System.Environment]::GetEnvironmentVariable("TLSPC_Hostname_$playBook",'Machine')
    Log-Message "retrieved TLSPC_hostname = $Env:TLSPC_Hostname"
}

# Retieve Syslog server
if (-not [Environment]::GetEnvironmentVariable("TLSPC_SyslogServer_$playBook", "Machine")) {
    Log-Message "TLSPC_SyslogServer = $TLSPC_SyslogServer" 
} else {
    Log-Message "No syslog server configured."
}

# Retieve Syslog Port
if ($TLSPC_SyslogServer) {
    if (-not [Environment]::GetEnvironmentVariable("TLSPC_SyslogPort_$playBook", "Machine")) {
        Log-Message "TLSPC_SyslogPort   = $TLSPC_SyslogPort" 
    } else {
        Log-Message "TLSPC_SyslogPort   = 514"
    }
}

if ($TLSPC_SyslogServer) { Log-Message "TLSPC_SyslogServer = $TLSPC_SyslogServer" 
if ($TLSPC_SyslogPort)   { Log-Message "TLSPC_SyslogPort   = $TLSPC_SyslogPort" } else {
                           Log-Message "TLSPC_SyslogPort   = 514"} }

# Perform authentication based on Platorm - CHANGE, BEST TO MAKE IT FIT FOR PURPOOSE
switch ($platform) {
#####################################################################################################################
################################ # TLSDC with windows Integrated Auth ###############################################
#####################################################################################################################
    {($_ -eq "tlsdc") -or ($_ -eq "tpp")} {
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

     {($_ -eq "tlspc") -or ($_ -eq "vaas")} {  
        
        # Set $TLSPC_CLIENTID as an environment variable for the current process only - OPTIONAL
        if ( [Environment]::GetEnvironmentVariable("TLSPC_CLIENTID_$playBook", "Machine")) {
            $TLSPC_CLIENTID = [System.Environment]::GetEnvironmentVariable("TLSPC_CLIENTID_$playBook",'Machine')
            Log-Message "retrieved TLSPC_CLIENTID = $TLSPC_CLIENTID"
        } else { Log-Message "No TLSPC_CLIENTID." }

        # Set $TLSPC_tokenURL as an environment variable for the current process only - OPTIONAL
        if ( [Environment]::GetEnvironmentVariable("TLSPC_TOKENURL_$playBook", "Machine")) {
            $TLSPC_tokenURL = [System.Environment]::GetEnvironmentVariable("TLSPC_TOKENURL_$playBook",'Machine')
            # setting token_url as environment variable as playbook requiers it
            $Env:TLSPC_tokenURL = $TLSPC_tokenURL
            Log-Message "retrieved TLSPC_TOKENURL_ = $TLSPC_tokenURL"
        } else { Log-Message "No TLSPC_TOKENURL." }

        # Set $TLSPC_OAuthIdpURL as an environment variable for the current process only - OPTIONAL
        if ( [Environment]::GetEnvironmentVariable("TLSPC_OAUTHIDPURL_$playBook", "Machine")) {
            $TLSPC_OAuthIdpURL = [System.Environment]::GetEnvironmentVariable("TLSPC_OAUTHIDPURL_$playBook",'Machine')
            Log-Message "retrieved TLSPC_OAUTHIDPURL_ = $TLSPC_OAuthIdpURL"
        } else { Log-Message "No TLSPC_OAuthIdpURL." }

        # take out, should be too short to stay in memory, alywas get a new client secret...
        #if ([Environment]::GetEnvironmentVariable("TLSPC_CLIENTSECRET", "User")) { Log-Message "TLSPC_CLIENTSECRET found in user world" }
        #if ([Environment]::GetEnvironmentVariable("TLSPC_CLIENTSECRET", "Proces")){ Log-Message "TLSPC_CLIENTSECRET found in process world" }

        if (-not [string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable("TLSPC_CLIENTSECRET", "User")) -and -not [string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable("TLSPC_CLIENTSECRET", "Process"))) {
            if ([Environment]::GetEnvironmentVariable("TLSPC_CLIENTSECRET_$playBook", "Machine")) {
                Log-Message("getting the secret")
                try {
                    Add-Type -AssemblyName System.Security
                    $encryptedBase64 = ([Environment]::GetEnvironmentVariable("TLSPC_CLIENTSECRET_$playBook", "Machine"))
                    Log-Message ("encryptedBase64 = $encryptedBase64")
                    $SecureStr = [System.Convert]::FromBase64String($encryptedBase64) 
                    Log-Message ("SecureStr = $SecureStr")
                    $bytes = [Security.Cryptography.ProtectedData]::Unprotect($SecureStr, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
                    Log-Message ("bytes = $bytes")
                    $TLSPC_ClientSecret = [System.Text.Encoding]::Unicode.GetString($bytes) 
                    # Do not log client secret, Log-Message ("TLSPC_ClientSecret_decoded = $TLSPC_ClientSecret")
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
            audience      = "https://api.venafi.cloud/"
            grant_type    = "client_credentials"
        } | ConvertTo-Json

        #$response = Invoke-RestMethod -Method Post -Uri $TLSPC_OAuthIdpURL -ContentType "application/json" -Body $jsonPayload
        #$env:TLSPC_ExternalJWT = $response.access_token
        #Log-Message("TLSPC_ExternalJWT = $env:TLSPC_ExternalJWT")
        
        try {
            $response = Invoke-RestMethod -Method Post -Uri $TLSPC_OAuthIdpURL -ContentType "application/json" -Body $jsonPayload
            $env:TLSPC_ExternalJWT = $response.access_token
            Log-Message("TLSPC_ExternalJWT retrieved.")
        }
        catch {
            Log-Message("Error occurred while trying to obtain the external JWT: $_")
        }


        #####################################################################################################################
        #####################################   it's not recommneded using API Keys... ######################################
        #####################################   this only exists for older clients..   ######################################
        #####################################################################################################################

        if ([Environment]::GetEnvironmentVariable("TLSPC_APIKEY", "User")) { Log-Message "APIKEY found in user world." }
        if ([Environment]::GetEnvironmentVariable("TLSPC_APIKEY", "Proces")){ Log-Message "APIKEY found in process world." }
        if (-not [string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable("TLSPC_APIKEY", "User")) -and -not [string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable("TLSPC_APIKEY", "Process"))) {
            if ([Environment]::GetEnvironmentVariable("TLSPC_APIKEY_$playBook", "Machine")) {
                try {
                    Add-Type -AssemblyName System.Security
                    $encryptedBase64 = ([Environment]::GetEnvironmentVariable("TLSPC_APIKEY_$playBook", "Machine"))
                    $SecureStr = [System.Convert]::FromBase64String($encryptedBase64) 
                    $bytes = [Security.Cryptography.ProtectedData]::Unprotect($SecureStr, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
                    $Env:TLSPC_APIKEY = [System.Text.Encoding]::Unicode.GetString($bytes) 
                    Log-Message "retrieved TLSPC_APIKEY, IT's NOT RECOMMENDED TO USE API KEYS, USE SERVICE ACCOUNTS INSTEAD!"  
                }
                catch {
                    Log-Message "An error occurred retrieving TLSPC_APIKEY: $($_.Exception.Message)"
                }  
            }
        }
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
$command = '& ' + "$vcertExePath" + ' -version'  + ' 2>&1 | %{ "$_" } | Tee-Object -FilePath ' + "$logFilePath" + ' -Append'
Log-Message $command
Invoke-Expression $command

# Define command run vcert with playbook - REQUIRED 
# $command = '& ' + "$vcertExePath" + ' run -d -f ' + "$playBookPath" + ' 2>&1 | %{ "$_" } | Tee-Object -FilePath ' + "$logFilePathR" + ' -Append'   
$command = '& ' + "$vcertExePath" + ' run -d -force-renew -f ' + "$playBookPath" + ' 2>&1 | %{ "$_" }'
Log-Message $command

try {
    # Execute vcert and capture the output
    $output = Invoke-Expression $command
    
    # Log the successful execution output
    Log-Message("Command executed successfully.")
}
catch {
    # Log the error that occurred during execution
    Log-Message("Error occurred while executing vcert: $_")
}

finally {
    # Log the output from the command execution
    $output | ForEach-Object { Log-Message $_ }

    # Revoke Grant - HIGHLY RECOMMENDED
    if ($platform -eq "tlsdc" -or $platform -eq "tpp") {
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
