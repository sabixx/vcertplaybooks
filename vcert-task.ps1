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
    [Parameter(Mandatory = $true)][string]$playbook_url,
    [Parameter(Mandatory = $false)][string]$TLSPC_APIKEY,
    [Parameter(Mandatory = $false)][string]$TLSPC_OAuthIdpURL,
    [Parameter(Mandatory = $false)][string]$TLSPC_tokenURL,
    [Parameter(Mandatory = $false)][string]$TLSPC_ClientID,
    [Parameter(Mandatory = $false)][string]$TLSPC_ClientSecret,
    [Parameter(Mandatory = $false)][string]$TLSPC_SyslogServer,
    [Parameter(Mandatory = $false)][string]$TLSPC_SyslogPort
)

# Function to determine the Syslog severity based on the log message
function Get-SyslogSeverity {
    param (
        [string]$Message
    )

    $severityValue = 6  # Default to "info" (severity 6) if no severity level is detected

    if ($Message -match "DEBUG") {
        $severityValue = 7  # debug
    }
    elseif ($Message -match "INFO") {
        $severityValue = 6  # info
    }
    elseif ($Message -match "WARN" -or $Message -match "WARNING") {
        $severityValue = 4  # warning
    }
    elseif ($Message -match "ERROR" -or $Message -match "ERR") {
        $severityValue = 3  # error
    }
    elseif ($Message -match "CRITICAL" -or $Message -match "CRIT") {
        $severityValue = 2  # critical
    }
    elseif ($Message -match "ALERT") {
        $severityValue = 1  # alert
    }
    elseif ($Message -match "EMERGENCY" -or $Message -match "EMERG") {
        $severityValue = 0  # emergency
    }

    return $severityValue
}

# Function to send the captured output to Graylog over UDP
function Send-SyslogMessageUDP {
    param (
        [string]$TLSPC_SyslogServer,
        [int]$TLSPC_SyslogPort = 514,
        [string]$Message,
        [string]$Hostname = $env:COMPUTERNAME, # Default to the current machine's hostname if not provided
        [string]$Category = 'Venafi/vcert'
    )

    $severityValue = Get-SyslogSeverity -Message $Message
    $facility = 1
    $priority = ($facility * 8) + $severityValue
    $syslogMsg = "<$priority> $Message $Hostname [Category=$Category]"

    # Send the message over UDP
    try {
        $udpClient = [System.Net.Sockets.UdpClient]::new()
        $udpClient.Connect($TLSPC_SyslogServer, $TLSPC_SyslogPort)
        $encodedMsg = [System.Text.Encoding]::UTF8.GetBytes($syslogMsg + "`n")  # Use UTF-8 encoding
        $udpClient.Send($encodedMsg, $encodedMsg.Length) | Out-Null  # Suppress output
        $udpClient.Close()
    }
    catch {
        Log-Message "Failed to send Syslog message: $_", -Syslog $false
    }
}

# Function to send the captured output to Graylog over TCP
function Send-SyslogMessageTCP {
    param (
        [string]$TLSPC_SyslogServer,
        [int]$TLSPC_SyslogPort = 514,
        [string]$Message,
        [string]$Hostname,
        [string]$Category = 'Venafi/vcert'
    )

    $severityValue = Get-SyslogSeverity -Message $Message
    $facility = 1
    $priority = ($facility * 8) + $severityValue
    $syslogMsg = "<$priority> $Message $Hostname [Category=$Category]"

    # Send the message over TCP
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient($TLSPC_SyslogServer, $TLSPC_SyslogPort)
        $stream = $tcpClient.GetStream()
        $encodedMsg = [System.Text.Encoding]::ASCII.GetBytes($syslogMsg + "`n")
        $stream.Write($encodedMsg, 0, $encodedMsg.Length)
        $stream.Flush()
        $stream.Close()
        $tcpClient.Close()
    }
    catch {
        Log-Message "Failed to send Syslog message: $_", -Syslog $false
    }
    finally {
        # write-host "send message: $Message"    
    }
}

Log-Message ("INFO Hello World")

# Function to append log messages with timestamps - RECOMMENDED
function Log-Message {
    param (
        [string]$Message,
        [bool]$Syslog = $true,
        [string]$SyslogCategory = 'vcert/wrapper'
    )

    $timestampPattern = '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}([+-]\d{2}\d{2})?'
    $timestamp = "{0:yyyy-MM-ddTHH:mm:ss.fff}{1}" -f (Get-Date), (Get-Date).ToString("zzz").Replace(":", "")

    if (-not ($Message -match $timestampPattern)) {
        $Message = "$timestamp`t$Message"
    }

    if ($Syslog -and $TLSPC_SyslogServer) {
        #Send-SyslogMessageTCP -Message $Message -Hostname "$Env:Computername" -TLSPC_SyslogServer $TLSPC_SyslogServer -TLSPC_SyslogPort $TLSPC_SyslogPort  -Category $SyslogCategory 
        Send-SyslogMessageUDP -Message $Message -Hostname "$Env:Computername" -TLSPC_SyslogServer $TLSPC_SyslogServer -TLSPC_SyslogPort $TLSPC_SyslogPort -Category $SyslogCategory
    }

    $Message | Out-File -FilePath $logFilePath -Append -Encoding UTF8
    #Add-Content -Path $logFilePath -Value "$Message"
    Write-Host "$Message"

}

$playBook = $playbook_url.Split('/')[-1] 
$tempPath = [System.IO.Path]::GettempPath()
$logFilePath = Join-Path -Path  "$tempPath" "vcertlog_$playBook.txt"
#$logFilePathRun = Join-Path -Path  "$tempPath" "vcert_run_log.txt"
$playBookPath = Join-Path -Path $tempPath -ChildPath $playBook

Log-Message "DEBUG`t==== Start ===="

# Retrieve SyslogServer - OPTIONAL
if ( [Environment]::GetEnvironmentVariable("TLSPC_SyslogServer_$playBook", "Machine")) {
    $TLSPC_SyslogServer = [System.Environment]::GetEnvironmentVariable("TLSPC_SyslogServer_$playBook", 'Machine')
}

# Retrieve SyslogPort - OPTIONAL
if ( [Environment]::GetEnvironmentVariable("TLSPC_SyslogPort_$playBook", "Machine")) {
    $TLSPC_SyslogPort = [System.Environment]::GetEnvironmentVariable("TLSPC_SyslogPort_$playBook", 'Machine')
}

# Set $TLSPC_Hostname as an environment variable for the current process only - OPTIONAL
if (-not [Environment]::GetEnvironmentVariable("TLSPC_Hostname_$playBook", "Machine")) {
    [Environment]::SetEnvironmentVariable("TLSPC_Hostname", [System.Net.Dns]::GetHostName(), "Process")
}
else {
    $Env:TLSPC_Hostname = [System.Environment]::GetEnvironmentVariable("TLSPC_Hostname_$playBook", 'Machine')
}

Log-Message "INFO`tplaybook_url       = $playbook_url"
Log-Message "INFO`tplaybook           = $playBook" 
Log-Message "INFO`tplaybook path      = $playBookPath" 
Log-Message "INFO`ttempPath           = $tempPath" 
Log-Message "INFO`tlog file           = $logFilePath" 
Log-Message "INFO`tTLSPC_OAuthIdpURL  = $TLSPC_OAuthIdpURL" 
Log-Message "INFO`tTLSPC_tokenURL     = $TLSPC_tokenURL"
Log-Message "INFO`tTLSPC_ClientID     = $TLSPC_ClientID" 
Log-Message "INFO`tTLSPC_SyslogServer = $TLSPC_SyslogServer"
Log-Message "INFO`tTLSPC_SyslogPort   = $TLSPC_SyslogPort"
Log-Message "INFO`tTLSPC_hostname     = $Env:TLSPC_Hostname"

if ($TLSPC_APIKEY) { Log-Message "WARN`tTLSPC_APIKEY      = API key used, not recommended" } 

# Check if the script is running with admin privileges - OPTINAL DEPENDS ON USE CASE
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Log-Message "INFO`tNot running as Administrator. Some use cases require administrator privileges."
    #exit #do not exit out, some use cases may not require admin permissions.
}

# check is playbook_url was provided - RECOMMENDED
if (-not $playbook_url) {
    Log-Message "CRITICAL`tno playbook_url provided, exiting."
    exit
}

try {
    # Download the Playbook - RECOMMENDED
    Invoke-WebRequest -Uri $playbook_url -OutFile $playBookPath
    Log-Message "INFO`tPlaybook downloaded to $playBookPath"
}
catch {
    Log-Message "CRITICAL`tFailed downloading playbook from $playbook_url. ERROR`t: $_"
}

# Determine the platform (vaas or tpp) - CHANGE, BEST TO MAKE IT FIT FOR PURPOOSE
try {
    $platform = switch -regex -file "$playBookPath" { 'platform:' { "$_" } }
    $platform = $platform -replace 'platform:', ''
    $platform = ($platform.Split("#"))[0].Trim()
    $platform = $platform -replace '[^a-zA-Z0-9]', '' 
    Log-Message "INFO`tPlatform = $platform"  
}
catch {
    Log-Message "CRITICAL`tcould not determine platform."
}

# Perform authentication based on Platorm - CHANGE, BEST TO MAKE IT FIT FOR PURPOOSE
switch ($platform) {
    #####################################################################################################################
    ################################ # TLSDC with windows Integrated Auth ###############################################
    #####################################################################################################################
    { ($_ -eq "tlsdc") -or ($_ -eq "tpp") } {
        try {
            $TPPurl = switch -regex (Get-Content "$playBookPath") { 'url:' { "$_" } }
            $TPPurl = $TPPurl -replace 'url:', ''
            $TPPurl = ($TPPurl.Split("#"))[0].Trim()
            Log-Message "DEBUG`tTPPurl = $TPPurl"  

            $client_id = switch -regex (Get-Content "$playBookPath") { 'clientId:' { "$_" } }
            if ($null -eq $client_id -or $client_id -eq "") {
                $client_id = "vcert-cli"
            }
            else {
                $client_id = $client_id -replace 'clientId:', ''
                $client_id = ($client_id.Split("#"))[0].Trim()
            }
            Log-Message "DEBUG`tclient_id = $client_id" 
            $response_grant = Invoke-RestMethod "$TPPUrl/vedauth/authorize/integrated" -UseDefaultCredentials -Method POST -Body (@{"client_id" = "$client_id"; "scope" = "certificate:manage" } | ConvertTo-Json) -ContentType "application/json" -UseBasicParsing
            $env:TPP_ACCESS_TOKEN = $response_grant.access_token
            $env:TPP_REFRESH_TOKEN = $response_grant.refresh_token

            Log-Message "INFO`tretrieved oAuth bearer token."  
        }
        catch {
            Log-Message "ERROR`t An ERROR`t occurred retrieving oAuth bearer token: $($_.Exception.Message)"
            Log-Message $response_grant
        }

        if (-not $Env:TPP_ACCESS_TOKEN) {
            Log-Message "CRITICAL`tno ACCESS_TOKEN set, exiting."
            exit
        }
    }

    #####################################################################################################################
    ################################## TLS PC with ServiceAccount JWT authentication  ###################################
    #####################################################################################################################

    { ($_ -eq "tlspc") -or ($_ -eq "vaas") } {  
        
        # Set $TLSPC_CLIENTID as an environment variable for the current process only - OPTIONAL
        if ( [Environment]::GetEnvironmentVariable("TLSPC_CLIENTID_$playBook", "Machine")) {
            $TLSPC_CLIENTID = [System.Environment]::GetEnvironmentVariable("TLSPC_CLIENTID_$playBook", 'Machine')
            Log-Message "DEBUG`tretrieved TLSPC_CLIENTID = $TLSPC_CLIENTID"
        } 

        # Set $TLSPC_tokenURL as an environment variable for the current process only - OPTIONAL
        if ( [Environment]::GetEnvironmentVariable("TLSPC_TOKENURL_$playBook", "Machine")) {
            $TLSPC_tokenURL = [System.Environment]::GetEnvironmentVariable("TLSPC_TOKENURL_$playBook", 'Machine')
            # setting token_url as environment variable as playbook requiers it
            $Env:TLSPC_tokenURL = $TLSPC_tokenURL
            Log-Message "DEBUG`tretrieved TLSPC_TOKENURL_ = $TLSPC_tokenURL"
        }

        # Set $TLSPC_OAuthIdpURL as an environment variable for the current process only - OPTIONAL
        if ( [Environment]::GetEnvironmentVariable("TLSPC_OAUTHIDPURL_$playBook", "Machine")) {
            $TLSPC_OAuthIdpURL = [System.Environment]::GetEnvironmentVariable("TLSPC_OAUTHIDPURL_$playBook", 'Machine')
            Log-Message "DEBUG`tretrieved TLSPC_OAUTHIDPURL_ = $TLSPC_OAuthIdpURL"
        }

        # Set $TLSPC_CLIENTSECRET as an environment variable for the current process only - OPTIONAL
        if (-not [string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable("TLSPC_CLIENTSECRET", "User")) -and -not [string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable("TLSPC_CLIENTSECRET", "Process"))) {
            if ([Environment]::GetEnvironmentVariable("TLSPC_CLIENTSECRET_$playBook", "Machine")) {
                Log-Message("DEBUG`tretieving clientsecret")
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
                    Log-Message "DEBUG`tretrieved TLSPC_CLIENTSECRET."  
                }
                catch {
                    Log-Message "ERROR`t An ERROR`t occurred retrieving TLSPC_CLIENTSECRET: $($_.Exception.Message)"
                }
            }
        }

        if (-not $TLSPC_ClientSecret -and -not $TLSPC_APIKEY) {
            Log-Message "CRITICAL`tno TLSPC_CLIENTSECRET nor API KEY, exiting."
            exit
        }

        # Create the JSON payload
        $jsonPayload = @{
            client_id     = $TLSPC_CLIENTID
            client_secret = $TLSPC_ClientSecret
            audience      = "https://api.venafi.cloud/"
            grant_type    = "client_credentials"
        } | ConvertTo-Json
        
        try {
            $response = Invoke-RestMethod -Method Post -Uri $TLSPC_OAuthIdpURL -ContentType "application/json" -Body $jsonPayload
            $env:TLSPC_ExternalJWT = $response.access_token
            Log-Message("DEBUG`tTLSPC_ExternalJWT retrieved.")
        }
        catch {
            Log-Message("ERROR`t could not obtain external JWT: $_")
        }


        #####################################################################################################################
        #####################################   it's not recommneded using API Keys... ######################################
        #####################################   this only exists for older clients..   ######################################
        #####################################################################################################################

        if ([Environment]::GetEnvironmentVariable("TLSPC_APIKEY", "User")) { Log-Message "WARN`tAPIKEY found in user world." }
        if ([Environment]::GetEnvironmentVariable("TLSPC_APIKEY", "Proces")) { Log-Message "WARN`tAPIKEY found in process world." }
        if (-not [string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable("TLSPC_APIKEY", "User")) -and -not [string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable("TLSPC_APIKEY", "Process"))) {
            if ([Environment]::GetEnvironmentVariable("TLSPC_APIKEY_$playBook", "Machine")) {
                try {
                    Add-Type -AssemblyName System.Security
                    $encryptedBase64 = ([Environment]::GetEnvironmentVariable("TLSPC_APIKEY_$playBook", "Machine"))
                    $SecureStr = [System.Convert]::FromBase64String($encryptedBase64) 
                    $bytes = [Security.Cryptography.ProtectedData]::Unprotect($SecureStr, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
                    $Env:TLSPC_APIKEY = [System.Text.Encoding]::Unicode.GetString($bytes) 
                    Log-Message "WARN`tretrieved TLSPC_APIKEY, IT's NOT RECOMMENDED TO USE API KEYS, USE SERVICE ACCOUNTS INSTEAD!"  
                }
                catch {
                    Log-Message "ERROR`t an ERROR`t occurred retrieving TLSPC_APIKEY: $($_.Exception.Message)"
                }  
            }
        }
    }

    default {
        Log-Message "CRITICAL`tUnsupported platform: $platform"
        exit
    }
}


# define vcert.zip donload release information
$apiUrl = "https://api.github.com/repos/Venafi/vcert/releases/latest"
Log-Message "DEBUG`tFetching the latest release from $apiUrl"

# Use Invoke-RestMethod to call the GitHub API - OPTIONAL, YOU MIGHT HOST VCERT ELSEWHER
try {
    $latestRelease = Invoke-RestMethod -Uri $apiUrl
    Log-Message "DEBUG`tLatest release information retrieved."
}
catch {
    Log-Message "ERROR`t Failed to retrieve the latest release information from $apiUrl. ERROR`t: $_"
}

# Attempt to find the Windows ZIP asset - OPTIONAL, YOU MIGHT HOST VCERT ELSEWHERE
try {
    $windowsZipAsset = $latestRelease.assets | Where-Object { $_.name -match "windows.*\.zip$" } | Select-Object -First 1  
    if ($null -eq $windowsZipAsset) {
        Log-Message "ERROR`t Windows ZIP file not found in the latest release."
        exit
    }
    else {
        Log-Message "DEBUG`tWindows ZIP file found in the latest release."
    }
}
catch {
    Log-Message "ERROR`t Failed to find the Windows ZIP asset. ERROR`t: $_"
}

# Extract the download URL - OPTIONAL, YOU MIGHT HOST VCERT ELSEWHERE
try {
    $windowsZipUrl = $windowsZipAsset.browser_download_url
    Log-Message "DEBUG`tvcert ZIP download URL: $windowsZipUrl"
}
catch {
    Log-Message "ERROR`t Failed to extract the vcert ZIP download URL. ERROR`t: $_"
}

# Define the path for the downloaded ZIP file - OPTIONAL, YOU MIGHT HOST VCERT ELSEWHERE
try {
    $zipFilePath = Join-Path -Path $tempPath -ChildPath "vcert_latest_windows.zip"
    Log-Message "DEBUG`tZIP file path defined as: $zipFilePath"
}
catch {
    # Log the ERROR`t message if defining the path fails
    Log-Message "ERROR`t Failed to define the ZIP file path. ERROR`t: $_"
}

# Download the ZIP file - OPTIONAL, YOU MIGHT HOST VCERT ELSEWHERE
try {
    Invoke-WebRequest -Uri $windowsZipUrl -OutFile $zipFilePath
    Log-Message "DEBUG`tZIP file downloaded to $zipFilePath"
}
catch {
    # Log the ERROR`t message if the download fails
    Log-Message "ERROR`t Failed to download the ZIP file from $windowsZipUrl. ERROR`t: $_"
}

# Extract the ZIP file directly to the temp directory, without subfolders - OPTIONAL, YOU MIGHT HOST VCERT ELSEWHERE
try {
    Expand-Archive -LiteralPath $zipFilePath -DestinationPath $tempPath -Force
    Log-Message "DEBUG`tvcert extracted to $tempPath"
}
catch {
    # Log the ERROR`t message if the extraction fails
    Log-Message "ERROR`t Failed to extract the ZIP file to $tempPath. ERROR`t: $_"
}
try {
    # Prepare the vcert execution - REQUIRED
    $vcertExePath = Join-Path -Path $tempPath -ChildPath "vcert.exe"
    Log-Message "DEBUG`tvcert executable path set to: $vcertExePath"
    Log-Message "DEBUG`t==== Vcert ===="
}
catch {
    # Log the ERROR`t message if there is an issue preparing the vcert execution path
    Log-Message "ERROR`t Failed to prepare the vcert executable path. ERROR`t: $_"
}

# Write the version to the log file - RECOMMENDED
$command = "$vcertExePath" + ' -version' + ' 2>&1 | %{ "$_" }'
Log-Message "INFO`t$command"   
try { 
    $versionOutput = Invoke-Expression $command
}
catch {
    Log-Message ("ERROR`t Failed to execute the vcert version command. ERROR`t: $_") -SyslogCategory "vcert/vcert"
}
$versionOutput | ForEach-Object { (Log-Message "INFO`t$_" -SyslogCategory "vcert/vcert") }


# $command = '& ' + "$vcertExePath" + ' run -d -f ' + "$playBookPath" + ' 2>&1 | %{ "$_" } | Tee-Object -FilePath ' + "$logFilePathR" + ' -Append'   
$command = "$vcertExePath" + ' run -f ' + "$playBookPath" + ' 2>&1 | %{ "$_" }'
Log-Message "INFO`t$command"

try {
    $output = Invoke-Expression $command
}
catch {
    Log-Message("CRITICAL`tsevere error occurred while executing vcert: $_") -SyslogCategory "vcert/vcert"
}
$output | ForEach-Object { (Log-Message $_ -SyslogCategory "vcert/vcert") }


# Revoke Grant for TPP - HIGHLY RECOMMENDED
if ($platform -eq "tlsdc" -or $platform -eq "tpp") {
    $token = $response_grant.access_token
    $headers = @{
        Authorization = "Bearer $token"
    }
    $response_revoke = Invoke-WebRequest -Uri "$TPPUrl/vedauth/Revoke/token" -Method 'GET' -Headers $headers -UseBasicParsing

    if ($response_revoke.StatusCode -eq 200) {
        Log-Message "DEBUG`tStatus Description: $($response_revoke.StatusDescription)"                
    }
    else {
        Log-Message "ERROR`t Request failed."
        Log-Message "ERROR`t Status Code: $($response_revoke.StatusCode)"
        Log-Message "ERROR`t Status Description: $($response_revoke.StatusDescription)"
        #Log-Message "ERROR`t Headers: $($response_revoke.Headers | ConvertTo-Json -Depth 10)"
        #Log-Message "ERROR`t Content: $($response_revoke.Content)"
    } 
}

 
