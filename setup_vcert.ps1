param (
    [Parameter(Mandatory=$false)][string]$TLSPC_Hostname,
    [Parameter(Mandatory=$true)][string]$TLSPC_PlaybookUrl,
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
        [string]$Category = 'Venafi/vcert-setup'
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
        Write-Log "Failed to send Syslog message: $_", -Syslog $false
    }
}

# Function to send the captured output to Graylog over TCP
function Send-SyslogMessageTCP {
    param (
        [string]$TLSPC_SyslogServer,
        [int]$TLSPC_SyslogPort = 514,
        [string]$Message,
        [string]$Hostname,
        [string]$Category = 'Venafi/vcert-setup'
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
        Write-Log "Failed to send Syslog message: $_", -Syslog $false
    }
    finally {
        # write-host "send message: $Message"    
    }
}

# Function to append log messages with timestamps - RECOMMENDED
function Write-Log {
    param (
        [string]$Message,
        [bool]$Syslog = $true,
        [string]$SyslogCategory = 'vcert/setup'
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
    Write-Host "$Message"

}

$tempPath = [System.IO.Path]::GetTempPath()
$logFilePath = Join-Path -Path  "$tempPath" "vcert_schtask_setup_log.txt"

# vcert task to run on daily basis
$scriptUrl = "https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/vcert-task.ps1"

$playBook = $TLSPC_PlaybookUrl.Split('/')[-1]

# Check if the script is running with admin privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Log "This script requires administrator privileges. Please run it as an administrator."
    start-sleep -Seconds 5
    exit
}

# write log entries:
Write-Log "TLSPC_PlaybookUrl = $TLSPC_PlaybookUrl"
Write-Log "playBook          = $playBook"
Write-Log "tempPath          = $tempPath"
Write-Log "scriptUrl         = $scriptUrl"
Write-Log "TLSPC_OAuthIdpURL = $TLSPC_OAuthIdpURL"
Write-Log "TLSPC_tokenURL    = $TLSPC_tokenURL"
Write-Log "TLSPC_ClientID    = $TLSPC_ClientID"
Write-Log "TLSPC_Hostname    = $TLSPC_Hostname"
if ($TLSPC_APIKEY) { Write-Log "TLSPC_APIKEY      = API key used, not recommended!" }

if ($TLSPC_CLIENTSECRET) { Write-Log "TLSPC_CLIENTSECRET= Fd93-xxxx" }

if ($TLSPC_SyslogServer) { Write-Log "Syslogserver      = $TLSPC_SyslogServer" 
if ($TLSPC_SyslogPort)   { Write-Log "SyslogPort        = $TLSPC_SyslogPort" } else {
                           Write-Log "SyslogPort        = 514"} }

# Creating the temporary environment variables in the process
if ("$TLSPC_Hostname") {
     [Environment]::SetEnvironmentVariable("TLSPC_Hostname_$playBook",$TLSPC_Hostname, "Machine")
     Write-Log "Sucessfully set TLSPC_Hostname_$playBook" 
}

if ("$TLSPC_ClientId") {
    [Environment]::SetEnvironmentVariable("TLSPC_CLIENTID_$playBook",$TLSPC_CLIENTID, "Machine")
    Write-Log "Sucessfully set TLSPC_CLIENTID_$playBook" 
}

if ("$TLSPC_tokenURL") {
    [Environment]::SetEnvironmentVariable("TLSPC_TOKENURL_$playBook",$TLSPC_tokenURL, "Machine")
    Write-Log "Sucessfully set TLSPC_TOKENURL_$playBook" 
}

if ("$TLSPC_OAuthIdpURL") {
    [Environment]::SetEnvironmentVariable("TLSPC_OAUTHIDPURL_$playBook",$TLSPC_OAuthIdpURL, "Machine")
    Write-Log "Sucessfully set TLSPC_OAuthIdpURL_$playBook" 
}

if ("$TLSPC_ClientSecret") {
    Add-Type -AssemblyName System.Security
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($TLSPC_ClientSecret)
    $SecureStr = [Security.Cryptography.ProtectedData]::Protect($bytes, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
    $SecureStrBase64 = [System.Convert]::ToBase64String($SecureStr)
    [Environment]::SetEnvironmentVariable("TLSPC_CLIENTSECRET_$playBook",$SecureStrBase64, "Machine") 
    Write-Log "TLSPC_CLIENTSECRET_$playBook set."     
} else {
    Write-Log "TLSPC_CLIENTSECRET determined during runtime." 
}

if ("$TLSPC_APIKEY") {
    Write-Log "It is not recommended using API keys, use ServiceAccounts and oAuth instead."    
    Add-Type -AssemblyName System.Security
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($TLSPC_APIKEY)
    $SecureStr = [Security.Cryptography.ProtectedData]::Protect($bytes, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
    $SecureStrBase64 = [System.Convert]::ToBase64String($SecureStr)
    [Environment]::SetEnvironmentVariable("TLSPC_APIKEY_$playBook",$SecureStrBase64, "Machine")  
}

if ("$TLSPC_SyslogServer") {
    [Environment]::SetEnvironmentVariable("TLSPC_SyslogServer_$playBook",$TLSPC_SyslogServer, "Machine")
    Write-Log "Sucessfully set TLSPC_SyslogServer_$playBook" 
}

if ("$TLSPC_SyslogPort") {
    [Environment]::SetEnvironmentVariable("TLSPC_SyslogPort_$playBook",$TLSPC_SyslogPort, "Machine")
    Write-Log "Sucessfully set TLSPC_SyslogPort_$playBook" 
}

# Generate a random hour and minute for the task to run
$randomHour = Get-Random -Minimum 8 -Maximum 10

# Generate a random hour and minute for the task to run
$randomMinute = Get-Random -Minimum 0 -Maximum 59

# Create the trigger for daily execution at the randomized time
$trigger = New-ScheduledTaskTrigger -Daily -At (Get-Date -Hour $randomHour -Minute $randomMinute -Second 0)
 
# change this for production from Bypass to 'AllSigned' and sign your vcert-task.ps1 with an internal trusted certificate, this will increase security 
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy RemoteSigned -Command `"& { `$playbook_url = '$TLSPC_PlaybookUrl'; `$scriptBlock = [scriptblock]::Create((New-Object System.Net.WebClient).DownloadString('$scriptUrl')); & `$scriptBlock -playbook_url `$playbook_url` }`""

# Set the task to run as the SYSTEM account
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
 
# Register the scheduled task with a specified name
$taskName = "vcert - $playBook"
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Description "runs the vcert playbook, checks certificates(s) and performs renewal when necessary"
Write-Log "Created task succesfully: vcert - $playBook" 