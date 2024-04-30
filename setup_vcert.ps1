param (
    [Parameter(Mandatory=$false)][string]$TLSPC_Hostname,
    [Parameter(Mandatory=$true)][string]$TLSPC_PlaybookUrl, 
    [Parameter(Mandatory=$true)][string]$TLSPC_APIKEY
)

$tempPath = [System.IO.Path]::GetTempPath()
$logFilePath = Join-Path -Path  "$tempPath" "vcert_schtask_setup.txt"

# vcert taks to run on daily basis
$scriptUrl = "https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/vcert-task.ps1"

$playBook = $TLSPC_PlaybookUrl.Split('/')[-1]

# Function to append log messages with timestamps
function Log-Message {
    param (
        [string]$Message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logFilePath -Value "[$timestamp] $Message"
    Write-Host $Message
}

# Check if the script is running with admin privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Log-Message "This script requires administrator privileges. Please run it as an administrator."
    exit
}

# write log entries:
Log-Message "TLSPC_PlaybookUrl = $TLSPC_PlaybookUrl"
Log-Message "playBook          = $playBook"
Log-Message "tempPath          = $tempPath"
Log-Message "scriptUrl         = $scriptUrl"
Log-Message "TLSPC_Hostname    = $TLSPC_Hostname"
Log-Message "TLSPC_APIKEY      = 1234-xxxx"


# Creating the temporary environment variables in the process
if ("TLSPC_Hostname") {
     [Environment]::SetEnvironmentVariable("TLSPC_Hostname",$TLSPC_Hostname, "Machine")
     Log-Message "Sucessfully set TLSPC_Hostname" 
}

#####################################################################################################################
################################### This is for demo/testing purposes only ##########################################
################################### replace it with a better way to        ##########################################
################################### reteive the API key during runtime in  ##########################################
################################### vcert-task.ps1                         ##########################################
#####################################################################################################################

[Environment]::SetEnvironmentVariable("TLSPC_APIKEY",$TLSPC_APIKEY, "Machine")
Log-Message "Sucessfully set TLSPC_APIKEY" 

#####################################################################################################################
################################### /END  demo/testing purposes only       ##########################################
#####################################################################################################################



# Generate a random hour and minute for the task to run
$randomMinute = Get-Random -Minimum 0 -Maximum 59

#Define the action to run PowerShell with URLs as script and 
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-Command `"& { `$playbook_url = '$TLSPC_PlaybookUrl'; `$scriptBlock = [scriptblock]::Create((New-Object System.Net.WebClient).DownloadString('$scriptUrl')); & `$scriptBlock -playbook_url `$playbook_url` }`""

# Create the trigger for daily execution at the randomized time
$trigger = New-ScheduledTaskTrigger -Daily -At (Get-Date -Hour $randomHour -Minute $randomMinute -Second 0)
 
# Set the task to run as the SYSTEM account
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
 
# Register the scheduled task with a specified name
$taskName = "vcert - $playBook"
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Description "runs the vcert playbook, checks certificates(s) and performs renewal when necessary"
Log-Message "Created task succesfully: vcert - $playBook"

# Read-Host -Prompt "Press Enter to exit. 
