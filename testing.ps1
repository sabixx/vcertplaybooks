param (
    [Parameter(Mandatory=$true)][string]$playbook_url
) 

$tempPath = [System.IO.Path]::GetTempPath()

$logFilePath = Join-Path -Path  "$tempPath" "vcert_testing_log.txt"

# Function to append log messages with timestamps
function Log-Message {
    param (
        [string]$Message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logFilePath -Value "[$timestamp] $Message"
    Write-Host $Message
}

Log-Message "==== Start ===="


# check is playbook_url was provided
if (-not $playbook_url) {
    Log-Message "no playbook_url provided, existing."
    exit
} else {
    Log-Message "using playbook_url = $playbook_url"
}

Log-Message "still running.... "