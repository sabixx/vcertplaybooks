## Deploying VCert at Scale on Windows Systems

This guide is intended to help deploy VCert at scale on Windows systems running in cloud infrastructure or non-domain joined computers. You can also use parts of this guide for domain-joined machines, though additional configurations may be necessary. This guide assumes familiarity with VCert and focuses on best practices for scheduled tasks, log files, and VCert deployment. You should be familiar with configuring Issuing Templates and Applications for TLS Protect Cloud, as well as API integrations and policies for TLS Datacenter.

At the end of this guide, you will know how to set up a scheduled task programmatically, download the latest version (or a version of your choice) of VCert, download a playbook, perform secure on-demand authentication, execute VCert, and understand security considerations and recommendations for logging.

When you want to execute VCert on a scheduled basis on a Windows system, there are a few topics to consider: what is being executed, how and who should run the scheduled task, how to perform the authentication, how to make changes or updates to the process, and how to log what has been executed.

On a high level, we want to perform the following tasks:
1. Download VCert
2. Download the playbook
3. Perform authentication
4. Run VCert
5. Log all actions

If you are in a domain environment, you might consider specific articles on setting up VCert in a domain-joined environment.

## Leveraging These Scripts in a Customer Environment

To deploy VCert at scale in a customer environment, you can host the necessary components on a web server and make appropriate changes to the scripts to fit your specific environment. This section will guide you on how to set up and customize the scripts for your use case.

### Steps to Host and Customize the Scripts

1. **Host VCert on a Web Server**
   - Download the VCert executable and host it on a secure web server accessible by your systems.
   - Update the script to point to the hosted VCert URL instead of the default GitHub URL.

2. **Host Your Playbooks on a Web Server**
   - Create and store your customized playbooks on a secure web server.
   - Ensure the playbooks are accessible by your systems and update the `playbook_url` parameter in the scripts to point to the hosted playbooks.

3. **Host Your Version of `vcert-task.ps1` on a Web Server**
   - Modify the `vcert-task.ps1` script as necessary for your environment.
   - Host the customized script on a secure web server.
   - Update the setup script to download the `vcert-task.ps1` from your web server.

4. **Host Your Version of `setup-scheduled-task.ps1` on a Web Server**
   - Customize the `setup-scheduled-task.ps1` script as necessary for your environment.
   - Host the modified script on a secure web server.
   - Distribute the URL of this script to the systems where you want to set up the scheduled task.

### Example Configuration Changes

Below are examples of how to modify the scripts for a customer environment.

#### Modified `vcert-task.ps1` Script

**Original Download VCert Section:**
```powershell
# Fetch the latest release from GitHub
$apiUrl = "https://api.github.com/repos/Venafi/vcert/releases/latest"
```

**Modified Download VCert Section:**
```powershell
# Fetch the VCert executable from the customer-hosted web server
$vcertUrl = "https://webserver.yourdomain.com/path/to/vcert.zip"
$zipFilePath = Join-Path -Path $tempPath -ChildPath "vcert_latest_windows.zip"
Invoke-WebRequest -Uri $vcertUrl -OutFile $zipFilePath
```

#### Modified `setup-scheduled-task.ps1` Script

**Original Script URL:**
```powershell
$scriptUrl = "https://webserver.yourdomain.com/sabixx/vcertplaybooks/main/vcert-task.ps1"
```

**Modified Script URL:**
```powershell
$scriptUrl = "https://webserver.yourdomain.com/path/to/vcert-task.ps1"
```

### Running the Scripts in Your Environment

1. **Setting Up the Environment**

   Ensure your web server is configured and accessible by all systems that need to run VCert. Verify the URL paths to VCert, playbooks, `vcert-task.ps1`, and `setup-scheduled-task.ps1` are correct and the files are hosted securely.

2. **Executing the Setup Script**

   Use the modified `setup-scheduled-task.ps1` script to set up the scheduled task on each system. Here are two example executions based on different playbooks:

   **Example 1: TLS Protect Cloud (vAaS)**
   ```powershell
   $Env:TLSPC_APIKEY = 'your-api-key'

   & { 
       $playbook_url = 'https://webserver.yourdomain.com/path/to/TLSPC_US_IIS.yaml'; 
       $scriptBlock = [scriptblock]::Create((New-Object System.Net.WebClient).DownloadString('https://webserver.yourdomain.com/path/to/vcert-task.ps1')); 
       & $scriptBlock -playbook_url $playbook_url 
   }
   ```

   **Example 2: TLS Datacenter (TPP)**
   ```powershell
   & { 
       $playbook_url = 'https://webserver.yourdomain.com/path/to/TLSDC_US_IIS.yaml'; 
       $scriptBlock = [scriptblock]::Create((New-Object System.Net.WebClient).DownloadString('https://webserver.yourdomain.com/path/to/vcert-task.ps1')); 
       & $scriptBlock -playbook_url $playbook_url 
   }
   ```

3. **Automating the Setup Across Multiple Systems**

   To automate the setup across multiple systems, you can use a configuration management tool like Ansible, Puppet, or Chef, or a scripting solution like PowerShell remoting or SCCM (System Center Configuration Manager). Ensure each system runs the modified `setup-scheduled-task.ps1` script with the appropriate parameters.

### Security Considerations

- **Secure Web Hosting**: Ensure the web server hosting the scripts and playbooks is secured using HTTPS and appropriate access controls.
- **Sensitive Information**: Avoid hardcoding sensitive information (e.g., API keys) in scripts. Instead, use secure methods like environment variables or secret management systems (e.g., CyberArk) to manage sensitive data.
- **Logging and Monitoring**: Implement robust logging and monitoring to track the execution of scheduled tasks and identify any issues promptly.

By following these steps, you can efficiently deploy VCert at scale in a customer environment, ensuring secure and automated certificate management across your Windows systems.

### Example Playbooks and Script Execution

#### TLS Protect Cloud (vAaS)
Playbook Configuration:
```yaml
config:
  connection:
    platform: vAaS
    credentials:
      apiKey: '{{ Env "TLSPC_APIKEY" }}'
certificateTasks:
  - name: IIS
    renewBefore: 20%
    setEnvVars: ["thumbprint"]
    request:
      csr: service
      subject:
        commonName: '{{ Env "TLSPC_Hostname" }}.mimdemo.com'
      sanDNS: 
        - '{{ Hostname | ToLower -}}.venafidemo.com'
      zone: 'IIS pull\ztAllowAll'
    installations:
      - format: CAPI
        capiLocation: 'LocalMachine\MY'
        useLegacyP12: '{{ Env "useLegacyP12" "false"}}'
        capiFriendlyName: 'vCert Playbook - TLSPC_US_IIS'
        capiIsNonExportable: True
        afterInstallAction: Import-Module Webadministration; Get-WebBinding vcert_website | where {($_.protocol -eq "https")} | % {$_.addsslcertificate($Env:VCERT_IIS_THUMBPRINT, "My")}
```

To execute this playbook:
```powershell
$Env:TLSPC_APIKEY = 'xxxx'

& { $playbook_url = 'https://developer.venafi.com/TLSPC_US_IIS.yaml'; $scriptBlock = [scriptblock]::Create((New-Object System.Net.WebClient).DownloadString('https://developer.venafi.com/vcert-task.ps1')); & $scriptBlock -playbook_url $playbook_url }
```

#### TLS Datacenter (TPP)
Playbook Configuration:
```yaml
config:
  connection:
    platform: tpp
    url: https://dc.tlsp.demo
    credentials:
      accessToken: '{{ Env "TPP_ACCESS_TOKEN" }}'
      refreshToken: '{{ Env "TPP_REFRESH_TOKEN" }}'
certificateTasks:
  - name: IIS
    renewBefore: 20%
    setEnvVars: ["thumbprint"]
    request:
      csr: service
      subject:
        commonName: '{{ Env "TLSPC_Hostname" }}.mimdemo.com'
      sanDNS: 
        - '{{ Hostname | ToLower -}}.venafidemo.com'
      zone: 'Certificates\vcert\IIS'
    installations:
      - format: CAPI
        capiLocation: 'LocalMachine\MY'
        capiFriendlyName: 'vCert Playbook - TLSDC_US_IIS'
        capiIsNonExportable: True
        afterInstallAction: Import-Module Webadministration; Get-WebBinding vcert_website | where {($_.protocol -eq "https")} | % {$_.addsslcertificate($Env:VCERT_IIS_THUMBPRINT, "My")}
```

To execute this playbook:
```powershell
& { $playbook_url = 'https://developer.venafi.com/TLSDC_US_IIS.yaml'; $scriptBlock = [scriptblock]::Create((New-Object System.Net.WebClient).DownloadString('https://developer.venafi.com/vcert-task.ps1')); & $scriptBlock -playbook_url $playbook_url }
```

### Detailed Description of the Execution Script

The script performs several key tasks: downloading VCert and the playbook, performing authentication, running VCert, and logging actions. Below is a detailed explanation of each part of the script:

#### Script Parameters
The script accepts a mandatory parameter `playbook_url`, which is the URL from which the playbook will be downloaded. This ensures the script has the necessary information to retrieve the playbook, making it flexible and reusable.

#### Logging Function
The logging function appends log messages with timestamps to a log file and prints them to the console. This is essential for troubleshooting and auditing, as it provides a traceable record of the script's execution.

```powershell
function Log-Message {
    param ([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logFilePathDownload -Value "[$timestamp] $Message"
    Write-Host $Message
}
```

#### Initialization of Variables and Logging Paths
These variables set up paths for temporary storage and log files, ensuring the script is portable and does not depend on specific file paths.

```powershell
$tempPath = [System.IO.Path]::GetTempPath()
$logFilePathDownload = Join-Path -Path "$tempPath" "vcert_download_log.txt"
$logFilePathRun = Join-Path -Path "$tempPath" "vcert_run_log.txt"
$playBookPath = Join-Path -Path $tempPath -ChildPath $playBook
```

#### Initial Logging of Parameters
This logs the initial parameters and paths being used, providing an initial state log for reference.

```powershell
Log-Message "==== Start ===="
Log-Message "playbook_url  = $playbook_url"
Log-Message "playbook path = $playBookPath"
Log-Message "tempPath      = $tempPath"
Log-Message "task log file = $logFilePathDownload"
Log-Message "vcert log file= $logFilePathRun"
```

#### Check for Administrator Privileges
This check ensures the script is running with the necessary privileges for certain tasks that require administrative rights.

```powershell
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Log-Message "Not running as Administrator. Some use cases require administrator privileges."
}
```

#### Validate `playbook_url` Parameter
This ensures the `playbook_url` parameter is provided, preventing the script from proceeding without this critical information.

```powershell
if (-not $playbook_url) {
    Log-Message "No playbook_url provided, exiting."
    exit
}
```

#### Download the Playbook
This command downloads the playbook from the provided URL to the temporary path, fetching the necessary configuration for VCert.

```powershell
Invoke-WebRequest -Uri $playbook_url -OutFile $playBookPath
Log-Message "Playbook downloaded to $playBookPath"
```

#### Determine the Platform
This block identifies the platform (e.g., `vaas` or `tpp`) specified in the playbook, determining the appropriate authentication and execution method for VCert.

```powershell
try {
    $platform = switch -regex -file "$playBookPath" {'platform:'{"$_"} }
    $platform = $platform -replace 'platform:', ''
    $platform = ($platform.Split("#"))[0].Trim()
    $platform = $platform -replace '[^a-zA-Z0-9]', ''
    Log-Message "Platform = $platform"
} catch {
    Log-Message "Could not determine platform."
}
```

#### Set Environment Variable for Hostname
This sets the `TLSPC_Hostname` environment variable based on the playbook or defaults to the system's hostname, providing necessary context for playbook execution.

```powershell
if (-not [Environment]::GetEnvironmentVariable("TLSPC_Hostname_$playBook", "Machine")) {
    Log-Message "No TLSPC_hostname_$playBook set, using ::GetHostName."
    [Environment]::SetEnvironmentVariable("TLSPC_Hostname", [System.Net.Dns]::GetHostName(), "Process")
} else {
    $Env:TLSPC_Hostname = [System.Environment]::GetEnvironmentVariable("TLSPC_Hostname_$playBook",'Machine')
    Log-Message "Retrieved TLSPC_hostname = $Env:TLSPC_Hostname"
}
```

#### Perform Authentication
This section authenticates with the appropriate platform (TPP or VAAS) using either OAuth tokens or API keys. Secure authentication is crucial for accessing the certificate management system. The script dynamically handles different authentication methods based on the platform, enhancing security and flexibility.


```powershell
switch ($platform) {
    'tpp' {
        try {
            $TPPurl = switch -regex (Get-Content "$playBookPath") {'url:'{"$_"} }
            $TPPurl = $TPPurl -replace 'url:', ''
            $TPPurl = ($TPPurl.Split("#"))[0].Trim()
            Log-Message "TPPurl = $TPPurl"

            $client_id = switch -regex (Get-Content "$playBookPath") {'clientId:'{"$_"} }
            $client_id = $client_id -replace 'clientId:', ''
            $client_id = ($client_id.Split("#"))[0].Trim()
            $client_id = if ($client_id) { $client_id } else { "vcert-cli" }
            Log-Message "client_id = $client_id"

            $response_grant = Invoke-RestMethod "$TPPurl/vedauth/authorize/integrated" -UseDefaultCredentials -Method POST -Body (@{"client_id"="$client_id"; "scope"="certificate:manage"} | ConvertTo-Json) -ContentType "application/json" -UseBasicParsing
            $env:TPP_ACCESS_TOKEN = $response_grant.access_token
            $env:TPP_REFRESH_TOKEN = $response_grant.refresh_token
            Log-Message "Retrieved oAuth bearer token."
        } catch {
            Log-Message "An error occurred retrieving oAuth bearer token: $($_.Exception.Message)"
            Log-Message $response_grant
        }

        if (-not $Env:TPP_ACCESS_TOKEN) {
            Log-Message "No TPP_ACCESS_TOKEN set, exiting."
            exit
        }
    }

    'vaas' {
        if ([Environment]::GetEnvironmentVariable("TLSPC_APIKEY_$playBook", "Machine")) {
            try {
                Add-Type -AssemblyName System.Security
                $encryptedBase64 = ([Environment]::GetEnvironmentVariable("TLSPC_APIKEY_$playBook", "Machine"))
                $SecureStr = [System.Convert]::FromBase64String($encryptedBase64)
                $SecureStr
            } catch {
                Log-Message "An error occurred retrieving TLSPC_APIKEY: $($_.Exception.Message)"
            }
        }

        if (-not $Env:TLSPC_APIKEY) {
            Log-Message "No TLSPC_APIKEY set, exiting."
            exit
        }
    }

    default {
        Log-Message "Unsupported platform: $platform"
        exit
    }
}
```

#### Download the Latest Release of VCert
This section fetches the latest release of VCert from a specified URL, ensuring the script uses the most recent version of the tool.

```powershell
$apiUrl = "https://developer.venafi.com/repos/Venafi/vcert/releases/latest"
Log-Message "Fetching the latest release from $apiUrl"
$latestRelease = Invoke-RestMethod -Uri $apiUrl
Log-Message "Latest release information retrieved."

$windowsZipAsset = $latestRelease.assets | Where-Object { $_.name -match "windows.*\.zip$" } | Select-Object -First 1
if ($null -eq $windowsZipAsset) {
    Log-Message "Windows ZIP file not found in the latest release."
    exit
}

$windowsZipUrl = $windowsZipAsset.browser_download_url
Log-Message "VCert ZIP download URL: $windowsZipUrl"
$zipFilePath = Join-Path -Path $tempPath -ChildPath "vcert_latest_windows.zip"
Invoke-WebRequest -Uri $windowsZipUrl -OutFile $zipFilePath
```

#### Extract VCert and Prepare for Execution
This part extracts the downloaded VCert ZIP file to a temporary directory and prepares the command for execution.

```powershell
Expand-Archive -LiteralPath $zipFilePath -DestinationPath $tempPath -Force
Log-Message "VCert extracted to $tempPath"

$vcertExePath = Join-Path -Path $tempPath -ChildPath "vcert.exe"
Log-Message "==== VCert ===="
$command = '& ' + "$vcertExePath" + ' -version'  + ' 2>&1 | %{ "$_" } | Tee-Object -FilePath ' + "$logFilePathRun" + ' -Append'
Log-Message $command
Invoke-Expression $command
```

#### Run VCert with the Playbook
This defines and executes the command to run VCert using the downloaded playbook, logging the output.

```powershell
$command = '& ' + "$vcertExePath" + ' run -f ' + "$playBookPath" + ' 2>&1 | %{ "$_" } | Tee-Object -FilePath ' + "$logFilePathRun" + ' -Append'
Log-Message $command
Invoke-Expression $command
```

#### Revoke OAuth Token (TPP Only)
After execution, the script revokes the OAuth token to maintain security.

```powershell
switch ($platform) {
    'tpp' { 
        $token = $response_grant.access_token
        $headers = @{
            Authorization = "Bearer $token"
        }
        $response_revoke = Invoke-WebRequest -Uri "$TPPurl/vedauth/Revoke/token" -Method 'GET' -Headers $headers -UseBasicParsing
        if ($response_revoke.StatusCode -eq 200) {
            Log-Message "Status Description: $($response_revoke.StatusDescription)"
        } else {
            Log-Message "Request failed."
            Log-Message "Status Code: $($response_revoke.StatusCode)"
            Log-Message "Status Description: $($response_revoke.StatusDescription)"
        }
    }
}
```

By following this detailed guide, you can efficiently deploy VCert on Windows systems, manage certificates at scale, and maintain high security and logging standards.



## Detailed Description of the Scheduled Task Setup Script

The script for setting up a scheduled task is designed to automate the execution of VCert on a Windows system at a regular interval. This script ensures that VCert runs daily to manage and renew certificates as needed, without manual intervention. It performs several key functions: setting environment variables, creating the scheduled task, and logging the setup process. Below is a detailed explanation of each part of the script.

### General Overview

This script accomplishes the following:
1. Validates and sets environment variables required for VCert execution.
2. Generates a randomized schedule for the task to avoid simultaneous execution on multiple systems.
3. Creates a scheduled task that runs the VCert execution script daily.
4. Logs all actions for auditing and troubleshooting purposes.

### Script Parameters
The script accepts the following parameters:
- `TLSPC_Hostname`: Optional. Specifies the hostname to be used in the playbook.
- `TLSPC_PlaybookUrl`: Mandatory. The URL of the playbook to be executed.
- `TLSPC_APIKEY`: Optional. The API key for authentication, which is recommended to be set at runtime instead of during setup.

```powershell
param (
    [Parameter(Mandatory=$false)][string]$TLSPC_Hostname,
    [Parameter(Mandatory=$true)][string]$TLSPC_PlaybookUrl, 
    [Parameter(Mandatory=$false)][string]$TLSPC_APIKEY
)
```

### Logging Function
The logging function appends log messages with timestamps to a log file and prints them to the console. This ensures that all actions are documented for future reference.

```powershell
function Log-Message {
    param ([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logFilePath -Value "[$timestamp] $Message"
    Write-Host $Message
}
```

### Initialization of Variables and Logging Paths
The script sets up paths for temporary storage and log files, ensuring it does not depend on specific file paths and remains portable.

```powershell
$tempPath = [System.IO.Path]::GetTempPath()
$logFilePath = Join-Path -Path "$tempPath" "vcert_schtask_setup_log.txt"
$scriptUrl = "https://developer.venafi.com/vcertplaybooks/main/vcert-task.ps1"
$playBook = $TLSPC_PlaybookUrl.Split('/')[-1]
```

### Check for Administrator Privileges
This check ensures that the script is running with the necessary privileges to create a scheduled task, which requires administrative rights.

```powershell
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Log-Message "This script requires administrator privileges. Please run it as an administrator."
    exit
}
```

### Initial Logging of Parameters
The script logs the initial parameters and paths being used. This provides a reference point for troubleshooting if needed.

```powershell
Log-Message "TLSPC_PlaybookUrl = $TLSPC_PlaybookUrl"
Log-Message "playBook          = $playBook"
Log-Message "tempPath          = $tempPath"
Log-Message "scriptUrl         = $scriptUrl"
Log-Message "TLSPC_Hostname    = $TLSPC_Hostname"
if ($TLSPC_APIKEY) { Log-Message "TLSPC_APIKEY      = Provided" }
else { Log-Message "TLSPC_APIKEY / TPP_ACCESS_TOKEN = not set, recommended" }
```

### Set Environment Variables
The script sets environment variables necessary for VCert execution, including the hostname and API key, if provided. It encrypts the API key for security.

```powershell
if ($TLSPC_Hostname) {
    [Environment]::SetEnvironmentVariable("TLSPC_Hostname_$playBook", $TLSPC_Hostname, "Machine")
    Log-Message "Successfully set TLSPC_Hostname_$playBook"
}

if ($TLSPC_APIKEY) {
    Log-Message "It is not recommended to provide the API Key with the setup. Instead, leverage vcert-task to determine API key at runtime!"
    Add-Type -AssemblyName System.Security
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($TLSPC_APIKEY)
    $SecureStr = [Security.Cryptography.ProtectedData]::Protect($bytes, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
    $SecureStrBase64 = [System.Convert]::ToBase64String($SecureStr)
    [Environment]::SetEnvironmentVariable("TLSPC_APIKEY_$playBook", $SecureStrBase64, "Machine")
} else {
    Log-Message "TLSPC_APIKEY / TPP_ACCESS_TOKEN determined during runtime."
}
```

### Generate Randomized Schedule
The script generates a randomized hour and minute for the task to run daily. This helps in avoiding simultaneous execution on multiple systems.

```powershell
$randomHour = Get-Random -Minimum 8 -Maximum 10
$randomMinute = Get-Random -Minimum 0 -Maximum 59

# Create the trigger for daily execution at the randomized time
$trigger = New-ScheduledTaskTrigger -Daily -At (Get-Date -Hour $randomHour -Minute $randomMinute -Second 0)
```

### Create Scheduled Task Action
This part creates the scheduled task action, specifying the PowerShell command to be executed. The command runs the VCert task script with the provided playbook URL.

```powershell
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy RemoteSigned -Command `"& { `$playbook_url = '$TLSPC_PlaybookUrl'; `$scriptBlock = [scriptblock]::Create((New-Object System.Net.WebClient).DownloadString('$scriptUrl')); & `$scriptBlock -playbook_url `$playbook_url }`""
```

### Set Task to Run as SYSTEM Account
The script sets the task to run with the SYSTEM account, ensuring it has the necessary permissions to execute VCert and manage certificates.

```powershell
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
```

### Register the Scheduled Task
The script registers the scheduled task with a specified name and logs the completion of the task creation.

```powershell
$taskName = "vcert - $playBook"
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Description "Runs the VCert playbook, checks certificates(s), and performs renewal when necessary"
Log-Message "Created task successfully: vcert - $playBook"
```

By following this detailed guide, you can set up a scheduled task to automate the execution of VCert on Windows systems. This ensures certificates are managed and renewed regularly, maintaining security and reducing manual effort. The script's logging capabilities provide a clear audit trail, making it easier to troubleshoot any issues that arise.
