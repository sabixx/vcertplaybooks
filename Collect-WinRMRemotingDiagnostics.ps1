<#
.SYNOPSIS
  Collects WinRM / PowerShell Remoting / auth / policy / firewall / DNS details into a report file.

.DESCRIPTION
  Run locally on the TARGET server in an elevated PowerShell session.
  Produces a timestamped text report under C:\Temp (or current directory if C:\Temp is missing).

  Optional: Provide -TestUser "DOMAIN\User" or ".\LocalUser" to evaluate access likelihood.

.EXAMPLE
  .\Collect-WinRMRemotingDiagnostics.ps1 -TestUser "domain\user"

.EXAMPLE
  .\Collect-WinRMRemotingDiagnostics.ps1 -TestUser "LOCALHOST\localadmin"
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $false)]
  [string]$TestUser
)

# ── Elevation gate (hard exit) ────────────────────────────────────────────────

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) {
  Write-Host ""
  Write-Host "  ERROR: This script must be run as Administrator." -ForegroundColor Red
  Write-Host ""
  Write-Host "  Most WinRM diagnostics require elevation. Without it, the report" -ForegroundColor Yellow
  Write-Host "  will be full of 'Access Denied' errors and the results are useless." -ForegroundColor Yellow
  Write-Host ""
  Write-Host "  How to fix:" -ForegroundColor Cyan
  Write-Host "    1. Right-click PowerShell -> 'Run as administrator'" -ForegroundColor Cyan
  Write-Host "    2. Then re-run:  .\Collect-WinRMRemotingDiagnostics.ps1" -ForegroundColor Cyan
  Write-Host ""
  exit 1
}

# ── Helper functions ──────────────────────────────────────────────────────────

function Write-Section {
  param([string]$Title)
  "`r`n" + ("=" * 80) + "`r`n# $Title`r`n" + ("=" * 80)
}

function Safe-Run {
  param(
    [string]$Label,
    [scriptblock]$Script
  )
  $header = Write-Section $Label
  try {
    $body = & $Script 2>&1 | Out-String
  }
  catch {
    $body = "ERROR: $($_.Exception.Message)`r`n$($_ | Out-String)"
  }
  return "$header`r`n$body"
}

function Test-LocalGroupMembership {
  <#
  .SYNOPSIS
    Tests whether a user is a member of a local group, including NESTED membership
    (e.g. jens -> Domain Admins -> Administrators).
  .DESCRIPTION
    Get-LocalGroupMember only shows direct members. A domain user who is an admin
    via a nested domain group (Domain Admins) won't appear in the direct list.
    This function uses multiple strategies:
      1. If the test user is the CURRENT user, check the Windows token SID list
      2. Use ADSI recursive enumeration of the local group
      3. Fall back to direct member list check
  #>
  param(
    [string]$UserName,
    [string]$GroupName
  )

  $result = @{
    IsMember     = $false
    Method       = "unknown"
    Details      = ""
    DirectMember = $false
  }

  $testUserNormalized = $UserName.ToUpper().Trim()

  # --- Strategy 1: Check the CURRENT user's Windows token ---
  # Most reliable: Windows already resolved all nested groups into the token
  $currentUser = "$env:USERDOMAIN\$env:USERNAME".ToUpper()
  if ($testUserNormalized -eq $currentUser) {
    try {
      $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
      $groupSidMap = @{
        "Administrators"          = "S-1-5-32-544"
        "Remote Management Users" = "S-1-5-32-580"
      }
      if ($groupSidMap.ContainsKey($GroupName)) {
        $targetSid = New-Object System.Security.Principal.SecurityIdentifier($groupSidMap[$GroupName])
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        if ($principal.IsInRole($targetSid)) {
          $result.IsMember = $true
          $result.Method   = "WindowsToken (current user SID groups)"
          $result.Details  = "User's token contains the SID for '$GroupName' ($($groupSidMap[$GroupName]))"
          return $result
        }
      }
    }
    catch { }
  }

  # --- Strategy 2: ADSI recursive member enumeration ---
  # Resolves nested groups (e.g. Domain Admins inside Administrators)
  try {
    $group = [ADSI]"WinNT://./$GroupName,group"
    $members = @($group.PSBase.Invoke("Members")) | ForEach-Object {
      $adspath = $_.GetType().InvokeMember("ADsPath", 'GetProperty', $null, $_, $null)
      $parts = $adspath -replace '^WinNT://', '' -split '/'
      if ($parts.Count -ge 2) {
        "$($parts[0])\$($parts[1])".ToUpper()
      }
    }

    $testUserShort = ($UserName.Split('\'))[-1].ToUpper()

    if ($members -contains $testUserNormalized) {
      $result.IsMember = $true
      $result.Method   = "ADSI recursive enumeration (exact match)"
      $result.Details  = "Found '$testUserNormalized' in recursive member list of '$GroupName'"
      return $result
    }
    elseif ($members | Where-Object { $_ -like "*\$testUserShort" }) {
      $matchedAs = ($members | Where-Object { $_ -like "*\$testUserShort" }) -join ", "
      $result.IsMember = $true
      $result.Method   = "ADSI recursive enumeration (username match)"
      $result.Details  = "Found user as: $matchedAs"
      return $result
    }
  }
  catch {
    $result.Details += "ADSI enumeration failed: $($_.Exception.Message). "
  }

  # --- Strategy 3: Direct member check via Get-LocalGroupMember ---
  try {
    if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue) {
      $directMembers = Get-LocalGroupMember -Group $GroupName -ErrorAction Stop
      $testUserShort = ($UserName.Split('\'))[-1].ToUpper()
      $found = $directMembers | Where-Object { $_.Name.ToUpper() -like "*\$testUserShort" }
      if ($found) {
        $result.IsMember     = $true
        $result.DirectMember = $true
        $result.Method       = "Get-LocalGroupMember (direct member)"
        $result.Details      = "Direct member: $($found.Name)"
        return $result
      }

      $groupMembers = $directMembers | Where-Object { $_.ObjectClass -eq 'Group' }
      if ($groupMembers) {
        $result.Details += "Direct group members that may contain user: $($groupMembers.Name -join ', '). "
      }
    }
  }
  catch {
    $result.Details += "Get-LocalGroupMember failed: $($_.Exception.Message). "
  }

  return $result
}

# ── Output path ───────────────────────────────────────────────────────────────

$ts      = Get-Date -Format "yyyyMMdd-HHmmss"
$outDir  = "C:\Temp"
if (-not (Test-Path $outDir)) { $outDir = (Get-Location).Path }
$outFile = Join-Path $outDir "WinRM-PSRemoting-Diag-$env:COMPUTERNAME-$ts.txt"

# ── Cache CIM queries ────────────────────────────────────────────────────────

$osInfo = Get-CimInstance Win32_OperatingSystem
$csInfo = Get-CimInstance Win32_ComputerSystem

# ── Begin report ──────────────────────────────────────────────────────────────

$report = [System.Text.StringBuilder]::new()

[void]$report.AppendLine("WinRM / PowerShell Remoting Diagnostics")
[void]$report.AppendLine("Computer     : $env:COMPUTERNAME")
[void]$report.AppendLine("User         : $env:USERDOMAIN\$env:USERNAME")
[void]$report.AppendLine("Elevated     : $isAdmin")
[void]$report.AppendLine("Timestamp    : $(Get-Date -Format o)")
[void]$report.AppendLine("OS           : $($osInfo.Caption) $($osInfo.Version)")
[void]$report.AppendLine("Domain       : $($csInfo.Domain)")
[void]$report.AppendLine("PartOfDomain : $($csInfo.PartOfDomain)")
[void]$report.AppendLine("PSVersion    : $($PSVersionTable.PSVersion)")
[void]$report.AppendLine("")

# ── 1) WinRM service + quick self-test ────────────────────────────────────────

[void]$report.AppendLine((Safe-Run "WinRM Service Status" {
  Get-Service WinRM | Format-List Status, StartType, Name, DisplayName, DependentServices, ServicesDependedOn
}))

[void]$report.AppendLine((Safe-Run "WinRM Quick Self-Test (Test-WSMan localhost)" {
  $result = Test-WSMan -ComputerName localhost -ErrorAction Stop
  $result | Format-List *
  "Result: WinRM is responding on localhost."
}))

[void]$report.AppendLine((Safe-Run "WinRM Config: Service" {
  winrm get winrm/config/service 2>&1
}))

[void]$report.AppendLine((Safe-Run "WinRM Config: Client" {
  winrm get winrm/config/client 2>&1
}))

[void]$report.AppendLine((Safe-Run "WinRM Config: Listeners" {
  winrm enumerate winrm/config/listener 2>&1
}))

[void]$report.AppendLine((Safe-Run "WSMan Provider Settings" {
  Get-ChildItem WSMan:\localhost -Recurse -ErrorAction SilentlyContinue |
    Format-Table PSPath, Name, Value -AutoSize -Wrap
}))

# ── 2) PSRemoting endpoints / permissions ─────────────────────────────────────

[void]$report.AppendLine((Safe-Run "PSSession Configurations (endpoints) + Permissions" {
  Get-PSSessionConfiguration -ErrorAction SilentlyContinue |
    Format-List Name, Enabled, Permission, StartupScript, RunAsUser, SecurityDescriptorSddl
}))

# ── 3) Local group membership ─────────────────────────────────────────────────

[void]$report.AppendLine((Safe-Run "Local Groups: Administrators / Remote Management Users / WinRMRemoteWMIUsers__" {
  foreach ($g in @("Administrators", "Remote Management Users", "WinRMRemoteWMIUsers__")) {
    "---- $g ----"
    try {
      if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue) {
        Get-LocalGroupMember -Group $g -ErrorAction Stop |
          Format-Table Name, ObjectClass, PrincipalSource -AutoSize
      }
      else {
        net localgroup $g 2>&1
      }
    }
    catch {
      "Group '$g' not found or could not be enumerated: $($_.Exception.Message)"
    }
    ""
  }
}))

# ── 4) Local Security Policy rights ──────────────────────────────────────────

[void]$report.AppendLine((Safe-Run "Local Security Policy Export (User Rights Assignment highlights)" {
  $cfg = Join-Path $env:TEMP "secpol-$ts.cfg"
  $seceditResult = secedit /export /cfg $cfg 2>&1 | Out-String

  if (-not (Test-Path $cfg)) {
    "secedit export FAILED (requires elevation). Output:`r`n$seceditResult"
    return
  }

  "Exported to: $cfg"
  ""

  $patterns = @(
    'SeNetworkLogonRight',
    'SeDenyNetworkLogonRight',
    'SeRemoteInteractiveLogonRight',
    'SeDenyRemoteInteractiveLogonRight',
    'SeInteractiveLogonRight',
    'SeDenyInteractiveLogonRight',
    'SeBatchLogonRight',
    'SeDenyBatchLogonRight',
    'SeServiceLogonRight',
    'SeDenyServiceLogonRight'
  )

  $content = Get-Content $cfg -ErrorAction Stop
  foreach ($pat in $patterns) {
    $match = $content | Where-Object { $_ -match $pat }
    if ($match) { $match }
    else { "$pat = (not defined in local policy)" }
  }

  Remove-Item $cfg -Force -ErrorAction SilentlyContinue
}))

# ── 5) UAC / Registry knobs ──────────────────────────────────────────────────

[void]$report.AppendLine((Safe-Run "Registry: UAC / Token Filter / WinRM related knobs" {
  $paths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
  )
  foreach ($p in $paths) {
    "---- $p ----"
    if (Test-Path $p) {
      Get-ItemProperty $p -ErrorAction SilentlyContinue | Format-List *
    }
    else { "Path not present." }
    ""
  }

  ""
  "---- Key WinRM-relevant values ----"
  $knobs = @(
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "LocalAccountTokenFilterPolicy"; Desc = "1 = remote local admin gets full token (needed for non-domain WinRM)" },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "FilterAdministratorToken"; Desc = "1 = built-in Admin also filtered" },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "EnableLUA"; Desc = "1 = UAC enabled" }
  )
  foreach ($k in $knobs) {
    try {
      $val = (Get-ItemProperty -Path $k.Path -Name $k.Name -ErrorAction Stop).$($k.Name)
      "{0} = {1}   ({2})" -f $k.Name, $val, $k.Desc
    }
    catch {
      "{0} = (not set)   ({1})" -f $k.Name, $k.Desc
    }
  }
}))

# ── 6) Firewall rules + port listening ────────────────────────────────────────

[void]$report.AppendLine((Safe-Run "Firewall: WinRM Rules + Listening Ports 5985/5986" {
  "---- Listening sockets (TCP 5985 / 5986) ----"
  try {
    if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
      Get-NetTCPConnection -LocalPort 5985, 5986 -ErrorAction SilentlyContinue |
        Format-Table LocalAddress, LocalPort, State, OwningProcess -AutoSize
    }
    else {
      netstat -ano | Select-String ":5985|:5986"
    }
  }
  catch {
    "No listeners found on 5985/5986 (WinRM may not be listening)."
  }
  ""

  "---- Firewall rules: 'Windows Remote Management' group ----"
  try {
    Get-NetFirewallRule -DisplayGroup "Windows Remote Management" -ErrorAction Stop |
      Format-Table Name, Enabled, Profile, Direction, Action -AutoSize
  }
  catch {
    "Get-NetFirewallRule failed or no rules found: $($_.Exception.Message)"
  }
  ""

  "---- Port filters on WinRM firewall rules ----"
  try {
    Get-NetFirewallRule -DisplayGroup "Windows Remote Management" -ErrorAction Stop |
      Get-NetFirewallPortFilter -ErrorAction Stop |
      Format-Table Protocol, LocalPort, RemotePort -AutoSize
  }
  catch {
    "Port filter query failed: $($_.Exception.Message)"
  }
}))

# ── 7) TLS / HTTPS certificate check ─────────────────────────────────────────

[void]$report.AppendLine((Safe-Run "WinRM HTTPS Listener Certificate" {
  $httpsListeners = Get-ChildItem WSMan:\localhost\Listener -ErrorAction SilentlyContinue |
    Where-Object { $_.Keys -contains "Transport=HTTPS" }

  if (-not $httpsListeners) {
    "No HTTPS listener configured. WinRM is HTTP-only (port 5985)."
    "To enable HTTPS, a server certificate is needed and a listener must be created."
    return
  }

  foreach ($listener in $httpsListeners) {
    "HTTPS Listener found:"
    Get-ChildItem "WSMan:\localhost\Listener\$($listener.Name)" -ErrorAction SilentlyContinue |
      Format-Table Name, Value -AutoSize

    $thumbprint = (Get-ChildItem "WSMan:\localhost\Listener\$($listener.Name)" -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -eq "CertificateThumbprint" }).Value

    if ($thumbprint) {
      ""
      "Certificate thumbprint: $thumbprint"
      $cert = Get-ChildItem "Cert:\LocalMachine\My\$thumbprint" -ErrorAction SilentlyContinue
      if ($cert) {
        "  Subject    : $($cert.Subject)"
        "  Issuer     : $($cert.Issuer)"
        "  NotBefore  : $($cert.NotBefore)"
        "  NotAfter   : $($cert.NotAfter)"
        "  HasPrivKey : $($cert.HasPrivateKey)"
        $daysLeft = ($cert.NotAfter - (Get-Date)).Days
        if ($daysLeft -lt 0)       { "  *** CERTIFICATE IS EXPIRED ($daysLeft days) ***" }
        elseif ($daysLeft -lt 30)  { "  *** WARNING: Certificate expires in $daysLeft days ***" }
        else                       { "  Valid for $daysLeft more days." }
      }
      else {
        "  *** Certificate NOT FOUND in LocalMachine\My store! HTTPS will fail. ***"
      }
    }
  }
}))

# ── 8) Event logs (summary only — count of errors/warnings) ──────────────────

[void]$report.AppendLine((Safe-Run "Event Logs: WinRM / PowerShell (error/warning summary)" {
  $logs = @(
    "Microsoft-Windows-WinRM/Operational",
    "Microsoft-Windows-PowerShell/Operational"
  )
  foreach ($log in $logs) {
    "---- $log ----"
    $logExists = Get-WinEvent -ListLog $log -ErrorAction SilentlyContinue
    if (-not $logExists) {
      "Log not found or not enabled."
      ""
      continue
    }

    $recent = Get-WinEvent -LogName $log -MaxEvents 200 -ErrorAction SilentlyContinue
    if (-not $recent) {
      "  No events found."
      ""
      continue
    }

    $errors   = @($recent | Where-Object { $_.Level -eq 2 }).Count
    $warnings = @($recent | Where-Object { $_.Level -eq 3 }).Count
    $info     = @($recent | Where-Object { $_.Level -eq 4 -or $_.Level -eq 0 }).Count
    $oldest   = ($recent | Select-Object -Last 1).TimeCreated
    $newest   = ($recent | Select-Object -First 1).TimeCreated

    "  Events scanned : $($recent.Count) (from $oldest to $newest)"
    "  Errors         : $errors"
    "  Warnings       : $warnings"
    "  Informational  : $info"

    # Show only the last 5 errors/warnings with a one-line summary each
    $problems = $recent | Where-Object { $_.Level -le 3 } | Select-Object -First 5
    if ($problems) {
      ""
      "  Last errors/warnings:"
      foreach ($evt in $problems) {
        $msgShort = ($evt.Message -split "`n")[0].Trim()
        if ($msgShort.Length -gt 120) { $msgShort = $msgShort.Substring(0, 120) + "..." }
        "    [{0}] {1} ID={2}: {3}" -f $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss"), $evt.LevelDisplayName, $evt.Id, $msgShort
      }
    }
    ""
  }
}))

# ── 9) Host identity / DNS ────────────────────────────────────────────────────

[void]$report.AppendLine((Safe-Run "Host Identity / DNS" {
  "Hostname  : $env:COMPUTERNAME"
  try   { "FQDN      : $([System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName)" }
  catch { "FQDN      : (could not resolve)" }
  ""
  "IP Addresses:"
  Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -ne "127.0.0.1" } |
    Format-Table InterfaceAlias, IPAddress, PrefixLength -AutoSize
  ""
  "DNS Servers:"
  Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
    Where-Object { $_.ServerAddresses } |
    Format-Table InterfaceAlias, ServerAddresses -AutoSize
}))

# ── 10) Optional: evaluate a specific user ────────────────────────────────────

if ($TestUser) {
  [void]$report.AppendLine((Safe-Run "TEST USER EVALUATION: $TestUser" {
    "Requested principal: $TestUser"
    ""

    # --- SID Resolution ---
    "--- SID Resolution ---"
    try {
      $nt  = New-Object System.Security.Principal.NTAccount($TestUser)
      $resolvedSid = $nt.Translate([System.Security.Principal.SecurityIdentifier])
      "SID: $resolvedSid"
    }
    catch {
      "Could not translate to SID (domain unreachable / account unknown): $($_.Exception.Message)"
    }
    ""

    # --- Group Membership (with nested group support) ---
    "--- Group Membership (includes nested groups: e.g. Domain Admins -> Administrators) ---"

    $adminCheck = Test-LocalGroupMembership -UserName $TestUser -GroupName "Administrators"
    $rmuCheck   = Test-LocalGroupMembership -UserName $TestUser -GroupName "Remote Management Users"

    "  Administrators         : $(if ($adminCheck.IsMember) { 'YES' } else { 'NO' })"
    if ($adminCheck.IsMember) {
      "    Method  : $($adminCheck.Method)"
      "    Details : $($adminCheck.Details)"
    }
    elseif ($adminCheck.Details) {
      "    Note    : $($adminCheck.Details)"
    }

    "  Remote Management Users: $(if ($rmuCheck.IsMember) { 'YES' } else { 'NO' })"
    if ($rmuCheck.IsMember) {
      "    Method  : $($rmuCheck.Method)"
      "    Details : $($rmuCheck.Details)"
    }
    elseif ($rmuCheck.Details) {
      "    Note    : $($rmuCheck.Details)"
    }
    ""

    # Show direct members for reference
    "--- Direct members of Administrators (for reference) ---"
    try {
      if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue) {
        Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop |
          Format-Table Name, ObjectClass, PrincipalSource -AutoSize
      }
      else { net localgroup Administrators 2>&1 }
    }
    catch { "Could not enumerate: $($_.Exception.Message)" }
    ""

    # --- Endpoint SDDL ---
    "--- Endpoint Security (Microsoft.PowerShell) ---"
    try {
      $epCfg = Get-PSSessionConfiguration -Name "Microsoft.PowerShell" -ErrorAction Stop
      "Permission : $($epCfg.Permission)"
      "SDDL       : $($epCfg.SecurityDescriptorSddl)"
    }
    catch {
      "Could not read endpoint config (requires elevation): $($_.Exception.Message)"
    }
    ""

    # --- Access Verdict ---
    "============================================"
    "  ACCESS VERDICT"
    "============================================"

    if ($adminCheck.IsMember) {
      ">>> User IS a local Administrator (via: $($adminCheck.Method))"
      ""

      # Determine if domain or local account
      $isDomainAccount = $false
      if ($TestUser -match '\\') {
        $domain = $TestUser.Split('\')[0].ToUpper()
        $isDomainAccount = ($domain -ne '.') -and
                           ($domain -ne $env:COMPUTERNAME.ToUpper()) -and
                           ($csInfo.PartOfDomain -eq $true)
      }

      if ($isDomainAccount) {
        "Domain admin account -> UAC token filtering does NOT apply to domain accounts."
        "WinRM remoting SHOULD WORK with full admin privileges."
        ""
        "NOTE: Re-run this script from an ELEVATED prompt to verify all WinRM config details."
      }
      else {
        $ltfp = $null
        try {
          $ltfp = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
            -Name "LocalAccountTokenFilterPolicy" -ErrorAction Stop).LocalAccountTokenFilterPolicy
        }
        catch { }

        if ($ltfp -eq 1) {
          "Local admin with LocalAccountTokenFilterPolicy = 1"
          "-> Full elevated token via WinRM. Remoting SHOULD WORK."
        }
        else {
          "Local admin but LocalAccountTokenFilterPolicy is NOT set."
          "-> WinRM will connect but get a FILTERED (non-admin) token due to UAC."
          "-> Many operations will fail with 'Access Denied'."
          ""
          "Fix: Set-ItemProperty -Path 'HKLM:\...\Policies\System' -Name 'LocalAccountTokenFilterPolicy' -Value 1 -Type DWord"
        }
      }
    }
    elseif ($rmuCheck.IsMember) {
      ">>> User is in 'Remote Management Users' -> WinRM access SHOULD WORK (non-admin, limited)."
    }
    else {
      ">>> User is NOT in Administrators or Remote Management Users."
      ">>> WinRM access will likely be DENIED unless the endpoint SDDL grants explicit access."
      ""
      "Possible fixes:"
      "  1. Add-LocalGroupMember -Group 'Remote Management Users' -Member '$TestUser'"
      "  2. Add-LocalGroupMember -Group 'Administrators' -Member '$TestUser'"
    }
    ""

    "--- Manual test command ---"
    "  Enter-PSSession -ComputerName $env:COMPUTERNAME -Credential (Get-Credential '$TestUser') -Authentication Negotiate"
  }))
}

# ── Automated Preflight Summary ───────────────────────────────────────────────

$summary = [System.Text.StringBuilder]::new()
[void]$summary.AppendLine("")
[void]$summary.AppendLine("=" * 80)
[void]$summary.AppendLine("  WINRM READINESS CHECK")
[void]$summary.AppendLine("=" * 80)
[void]$summary.AppendLine("")

$allPass = $true

# Check 1: Elevated?
if ($isAdmin) {
  [void]$summary.AppendLine("  [PASS] Running elevated (Administrator)")
}
else {
  [void]$summary.AppendLine("  [FAIL] NOT running elevated - results will be incomplete")
  [void]$summary.AppendLine("         Fix: Right-click PowerShell -> 'Run as administrator'")
  $allPass = $false
}

# Check 2: WinRM service running?
$winrmSvc = Get-Service WinRM -ErrorAction SilentlyContinue
if ($winrmSvc -and $winrmSvc.Status -eq 'Running') {
  [void]$summary.AppendLine("  [PASS] WinRM service is running (StartType: $($winrmSvc.StartType))")
}
elseif ($winrmSvc) {
  [void]$summary.AppendLine("  [FAIL] WinRM service exists but is $($winrmSvc.Status) (StartType: $($winrmSvc.StartType))")
  [void]$summary.AppendLine("         Fix: Start-Service WinRM; Set-Service WinRM -StartupType Automatic")
  $allPass = $false
}
else {
  [void]$summary.AppendLine("  [FAIL] WinRM service not found")
  [void]$summary.AppendLine("         Fix: Enable-PSRemoting -Force")
  $allPass = $false
}

# Check 3: Ports 5985/5986 listening?
$listening5985 = $false
$listening5986 = $false
try {
  if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
    $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
    $listening5985 = ($listeners | Where-Object { $_.LocalPort -eq 5985 }) -ne $null
    $listening5986 = ($listeners | Where-Object { $_.LocalPort -eq 5986 }) -ne $null
  }
  else {
    $netstatOut = netstat -ano 2>$null
    $listening5985 = ($netstatOut | Select-String ":5985.*LISTENING") -ne $null
    $listening5986 = ($netstatOut | Select-String ":5986.*LISTENING") -ne $null
  }
}
catch { }

if ($listening5985 -or $listening5986) {
  $ports = @()
  if ($listening5985) { $ports += "5985 (HTTP)" }
  if ($listening5986) { $ports += "5986 (HTTPS)" }
  [void]$summary.AppendLine("  [PASS] Listening on port(s): $($ports -join ', ')")
}
else {
  [void]$summary.AppendLine("  [FAIL] Not listening on 5985 or 5986")
  [void]$summary.AppendLine("         Fix: Enable-PSRemoting -Force; or check WinRM listeners")
  $allPass = $false
}

# Check 4: Firewall rules enabled?
$fwPass = $false
try {
  $fwRules = Get-NetFirewallRule -DisplayGroup "Windows Remote Management" -ErrorAction Stop
  $enabledRules = $fwRules | Where-Object { $_.Enabled -eq $true -and $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' }
  if ($enabledRules) {
    $profiles = ($enabledRules | ForEach-Object { $_.Profile }) -join ', '
    [void]$summary.AppendLine("  [PASS] Firewall allows WinRM inbound (Profiles: $profiles)")
    $fwPass = $true
  }
}
catch { }
if (-not $fwPass) {
  [void]$summary.AppendLine("  [FAIL] No enabled inbound firewall rules for WinRM")
  [void]$summary.AppendLine("         Fix: Enable-PSRemoting -Force; or enable 'Windows Remote Management' firewall rules")
  $allPass = $false
}

# Check 5: User group membership (only if -TestUser provided)
if ($TestUser) {
  $adminChk = Test-LocalGroupMembership -UserName $TestUser -GroupName "Administrators"
  $rmuChk   = Test-LocalGroupMembership -UserName $TestUser -GroupName "Remote Management Users"

  if ($adminChk.IsMember) {
    [void]$summary.AppendLine("  [PASS] '$TestUser' is in Administrators (via: $($adminChk.Method))")

    # Check 6: LocalAccountTokenFilterPolicy (only relevant for local admin accounts)
    $isDomainAcct = $false
    if ($TestUser -match '\\') {
      $dom = $TestUser.Split('\')[0].ToUpper()
      $isDomainAcct = ($dom -ne '.') -and ($dom -ne $env:COMPUTERNAME.ToUpper()) -and ($csInfo.PartOfDomain)
    }

    if ($isDomainAcct) {
      [void]$summary.AppendLine("  [PASS] Domain account - UAC token filtering does not apply")
    }
    else {
      $ltfp = $null
      try {
        $ltfp = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
          -Name "LocalAccountTokenFilterPolicy" -ErrorAction Stop).LocalAccountTokenFilterPolicy
      }
      catch { }

      if ($ltfp -eq 1) {
        [void]$summary.AppendLine("  [PASS] LocalAccountTokenFilterPolicy = 1 (full remote admin token)")
      }
      else {
        [void]$summary.AppendLine("  [WARN] LocalAccountTokenFilterPolicy not set - local admin gets filtered token via WinRM")
        [void]$summary.AppendLine("         Fix: Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy' -Value 1 -Type DWord")
        $allPass = $false
      }
    }
  }
  elseif ($rmuChk.IsMember) {
    [void]$summary.AppendLine("  [PASS] '$TestUser' is in Remote Management Users (non-admin, limited)")
  }
  else {
    [void]$summary.AppendLine("  [FAIL] '$TestUser' is NOT in Administrators or Remote Management Users")
    $detail = ""
    if ($adminChk.Details) { $detail = " ($($adminChk.Details))" }
    if ($detail) { [void]$summary.AppendLine("         Note:$detail") }
    [void]$summary.AppendLine("         Fix: Add-LocalGroupMember -Group 'Remote Management Users' -Member '$TestUser'")
    $allPass = $false
  }
}
else {
  [void]$summary.AppendLine("  [SKIP] User group check - no -TestUser specified")
}

# Overall verdict
[void]$summary.AppendLine("")
if ($allPass) {
  [void]$summary.AppendLine("  >>> VERDICT: WinRM remoting should work.")
}
else {
  [void]$summary.AppendLine("  >>> VERDICT: Issues found - see FAIL/WARN items above.")
}
[void]$summary.AppendLine("")
[void]$summary.AppendLine("=" * 80)

# Prepend summary to the top of the report (after the header)
$finalReport = $report.ToString()
$headerEnd   = $finalReport.IndexOf("`r`n`r`n=")
if ($headerEnd -lt 0) { $headerEnd = $finalReport.IndexOf("`n`n=") }
if ($headerEnd -gt 0) {
  $finalReport = $finalReport.Substring(0, $headerEnd) + "`r`n" + $summary.ToString() + $finalReport.Substring($headerEnd)
}
else {
  $finalReport = $summary.ToString() + "`r`n" + $finalReport
}

# ── Write report ──────────────────────────────────────────────────────────────

$finalReport | Out-File -FilePath $outFile -Encoding UTF8

# Also print the summary to console
$summaryText = $summary.ToString()
foreach ($line in ($summaryText -split "`r?`n")) {
  if     ($line -match '\[PASS\]')    { Write-Host $line -ForegroundColor Green }
  elseif ($line -match '\[FAIL\]')    { Write-Host $line -ForegroundColor Red }
  elseif ($line -match '\[WARN\]')    { Write-Host $line -ForegroundColor Yellow }
  elseif ($line -match '\[SKIP\]')    { Write-Host $line -ForegroundColor DarkGray }
  elseif ($line -match 'VERDICT.*should work') { Write-Host $line -ForegroundColor Green }
  elseif ($line -match 'VERDICT.*Issues')      { Write-Host $line -ForegroundColor Red }
  elseif ($line -match 'Fix:')        { Write-Host $line -ForegroundColor Cyan }
  else                                { Write-Host $line }
}

Write-Host ""
Write-Host "Full report: $outFile" -ForegroundColor Green
