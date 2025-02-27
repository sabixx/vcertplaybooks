This is a demo how to setup vcert with a playbook on a windows system as a scheduled task. 
The only thing that's beeing created by setup-vcert.ps1 is a scheduled task.
No other local files will be created. 

It can be used to create a scheduled task, or just run it once and not run consecutive.

Before using it, check the corresponding playbook it the zone matches your policy, the hostname, domain name and if after install comands comply with your configuration and if your API key, oAuth scope maches the use case.

For other purposes other than demos the scripts should be modified to 'fit for puropose'.

In order to setup a taks the follwoing command can be execute:
 

# Create a scheduled Taks:

# ServiceAccount and exteranl JWT authentication
```
$TLSPC_OAuthIdpURL = https://dev-opv4np2n306var5k.us.auth0.com/oauth/token
$TLSPC_tokenURL = https://api.venafi.cloud/v1/oauth2/v2.0/8152c781-d872-11ec-a937-d73bd47a18d5/token
$TLSPC_ClientID = "ZwkLAcWEE2gwz7ntpmlD76gQFhHXNVPP"
$TLSPC_ClientSecret = 'xxx'
$TLSPC_SyslogServer = "k8cluster.tlsp.demo"
$TLSPC_SyslogPort = 514; 

& {
    $TLSPC_hostname = 'vcert_website';
    $TLSPC_PlaybookUrl = 'https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/TLSPC_US_IIS_ServiceAccount.yaml';
    $scriptBlock = [scriptblock]::Create((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/setup_vcert.ps1'));
    & $scriptBlock -TLSPC_hostname $TLSPC_hostname -TLSPC_PlaybookUrl $TLSPC_PlaybookUrl -TLSPC_OAuthIdpURL $TLSPC_OAuthIdpURL -TLSPC_tokenURL $TLSPC_tokenURL -TLSPC_ClientID $TLSPC_ClientID -TLSPC_ClientSecret $TLSPC_ClientSecret -TLSPC_SyslogServer $TLSPC_SyslogServer -TLSPC_SyslogPort $TLSPC_SyslogPort
}
```

## RDP 
```
$TLSPC_OAuthIdpURL = "https://dev-opv4np2n306var5k.us.auth0.com/oauth/token"
$TLSPC_tokenURL = "https://api.venafi.cloud/v1/oauth2/v2.0/8152c781-d872-11ec-a937-d73bd47a18d5/token"
$TLSPC_ClientID = "ZwkLAcWEE2gwz7ntpmlD76gQFhHXNVPP"
$TLSPC_ClientSecret = 'xxx'
$TLSPC_SyslogServer = "k8cluster.tlsp.demo"
$TLSPC_SyslogPort = 514; 

& {
    # $TLSPC_hostname = ''; #not set, using the hostname
    $TLSPC_PlaybookUrl = 'https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/TLSPC_US_RDP_Demo.yaml';
    $scriptBlock = [scriptblock]::Create((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/setup_vcert.ps1'));
    & $scriptBlock -TLSPC_hostname $TLSPC_hostname -TLSPC_PlaybookUrl $TLSPC_PlaybookUrl -TLSPC_OAuthIdpURL $TLSPC_OAuthIdpURL -TLSPC_tokenURL $TLSPC_tokenURL -TLSPC_ClientID $TLSPC_ClientID -TLSPC_ClientSecret $TLSPC_ClientSecret -TLSPC_SyslogServer $TLSPC_SyslogServer -TLSPC_SyslogPort $TLSPC_SyslogPort
} 
```


## TLS DC with Windows Integrated Auth

### IIS DC demo
```
& {
    $TLSPC_hostname = 'vcert_website';
    $TLSPC_PlaybookUrl = 'https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/TLSDC_IIS_Demo.yaml';
    $scriptBlock = [scriptblock]::Create((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/setup_vcert.ps1'));
    & $scriptBlock -TLSPC_hostname $TLSPC_hostname -TLSPC_PlaybookUrl $TLSPC_PlaybookUrl -TLSPC_SyslogServer $TLSPC_SyslogServer -TLSPC_SyslogPort $TLSPC_SyslogPort
}
```

### RDP DC demo
```
& {
    $TLSPC_hostname = '';
    $TLSPC_SyslogServer = "k8cluster.tlsp.demo"
    $TLSPC_SyslogPort = 514; 
    $TLSPC_PlaybookUrl = 'https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/TLSDC_RDP_Demo.yaml';
    $scriptBlock = [scriptblock]::Create((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/setup_vcert.ps1'));
    & $scriptBlock -TLSPC_hostname $TLSPC_hostname -TLSPC_PlaybookUrl $TLSPC_PlaybookUrl -TLSPC_SyslogServer $TLSPC_SyslogServer -TLSPC_SyslogPort $TLSPC_SyslogPort
}
```



# run once examples:

## TLS PC US

```
$TLSPC_OAuthIdpURL = "https://dev-opv4np2n306var5k.us.auth0.com/oauth/token"
$TLSPC_tokenURL = "https://api.venafi.cloud/v1/oauth2/v2.0/8152c781-d872-11ec-a937-d73bd47a18d5/token"
$TLSPC_ClientID = "ZwkLAcWEE2gwz7ntpmlD76gQFhHXNVPP"
$TLSPC_ClientSecret = 'xxx'
$TLSPC_PlaybookUrl = 'https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/TLSPC_US_IIS_ServiceAccount.yaml';
$TLSPC_hostname = 'vcert_website';

& { $scriptBlock = [scriptblock]::Create((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/vcert-task.ps1')); & $scriptBlock -playbook_url $TLSPC_PlaybookUrl -TLSPC_OAuthIdpURL $TLSPC_OAuthIdpURL -TLSPC_tokenURL $TLSPC_tokenURL -TLSPC_ClientID $TLSPC_ClientID -TLSPC_ClientSecret $TLSPC_ClientSecret -TLSPC_SyslogServer 'k8cluster.tlsp.demo' -TLSPC_SyslogPort '514' }
```

## TLS DC with Windows Integrated Auth
```
& { $playbook_url = 'https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/TLSDC_US_IIS_No_Install.yaml'; $scriptBlock = [scriptblock]::Create((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/vcert-task.ps1')); & $scriptBlock -playbook_url $playbook_url -TLSPC_SyslogServer 'k8cluster.tlsp.demo' -TLSPC_SyslogPort '514' }
```


## TLSPC enable WINRM

``` 
$Env:TLSPC_APIKEY = 'xxxx'
& { $playbook_url = 'https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/TLSPC_ENABLE_WINRM_HTTPS_Demo.yaml'; $scriptBlock = [scriptblock]::Create((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/vcert-task.ps1')); & $scriptBlock -playbook_url $playbook_url 
```

# Deprecated via API key

``` 
$Env:TLSPC_APIKEY = 'xxxx'

& { $playbook_url = 'https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/TLSPC_US_IIS.yaml'; $scriptBlock = [scriptblock]::Create((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/vcert-task.ps1')); & $scriptBlock -playbook_url $playbook_url -TLSPC_SyslogServer 'k8cluster.tlsp.demo' -TLSPC_SyslogPort '514' }
```


### Legacy support

To run on Windows Server 2016 and older it TLS 1.2 need to be configured, before running.
```
# Set the Security Protocol to TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
 ```
