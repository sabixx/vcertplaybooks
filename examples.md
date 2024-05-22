This is a demo how to setup vcert with a playbook on a windows system as a scheduled task. 
The only thing that's beeing created by setup-vcert.ps1 is a scheduled task.
No other local files will be created. 

It can be used to create a scheduled task, or just run it once and not run consecutive.

Before using it, check the corresponding playbook it the zone matches your policy, the hostname, domain name and if after install comands comply with your configuration and if your API key, oAuth scope maches the use case.

For other purposes other than demos the scripts should be modified to 'fit for puropose'.

In order to setup a taks the follwoing command can be execute:
 

# Create scheduled Taks:

### for IIS with a website called vcert_website and TLS PC use this:
## TLS PC
```
& {
    $TLSPC_hostname = 'website1';
    $TLSPC_PlaybookUrl = 'https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/TLSPC_US_IIS.yaml';
    $scriptBlock = [scriptblock]::Create((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/setup_vcert.ps1'));
    & $scriptBlock -TLSPC_hostname $TLSPC_hostname -TLSPC_PlaybookUrl $TLSPC_PlaybookUrl
}
```
# with API key (will be set as an encrypted environment variable protected by the DPAPI key)
```
& {
    $TLSPC_hostname = 'website1';
    $TLSPC_PlaybookUrl = 'https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/TLSPC_US_IIS.yaml';
    $TLSPC_APIKEY = 'xxx';
    $scriptBlock = [scriptblock]::Create((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/setup_vcert.ps1'));
    & $scriptBlock -TLSPC_hostname $TLSPC_hostname -TLSPC_PlaybookUrl $TLSPC_PlaybookUrl -TLSPC_APIKEY $TLSPC_APIKEY
}
```

```
& {
    $TLSPC_hostname = 'website1';
    $TLSPC_PlaybookUrl = 'https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/TLSPC_US_IIS_P12.yaml';
    $TLSPC_APIKEY = 'xxx';
    $scriptBlock = [scriptblock]::Create((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/setup_vcert.ps1'));
    & $scriptBlock -TLSPC_hostname $TLSPC_hostname -TLSPC_PlaybookUrl $TLSPC_PlaybookUrl -TLSPC_APIKEY $TLSPC_APIKEY
}
```
## TLS DC
Windows Integrated Auth
```
& {
    $TLSPC_hostname = 'website1';
    $TLSPC_PlaybookUrl = 'https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/TLSDC_US_IIS_No_Install.yaml';
    $scriptBlock = [scriptblock]::Create((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/setup_vcert.ps1'));
    & $scriptBlock -TLSPC_hostname $TLSPC_hostname -TLSPC_PlaybookUrl $TLSPC_PlaybookUrl
}
```

# run once examples:

## TLS PC
``` 
$Env:TLSPC_APIKEY = 'xxxx'
```

```
& { $playbook_url = 'https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/TLSPC_US_IIS_No_Install.yaml'; $scriptBlock = [scriptblock]::Create((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/vcert-task.ps1')); & $scriptBlock -playbook_url $playbook_url }
```

```
& { $playbook_url = 'https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/TLSPC_US_IIS_P12.yaml'; $scriptBlock = [scriptblock]::Create((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/vcert-task.ps1')); & $scriptBlock -playbook_url $playbook_url }
```

## TLS DC
```

```


### Legacy support

To run on Windows Server 2016 and older it TLS 1.2 need to be configured, before running.
```
# Set the Security Protocol to TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
 ```