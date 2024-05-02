This is a demo how to setup vcert with a playbook on a windows system as a scheduled task. 
The only thing that's beeing created by setup-vcert.ps1 is a scheduled taks.
No other local files will be created

In order to setup a taks the follwoing command can be execute:
 
# Create scheduled Taks:

### for IIS with a website called vcert_website and TLS PC use this:
```
& {
    $TLSPC_hostname = 'website1';
    $TLSPC_PlaybookUrl = 'https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/TLSPC_US_IIS.yaml';
    $scriptBlock = [scriptblock]::Create((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/setup_vcert.ps1'));
    & $scriptBlock -TLSPC_hostname $TLSPC_hostname -TLSPC_PlaybookUrl $TLSPC_PlaybookUrl
}
```
### for Demo purposed, with API Key 
```
& {
    $TLSPC_hostname = 'website1';
    $TLSPC_PlaybookUrl = 'https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/TLSPC_US_IIS.yaml';
    $TLSPC_APIKEY = 'xxx';
    $scriptBlock = [scriptblock]::Create((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/setup_vcert.ps1'));
    & $scriptBlock -TLSPC_hostname $TLSPC_hostname -TLSPC_PlaybookUrl $TLSPC_PlaybookUrl -TLSPC_APIKEY $TLSPC_APIKEY
}
```

# run once examples:

``` 
$Env:TLSPC_APIKEY = 'xxxx'
```

```
& { $playbook_url = 'https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/TLSPC_US_IIS_No_Install.yaml'; $scriptBlock = [scriptblock]::Create((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/vcert-task.ps1')); & $scriptBlock -playbook_url $playbook_url }
```

```
& { $playbook_url = 'https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/TLSPC_US_IIS_P12.yaml'; $scriptBlock = [scriptblock]::Create((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/vcert-task.ps1')); & $scriptBlock -playbook_url $playbook_url }
```
 
