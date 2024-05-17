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
# with API key (will be set as an encrypted environment variable protrected by the DPAPI key)
```
& {
    $TLSPC_hostname = 'website1';
    $TLSPC_PlaybookUrl = 'https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/TLSPC_US_IIS.yaml';
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
& { $playbook_url = 'https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/TLSDC_US_IIS_No_Install.yaml'; $scriptBlock = [scriptblock]::Create((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/vcert-task.ps1')); & $scriptBlock -playbook_url $playbook_url }
```


### Legacy suppoert

To run on Windows Server 2016 and older it TLS 1.2 need to be confiured, before running
It might requier additional changes
```
# Set the Security Protocol to TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
 ```





## Disclaimer

This software is provided "as is", without warranty of any kind, express or
implied, including but not limited to the warranties of merchantability,
fitness for a particular purpose and noninfringement. In no event shall the
authors or copyright holders be liable for any claim, damages or other
liability, whether in an action of contract, tort or otherwise, arising from,
out of or in connection with the software or the use or other dealings in the
software.


## License

Copyright 2024 Jens Sabitzer

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.