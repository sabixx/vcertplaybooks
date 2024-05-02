This is a demo how to setup vcert with a playbook on a windows system as a scheduled task. 
The only thing that's beeing created by setup-vcert.ps1 is a scheduled taks.
No other local files will be created

In order to setup a taks the follwoing command can be execute:

Invoke-Expression (Invoke-WebRequest -Uri https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/setup_vcert.ps1 -UseBasicParsing).Content -TLSPChostname website1 -TLSPC_PlaybookUrl https://raw.githubusercontent.com/sabixx/vcertplaybooks/main/TLSPC_US_IIS.yaml -TLSPC_APIKEY "xxx"
