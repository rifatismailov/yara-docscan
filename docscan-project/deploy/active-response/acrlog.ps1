# Show the last 20 lines of this Windows PC's Wazuh Active Response log.
$ErrorActionPreference = 'Stop'
Get-Content "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log" -Tail 20
