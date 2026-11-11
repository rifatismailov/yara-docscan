# Convenience bootstrapper for installing the Wazuh CommandRunner.
$ErrorActionPreference = 'Stop'
irm 'http://<server>:8080/active-response/Install-CommandRunner.ps1' | iex
