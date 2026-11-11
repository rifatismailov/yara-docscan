Wazuh Active Response: run an approved policy script on Windows agents
====================================================================

This folder contains a local Wazuh entry point. The manager sends a relative
script path. The agent downloads that .ps1 from the fixed server URL, checks
its SHA256 sidecar, and runs it as the Wazuh agent service account (normally
LocalSystem).

One-time setup on each Windows PC
---------------------------------
Run Install-CommandRunner.ps1 from an elevated PowerShell after publishing
CommandRunner.zip and CommandRunner.zip.sha256 at:
  http://<server>:8080/active-response/

Publish a policy script
-----------------------
Put the approved script and its SHA256 sidecar in any directory on the HTTP
server, for example:
  /policy/al_enf_ad.ps1
  /policy/al_enf_ad.ps1.sha256

The sidecar must contain the lowercase or uppercase SHA256 hex digest (a
standard "<hash>  <filename>" line is fine). The runner refuses to execute
scripts without a matching sidecar. Paths are relative to
http://<server>:8080 and may contain folders, e.g. policy/al_enf_ad.ps1
or scripts/db_refresh.ps1. Each path segment must contain only letters,
digits, underscore, or hyphen; traversal, backslashes, URLs, and other hosts
are rejected.

Run on all agents
-----------------
In Wazuh API Console, send:
  PUT /active-response
  {"command":"!commanda-runer.cmd","arguments":["policy/al_enf_ad.ps1"]}

Omitting agents_list selects all agents. To target selected agents, add
?agents_list=001,002 to the endpoint. The same runner can execute a different
approved .ps1 by changing the argument, for example
maintenance/db_refresh.ps1.

Important behavior
------------------
Scripts execute with SYSTEM-level permissions. Only publish scripts reviewed
for this privilege. This deployment currently uses HTTP on the internal
network; SHA256 fetched from the same HTTP server detects accidental
corruption but does not authenticate the publisher. Use HTTPS with a trusted
certificate or a separately trusted signature before relying on it across an
untrusted network.

The runner writes its status to the Windows agent's active-responses.log. That
local file is not automatically an alert in Wazuh Discover; configure agent
log collection and matching rules if centralized results are required.
