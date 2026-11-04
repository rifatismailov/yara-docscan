#!/bin/sh
# DocScan — Wazuh MANAGER side (run as root on the manager, once).
#
#   sh cleanup_manager.sh            # apply
#   sh cleanup_manager.sh --dry-run  # show what would change
#
# 1) backs up /var/ossec/etc/ossec.conf
# 2) removes the old active-response wiring: <command> and <active-response> blocks for
#    doc-scan / yara-scan (the agents no longer have those scripts — install.ps1 removed them)
# 3) installs /var/ossec/etc/rules/docscan_rules.xml for the new DocScan JSON events
#    (agents ship C:\ProgramData\DocScan\results\docscan-results.json via <localfile> json)
# 4) checks the configuration with wazuh-analysisd -t and only then restarts the manager;
#    on a failed check everything is rolled back.
set -eu

OSSEC=/var/ossec
CONF=$OSSEC/etc/ossec.conf
RULES=$OSSEC/etc/rules/docscan_rules.xml
TS=$(date +%Y%m%d-%H%M%S)
DRY=0; [ "${1:-}" = "--dry-run" ] && DRY=1

[ -f "$CONF" ] || { echo "no $CONF — is this the Wazuh manager?"; exit 1; }
command -v perl >/dev/null || { echo "perl is required"; exit 1; }

TMP=$(mktemp)
# drop <command>..</command> / <active-response>..</active-response> that mention doc-scan or yara-scan
# order matters: <active-response> first (it contains a nested <command>name</command>),
# then the <command> DEFINITIONS (the ones with <name>)
perl -0777 -pe '
  s{[ \t]*<active-response>(?:(?!</active-response>).)*?\b(?:doc-scan|yara-scan)\b(?:(?!</active-response>).)*?</active-response>[ \t]*\r?\n?}{}gs;
  s{[ \t]*<command>(?:(?!</command>).)*?<name>\s*(?:doc-scan|yara-scan)\s*</name>(?:(?!</command>).)*?</command>[ \t]*\r?\n?}{}gs;
' "$CONF" > "$TMP"

echo "--- ossec.conf changes:"
diff -u "$CONF" "$TMP" || true

RULES_XML='<!-- DocScan (yara64 + watcher): events from C:\ProgramData\DocScan\results\docscan-results.json
     shipped by the agent with <localfile><log_format>json</log_format>. IDs 101200-101209. -->
<group name="docscan,">

  <rule id="101200" level="3">
    <decoded_as>json</decoded_as>
    <field name="source">^docscan$</field>
    <description>DocScan: $(verdict) $(file.path)</description>
  </rule>

  <rule id="101201" level="12">
    <if_sid>101200</if_sid>
    <field name="verdict">^HIGH$</field>
    <description>DocScan HIGH: $(docscan.findings) in $(file.path) (disarm: $(disarm))</description>
    <group>docscan_high,</group>
  </rule>

  <rule id="101202" level="7">
    <if_sid>101200</if_sid>
    <field name="verdict">^MEDIUM$</field>
    <description>DocScan MEDIUM: $(docscan.findings) in $(file.path)</description>
  </rule>

  <rule id="101203" level="10">
    <if_sid>101200</if_sid>
    <field name="disarm">^failed</field>
    <description>DocScan: disarm FAILED for $(file.path): $(disarm)</description>
  </rule>

  <rule id="101204" level="5">
    <if_sid>101200</if_sid>
    <field name="verdict">^ERROR$</field>
    <description>DocScan: scan error for $(file.path)</description>
  </rule>

</group>'

if [ "$DRY" = 1 ]; then
  echo "--- would write $RULES:"; echo "$RULES_XML"; rm -f "$TMP"; exit 0
fi

cp -p "$CONF" "$CONF.docscan-$TS.bak"
[ -f "$RULES" ] && cp -p "$RULES" "$RULES.docscan-$TS.bak"
cat "$TMP" > "$CONF"; rm -f "$TMP"
echo "$RULES_XML" > "$RULES"
chown root:wazuh "$RULES" 2>/dev/null || true
chmod 660 "$RULES"

if ! "$OSSEC/bin/wazuh-analysisd" -t; then
  echo "configuration check FAILED — rolling back"
  cp -p "$CONF.docscan-$TS.bak" "$CONF"
  if [ -f "$RULES.docscan-$TS.bak" ]; then cp -p "$RULES.docscan-$TS.bak" "$RULES"; else rm -f "$RULES"; fi
  exit 1
fi

if command -v systemctl >/dev/null; then systemctl restart wazuh-manager; else "$OSSEC/bin/wazuh-control" restart; fi
echo "done. backup: $CONF.docscan-$TS.bak ; rules: $RULES"
echo "the old decoder 'docscan' and rules 101090-101108 (wazuh-docscan: lines) can stay — nothing produces them any more."
