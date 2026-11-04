#!/bin/sh
# DocScan — Wazuh MANAGER side (run as root on the manager, once).
#
#   sh cleanup_manager.sh            # apply
#   sh cleanup_manager.sh --dry-run  # show what would change
#
# 1) backs up /var/ossec/etc/ossec.conf
# 2) removes the old active-response wiring: <command> and <active-response> blocks for
#    doc-scan / yara-scan (the agents no longer have those scripts — install.ps1 removed them)
# 3) checks the configuration with wazuh-analysisd -t and only then restarts the manager;
#    on a failed check everything is rolled back.
# Rules for the DocScan JSON events (group "docscan", 101090-101108) live in
# /var/ossec/etc/rules/local_rules.xml — this script does NOT install a second rule set.
set -eu

OSSEC=/var/ossec
CONF=$OSSEC/etc/ossec.conf
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

if [ "$DRY" = 1 ]; then
  rm -f "$TMP"; exit 0
fi

cp -p "$CONF" "$CONF.docscan-$TS.bak"
cat "$TMP" > "$CONF"; rm -f "$TMP"

if ! "$OSSEC/bin/wazuh-analysisd" -t; then
  echo "configuration check FAILED — rolling back"
  cp -p "$CONF.docscan-$TS.bak" "$CONF"
  exit 1
fi

if command -v systemctl >/dev/null; then systemctl restart wazuh-manager; else "$OSSEC/bin/wazuh-control" restart; fi
echo "done. backup: $CONF.docscan-$TS.bak"
[ -f "$OSSEC/etc/rules/docscan_rules.xml" ] && echo "NOTE: $OSSEC/etc/rules/docscan_rules.xml exists — remove it if it duplicates the docscan group in local_rules.xml"
echo "the old decoder 'docscan' (prematch 'wazuh-docscan: ') can stay — nothing produces those lines any more."
