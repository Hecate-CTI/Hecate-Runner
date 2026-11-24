#!/usr/bin/env bash
# Apply BAS optional/live-only policy into service env files and restart Hecate.
# Requires sudo. Usage: sudo bash scripts/apply-bas-policy-restart.sh
set -euo pipefail

TECHNIQUES='T1003.008,T1005,T1007,T1016,T1018,T1027,T1033,T1036.005,T1041,T1046,T1049,T1053.003,T1057,T1059.004,T1069.001,T1070.004,T1071.001,T1082,T1083,T1087.001,T1105,T1124,T1140,T1190,T1222.002,T1518.001,T1526,T1543.002,T1552.001,T1613'

upsert() {
  local file="$1" key="$2" value="$3"
  if [[ ! -f "$file" ]]; then
    echo "missing env file: $file" >&2
    exit 1
  fi
  if grep -q "^${key}=" "$file"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "$file"
  else
    printf '\n%s=%s\n' "$key" "$value" >>"$file"
  fi
  echo "  set ${key} in ${file}"
}

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run with sudo: sudo bash $0" >&2
  exit 1
fi

echo "Updating service env files..."
for envfile in /etc/hecate/reader.env /etc/hecate/writer.env /etc/hecate/slack.env; do
  if [[ ! -f "$envfile" ]]; then
    echo "  skip missing $envfile"
    continue
  fi
  upsert "$envfile" HECATE_BAS_ENABLED true
  upsert "$envfile" HECATE_BAS_MODE caldera
  upsert "$envfile" HECATE_BAS_AUTO_EXECUTE_LIVE true
  upsert "$envfile" HECATE_BAS_FALLBACK_TO_MOCK false
  upsert "$envfile" HECATE_RUNNER_ALLOW_MOCK false
  upsert "$envfile" HECATE_BAS_AUTO_TECHNIQUES "$TECHNIQUES"
done

echo "Restarting services..."
systemctl restart hecate-runner-daemon.service hecate-runner-maintenance.service hecate-slack-bot.service
sleep 2
systemctl is-active hecate-runner-daemon.service hecate-runner-maintenance.service hecate-slack-bot.service

echo "Daemon BAS env:"
pid="$(systemctl show -p MainPID --value hecate-runner-daemon.service)"
tr '\0' '\n' <"/proc/${pid}/environ" | grep -E '^HECATE_BAS_|^HECATE_RUNNER_ALLOW_MOCK=' | sort

echo "Done."
