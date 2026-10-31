#!/usr/bin/env bash
# Run only the script shipped with the verified Actions artifact, as the
# administrator of an explicitly prepared dedicated Ubuntu IPVS director.
set -euo pipefail
if [[ $# != 2 || $1 != --dedicated-director || $EUID != 0 ]]; then
  echo 'Usage as root: install-frontdoor.sh --dedicated-director /absolute/fresh-generated-bundle' >&2
  exit 2
fi
bundle=$(realpath -- "$2")
[[ -f "$bundle/keepalived.conf" && -f "$bundle/fixed-ingress.json" ]]
exec 9>/run/nestlink-fixed-ingress.lock
flock -n 9
group=$(jq -er '.group.group_id' "$bundle/fixed-ingress.json")
vip=$(jq -er '.group.public_ips | select(length == 1) | .[0]' "$bundle/fixed-ingress.json")
[[ $group =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]
[[ $vip =~ ^[0-9.]+$ ]]
for binary in /usr/sbin/keepalived /usr/sbin/ipvsadm /usr/sbin/ip /usr/sbin/sysctl; do
  [[ -x $binary ]]
done
if systemctl is-active --quiet keepalived || [[ -n "$(/usr/sbin/ipvsadm --save --numeric)" ]]; then
  echo 'Director already has a keepalived/IPVS owner; refusing to replace it.' >&2
  exit 1
fi
ip -json address show | jq -e --arg vip "$vip" '[.[].addr_info[] | select(.local == $vip)] | length > 0' >/dev/null
for setting in net.ipv4.ip_forward net.ipv4.vs.expire_nodest_conn net.ipv4.vs.expire_quiescent_template; do
  [[ $(/usr/sbin/sysctl -n "$setting") == 1 ]]
done
/usr/sbin/ipvsadm --list --timeout | awk 'NR == 1 {if ($NF > 5) exit 1}'
/usr/sbin/keepalived --config-test --use-file="$bundle/keepalived.conf"
destination=/etc/nestlink-fixed-ingress/$group
unit=nestlink-fixed-ingress-$group.service
[[ ! -e $destination && ! -e /etc/systemd/system/$unit ]]
install -d -m 0700 -- "$destination"
install -m 0600 -- "$bundle/keepalived.conf" "$destination/keepalived.conf"
install -m 0600 -- "$bundle/fixed-ingress.json" "$destination/fixed-ingress.json"
cat > "/etc/systemd/system/$unit" <<EOF
[Unit]
Description=NestLink exact fixed ingress group $group
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=/usr/sbin/keepalived --dont-fork --check --log-console --use-file=$destination/keepalived.conf --pid=/run/nestlink-fixed-ingress-$group.pid --checkers_pid=/run/nestlink-fixed-ingress-$group-checkers.pid
KillMode=control-group
TimeoutStopSec=15
Restart=no
[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "/etc/systemd/system/$unit"
systemctl daemon-reload
systemctl enable --now "$unit"
systemctl is-active --quiet "$unit"
/usr/sbin/ipvsadm --list --numeric
echo "Fixed ingress owner started: $unit; qualify new connections and exact teardown with same-source evidence."
