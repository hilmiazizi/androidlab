#!/bin/bash
# System-proxy + transparent redirect to Burp.
# Apps that ignore the system proxy still hit iptables DNAT for TCP 80/443.
# QUIC/UDP 443, IPv6 and Private DNS are blocked so they cannot bypass it.
# DNATed TLS requires "Support invisible proxying" on the Burp listener.
#
# Applying this also kills existing direct 80/443 flows: conntrack keeps the
# old NAT decision for connections opened before the rules.

PROXY_HOST=192.168.18.21
PROXY_PORT=8080
REMOTE=/data/local/tmp/proxy_rules.sh

adb root
adb wait-for-device

if adb shell "toybox nc -w 2 $PROXY_HOST $PROXY_PORT </dev/null >/dev/null 2>&1"; then
  echo "[+] device can reach $PROXY_HOST:$PROXY_PORT"
else
  echo "[!] WARNING: device cannot reach $PROXY_HOST:$PROXY_PORT" >&2
fi

adb shell settings put global http_proxy "${PROXY_HOST}:${PROXY_PORT}"
adb shell settings put global global_http_proxy_host "${PROXY_HOST}"
adb shell settings put global global_http_proxy_port "${PROXY_PORT}"
adb shell settings put global private_dns_mode off

adb shell setprop http.proxyHost "${PROXY_HOST}"
adb shell setprop http.proxyPort "${PROXY_PORT}"
adb shell setprop https.proxyHost "${PROXY_HOST}"
adb shell setprop https.proxyPort "${PROXY_PORT}"

TMP=$(mktemp)
cat > "$TMP" << 'EOF'
#!/system/bin/sh
PROXY_HOST=192.168.18.21
PROXY_PORT=8080
NAT_CHAIN=BURP_OUT
QUIC_CHAIN=BURP_QUIC
QUIC6_CHAIN=BURP6_QUIC
GUARD_CHAIN=BURP_GUARD
GUARD6_CHAIN=BURP6_GUARD
PORTS="80 443 8080 8443 8888 9443 10443 853"

# Remove rules from older versions of this script that edited OUTPUT directly.
remove_legacy() {
  for p in $PORTS; do
    while iptables -t nat -D OUTPUT -p tcp --dport $p -j DNAT --to-destination $PROXY_HOST:$PROXY_PORT 2>/dev/null; do :; done
  done
  while iptables -t nat -D OUTPUT -d $PROXY_HOST -j RETURN 2>/dev/null; do :; done
  while iptables -t nat -D OUTPUT -d 127.0.0.0/8 -j RETURN 2>/dev/null; do :; done
  while iptables -t nat -D OUTPUT -d 192.168.74.0/24 -j RETURN 2>/dev/null; do :; done
  while iptables -t nat -D OUTPUT -o lo -j RETURN 2>/dev/null; do :; done
  while iptables -t nat -D POSTROUTING -p tcp --dport 80 -j MASQUERADE 2>/dev/null; do :; done
  while iptables -t nat -D POSTROUTING -p tcp --dport 443 -j MASQUERADE 2>/dev/null; do :; done
  while iptables -D OUTPUT -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable 2>/dev/null; do :; done
  while iptables -D OUTPUT -p udp --dport 80 -j REJECT --reject-with icmp-port-unreachable 2>/dev/null; do :; done
}

unhook() {
  while iptables -t nat -D OUTPUT -j $NAT_CHAIN 2>/dev/null; do :; done
  while iptables -D OUTPUT -j $QUIC_CHAIN 2>/dev/null; do :; done
  while iptables -D OUTPUT -j $GUARD_CHAIN 2>/dev/null; do :; done
  if command -v ip6tables >/dev/null 2>&1; then
    while ip6tables -D OUTPUT -j $QUIC6_CHAIN 2>/dev/null; do :; done
    while ip6tables -D OUTPUT -j $GUARD6_CHAIN 2>/dev/null; do :; done
  fi
}

remove_chains() {
  iptables -t nat -F $NAT_CHAIN 2>/dev/null
  iptables -t nat -X $NAT_CHAIN 2>/dev/null
  iptables -F $QUIC_CHAIN 2>/dev/null
  iptables -X $QUIC_CHAIN 2>/dev/null
  iptables -F $GUARD_CHAIN 2>/dev/null
  iptables -X $GUARD_CHAIN 2>/dev/null
  if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -F $QUIC6_CHAIN 2>/dev/null
    ip6tables -X $QUIC6_CHAIN 2>/dev/null
    ip6tables -F $GUARD6_CHAIN 2>/dev/null
    ip6tables -X $GUARD6_CHAIN 2>/dev/null
  fi
}

remove_legacy
unhook
remove_chains

for iface in all default wlan0 radio0 eth0; do
  echo 1 > /proc/sys/net/ipv6/conf/$iface/disable_ipv6 2>/dev/null
done

# DNAT in a dedicated chain so netd/OEM rules in OUTPUT stay intact.
iptables -t nat -N $NAT_CHAIN
iptables -t nat -A $NAT_CHAIN -d $PROXY_HOST -j RETURN
iptables -t nat -A $NAT_CHAIN -d 127.0.0.0/8 -j RETURN
iptables -t nat -A $NAT_CHAIN -d 192.168.74.0/24 -j RETURN
iptables -t nat -A $NAT_CHAIN -o lo -j RETURN
for p in $PORTS; do
  iptables -t nat -A $NAT_CHAIN -p tcp --dport $p -j DNAT --to-destination $PROXY_HOST:$PROXY_PORT
done
iptables -t nat -I OUTPUT 1 -j $NAT_CHAIN

# QUIC/HTTP3 bypass.
iptables -N $QUIC_CHAIN
iptables -A $QUIC_CHAIN -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable
iptables -A $QUIC_CHAIN -p udp --dport 80 -j REJECT --reject-with icmp-port-unreachable
iptables -I OUTPUT 1 -j $QUIC_CHAIN

# IPv6 web traffic bypasses the IPv4 DNAT; block it if sysctl was read-only.
if command -v ip6tables >/dev/null 2>&1; then
  ip6tables -N $QUIC6_CHAIN
  ip6tables -A $QUIC6_CHAIN -p tcp --dport 80 -j REJECT
  ip6tables -A $QUIC6_CHAIN -p tcp --dport 443 -j REJECT
  ip6tables -A $QUIC6_CHAIN -p udp --dport 80 -j REJECT
  ip6tables -A $QUIC6_CHAIN -p udp --dport 443 -j REJECT
  ip6tables -I OUTPUT 1 -j $QUIC6_CHAIN
fi

# Conntrack keeps the NAT decision a flow was created with. Flows opened
# before the rules would keep bypassing them, even though new flows are DNATed.
# Filter OUTPUT runs after nat, so proxied flows show dport 8080; killing
# remaining direct 80/443 flows forces apps to reconnect through the proxy.
iptables -N $GUARD_CHAIN
iptables -A $GUARD_CHAIN -d 127.0.0.0/8 -j RETURN
iptables -A $GUARD_CHAIN -d $PROXY_HOST -j RETURN
iptables -A $GUARD_CHAIN -d 192.168.74.0/24 -j RETURN
iptables -A $GUARD_CHAIN -p tcp --dport 80 -m conntrack --ctstate ESTABLISHED -j REJECT --reject-with tcp-reset
iptables -A $GUARD_CHAIN -p tcp --dport 443 -m conntrack --ctstate ESTABLISHED -j REJECT --reject-with tcp-reset
iptables -I OUTPUT 1 -j $GUARD_CHAIN

if command -v ip6tables >/dev/null 2>&1; then
  ip6tables -N $GUARD6_CHAIN
  ip6tables -A $GUARD6_CHAIN -d ::1/128 -j RETURN
  ip6tables -A $GUARD6_CHAIN -p tcp --dport 80 -m conntrack --ctstate ESTABLISHED -j REJECT --reject-with tcp-reset
  ip6tables -A $GUARD6_CHAIN -p tcp --dport 443 -m conntrack --ctstate ESTABLISHED -j REJECT --reject-with tcp-reset
  ip6tables -I OUTPUT 1 -j $GUARD6_CHAIN
fi

echo ===== nat OUTPUT =====
iptables -t nat -L OUTPUT -n -v
echo
echo ===== filter OUTPUT head =====
iptables -L OUTPUT -n -v | head -15
echo
echo ===== ipv6 disable =====
cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null
EOF

adb push "$TMP" "$REMOTE" >/dev/null
rm -f "$TMP"
adb shell chmod 755 "$REMOTE"
adb shell sh "$REMOTE"

echo
echo "[+] http_proxy = $(adb shell settings get global http_proxy | tr -d '\r')"
echo "[i] Burp listener needs 'Support invisible proxying' for DNATed apps."
