# -*- coding: utf-8 -*-
"""
Superonline TV+ OpenWrt Manager - Şablon Dosyası.

Bu modül, oluşturulacak shell scriptleri için gerekli olan
metin şablonlarını (string templates) barındırır.
"""

from typing import Final

# Kurulum Betiği Şablonu
SHELL_SCRIPT_TEMPLATE: Final[str] = r"""#!/bin/sh

# ==============================================================================
# DOSYA ADI: setup_tvplus.sh
# VERSİYON: 1.1
# KONFIGURASYON:
#   - VLAN ID: <<VLAN_ID>>
#   - WAN Interface: <<WAN_INTERFACE>>
#   - LAN Interface: <<LAN_INTERFACE>>
#   - IPTV Interface Name: <<IPTV_INTERFACE>>
#   - TV Zone Name: <<TV_ZONE_NAME>>
#   - IGMP Version: <<IGMP_VERSION>>
#
# AÇIKLAMA:
#   Bu betik, Turkcell Superonline TV+ (IPTV) hizmetini OpenWrt üzerinde
#   yapılandırmak için kullanılır.
# ==============================================================================

set -e  # Hata durumunda betiği durdur
set -u  # Tanımsız değişken kullanılırsa durdur

echo "=================================================================================="
echo "🚀 SUPERONLINE TV+ KURULUMU (VLAN <<VLAN_ID>>) BAŞLATILIYOR..."
echo "=================================================================================="

# --- BÖLÜM 0: SİSTEM SAATİ ---
echo "🕒 [0/7] Sistem saati ve NTP ayarlanıyor..."
uci set system.@system[0].zonename='<<TIMEZONE>>'
uci set system.@system[0].timezone='<<TIMEZONE_CODE>>'
uci delete system.ntp.server >/dev/null 2>&1 || true
uci add_list system.ntp.server='<<NTP_SERVER>>'
uci set system.ntp.enable_server='1'
uci commit system
/etc/init.d/system restart
/etc/init.d/sysntpd restart

# Saat kontrolü (SSL ve Sertifika hatalarını önlemek için)
CURRENT_YEAR=$(date +%Y)
if [ "$CURRENT_YEAR" -lt 2026 ]; then
    echo "    ⚠️ UYARI: Sistem saati güncel değil. HTTP üzerinden eşitleniyor..."
    HTTP_DATE=$(wget -qS --spider http://google.com 2>&1 | grep -i "^  Date:" | sed 's/  Date: //g')
    if [ -n "$HTTP_DATE" ]; then
        date -s "$HTTP_DATE" >/dev/null 2>&1 || echo "    ⚠️ Saat ayarlanamadı."
    fi
fi

# --- BÖLÜM 1: PAKET KURULUMU ---
echo "📦 [1/7] Gerekli paketler kontrol ediliyor..."
opkg update >/dev/null 2>&1 || echo "⚠️ Paket listesi güncellenemedi."
PACKAGES="igmpproxy ip-full"
for PKG in $PACKAGES; do
    if opkg list-installed | grep -q "^$PKG"; then
        echo "    > $PKG zaten kurulu."
    else
        echo "    > $PKG kuruluyor..."
        opkg install "$PKG" >/dev/null 2>&1
    fi
done

# --- BÖLÜM 2: PERFORMANS ---
echo "⚙️ [2/7] Flow Offloading ve Snooping ayarlanıyor..."
uci set firewall.@defaults[0].flow_offloading='0'
uci set firewall.@defaults[0].flow_offloading_hw='0'
if uci get network.<<LAN_INTERFACE>> >/dev/null 2>&1; then
    # Multicast trafiğinin Wi-Fi performansını düşürmemesi için snooping açılır
    uci set network.<<LAN_INTERFACE>>.igmp_snooping='1'
    uci set network.<<LAN_INTERFACE>>.multicast_to_unicast='1' 2>/dev/null || true
fi

# --- BÖLÜM 3: ARAYÜZ ---
echo "📺 [3/7] IPTV Arayüzü (<<IPTV_INTERFACE>>) oluşturuluyor..."

# 3.1. WAN Fiziksel Cihaz Tespiti
DETECTED_DEV=$(uci -q get network.wan.device)
if [ -z "$DETECTED_DEV" ]; then
    DETECTED_DEV=$(uci -q get network.wan.ifname)
fi

if [ -z "$DETECTED_DEV" ]; then
    echo "    ℹ️ Otomatik WAN tespiti yapılamadı."
    WAN_PHY_DEV="<<WAN_INTERFACE>>"
else
    if echo "$DETECTED_DEV" | grep -q "br-"; then
        echo "    ⚠️ Tespit edilen arayüz bir Köprü (Bridge): $DETECTED_DEV"
        echo "    ⚠️ Stabilite için kullanıcının belirttiği fiziksel arayüz kullanılacak: <<WAN_INTERFACE>>"
        WAN_PHY_DEV="<<WAN_INTERFACE>>"
    else
        WAN_PHY_DEV="$DETECTED_DEV"
        echo "    ✅ WAN Cihazı Otomatik Tespit Edildi: $WAN_PHY_DEV"
    fi
fi

# 3.2. Temizlik
WAN_PHY_DEV=${WAN_PHY_DEV%%.*}
echo "    👉 Hedef Fiziksel Arayüz: $WAN_PHY_DEV"

uci delete network.<<IPTV_INTERFACE>>_dev 2>/dev/null || true
uci delete network.<<IPTV_INTERFACE>> 2>/dev/null || true

VLAN_ID="<<VLAN_ID>>"
VLAN_DEV="${WAN_PHY_DEV}.${VLAN_ID}"

# 3.3. Device Tanımı
uci set network.<<IPTV_INTERFACE>>_dev=device
uci set network.<<IPTV_INTERFACE>>_dev.name="$VLAN_DEV"
uci set network.<<IPTV_INTERFACE>>_dev.macaddr='<<MAC_ADDRESS>>'
uci set network.<<IPTV_INTERFACE>>_dev.type='8021q'
uci set network.<<IPTV_INTERFACE>>_dev.ifname="$WAN_PHY_DEV"
uci set network.<<IPTV_INTERFACE>>_dev.vid="$VLAN_ID"
uci set network.<<IPTV_INTERFACE>>_dev.igmpversion='<<IGMP_VERSION>>'

# 3.4. Interface Tanımı
uci set network.<<IPTV_INTERFACE>>=interface
uci set network.<<IPTV_INTERFACE>>.proto='dhcp'
uci set network.<<IPTV_INTERFACE>>.device="$VLAN_DEV"
uci set network.<<IPTV_INTERFACE>>.defaultroute='0'
uci set network.<<IPTV_INTERFACE>>.peerdns='0'
uci set network.<<IPTV_INTERFACE>>.metric='20'

# 3.5. DHCP Options ve MAC
echo "    > DHCP Kimlikleri yazılıyor (MAC, Vendor ID, Client ID, Hostname Hex)..."
uci set network.<<IPTV_INTERFACE>>.macaddr='<<MAC_ADDRESS>>'
uci set network.<<IPTV_INTERFACE>>.vendorid='<<VENDOR_ID>>'

# Client ID (Option 61): Manager tarafından temizlenen ham hex verisi yazılır.
uci set network.<<IPTV_INTERFACE>>.clientid='<<CLIENT_ID>>'

# Hostname (Option 12): OpenWrt standart hostname'i reddettiği için sendopts (Hex) kullanılır.
uci delete network.<<IPTV_INTERFACE>>.hostname 2>/dev/null || true
uci delete network.<<IPTV_INTERFACE>>.sendopts 2>/dev/null || true
uci add_list network.<<IPTV_INTERFACE>>.sendopts='12:<<HOST_NAME_HEX>>'

# Option 55: Reqopts
uci delete network.<<IPTV_INTERFACE>>.reqopts 2>/dev/null || true
uci add_list network.<<IPTV_INTERFACE>>.reqopts='1'
uci add_list network.<<IPTV_INTERFACE>>.reqopts='3'
uci add_list network.<<IPTV_INTERFACE>>.reqopts='6'
uci add_list network.<<IPTV_INTERFACE>>.reqopts='51'
uci add_list network.<<IPTV_INTERFACE>>.reqopts='54'
uci add_list network.<<IPTV_INTERFACE>>.reqopts='43'
uci add_list network.<<IPTV_INTERFACE>>.reqopts='121'
uci add_list network.<<IPTV_INTERFACE>>.reqopts='120'

# 3.6. L2 Önceliği (VLAN Priority 4 / 802.1p Egress QoS)
echo "    > VLAN Priority (Egress QoS 4) ayarlanıyor..."
sed -i '/exit 0/d' /etc/rc.local
echo "ip link set $VLAN_DEV type vlan egress 0:4 1:4 2:4 3:4 4:4 5:4 6:4 7:4" >> /etc/rc.local
echo "exit 0" >> /etc/rc.local
# Anlık olarak uygula (hata verirse yoksay)
ip link set "$VLAN_DEV" type vlan egress 0:4 1:4 2:4 3:4 4:4 5:4 6:4 7:4 2>/dev/null || true

# --- BÖLÜM 4: FIREWALL ---
echo "🔥 [4/7] Firewall (<<TV_ZONE_NAME>>) ve DNS Rebind ayarları..."
uci delete firewall.<<TV_ZONE_NAME>> 2>/dev/null || true
uci set firewall.<<TV_ZONE_NAME>>=zone
uci set firewall.<<TV_ZONE_NAME>>.name='<<TV_ZONE_NAME>>'
uci set firewall.<<TV_ZONE_NAME>>.network='<<IPTV_INTERFACE>>'
uci set firewall.<<TV_ZONE_NAME>>.input='ACCEPT'
uci set firewall.<<TV_ZONE_NAME>>.output='ACCEPT'
uci set firewall.<<TV_ZONE_NAME>>.forward='REJECT'
uci set firewall.<<TV_ZONE_NAME>>.masq='1'
uci set firewall.<<TV_ZONE_NAME>>.mtu_fix='1'

# LAN -> TV Forwarding
uci delete firewall.lan_to_tv_forwarding 2>/dev/null || true
uci set firewall.lan_to_tv_forwarding=forwarding
uci set firewall.lan_to_tv_forwarding.src='<<LAN_ZONE>>'
uci set firewall.lan_to_tv_forwarding.dest='<<TV_ZONE_NAME>>'

# IGMP İzin Kuralı
uci delete firewall.tv_igmp_rule 2>/dev/null || true
uci set firewall.tv_igmp_rule=rule
uci set firewall.tv_igmp_rule.name='Allow-IGMP-TV'
uci set firewall.tv_igmp_rule.src='<<TV_ZONE_NAME>>'
uci set firewall.tv_igmp_rule.dest='<<LAN_ZONE>>'
uci set firewall.tv_igmp_rule.proto='igmp'
uci set firewall.tv_igmp_rule.dest_ip='224.0.0.0/4'
uci set firewall.tv_igmp_rule.target='ACCEPT'

# TV UDP Multicast İzin Kuralı (Yayın Verisi)
uci delete firewall.tv_udp_rule 2>/dev/null || true
uci set firewall.tv_udp_rule=rule
uci set firewall.tv_udp_rule.name='Allow-UDP-TV-Multicast'
uci set firewall.tv_udp_rule.src='<<TV_ZONE_NAME>>'
uci set firewall.tv_udp_rule.dest='<<LAN_ZONE>>'
uci set firewall.tv_udp_rule.proto='udp'
uci set firewall.tv_udp_rule.dest_ip='224.0.0.0/4'
uci set firewall.tv_udp_rule.target='ACCEPT'

# DNS Rebind Koruması
uci -q del_list dhcp.@dnsmasq[0].rebind_domain='/superonline.net/'
uci -q del_list dhcp.@dnsmasq[0].rebind_domain='/superonline.com/'
uci -q del_list dhcp.@dnsmasq[0].rebind_domain='/superonlinetv.com/'
uci add_list dhcp.@dnsmasq[0].rebind_domain='/superonline.net/'
uci add_list dhcp.@dnsmasq[0].rebind_domain='/superonline.com/'
uci add_list dhcp.@dnsmasq[0].rebind_domain='/superonlinetv.com/'

# --- BÖLÜM 5: IGMP PROXY ---
echo "📺 [5/7] IGMP Proxy dosyası yazılıyor..."
cat <<EOF > /etc/config/igmpproxy
config igmpproxy
    option quickleave 1
config phyint
    option network <<IPTV_INTERFACE>>
    option zone <<TV_ZONE_NAME>>
    option direction upstream
    list altnet 225.0.0.0/8
    list altnet 233.0.0.0/8
    list altnet 239.0.0.0/8
    list altnet 176.235.0.0/16
    list altnet 10.0.0.0/8
config phyint
    option network <<LAN_INTERFACE>>
    option zone <<LAN_ZONE>>
    option direction downstream
    option igmp_version <<IGMP_VERSION>> 
EOF

# --- BÖLÜM 6: ROTA VE HOTPLUG ---
echo "📝 [6/7] Hotplug scripti oluşturuluyor..."
uci commit network

cat << 'EOF_HOTPLUG' > /etc/hotplug.d/iface/99-tvplus-calc
#!/bin/sh
# Auto-generated by setup_tvplus.sh

[ "$INTERFACE" = "<<IPTV_INTERFACE>>" ] || return 0
[ "$ACTION" = "ifup" ] || return 0

logger -t IPTV_LOG "IPTV (<<IPTV_INTERFACE>>) aktif. Statik rotalar hesaplanıyor..."

if [ -z "$DEVICE" ]; then return 1; fi

CIDR_DATA=""
ATTEMPT=1
while [ $ATTEMPT -le 5 ]; do
    CIDR_DATA=$(ip -4 -o addr show dev $DEVICE | awk '{print $4}' | head -1)
    if [ -n "$CIDR_DATA" ]; then break; fi
    sleep 2
    ATTEMPT=$((ATTEMPT + 1))
done

if [ -z "$CIDR_DATA" ]; then
    logger -t IPTV_LOG "HATA: $DEVICE üzerinde IP adresi alınamadı."
    return 1
fi

# Gateway Hesaplama (Fallback mekanizması)
CALCULATED_GW=$(echo "$CIDR_DATA" | awk -F'[./]' '{
    ip1=$1; ip2=$2; ip3=$3; ip4=$4; mask=$5
    ip_int = (ip1 * 16777216) + (ip2 * 65536) + (ip3 * 256) + ip4
    host_bits = 32 - mask
    divisor = 2 ^ host_bits
    net_int = int(ip_int / divisor) * divisor
    gw_int = net_int + 1
    o1 = int(gw_int / 16777216)
    gw_int = gw_int % 16777216
    o2 = int(gw_int / 65536)
    gw_int = gw_int % 65536
    o3 = int(gw_int / 256)
    o4 = gw_int % 256
    print o1"."o2"."o3"."o4
}')

# Option 3 (Gateway) varsa ubus uzerinden alınacak
OPTION3_GW=$(ubus call network.interface.<<IPTV_INTERFACE>> status 2>/dev/null | awk '/"nexthop":/ {print $2}' | tr -d ',"' | head -n 1)

ACTIVE_GW=""
if [ -n "$OPTION3_GW" ]; then
    logger -t IPTV_LOG "Option 3 Gateway bulundu: $OPTION3_GW"
    ACTIVE_GW="$OPTION3_GW"
elif [ -n "$CALCULATED_GW" ]; then
    logger -t IPTV_LOG "Option 3 bulunamadı. Hesaplanan Fallback Gateway kullanılıyor: $CALCULATED_GW"
    ACTIVE_GW="$CALCULATED_GW"
else
    logger -t IPTV_LOG "HATA: Gateway bulunamadı veya hesaplanamadı."
    return 1
fi

if [ -n "$ACTIVE_GW" ]; then
    logger -t IPTV_LOG "Aktif Gateway: $ACTIVE_GW. Rotalar ekleniyor..."
    
    # Statik rotalar (Superonline TV Sunucuları)
    ip route replace 172.31.128.0/19 via $ACTIVE_GW dev $DEVICE
    ip route replace 176.43.0.0/24 via $ACTIVE_GW dev $DEVICE
    ip route replace 176.235.0.0/20 via $ACTIVE_GW dev $DEVICE
    ip route replace 176.235.0.0/16 via $ACTIVE_GW dev $DEVICE
    ip route replace 10.31.0.0/16 via $ACTIVE_GW dev $DEVICE
    ip route replace 10.0.0.0/8 via $ACTIVE_GW dev $DEVICE
    ip route replace 172.16.0.0/12 via $ACTIVE_GW dev $DEVICE
    
    # 213.74.x.x DNS Rotaları
    ip route replace 213.74.0.0/16 via $ACTIVE_GW dev $DEVICE
else
    logger -t IPTV_LOG "HATA: Rotalar uygulanamadı."
fi
EOF_HOTPLUG
chmod +x /etc/hotplug.d/iface/99-tvplus-calc

# --- BÖLÜM 7: KAYDET ---
echo "💾 [7/7] Kaydediliyor ve servisler yeniden başlatılıyor..."
uci commit network
uci commit firewall
uci commit system
uci commit dhcp
/etc/init.d/network restart
/etc/init.d/firewall restart
/etc/init.d/dnsmasq restart
/etc/init.d/igmpproxy enable
/etc/init.d/igmpproxy restart
echo "✅ KURULUM BAŞARIYLA TAMAMLANDI."
"""

# Kaldırma Betiği Şablonu
UNINSTALL_SCRIPT_TEMPLATE: Final[str] = r"""#!/bin/sh

# ==============================================================================
# DOSYA ADI: uninstall_tvplus.sh
# AÇIKLAMA:
#   Bu betik, setup_tvplus.sh tarafından yapılan değişiklikleri
#   geri alır (Hotplug, Firewall, Network, IGMP Proxy).
# ==============================================================================

set -u

echo "=================================================================================="
echo "🗑️ SUPERONLINE TV+ KALDIRMA İŞLEMİ BAŞLATILIYOR..."
echo "=================================================================================="

# --- 1. HOTPLUG TEMİZLİĞİ ---
echo "🧹 [1/5] Hotplug scripti siliniyor..."
if [ -f "/etc/hotplug.d/iface/99-tvplus-calc" ]; then
    rm -f /etc/hotplug.d/iface/99-tvplus-calc
    echo "    ✅ /etc/hotplug.d/iface/99-tvplus-calc silindi."
else
    echo "    ℹ️ Hotplug scripti zaten yok."
fi

# --- 2. IGMP PROXY ---
echo "🛑 [2/5] IGMP Proxy devre dışı bırakılıyor..."
/etc/init.d/igmpproxy stop >/dev/null 2>&1 || true
/etc/init.d/igmpproxy disable >/dev/null 2>&1 || true

echo "" > /etc/config/igmpproxy
echo "    ✅ IGMP Proxy konfigürasyonu temizlendi."

# --- 3. FIREWALL AYARLARI ---
echo "🔥 [3/5] Firewall kuralları ve Zone (<<TV_ZONE_NAME>>) siliniyor..."

# Kural ve Forwarding silme
uci -q delete firewall.tv_igmp_rule
uci -q delete firewall.lan_to_tv_forwarding

# Zone silme
uci -q delete firewall.<<TV_ZONE_NAME>>

echo "    ✅ Firewall ayarları kaldırıldı."

# --- 4. NETWORK VE ARAYÜZLER ---
echo "🌐 [4/5] Ağ arayüzleri (<<IPTV_INTERFACE>>) siliniyor..."

# Interface silme
uci -q delete network.<<IPTV_INTERFACE>>

# Device (VLAN) silme - Modern DSA
uci -q delete network.<<IPTV_INTERFACE>>_dev

# DNS Rebind temizliği
uci -q del_list dhcp.@dnsmasq[0].rebind_domain='/superonline.net/'
uci -q del_list dhcp.@dnsmasq[0].rebind_domain='/superonline.com/'
uci -q del_list dhcp.@dnsmasq[0].rebind_domain='/superonlinetv.com/'


echo "    ✅ Ağ ve DNS ayarları temizlendi."

# --- 5. KAYDET VE UYGULA ---
echo "💾 [5/5] Değişiklikler uygulanıyor..."
uci commit network
uci commit firewall
uci commit dhcp
uci commit system

echo "🔄 Servisler yeniden başlatılıyor..."
/etc/init.d/network restart
/etc/init.d/firewall restart
/etc/init.d/dnsmasq restart

echo "✅ KALDIRMA İŞLEMİ BAŞARIYLA TAMAMLANDI."
echo "   Cihazınız eski haline döndürüldü."
"""

# Rota Keşif Şablonu
ROUTE_FINDER_TEMPLATE: Final[str] = r"""#!/bin/sh
# ==============================================================================
# DOSYA ADI: find_routes.sh
# AÇIKLAMA: DHCP Option 121 (Classless Static Route) yakalayıcı.
# ==============================================================================

set -u

echo "🔍 SUPERONLINE ROTA KEŞİF ARACI"
echo "--------------------------------"

# 1. tcpdump kontrolü
if ! opkg list-installed | grep -q "tcpdump"; then
    echo "📦 tcpdump bulunamadı, kuruluyor..."
    opkg update && opkg install tcpdump
fi

# 2. Arayüzü belirle
VLAN_ID="<<VLAN_ID>>"
WAN_DEV=$(uci -q get network.wan.device || echo "<<WAN_INTERFACE>>")
WAN_DEV=${WAN_DEV%%.*}
IFACE="${WAN_DEV}.${VLAN_ID}"

echo "📡 Dinlenecek Arayüz: $IFACE"

# 3. Dinlemeyi başlat
LOG_FILE="/tmp/dhcp_capture.log"
rm -f "$LOG_FILE"

# Arka planda dinle
tcpdump -i "$IFACE" -vvv -n port 67 or port 68 -c 10 -s 0 > "$LOG_FILE" 2>&1 &
TCPDUMP_PID=$!

# 4. DHCP isteğini tetikle (Renew)
ifdown <<IPTV_INTERFACE>>
sleep 3
ifup <<IPTV_INTERFACE>>

# 5. Bekle
echo "⏳ DHCP işlemi bekleniyor (20 saniye)..."
sleep 20

# 6. Temizle
if kill -0 $TCPDUMP_PID 2>/dev/null; then
    kill $TCPDUMP_PID 2>/dev/null
fi

echo "--------------------------------"
echo "📊 ANALİZ SONUCU:"
echo "--------------------------------"

if grep -iE "Classless-Static-Route|Option 121" "$LOG_FILE"; then
    echo "✅ DHCP OPTION 121 BULUNDU!"
    grep -iE "Classless-Static-Route|Option 121" "$LOG_FILE"
else
    echo "❌ Option 121 GÖRÜLEMEDİ. Manuel ayar gerekebilir."
fi
"""
