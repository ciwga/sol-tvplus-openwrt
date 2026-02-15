#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Superonline TV+ OpenWrt Manager (CLI).

Yasal Uyarı:
    Bu yazılımın Turkcell Superonline ile resmi bir bağlantısı yoktur.
    Tamamen eğitim, test ve ağ yönetimi amaçlıdır.
"""

import sys
from typing import Dict, List, Tuple
from manager import SuperonlineManager
from utils import write_safe_file, print_ssh_usage

def run_cli() -> None:
    """Komut satırı arayüzünü (CLI) başlatır ve yönetir."""
    print("\n" + "=" * 60)
    print("📺 SUPERONLINE TV+ OPENWRT YÖNETİCİSİ (CLI v1.0 - Modular)")
    print("============================================================")
    print("UYARI: Bu araç sadece konfigürasyon dosyası üretir.")
    print("Router'ınıza yüklemeden önce dosyaları inceleyiniz.")
    print("============================================================\n")

    manager = SuperonlineManager()
    defaults = manager.defaults
    user_config: Dict[str, str] = {}

    prompts: List[Tuple[str, str]] = [
        ("vlan_id", f"VLAN ID [{defaults['vlan_id']}]: "),
        ("wan_interface",
         f"WAN Fiziksel Portu (örn: eth0) [{defaults['wan_interface']}]: "),
        ("lan_interface",
         f"LAN Mantıksal Arayüzü (örn: lan) [{defaults['lan_interface']}]: "),
        ("lan_zone",
         f"LAN Firewall Zone (örn: lan) [{defaults['lan_zone']}]: "),
        ("iptv_interface",
         f"IPTV Arayüz İsmi [{defaults['iptv_interface']}]: "),
        ("tv_zone_name",
         f"TV Firewall Zone İsmi [{defaults['tv_zone_name']}]: "),
        ("igmp_version",
         f"IGMP Version (2/3) [{defaults['igmp_version']}]: "),
    ]

    print("AYARLAR (Varsayılan değer için Enter'a basın):")

    for key, text in prompts:
        valid = False
        while not valid:
            try:
                val = input(text).strip()
                final_val = val if val else str(defaults[key])
                validated_val = manager.validate_input(key, final_val)
                user_config[key] = validated_val
                valid = True
            except ValueError as e:
                print(f"❌ {e}")
                print("Lütfen tekrar deneyin.")
            except EOFError:
                print("\n❌ Girdi akışı kesildi.")
                sys.exit(1)
            except KeyboardInterrupt:
                print("\n\n❌ İşlem iptal edildi.")
                sys.exit(0)

    for key, val in defaults.items():
        if key not in user_config:
            user_config[key] = str(val)

    try:
        manager.check_conflicts(user_config)
    except ValueError as e:
        print(f"\n🛑 YAPILANDIRMA HATASI: {e}")
        sys.exit(1)

    print("\nNE YAPMAK İSTİYORSUNUZ?")
    print("1. Kurulum ve Kaldırma Dosyalarını Oluştur (setup + uninstall)")
    print("2. Rota Keşif Aracını Oluştur (find_routes.sh)")
    print("3. Hepsini Oluştur (Önerilen)")

    choice = ""
    while choice not in ["1", "2", "3"]:
        try:
            choice = input("Seçiminiz (1/2/3): ").strip()
            if choice not in ["1", "2", "3"]:
                print("Lütfen geçerli bir seçim yapın.")
        except EOFError:
            print("\nÇıkış yapılıyor...")
            sys.exit(0)
        except KeyboardInterrupt:
            print("\n\n❌ İşlem iptal edildi.")
            sys.exit(0)

    if choice in ["1", "3"]:
        content_setup = manager.generate_setup_script(user_config)
        write_safe_file("setup_tvplus.sh", content_setup)
        print_ssh_usage("setup_tvplus.sh")
        
        content_uninstall = manager.generate_uninstall_script(user_config)
        write_safe_file("uninstall_tvplus.sh", content_uninstall)
        print_ssh_usage("uninstall_tvplus.sh")

    if choice in ["2", "3"]:
        content_route = manager.generate_route_finder(user_config)
        write_safe_file("find_routes.sh", content_route)
        print_ssh_usage("find_routes.sh")

if __name__ == "__main__":
    try:
        run_cli()
    except KeyboardInterrupt:
        print("\n\n❌ İşlem kullanıcı tarafından iptal edildi.")
        sys.exit(0)
    except Exception as ex:
        print(f"\n\n❌ Kritik Sistem Hatası: {ex}")
        sys.exit(1)