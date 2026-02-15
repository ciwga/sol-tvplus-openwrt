# -*- coding: utf-8 -*-
"""
Konfigürasyon yönetimi ve iş mantığı.
"""

import re
from typing import Dict, Any, Final

from templates import (
        SHELL_SCRIPT_TEMPLATE, 
        UNINSTALL_SCRIPT_TEMPLATE, 
        ROUTE_FINDER_TEMPLATE
    )


REGEX_VLAN: Final[re.Pattern] = re.compile(r"^\d+$")
REGEX_SAFE_INPUT: Final[re.Pattern] = re.compile(r"^[a-zA-Z0-9_][a-zA-Z0-9_\-\.]*$")


class SuperonlineManager:
    """Superonline Tv+ yapılandırma ve analiz yöneticisi."""

    def __init__(self) -> None:
        """Varsayılan yapılandırma ayarlarını başlatır."""
        self.defaults: Dict[str, Any] = {
            "vlan_id": "103",
            "wan_interface": "eth0",
            "lan_interface": "lan",
            "lan_zone": "lan",
            "iptv_interface": "iptv",
            "tv_zone_name": "tv_zone",
            "igmp_version": "2",
            "timezone": "Europe/Istanbul",
            "timezone_code": "TRT-3",
            "ntp_server": "cpentp.superonline.net",
        }

    def validate_input(self, key: str, value: str) -> str:
        """Kullanıcı girdisini doğrular."""
        value = value.strip()
        if not value:
            raise ValueError(f"HATA: '{key}' alanı boş bırakılamaz.")

        if key == "vlan_id":
            if not REGEX_VLAN.match(value):
                raise ValueError(f"HATA: '{key}' sadece sayısal değer alabilir.")
            if not (1 <= int(value) <= 4094):
                raise ValueError("HATA: VLAN ID 1-4094 arasında olmalıdır.")
            return value
        
        if key == "igmp_version":
            if value not in ("2", "3"):
                raise ValueError(f"HATA: IGMP Sürümü sadece '2' veya '3' olabilir.")
            return value

        if value.startswith("-") or value.startswith("."):
            raise ValueError(f"HATA: '{key}' değeri tire veya nokta ile başlayamaz.")

        if not REGEX_SAFE_INPUT.match(value):
            raise ValueError(
                f"HATA: '{key}' alanında geçersiz karakterler var."
            )
        if ".." in value:
            raise ValueError(f"HATA: '{key}' alanında ardışık nokta (..) kullanılamaz.")
        return value

    def check_conflicts(self, config: Dict[str, str]) -> None:
        """Çakışmaları kontrol eder."""
        iptv_iface = config.get("iptv_interface", "")
        lan_iface = config.get("lan_interface", "")
        lan_zone = config.get("lan_zone", "")
        tv_zone = config.get("tv_zone_name", "")

        if iptv_iface == lan_iface:
            raise ValueError("HATA: IPTV arayüz ismi LAN arayüzü ile aynı olamaz!")
        if iptv_iface == "wan":
            raise ValueError("HATA: IPTV arayüzü için 'wan' ismini kullanamazsınız.")
        if lan_zone == tv_zone:
            raise ValueError("HATA: LAN ve TV Firewall Zone isimleri aynı olamaz!")

    def generate_setup_script(self, config: Dict[str, str]) -> str:
        """Kurulum shell scriptini oluşturur."""
        script = SHELL_SCRIPT_TEMPLATE
        for key, val in config.items():
            placeholder = f"<<{key.upper()}>>"
            script = script.replace(placeholder, str(val))
        return script
    
    def generate_uninstall_script(self, config: Dict[str, str]) -> str:
        """Kaldırma shell scriptini oluşturur."""
        script = UNINSTALL_SCRIPT_TEMPLATE
        replacements = {
            "<<IPTV_INTERFACE>>": str(config.get("iptv_interface", "iptv")),
            "<<TV_ZONE_NAME>>": str(config.get("tv_zone_name", "tv_zone")),
        }
        for placeholder, value in replacements.items():
            script = script.replace(placeholder, value)
        return script

    def generate_route_finder(self, config: Dict[str, str]) -> str:
        """Rota keşif scriptini oluşturur."""
        script = ROUTE_FINDER_TEMPLATE
        replacements = {
            "<<VLAN_ID>>": str(config.get("vlan_id", "103")),
            "<<IPTV_INTERFACE>>": str(config.get("iptv_interface", "iptv")),
            "<<WAN_INTERFACE>>": str(config.get("wan_interface", "eth0")),
        }
        for placeholder, value in replacements.items():
            script = script.replace(placeholder, value)
        return script