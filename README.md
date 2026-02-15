# 📺 Superonline TV+ OpenWrt Manager

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)
![OpenWrt](https://img.shields.io/badge/OpenWrt-21.02%2B-blueviolet?style=for-the-badge&logo=openwrt)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**Turkcell Superonline TV+ (IPTV)** hizmetini OpenWrt tabanlı router'larda sorunsuz kullanmak için gerekli olan karmaşık ağ yapılandırmasını (VLAN, IGMP Proxy, Firewall, Rota) otomatize eden, modüler ve güvenli bir CLI aracıdır.

---

## 🚀 Özellikler

Bu araç, manuel yapılandırma hatalarını ortadan kaldırır ve aşağıdaki işlemleri yönetir:

### 1. Kurulum (`setup_tvplus.sh`)
* ✅ **VLAN Ayarları:** (Varsayılan 103) Gerekli 802.1q yapılandırmasını DSA veya swconfig mimarisine uygun hazırlar.
* ✅ **IGMP Proxy & Snooping:** Multicast yayınların donmasını engeller ve Wi-Fi performansını korur.
* ✅ **Firewall Zone:** TV+ trafiğini izole eder ve gerekli port izinlerini (Input/Forward) otomatik tanımlar.
* ✅ **DNS Rebind Koruması:** Superonline domainleri için DNS Rebind korumasını otomatik olarak esnetir.
* ✅ **Sistem Saati (NTP):** Yayın akışının düzgün çalışması için zaman senkronizasyonunu sağlar.

### 2. Kaldırma / Temizlik (`uninstall_tvplus.sh`)
* 🗑️ **Tam Temizlik:** Yapılan tüm konfigürasyonları (Interface, Device, Zone, Firewall kuralları) güvenli bir şekilde siler.
* 🔄 **Geri Alma:** Router ayarlarını, script çalıştırılmadan önceki haline (ilgili bölümler için) döndürür.

### 3. Rota Analizi (`find_routes.sh`)
* 🕵️ **Route Finder:** ISP tarafından gönderilen dinamik rotaları (DHCP Option 121 / Classless Static Route) analiz etmek için `tcpdump` tabanlı bir dinleyici oluşturur.

---

## 📂 Proje Yapısı (Modüler)


* `main.py`: Kullanıcı arayüzü (CLI) ve ana giriş noktası.
* `manager.py`: İş mantığı, konfigürasyon yönetimi ve validasyon kuralları.
* `templates.py`: Shell script şablonlarını barındıran veri dosyası.
* `utils.py`: Dosya yazma, izin yönetimi ve SSH yardımcı fonksiyonları.

---

## 📋 Gereksinimler

* **Bilgisayarınızda:** Python 3.8 veya üzeri.
* **Router:** OpenWrt 19.07 sürümü ve üzeri (21.02+ ve DSA mimarisi önerilir).
* **SSH Erişimi:** Router'a `root` yetkisi ile erişebilmelisiniz.

---

## 🛠️ Kurulum ve Kullanım

### 1. Aracı Çalıştırın
Tüm python dosyalarını (`main.py`, `manager.py`, `templates.py`, `utils.py`) aynı klasöre indirin ve terminalde ana dosyayı çalıştırın:

```bash
python3 main.py
```

Sihirbaz sizi yönlendirecektir:
1.  **VLAN ID:** Genellikle `103`.
2.  **WAN Portu:** Router'ın internet kablosunun takılı olduğu fiziksel port (örn: `eth0`, `wan`).
3.  **LAN Arayüzü:** Yerel ağınızın mantıksal adı (örn: `lan`).

### 2. Oluşturulan Dosyaları Router'a Gönderin
Script başarıyla tamamlandığında çalışma dizininde `.sh` uzantılı dosyalar oluşturacaktır.

#### A. Kurulum İçin:
`setup_tvplus.sh` dosyasını router'a gönderin ve çalıştırın.

**Linux/macOS (Tek Komut):**
```bash
cat setup_tvplus.sh | ssh root@192.168.1.1 "cat > /tmp/setup_tvplus.sh && chmod +x /tmp/setup_tvplus.sh && /tmp/setup_tvplus.sh"
```

#### B. Kaldırmak İçin:
Eğer ayarları silmek isterseniz `uninstall_tvplus.sh` dosyasını kullanın:

```bash
cat uninstall_tvplus.sh | ssh root@192.168.1.1 "cat > /tmp/uninstall_tvplus.sh && chmod +x /tmp/uninstall_tvplus.sh && /tmp/uninstall_tvplus.sh"
```

---

## ⚠️ Yasal Uyarı (Disclaimer)

**Lütfen dikkatlice okuyunuz:**

1.  **Resmiyet:** Bu yazılımın **Turkcell Superonline** ile hiçbir resmi bağlantısı, iş ortaklığı veya onayı **yoktur**. Tamamen bireysel eğitim, test ve ağ yönetimi hobileri kapsamında geliştirilmiştir.
2.  **Sorumluluk:** Bu yazılım "OLDUĞU GİBİ" (AS IS) sunulmaktadır. Yazılımın kullanımı sonucunda donanımınızda, yazılımınızda veya internet servisinizde oluşabilecek herhangi bir kesinti, arıza veya veri kaybından **kullanıcı sorumludur**.
3.  **Hizmet Şartları:** ISP (İnternet Servis Sağlayıcı) sözleşmenizi ihlal etmediğinizden emin olunuz. Bu araç sadece router tarafındaki yerel ayarları (Client-side) düzenler, ISP altyapısına müdahale etmez.

---

## 🤝 Katkıda Bulunma

Hataları raporlamak veya özellik eklemek için lütfen "Issue" açın veya "Pull Request" gönderin.

## 📄 Lisans

Bu proje [MIT Lisansı](LICENSE) ile lisanslanmıştır.
