# -*- coding: utf-8 -*-
"""
Dosya işlemleri ve yardımcı fonksiyonlar.
"""

import os
import stat
from pathlib import Path

def write_safe_file(filename: str, content: str) -> None:
    """İçeriği belirtilen dosyaya güvenli bir şekilde yazar ve izinleri ayarlar.

    Args:
        filename (str): Oluşturulacak dosya adı.
        content (str): Dosyaya yazılacak içerik.
    """
    try:
        target_path = Path(filename).resolve()
        current_working_dir = Path.cwd().resolve()

        is_safe_path = False
        try:
            if hasattr(target_path, 'is_relative_to'):
                is_safe_path = target_path.is_relative_to(current_working_dir)
            else:
                is_safe_path = str(target_path).startswith(str(current_working_dir))
        except Exception:
            is_safe_path = False

        if not is_safe_path:
            print(
                f"❌ GÜVENLİK HATASI: Hedef dosya yolu çalışma dizini dışında: "
                f"'{target_path}'"
            )
            return

        with target_path.open("w", encoding="utf-8", newline='\n') as f:
            f.write(content)

        if hasattr(os, "chmod") and hasattr(stat, "S_IEXEC"):
            try:
                st = os.stat(target_path)
                os.chmod(target_path, st.st_mode | stat.S_IEXEC)
            except OSError as perm_err:
                print(f"⚠️ Uyarı: Dosya izinleri ayarlanamadı: {perm_err}")

        print(f"✅ Dosya başarıyla oluşturuldu: {target_path}")

    except PermissionError:
        print(f"❌ HATA: '{filename}' dosyasına yazma izniniz yok.")
    except IsADirectoryError:
        print(f"❌ HATA: '{filename}' bir dizin, dosya değil.")
    except IOError as e:
        print(f"❌ Dosya yazma hatası ({filename}): {e}")
    except Exception as e:
        print(f"❌ Beklenmeyen hata ({filename}): {e}")


def print_ssh_usage(filename: str) -> None:
    """SSH kullanım ipuçlarını ekrana basar."""
    try:
        current_dir = Path.cwd().resolve()
        local_path = current_dir / filename
        remote_tmp_path = f"/tmp/{filename}"
        
        cmd = (
            f'cat "{local_path}" | ssh root@192.168.1.1 '
            f'"cat > {remote_tmp_path} && chmod +x {remote_tmp_path} && {remote_tmp_path}"'
        )
        
        print(f"\n    💡 İPUCU: '{filename}' dosyasını router'da tek seferde çalıştırmak için:")
        print(f"    {cmd}")
    except Exception:
        pass