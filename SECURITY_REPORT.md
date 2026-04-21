# Barron Obfuscator - Güvenlik Analizi Raporu

**Tarih:** 23.01.2026
**Puan:** 65/100 (Orta Seviye)

## Özet
Proje, temel düzeyde koruma sağlayan ancak deneyimli bir tersine mühendis (reverse engineer) tarafından aşılabilecek zafiyetler barındıran bir yapıdadır. Sunucu tarafı güvenliği (Backend) oldukça sağlamken, İstemci tarafı (Plugin/Injector) korumaları zayıftır.

## Detaylı Puanlama

### 1. Obfuscation (Kod Karıştırma) - 50/100
*   **[+] String Şifreleme:** Mevcut, ancak anahtarların yönetimi statik olabilir.
*   **[+] Akış Kontrolü:** `try-catch` blokları ile akış değiştirme ve `switch` mekanizmaları iyi düşünülmüş.
*   **[-] Bytecode:** Java bytecode doğası gereği kolayca decompile edilebilir (C++ native kütüphane kullanılmadığı sürece).
*   **[-] Sabit Değerler:** "OFFLINE_TOKEN" gibi kritik stringler kod içinde açıkça görünüyor.

### 2. Lisans Sistemi (Client Ops) - 40/100
*   **[-] Zayıf HWID:** "Hardware Hash" olarak adlandırılan yapı aslında `IP:Port` bilgisini kullanıyor. Sunucu IP'si değişirse veya plugin localde test edilirse hash değişiyor. Gerçek donanım (CPU, MAC, Anakart ID) kontrolü yok.
*   **[!] Kritik Zafiyet (Offline Mod):** `LicenseCheckInjector.java` içinde çevrimdışı kontrolü için `OFFLINE_TOKEN` string sabiti kullanılıyor. Bir saldırgan sadece bu stringi dönen bir metod yazarak lisans kontrolünü atlatabilir.
*   **[-] Token Doğrulama:** İstemci tarafında sunucudan gelen token'ın sadece uzunluğu (Length > 32) kontrol ediliyor. İmza doğrulaması (HMAC) tam yapılmıyor.

### 3. Backend Güvenliği (Server Ops) - 90/100
*   **[+] SQL Güvenliği:** `DatabaseManager` içinde `PreparedStatement` kullanımı tutarlı, SQL Injection riski düşük.
*   **[+] Kimlik Doğrulama:** Parolalar `BCrypt` ile hashleniyor, bu endüstri standardıdır.
*   **[+] Ağ Güvenliği:** Cloudflare IP çözümlemesi ve Rate Limiting (Hız Sınırlama) başarıyla eklendi.
*   **[+] Loglama:** Şüpheli aktiviteler (çoklu IP kullanımı) tespit edilip loglanıyor.

## Tavsiyeler ve İyileştirme Planı

### Kısa Vadeli (Hemen Yapılmalı)
1.  **HWID Mantığını Geliştirin:** Sadece IP/Port yerine `System.getProperty("os.arch")`, `Runtime.getRuntime().availableProcessors()` gibi sistem özelliklerini de hash'e katın.
2.  **Offline Token'ı Kaldırın:** "OFFLINE_TOKEN" gibi sabitler yerine, sunucudan gelen imzalı ve süreli bir lisans dosyası (RSA imzalı) kullanın.
3.  **İstemci Token Kontrolü:** Sunucudan gelen `sessionToken`'ı istemci tarafında da gizli anahtarla (Shared Secret) doğrulayın, sadece uzunluğuna bakmayın.

### Uzun Vadeli
1.  **Native Kütüphane (JNI):** Lisans kontrolünün kritik kısımlarını C/C++ ile yazıp `.dll`/`.so` olarak gömün. Decompile edilmesi çok daha zorlaşır.
2.  **Dinamik Kod Yükleme:** Plugin'in asıl işlevsel kodunu sunucudan şifreli olarak çekip hafızada (memory) çalıştırın.

## Sonuç
Proje "Script Kiddie" seviyesindeki saldırganlara ve basit crack girişimlerine karşı korur ancak profesyonel bir saldırgana karşı dirençsizdir. Ticari bir ürün için HWID ve Offline lisanslama mantığının baştan yazılması önerilir.
