package dev.barron.i18n;

import java.util.HashMap;
import java.util.Map;

/**
 * Internationalization system for Barron License Manager
 * Supports: Turkish (default), English, Chinese
 */
public class I18n {

    public enum Language {
        TURKISH("tr", "Türkçe"),
        ENGLISH("en", "English"),
        CHINESE("cn", "中文");

        private final String code;
        private final String displayName;

        Language(String code, String displayName) {
            this.code = code;
            this.displayName = displayName;
        }

        public String getCode() {
            return code;
        }

        public String getDisplayName() {
            return displayName;
        }
    }

    private static Language currentLanguage = Language.TURKISH;
    private static final Map<String, Map<Language, String>> translations = new HashMap<>();

    static {
        // Page names
        add("page.encrypt", "Şifreleme", "Encryption", "加密");
        add("page.licenses", "Lisans Üretimi", "License Generation", "许可证生成");
        add("page.manage", "Yönetim", "Management", "管理");
        add("page.settings", "Ayarlar", "Settings", "设置");

        // Encryption page
        add("encrypt.title", "Plugin Şifreleme", "Plugin Encryption", "插件加密");
        add("encrypt.dragjar", "JAR dosyasını buraya sürükle", "Drag JAR file here", "将JAR文件拖到这里");
        add("encrypt.mode.normal", "Normal Şifreleme", "Normal Encryption", "普通加密");
        add("encrypt.mode.server", "Sunucu Taraflı", "Server-Side", "服务器端");
        add("encrypt.mode.normal.desc", "Kolay ve hızlı", "Easy and fast", "简单快速");
        add("encrypt.mode.server.desc", "Maksimum güvenlik", "Maximum security", "最大安全");
        add("encrypt.button", "🚀 ŞİFRELE", "🚀 ENCRYPT", "🚀 加密");
        add("encrypt.settings", "Şifreleme Ayarları", "Encryption Settings", "加密设置");
        add("encrypt.string", "String Şifreleme", "String Encryption", "字符串加密");
        add("encrypt.rename", "İsim Değiştirme", "Identifier Renaming", "标识符重命名");
        add("encrypt.controlflow", "Kontrol Akışı", "Control Flow", "控制流");
        add("encrypt.deadcode", "Sahte Kod", "Dead Code", "死代码");
        add("encrypt.antidebug", "Anti-Debug", "Anti-Debug", "反调试");

        // License page
        add("license.title", "Lisans Üretimi", "License Generation", "许可证生成");
        add("license.plugins", "Şifrelenmiş Pluginler", "Encrypted Plugins", "加密的插件");
        add("license.doubleclick", "Çift tıkla → Yeni lisans oluştur", "Double-click → Create new license",
                "双击 → 创建新许可证");
        add("license.duration", "Lisans Süresi", "License Duration", "许可证期限");
        add("license.unlimited", "Süresiz", "Unlimited", "无限期");
        add("license.limited", "Süreli", "Limited", "限时");
        add("license.days", "gün", "days", "天");
        add("license.created", "Lisans oluşturuldu", "License created", "许可证已创建");
        add("license.copy", "Kopyala", "Copy", "复制");

        // Management page
        add("manage.title", "Lisans Yönetimi", "License Management", "许可证管理");
        add("manage.key", "Lisans Anahtarı", "License Key", "许可证密钥");
        add("manage.user", "Kullanıcı", "User", "用户");
        add("manage.ips", "IP Adresleri", "IP Addresses", "IP地址");
        add("manage.expires", "Süre", "Expires", "到期");
        add("manage.status", "Durum", "Status", "状态");
        add("manage.online", "Online", "Online", "在线");
        add("manage.offline", "Offline", "Offline", "离线");
        add("manage.delete", "Seçili Sil", "Delete Selected", "删除选中");
        add("manage.refresh", "Yenile", "Refresh", "刷新");
        add("manage.search", "Ara...", "Search...", "搜索...");
        add("manage.notactivated", "Aktif değil", "Not activated", "未激活");

        // Settings page
        add("settings.title", "Ayarlar", "Settings", "设置");
        add("settings.language", "Dil", "Language", "语言");
        add("settings.mysql", "MySQL Bağlantısı", "MySQL Connection", "MySQL连接");
        add("settings.host", "Host", "Host", "主机");
        add("settings.port", "Port", "Port", "端口");
        add("settings.user", "Kullanıcı", "User", "用户");
        add("settings.password", "Şifre", "Password", "密码");
        add("settings.database", "Veritabanı", "Database", "数据库");
        add("settings.loadbalancer", "Load Balancer (Yedek Sunucu)", "Load Balancer (Backup Server)", "负载均衡器（备份服务器）");
        add("settings.backup.host", "Yedek MySQL Host", "Backup MySQL Host", "备份MySQL主机");
        add("settings.backup.copy", "Verileri Yedek Sunucuya Kopyala", "Copy Data to Backup Server", "将数据复制到备份服务器");
        add("settings.webport", "Web Panel Portu", "Web Panel Port", "Web面板端口");
        add("settings.save", "Kaydet", "Save", "保存");
        add("settings.test", "Bağlantıyı Test Et", "Test Connection", "测试连接");

        // Common
        add("common.success", "Başarılı", "Success", "成功");
        add("common.error", "Hata", "Error", "错误");
        add("common.warning", "Uyarı", "Warning", "警告");
        add("common.yes", "Evet", "Yes", "是");
        add("common.no", "Hayır", "No", "否");
        add("common.cancel", "İptal", "Cancel", "取消");
        add("common.ok", "Tamam", "OK", "确定");
    }

    private static void add(String key, String tr, String en, String cn) {
        Map<Language, String> langMap = new HashMap<>();
        langMap.put(Language.TURKISH, tr);
        langMap.put(Language.ENGLISH, en);
        langMap.put(Language.CHINESE, cn);
        translations.put(key, langMap);
    }

    public static String get(String key) {
        Map<Language, String> langMap = translations.get(key);
        if (langMap == null)
            return key;
        String value = langMap.get(currentLanguage);
        return value != null ? value : key;
    }

    public static void setLanguage(Language language) {
        currentLanguage = language;
    }

    public static Language getLanguage() {
        return currentLanguage;
    }
}
