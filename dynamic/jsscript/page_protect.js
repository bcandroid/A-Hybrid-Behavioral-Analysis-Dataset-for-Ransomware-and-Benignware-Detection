var vpExportAddress = Module.getExportByName("kernel32.dll", "VirtualProtect");
Interceptor.attach(vpExportAddress, {   
    onEnter: function(args) {
        var vpProtect = args[2].toInt32();  // Bellek koruma bayrağını al

        // Koruma türlerini çözümlemek için bir fonksiyon
        var protectionType = getProtectionType(vpProtect);
        send({
                    'func': protectionType
                });
    }
});

// Koruma bayrağını açıklayan fonksiyon
function getProtectionType(protectionFlag) {
    switch (protectionFlag) {
        case 0x01:
            return "PAGE_READONLY";                 // Bellek sadece okuma için erişilebilir
        case 0x02:
            return "PAGE_READWRITE";                // Bellek hem okuma hem de yazma için erişilebilir
        case 0x04:
            return "PAGE_WRITECOPY";                // Bellek yazmaya kopyalanabilir
        case 0x08:
            return "PAGE_EXECUTE";                  // Bellek yalnızca çalıştırma için erişilebilir
        case 0x10:
            return "PAGE_EXECUTE_READ";             // Bellek okuma ve çalıştırma için erişilebilir
        case 0x20:
            return "PAGE_EXECUTE_READWRITE";        // Bellek okuma, yazma ve çalıştırma için erişilebilir
        case 0x40:
            return "PAGE_EXECUTE_WRITE";            // Bellek hem yazma hem de çalıştırma için erişilebilir
        case 0x80:
            return "PAGE_WRITECOPY";                // Bellek yazmaya kopyalanabilir
        case 0x100:
            return "PAGE_GUARD";                   // Bellek koruma mekanizması etkin
        case 0x200:
            return "PAGE_NOCACHE";                 // Bellek önbelleklenemez
        case 0x400:
            return "PAGE_WRITECOMBINE";            // Bellek yazma birleşiminde kullanılabilir
        case 0x1000:
            return "PAGE_NOACCESS";                // Belleğe erişim yok
        case 0x2000:
            return "PAGE_EXECUTE_WRITECOPY";       // Bellek çalıştırma ve yazma için kopyalanabilir
        case 0x80000000:
            return "PAGE_SECTION";                 // Bellek bölüm sayfası
        case 0x40000000:
            return "PAGE_PHYSICAL";                // Fiziksel bellek sayfası
        case 0x80000000:
            return "PAGE_USER";                    // Kullanıcı modu bellek sayfası
        default:
            return "Unknown protection: " + protectionFlag.toString(16);  // Bilinmeyen koruma türü
    }
}

