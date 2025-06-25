var pGetProcAddress = Module.findExportByName(null, "GetProcAddress");
Interceptor.attach(pGetProcAddress, {
    onEnter: function(args) {
        var funcPtr = args[1];

        // Bellek adresi NULL mı?
        if (funcPtr.isNull()) {
            return; // NULL adresi ise hiçbir şey yapma
        }

        // Bellek adresinin okunabilir olup olmadığını kontrol et
        try {
            // Bellek bölgesi 4 byte'lık okuma izinli mi?
            if (Memory.protect(funcPtr, 4, 'r')) {
                var funcName = Memory.readUtf8String(funcPtr);
                send({
                    'func': args[1].readUtf8String()
                });
            }
        } catch (e) {
            // Bellek okuma hatası durumunda hiçbir şey yapma
            return;
        }
    }
});
