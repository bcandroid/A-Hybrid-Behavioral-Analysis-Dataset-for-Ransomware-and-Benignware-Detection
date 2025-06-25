function instrumentCreateMutex(opts) {
	if(opts.ex) {
		var pCreateMutex = opts.unicode ? Module.findExportByName(null, "CreateMutexExW")
                                    	: Module.findExportByName(null, "CreateMutexExA");
    } else {
		var pCreateMutex = opts.unicode ? Module.findExportByName(null, "CreateMutexW")
                                    	: Module.findExportByName(null, "CreateMutexA");
    }
	Interceptor.attach(pCreateMutex, {
		onEnter: function(args) {
			if(opts.ex) {
				var mutex = opts.unicode ? args[1].readUtf16String() : args[1].readUtf8String();
			} else {
				var mutex = opts.unicode ? args[2].readUtf16String() : args[2].readUtf8String();
			}
			send({
				'hook': 'CreateMutex'
			});
		}
	});
}
instrumentCreateMutex({unicode: 0, ex: 0});
instrumentCreateMutex({unicode: 1, ex: 0});
instrumentCreateMutex({unicode: 0, ex: 1});
instrumentCreateMutex({unicode: 1, ex: 1});
