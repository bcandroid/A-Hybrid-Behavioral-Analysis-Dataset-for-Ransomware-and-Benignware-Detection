//source: https://github.com/fr0gger/MalwareMuncher
const REG_KEYS = {
	0x80000000: "HKEY_CLASSES_ROOT",
	0x80000001: "HKEY_CURRENT_USER",
	0x80000002: "HKEY_LOCAL_MACHINE",
	0x80000003: "HKEY_USERS",
	0x80000004: "HKEY_PERFORMANCE_DATA",
	0x80000005: "HKEY_CURRENT_CONFIG",
	0x80000006: "HKEY_DYN_DATA",
	0x80000050: "HKEY_PERFORMANCE_TEXT",
	0x80000060: "HKEY_PERFORMANCE_NLSTEXT"
}
function instrumentRegCreateKey(opts) {
	if(opts.ex) {
		var pRegCreateKey = opts.unicode ? Module.findExportByName(null, "RegCreateKeyExW")
                                         : Module.findExportByName("Advapi32.dll", "RegCreateKeyExA");
    } else {
		var pRegCreateKey = opts.unicode ? Module.findExportByName(null, "RegCreateKeyW")
                                         : Module.findExportByName(null, "RegCreateKeyA");    	
    }
	Interceptor.attach(pRegCreateKey, {
		onEnter: function(args) {
			this.regkey = opts.unicode ? args[1].readUtf16String() : args[1].readUtf8String();
			var regclass = REG_KEYS[args[0].toInt32()>>>0];
			if(regclass != undefined)
				this.regkey = regclass + "\\" + this.regkey;
			else
				this.regkey = "\\" + this.regkey;

			this.handle = opts.ex ? args[7] : args[2];
		},
		onLeave: function(retval) {
			send({
				'hook': 'RegCreateKey'
			});
		}
	});
}
instrumentRegCreateKey({unicode: 0, ex: 0});
instrumentRegCreateKey({unicode: 1, ex: 0});
instrumentRegCreateKey({unicode: 0, ex: 1});
instrumentRegCreateKey({unicode: 1, ex: 1});

function instrumentRegOpenKey(opts) {
	if(opts.ex) {
		var pRegOpenKey = opts.unicode ? Module.findExportByName(null, "RegOpenKeyExW")
                                       : Module.findExportByName(null, "RegOpenKeyExA");
    } else {
		var pRegOpenKey = opts.unicode ? Module.findExportByName(null, "RegOpenKeyW")
                                       : Module.findExportByName(null, "RegOpenKeyA");    	
    }
	Interceptor.attach(pRegOpenKey, {
		onEnter: function(args) {
			this.regkey = opts.unicode ? args[1].readUtf16String() : args[1].readUtf8String();
			var regclass = REG_KEYS[args[0].toInt32()>>>0];
			if(regclass != undefined)
				this.regkey = regclass + "\\" + this.regkey;
			else
				this.regkey = "\\" + this.regkey;

			this.handle = opts.ex ? args[4] : args[2];
		},
		onLeave: function(retval) {
			send({
				'hook': 'RegOpenKey'
			});
		}
	});
}
instrumentRegOpenKey({unicode: 0, ex: 0});
instrumentRegOpenKey({unicode: 1, ex: 0});
instrumentRegOpenKey({unicode: 0, ex: 1});
instrumentRegOpenKey({unicode: 1, ex: 1});

function instrumentRegQueryValueEx(opts) {
	var pRegQueryValueEx = opts.unicode ? Module.findExportByName(null, "RegQueryValueExW")
                                        : Module.findExportByName(null, "RegQueryValueExA");
	Interceptor.attach(pRegQueryValueEx, {
		onEnter: function(args) {
			var regvalue = opts.unicode ? args[1].readUtf16String() : args[1].readUtf8String();
			var handle = args[0].toInt32();
			send({
				'hook': 'RegQueryValueEx'
			});
		}
	});
}
instrumentRegQueryValueEx({unicode: 0});
instrumentRegQueryValueEx({unicode: 1});

function instrumentRegSetValueEx(opts) {
	var pRegSetValueEx = opts.unicode ? Module.findExportByName(null, "RegSetValueExW")
                                      : Module.findExportByName(null, "RegSetValueExA");
	Interceptor.attach(pRegSetValueEx, {
		onEnter: function(args) {
			var regvalue = opts.unicode ? args[1].readUtf16String() : args[1].readUtf8String();
			var handle = args[0].toInt32();
			send({
				'hook': 'RegSetValueEx'
			});
		}
	});
}
instrumentRegSetValueEx({unicode: 0});
instrumentRegSetValueEx({unicode: 1});

function instrumentRegDeleteValue(opts) {
	var pRegDeleteValue = opts.unicode ? Module.findExportByName(null, "RegDeleteValueW")
                                       : Module.findExportByName(null, "RegDeleteValueA");
	Interceptor.attach(pRegDeleteValue, {
		onEnter: function(args) {
			var regvalue = opts.unicode ? args[1].readUtf16String() : args[1].readUtf8String();
			var handle = args[0].toInt32();
			send({
				'hook': 'RegDeleteValue'
			});
		}
	});
}
instrumentRegDeleteValue({unicode: 0});
instrumentRegDeleteValue({unicode: 1});
