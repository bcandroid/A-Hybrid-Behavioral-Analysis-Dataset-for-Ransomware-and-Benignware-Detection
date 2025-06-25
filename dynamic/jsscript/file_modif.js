//source: https://github.com/fr0gger/MalwareMuncher
const FILE_ACCESS_MASKS = {
	"GENERIC_ALL": 0x10000000,
	"GENERIC_EXECUTE": 0x20000000,	
	"GENERIC_WRITE": 0x40000000,
	"GENERIC_READ": 0x80000000
};

const FILE_CREATION_ACTIONS = {
	"CREATE_ALWAYS": 2,
	"CREATE_NEW": 1,
	"OPEN_ALWAYS": 4,
	"OPEN_EXISTING": 3,
	"TRUNCATE_EXISTING": 5
};

function instrumentCreateFile(opts) {
	var pCreateFile = opts.unicode ? Module.findExportByName(null, "CreateFileW")
                                   : Module.findExportByName(null, "CreateFileA");
	Interceptor.attach(pCreateFile, {
		onEnter: function(args) {
			this.path = opts.unicode ? args[0].readUtf16String() : args[0].readUtf8String();
			var mask = args[1].toInt32();
			var action = args[4].toInt32();

			this.new = 0;
			if(action == FILE_CREATION_ACTIONS["CREATE_ALWAYS"] || action == FILE_CREATION_ACTIONS["CREATE_NEW"])
				this.new = 1;
		},
		onLeave: function(retval) {
			send({
				'hook': 'CreateFile'
			});
		}
	});
}
instrumentCreateFile({unicode: 0});
instrumentCreateFile({unicode: 1});


var pWriteFile = Module.getExportByName(null, "WriteFile");
Interceptor.attach(pWriteFile, {
	onEnter: function(args) {
		send({
			'hook': 'WriteFile'
		});
	}
});

function instrumentMoveFile(opts) {
	if(opts.ex) {
		var pMoveFile = opts.unicode ? Module.findExportByName(null, "MoveFileExW")
                                     : Module.findExportByName(null, "MoveFileExA");
    } else {
		var pMoveFile = opts.unicode ? Module.findExportByName(null, "MoveFileW")
                                     : Module.findExportByName(null, "MoveFileA");
    }
	Interceptor.attach(pMoveFile, {
		onEnter: function(args) {
			var oldpath = opts.unicode ? args[0].readUtf16String() : args[0].readUtf8String();
			var newpath = opts.unicode ? args[1].readUtf16String() : args[1].readUtf8String();
			send({
				'hook': 'MoveFile'
			});
		}
	});
}
instrumentMoveFile({unicode: 0, ex: 0});
instrumentMoveFile({unicode: 1, ex: 0});
instrumentMoveFile({unicode: 0, ex: 1});
instrumentMoveFile({unicode: 1, ex: 1});

function instrumentCopyFile(opts) {
	if(opts.ex) {
		var pCopyFile = opts.unicode ? Module.findExportByName(null, "CopyFileExW")
                                     : Module.findExportByName(null, "CopyFileExA");
    } else {
		var pCopyFile = opts.unicode ? Module.findExportByName(null, "CopyFileW")
                                     : Module.findExportByName(null, "CopyFileA");
    }
	Interceptor.attach(pCopyFile, {
		onEnter: function(args) {
			var oldpath = opts.unicode ? args[0].readUtf16String() : args[0].readUtf8String();
			var newpath = opts.unicode ? args[1].readUtf16String() : args[1].readUtf8String();
			send({
				'hook': 'CopyFile'
			});
		}
	});
}
instrumentCopyFile({unicode: 0, ex: 0});
instrumentCopyFile({unicode: 1, ex: 0});
instrumentCopyFile({unicode: 0, ex: 1});
instrumentCopyFile({unicode: 1, ex: 1});

function instrumentDeleteFile(opts) {
	var pDeleteFile = opts.unicode ? Module.findExportByName(null, "DeleteFileW")
                                   : Module.findExportByName(null, "DeleteFileA");
	Interceptor.attach(pDeleteFile, {
		onEnter: function(args) {
			var path = opts.unicode ? args[0].readUtf16String() : args[0].readUtf8String();
			send({
				'hook': 'DeleteFile'
			});
		}
	});
}
instrumentDeleteFile({unicode: 0});
instrumentDeleteFile({unicode: 1});
