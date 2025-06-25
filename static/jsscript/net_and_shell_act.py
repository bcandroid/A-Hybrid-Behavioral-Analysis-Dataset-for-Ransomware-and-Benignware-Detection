// Source: https://github.com/fr0gger/MalwareMuncher
var DEBUG_FLAG = true;

// Allow Shell commands
var ALLOW_SHELL = false;

// Allow DNS Requests
var DISABLE_DNS = false;

// Allow WSASend
var DISABLE_WSASEND = true;

// Allow COM Object lookup
var DISABLE_COM_INIT = true;

recv('set_script_vars', function onMessage(setting) {

    debug("Setting Script Vars...")
    DEBUG_FLAG = setting['debug'];
    debug(" - DEBUG_FLAG: " +  DEBUG_FLAG);
    DISABLE_DNS = setting['disable_dns'];
    debug(" - DISABLE_DNS: " +  DISABLE_DNS);
    ALLOW_SHELL = setting['allow_shell'];
    debug(" - ALLOW_SHELL: " +  DISABLE_DNS);
    DISABLE_WSASEND = setting['disable_send'];
    debug(" - DISABLE_WSASEND: " +  DISABLE_WSASEND);
    DISABLE_COM_INIT = setting['disable_com'];
    debug(" - DISABLE_COM_INIT: " +  DISABLE_COM_INIT);

});

function debug(msg)
{
    if(DEBUG_FLAG == true){
        send({
            name: 'log',
            payload: msg
        });
        recv('ack', function () {}).wait();
    }
}

function log_instr(msg){
    send({
        name: 'instr',
        hookdata: msg
    });
}

const NAMESPACE = {
    0:"NS_ALL",
    12:"NS_DNS",
    13:"NS_NETBT",
    14:"NS_WINS",
    15:"NS_NLA",
    16:"NS_BTH",
    32:"NS_NTDS",
    37:"NS_EMAIL",
    38:"NS_PNRPNAME",
    39:"NS_PNRPCLOUD"
};

const WSAHOST_NOT_FOUND = 11001;

var ptrGetAddrInfoExW = Module.findExportByName("WS2_32.DLL", "GetAddrInfoExW");
var GetAddrInfoExW = new NativeFunction(ptrGetAddrInfoExW, 'int', ['pointer', 'pointer', 'uint', 'pointer','pointer','pointer', 'pointer', 'pointer', 'pointer', 'pointer']);

Interceptor.replace(ptrGetAddrInfoExW, new NativeCallback(function (pName, pServiceName, dwNameSpace, lpNspId, pHints, ppResult, timeout, lpOverlapped, lpCompletionRoutine, lpNameHandle) {
    var retval = WSAHOST_NOT_FOUND;
    if (!DISABLE_DNS) {
        retval = GetAddrInfoExW(pName, pServiceName, dwNameSpace, lpNspId, pHints, ppResult, timeout, lpOverlapped, lpCompletionRoutine, lpNameHandle);
    }
    
    var namespaceName = NAMESPACE[dwNameSpace] || "UNKNOWN";
    
    send({
        hook: namespaceName
    });
    
    return retval;
}, 'int', ['pointer', 'pointer', 'uint', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer'], 'stdcall'));


var ptrWSASend = Module.findExportByName("WS2_32.DLL", "WSASend");
var WSASend = new NativeFunction(ptrWSASend, 'int', ['pointer', 'pointer', 'uint', 'pointer','uint','pointer', 'pointer']);
var buffer = null; // buffer değişkenini global olarak tanımlıyoruz

Interceptor.replace(ptrWSASend, new NativeCallback(function (s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine) {
    var retval = 10060;
    if(!DISABLE_WSASEND) {
        retval = WSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
    }
    else {
        // Eğer buffer önceki buffer ile aynıysa, işlemi geçiyoruz
        if (buffer === lpBuffers) {
            return retval;
        }
        buffer = lpBuffers; // buffer'ı güncelliyoruz
    }
    debug("----------------------");
    debug("   |-- Socket (" + s + ")");
    debug("   |-- LPWSABUF (" + lpBuffers + ")");
    debug("   |-- Buffers " + dwBufferCount);

    var buff_len = Memory.readInt(ptr(lpBuffers));
    debug("Buffer Length: " + buff_len);
    var lpwbuf = lpBuffers;
    lpwbuf = lpwbuf.toInt32() + 4;
    var dptr = Memory.readInt(ptr(lpwbuf));

    var request_data = Memory.readCString(ptr(dptr), buff_len);

    try {
        debug("-- Request Data --");
        debug(request_data);
        debug("-- Request Data End --");
        
        // Veriyi send fonksiyonu ile gönderiyoruz
        send({
            hook: "WSASend", 
            request_data: request_data
        });
    }
    catch(err) {
        debug("Error in reading or sending data: " + err);
    }

    return retval;

}, 'int', ['pointer', 'pointer', 'uint', 'pointer', 'uint', 'pointer', 'pointer'], 'stdcall'));

var ptrWSAStartup = Module.findExportByName("WS2_32.DLL", "WSAStartup");
Interceptor.attach(ptrWSAStartup, {
    onEnter: function (args) {
        send({
            hook: "WSAStartup"
        });
    },
    onLeave: function (retval) {
        if (retval.toInt32() > 0) {
            debug("WSAStartup completed successfully");
        }
    }
});

var ptrWSAAddressToStringW = Module.findExportByName("WS2_32.DLL", "WSAAddressToStringW");
Interceptor.attach(ptrWSAAddressToStringW, {
    onEnter: function (args) {
        send({
            hook: "WSAAddressToStringW"
        });
    },
    onLeave: function (retval) {
        if (retval.toInt32() > 0) {
            // Başarı durumu
            debug("WSAAddressToStringW completed successfully");
        }
    }
});

var ptrShellExecute = Module.findExportByName("Shell32.dll", "ShellExecuteExW");
var ShellExecute = new NativeFunction(ptrShellExecute, 'int', ['pointer']);

Interceptor.replace(ptrShellExecute, new NativeCallback(function (executeinfo) {
    var retval = false;
    retval = ShellExecute(executeinfo);

    var shellinfo_ptr = executeinfo;
    var structure_size = Memory.readUInt(shellinfo_ptr);
    var ptr_file = Memory.readPointer(shellinfo_ptr.add(16));
    var ptr_params = Memory.readPointer(shellinfo_ptr.add(20));
    var nshow = Memory.readInt(shellinfo_ptr.add(28));

    var lpfile = Memory.readUtf16String(ptr(ptr_file));
    var lpparams = Memory.readUtf16String(ptr(ptr_params));

    send({
        hook: SHOWCMD[nshow]
    });

    return retval;
}, 'int', ['pointer'], 'stdcall'));

// SHOWCMD sabitleri
const SHOWCMD = {
    0: "SW_HIDE",
    1: "SW_SHOWNORMAL",
    2: "SW_SHOWMINIMIZED",
    3: "SW_SHOWMAXIMIZED",
    4: "SW_SHOWNOACTIVATE",
    5: "SW_SHOW",
    6: "SW_MINIMIZE",
    7: "SW_SHOWMINNOACTIVE",
    8: "SW_SHOWNA",
    9: "SW_RESTORE",
    10: "SW_SHOWDEFAULT"
};
