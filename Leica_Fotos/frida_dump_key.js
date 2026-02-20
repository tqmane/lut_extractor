// dump_key_native_string.js

function hookNative() {
    var libraryName = "libnative-lib.so";
    var funcName = "Java_com_leicacamera_obfuscation_NativeKeyProvider_getKey";
    
    var module = Process.findModuleByName(libraryName);
    
    if (module) {
        console.log("[+] Library found: " + module.name + " Base: " + module.base);
        var funcAddr = module.findExportByName(funcName);
        
        if (funcAddr) {
            console.log("[+] Function found at: " + funcAddr);
            
            Interceptor.attach(funcAddr, {
                onEnter: function(args) {
                    console.log("[*] Native getKey() called");
                },
                onLeave: function(retval) {
                    console.log("[*] Native getKey() returned: " + retval);
                    
                    if (retval.isNull()) return;

                    Java.perform(function() {
                        try {
                            // Try casting to String first as the previous error suggested it might not be [C
                            var strObj = Java.cast(retval, Java.use("java.lang.String"));
                            var keyStr = strObj.toString();
                            
                            console.log("--------------------------------------------------");
                            console.log("KEY FOUND (String): " + keyStr);
                            
                            var keyHex = "";
                            for (var i = 0; i < keyStr.length; i++) {
                                keyHex += keyStr.charCodeAt(i).toString(16).padStart(2, '0');
                            }
                            console.log("KEY FOUND (Hex):    " + keyHex);
                            console.log("--------------------------------------------------");
                            
                            Interceptor.detachAll();

                        } catch(e) {
                            console.log("[-] String cast failed: " + e);
                            
                            // Fallback: Try to inspect object type
                            try {
                                var obj = Java.cast(retval, Java.use("java.lang.Object"));
                                console.log("[-] Actual Object Type: " + obj.getClass().getName());
                            } catch (e2) {
                                console.log("[-] Could not get object type: " + e2);
                            }
                        }
                    });
                }
            });
            return true;
        }
    }
    return false;
}

var interval = setInterval(function() {
    if (hookNative()) {
        clearInterval(interval);
        console.log("[+] Hook installed.");
    }
}, 1000);

console.log("[*] Monitoring for library load...");
