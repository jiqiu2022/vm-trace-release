function prepareArgs(args) {
    if (args === undefined || !Array.isArray(args)) {
        args = [];
    }
    var argNum = args.length;
    var argSize = Process.pointerSize * argNum;
    var argsPtr = Memory.alloc(argSize);

    for (var i = 0; i < argNum; i++) {
        var arg = args[i];
        var argPtr;
        if (!arg){
            arg=0
        }
        if (arg instanceof NativePointer) {
            // 如果是 NativePointer，直接使用
            argPtr = arg;
        }else if(typeof arg === 'object' ){
            // 如果是对象，直接转换为指针
            //形如 jstring Java_com_demo_app_genToken(JNIEnv *env, jobject obj, long str)这种registerNative的函数参数对象可以处理
            argPtr = ptr(arg);
        }
    
        else if (typeof arg === 'number') {
            // 如果是数字，直接转换为指针
            argPtr = ptr(arg);
        } else if (typeof arg === 'string') {
            // 如果是字符串，分配内存并获取指针
            argPtr = Memory.allocUtf8String(arg);
        } else if (typeof arg === 'object' && arg.hasOwnProperty('handle')) {
            // 如果是带有 handle 属性的对象（如 JNIEnv）
            argPtr = arg.handle;
        } else if (typeof arg === 'object' && arg instanceof ArrayBuffer) {
            // 如果是二进制数据，分配内存并写入数据
            var dataPtr = Memory.alloc(arg.byteLength);
            Memory.writeByteArray(dataPtr, arg);
            argPtr = dataPtr;
        } else {
            console.error('Unsupported argument type at index ' + i + ':', typeof arg);
            throw new TypeError('Unsupported argument type at index ' + i + ': ' + typeof arg);
        }

        // 将参数指针写入参数数组
        Memory.writePointer(argsPtr.add(i * Process.pointerSize), argPtr);
    }

    return {
        argsPtr: argsPtr,
        argNum: argNum
    };
}

var  dlopenPtr = Module.findExportByName(null, 'dlopen');
var  dlopen = new NativeFunction(dlopenPtr, 'pointer', ['pointer', 'int']);
var soPath = "/data/local/tmp/test.so"; // 示例路径
var  soPathPtr = Memory.allocUtf8String(soPath);
var handle = dlopen(soPathPtr, 2);

var traceaddr = Module.findExportByName("test.so", 'vm_call');
// 更新函数签名：最后一个参数从 openStrLog 变为 windowSize
var trace = new NativeFunction(traceaddr, 'pointer', ['pointer', 'pointer', 'uint32','pointer','size_t']);
var aimbase =Module.findBaseAddress("libRequestEncoder.so");
var targetFuncAddr = aimbase.add(0x61bf4);
console.log(handle);
Interceptor.replace(targetFuncAddr, new NativeCallback(function (arg0,arg1,arg2,arg3,arg4,arg5) {
    console.log("memory_function called with pointer: " + ptr);
    var args =[arg0,arg1,arg2,arg3,arg4,arg5];
    var {argsPtr, argNum} = prepareArgs(args);
    var argPtr1 = Memory.allocUtf8String("/data/user/0/com.fenbi.android.leo/log.txt");
    // 使用 windowSize 参数 (0x200) 替代原来的 openStrLog 参数 (6)
    // openStrLog 现在已经在 vm_call 函数内部固定为 6
    var res =trace(targetFuncAddr, argsPtr, argNum, argPtr1, 0x200); // 使用较大的窗口大小 0x200
    return ptr(res);
}, 'pointer', ['pointer','pointer','pointer','pointer','uint32']));
function call(){
    Java.perform(function() {
        console.log("gan_sign script loaded successfully");

        // 使用要 hook 的 Java 类
        var e = Java.use("com.fenbi.android.leo.utils.e");

        // 定义输入参数
        var str = "/leo-gateway/android/auth/password";  // 要访问的链接
        var str2 = "wdi4n2t8edr";  // 固定参数
        var intParam = -28673;  // 获取 int 参数

        // 调用目标方法并获取返回值
        var result = e.zcvsd1wr2t(str, str2, intParam);

        // 输出输入参数
        console.log("input: ", str, str2, intParam);

        // 发送返回值到 Frida 客户端
        send(result);

        // 输出返回结果
        console.log("output: ", result);
    });


}