# 如何开始我们的trace之旅

# 第三方工具推荐
- 支持本trace格式的分析 https://github.com/bobmis/TraceAnalyzer-main  

# 注意事项

本trace目前仅支持了arm64架构，在一些老的机型上走的是arm32，是无法trace的，后面会优先支持\

- 2025.12.25更新，不再依赖面具模块刷入读取内存，支持安卓14+系统
- 签名发生变化 vm_call 改为qbdi_vm_call  

# 从零开始使用这个trace

## 前戏准备

关闭 selinux

```bash
adb shell
su
setenforce 0
```

推送test.so到/data/local/tmp‍

## 开始trace

trace脚本有两种注入方法 attach/spwan

### attach注入法

首先以文章中的xiaoyuan来做讲解 第一篇文章在此
https://bbs.kanxue.com/thread-283960.htm 
xiaoyuan带着msao（见文章），我们可以使用spwan使用过掉msao的脚本

然后在attach注入

`frida -U -f com.fenbi.android.leo -l /Users/mac/Documents/androidtools/bypassmsao.js`​

‍

![CleanShot_2025_02_10_at_21_36_32](assets/CleanShot_2025_02_10_at_21_36_32-20250210213636-i0s8hga.png)​

在这个状态下粘贴demo/xiaoyuan/xiaoyuan.js进到shell里

![CleanShot_2025_02_10_at_21_37_18](assets/CleanShot_2025_02_10_at_21_37_18-20250210213723-u6vm9r4.png)​

然后按回车就可以了

‍

如果遇到了这个报错

![CleanShot_2025_02_10_at_21_38_09](assets/CleanShot_2025_02_10_at_21_38_09-20250210213817-du7l29p.png)​

首先你需要检查是否setenfore 0这个命令是否运行，因为selinux不关闭无法注入/data/local/tmp目录下的东西

第二要检查你是否把so移动到合适的位置

至于为什么是data/local/tmp 因为所有app都对这个目录有可读权限

```javascript
var  dlopenPtr = Module.findExportByName(null, 'dlopen');
var  dlopen = new NativeFunction(dlopenPtr, 'pointer', ['pointer', 'int']);
var  soPath = "/data/local/tmp/test.so"; // 示例路径
var  soPathPtr = Memory.allocUtf8String(soPath);
var  handle = dlopen(soPathPtr, 2);
```

你可以在这里找到注入逻辑手动注入so到app进程中

![CleanShot_2025_02_10_at_21_40_49](assets/CleanShot_2025_02_10_at_21_40_49-20250210214059-cjstf15.png)​

如果正常注入的话，你可以通过输入handle拿到注入so的数值‍

在一切注入无误后 我们可以主动调用

![CleanShot_2025_02_10_at_21_41_38](assets/CleanShot_2025_02_10_at_21_41_38-20250210214156-5duv42c.png)​

在出现结果以后建议立马按ctrl+D 退出

![CleanShot_2025_02_10_at_21_42_12](assets/CleanShot_2025_02_10_at_21_42_12-20250210214234-gi1xzo3.png)​

为什么要退出？ 因为其他接口也会调用到这个函数逻辑里，如果不退出可能会出现log.log的内容和你frida打印不一致的情况

就没有什么别的好方法了吗？ 有，让我们来看spwan注入方法

### spwan注入方法 感谢D_Z66666大佬帮忙共同完成

这个脚本是trace某宝的
> 如果不需要打印内存 把        var res =vmtrace(targetFuncAddr, argsPtr,argNum,argPtr1,1); 最后一个1 改成0
```javascript
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
        if (!arg) {
            arg = 0
        }
        if (arg instanceof NativePointer) {
            // 如果是 NativePointer，直接使用
            argPtr = arg;
        } else if (typeof arg === 'number') {
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

var vmtraceAddr;
var vmtrace;


function hook_sub_1329B0() {
    var aimbase =Module.findBaseAddress("libsgmainso-6.6.231204.so");
    console.log("start hook");
    var targetFuncAddr = aimbase.add(0x1329B0);
    Interceptor.replace(targetFuncAddr, new NativeCallback(function (arg0,arg1,arg2,arg3,arg4,arg5) {
        console.log("trace调用了");
        Interceptor.revert(targetFuncAddr);
        Interceptor.flush();
        var args =[arg0,arg1,arg2,arg3,arg4,arg5];
        var {argsPtr, argNum} = prepareArgs(args);
        var argPtr1 = Memory.allocUtf8String("/data/user/0/com.taobao.taobao/log.txt");
        var res =vmtrace(targetFuncAddr, argsPtr,argNum,argPtr1,1);
        console.log(res)
        return res;
    }, 'pointer', ['pointer','pointer','pointer','pointer','pointer','pointer']));
}

function hook_soload() {
    var  dlopenPtr = Module.findExportByName(null, 'dlopen');
    var  dlopen = new NativeFunction(dlopenPtr, 'pointer', ['pointer', 'int']);
    var soPath = "/data/local/tmp/test.so"; // 示例路径
    var  soPathPtr = Memory.allocUtf8String(soPath);
    var handle = dlopen(soPathPtr, 2);
    console.log(handle);
    vmtraceAddr = Module.findExportByName("test.so", 'qbdi_vm_call');
    vmtrace = new NativeFunction(vmtraceAddr, 'pointer', ['pointer', 'pointer', 'uint32', 'pointer', 'uint32']);

    var isinit = 0;
    var dlopen_addr = Module.findExportByName(null, "android_dlopen_ext");
    var find = 0;
    console.log("android_dlopen_ext: ", dlopen_addr);
    Interceptor.attach(dlopen_addr, {
        onEnter: function (args) {
            var addr = args[0];
            var str = ptr(addr).readCString();
            this.name = str;

            if (str.indexOf("libsgmainso-6.6.231204.so") >= 0) {
                console.log("dlopen==> " + (str));
                find = 1;
            } else {
                find = 0;
            }
        },
        onLeave: function (retval) {
            if (find > 0) {
                if (isinit == 0) {
                    hook_sub_1329B0();
                    isinit = 1;
                }

            }
        }
    })


}
setImmediate(hook_soload)
```

我来带大家简单读一下这个脚本，

hook了so加载的地方，当目标so加载完成的时候开始hook，但是如果你想hook init函数段则需要更改时机

```javascript
Interceptor.revert(targetFuncAddr);
Interceptor.flush();
```

这两句代码保证被替换的函数只被替换一次后就被还原，保证你的trace只走一次，只生成一份log

防止一个高频调用的函数一直处于trace状态，导致trace文件被覆盖

注意 new NativeCallback(function (arg0,arg1,arg2,arg3,arg4,arg5)

参数的个数需要根据函数的签名填写，如果填写多了/少了就可能造成崩溃，所以最重要的是确定好要传入的参数

‍

# 常见问题

## Error: expected a pointer

![CleanShot_2025_02_10_at_21_38_09](assets/CleanShot_2025_02_10_at_21_38_09-20250210213817-du7l29p.png)​

首先你需要检查是否setenfore 0这个命令是否运行，因为selinux不关闭无法注入/data/local/tmp目录下的东西

第二要检查你是否把so移动到合适的位置

至于为什么是data/local/tmp 因为所有app都对这个目录有可读权限

‍
