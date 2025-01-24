Response:
### 功能归纳

`script-runtime.js` 是 Frida 动态插桩工具的核心脚本运行时文件，主要负责处理脚本的执行、消息分发、异常处理、以及与底层系统的交互。以下是该文件的主要功能：

1. **消息分发与处理**：
   - 通过 `MessageDispatcher` 类处理来自 Frida 核心的消息分发。它负责接收、解析和分发消息，支持 RPC（远程过程调用）机制。
   - 支持 `recv` 和 `send` 方法，用于脚本与 Frida 核心之间的通信。

2. **异常处理**：
   - 通过 `Error.prepareStackTrace` 自定义错误堆栈信息的格式化输出。
   - 提供 `dispatchException` 方法，用于捕获并分发异常信息。

3. **底层指针操作**：
   - 提供 `BNativePointer` 类，用于处理本地指针操作，支持指针的加减、位运算、读写内存等操作。
   - 支持 `int64` 和 `uint64` 类型的大整数操作。

4. **调试功能**：
   - 提供 `gdb` 模块，用于与 GDB 调试器交互，支持读取和写入内存、寄存器等操作。
   - 提供 `hexdump` 函数，用于以十六进制格式打印内存内容。

5. **控制台输出**：
   - 提供 `Console` 类，用于控制台日志输出，支持 `info`、`log`、`debug`、`warn`、`error` 等不同级别的日志输出。

6. **模块与进程管理**：
   - 提供 `Module` 和 `Process` 对象，用于枚举模块、查找导出函数、管理进程等操作。
   - 支持 `enumerateModules`、`findExportByName` 等方法，用于获取模块信息和导出函数。

7. **脚本运行时环境**：
   - 提供 `Script` 对象，用于管理脚本的运行时环境，支持设置全局访问处理器等操作。

### 二进制底层与 Linux 内核相关功能

1. **内存操作**：
   - `BNativePointer` 类提供了对内存的直接读写操作，支持读取和写入不同大小的数据类型（如 `S8`、`U8`、`S16`、`U16` 等）。
   - 通过 `readByteArray` 和 `writeByteArray` 方法，可以读取和写入字节数组。

2. **进程与模块管理**：
   - `Process` 对象提供了对当前进程的管理功能，如获取进程 ID、平台信息、代码签名策略等。
   - `Module` 对象提供了对模块的管理功能，如枚举模块、查找导出函数等。

3. **调试功能**：
   - `gdb` 模块提供了与 GDB 调试器的交互功能，支持读取和写入内存、寄存器等操作。

### LLDB 调试示例

假设我们想要使用 LLDB 复刻 `BNativePointer` 类的 `readPointer` 方法的功能，以下是一个 LLDB Python 脚本示例：

```python
import lldb

def read_pointer(process, address):
    # 读取指针地址处的值
    error = lldb.SBError()
    pointer_value = process.ReadPointerFromMemory(address, error)
    if error.Success():
        return pointer_value
    else:
        raise Exception(f"Failed to read pointer at address {hex(address)}: {error}")

# 示例使用
def main():
    target = lldb.debugger.GetSelectedTarget()
    process = target.GetProcess()
    address = 0x100000000  # 替换为你要读取的地址
    pointer_value = read_pointer(process, address)
    print(f"Pointer value at {hex(address)}: {hex(pointer_value)}")

if __name__ == "__main__":
    main()
```

### 假设输入与输出

假设我们有一个指针地址 `0x100000000`，我们想要读取该地址处的指针值。

- **输入**：`0x100000000`
- **输出**：`0x200000000`（假设该地址处的指针值为 `0x200000000`）

### 常见使用错误

1. **指针越界**：
   - 用户可能会尝试读取或写入无效的内存地址，导致程序崩溃或未定义行为。
   - **示例**：`ptr(0xdeadbeef).readPointer()`，如果 `0xdeadbeef` 是一个无效地址，可能会导致崩溃。

2. **类型不匹配**：
   - 用户可能会错误地使用 `int64` 和 `uint64` 类型，导致数值溢出或符号错误。
   - **示例**：`int64(-1).toUInt32()`，可能会导致意外的结果。

3. **未处理的异常**：
   - 用户可能没有正确处理异常，导致脚本在遇到错误时无法继续执行。
   - **示例**：`try { ptr(0).readPointer() } catch (e) { console.log(e) }`，如果没有捕获异常，脚本可能会中断。

### 用户操作路径

1. **加载脚本**：
   - 用户通过 Frida 加载脚本，脚本开始执行 `script-runtime.js` 中的初始化代码。

2. **消息分发**：
   - 用户通过 `recv` 和 `send` 方法与 Frida 核心进行通信，`MessageDispatcher` 负责处理这些消息。

3. **内存操作**：
   - 用户通过 `BNativePointer` 类进行内存读写操作，`gdb` 模块提供底层支持。

4. **调试与日志**：
   - 用户通过 `Console` 类输出日志信息，通过 `hexdump` 函数查看内存内容。

5. **异常处理**：
   - 如果脚本执行过程中发生异常，`dispatchException` 方法会捕获并分发异常信息。

通过以上步骤，用户可以逐步深入到 Frida 的底层操作，实现动态插桩和调试功能。
### 提示词
```
这是目录为frida/subprojects/frida-python/build/subprojects/frida-core/src/barebone/script-runtime.js.p/script-runtime.js的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```javascript
📦
5833 /script-runtime/entrypoint.js.map
4457 /script-runtime/entrypoint.js
1315 /script-runtime/console.js.map
978 /script-runtime/console.js
233 /script-runtime/gdb.js.map
22 /script-runtime/gdb.js
2553 /script-runtime/hexdump.js.map
1131 /script-runtime/hexdump.js
3224 /script-runtime/message-dispatcher.js.map
2395 /script-runtime/message-dispatcher.js
6615 /script-runtime/primitives.js.map
4287 /script-runtime/primitives.js
✄
{"version":3,"file":"entrypoint.js","names":["Console","hexdump","MessageDispatcher","BNativePointer","BInt64","BUInt64","messageDispatcher","Error","prepareStackTrace","error","stack","toString","Object","defineProperties","globalThis","global","enumerable","value","$rt","dispatchException","e","message","type","description","undefined","fileName","lineNumber","columnNumber","_send","JSON","stringify","dispatchMessage","json","data","parse","dispatch","rpc","exports","recv","callback","arguments","length","subscribe","send","payload","ptr","v","NULL","NativePointer","int64","Int64","uint64","UInt64","NativeFunction","Function","constructor","address","retType","argTypes","super","_NativeFunction_retType","set","this","_NativeFunction_argTypes","handle","__classPrivateFieldSet","getMarshalerFor","map","Proxy","apply","target","thiz","args","_invoke","nativeArgs","i","__classPrivateFieldGet","toNative","nativeRetval","$v","fromNative","NativeCallback","func","retTypeMarshaler","argTypeMarshalers","code","Memory","alloc","Process","pageSize","_NativeCallback_func","_NativeCallback_retType","_NativeCallback_argTypes","_NativeCallback_code","_installNativeCallback","returnAddress","context","ic","threadId","depth","errno","jsArgs","jsRetval","call","Module","findExportByName","moduleName","exportName","getExportByName","ObjC","available","Swift","Java","console","Script","runtime","setGlobalAccessHandler","handler","id","platform","codeSigningPolicy","isDebuggerAttached","enumerateModules","name","base","size","path","enumerateImports","enumerateExports","enumerateSymbols","enumerateRanges","setExceptionHandler","marshalers","pointer","int","Number","BigInt","t","m"],"sourceRoot":"/root/frida/subprojects/frida-python/build/subprojects/frida-core/src/barebone/script-runtime.js.p/script-runtime/","sources":["entrypoint.ts"],"mappings":"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"}
✄
var e,t,r,a,n,i,o=this&&this.__classPrivateFieldSet||function(e,t,r,a,n){if("m"===a)throw new TypeError("Private method is not writable");if("a"===a&&!n)throw new TypeError("Private accessor was defined without a setter");if("function"==typeof t?e!==t||!n:!t.has(e))throw new TypeError("Cannot write private member to an object whose class did not declare it");return"a"===a?n.call(e,r):n?n.value=r:t.set(e,r),r},l=this&&this.__classPrivateFieldGet||function(e,t,r,a){if("a"===r&&!a)throw new TypeError("Private accessor was defined without a getter");if("function"==typeof t?e!==t||!a:!t.has(e))throw new TypeError("Cannot read private member from an object whose class did not declare it");return"m"===r?a:"a"===r?a.call(e):a?a.value:t.get(e)};import{Console as s}from"./console.js";import{hexdump as u}from"./hexdump.js";import{MessageDispatcher as c}from"./message-dispatcher.js";import{BNativePointer as m,BInt64 as p,BUInt64 as v}from"./primitives.js";const f=new c;Error.prepareStackTrace=(e,t)=>e.toString()+"\n"+t;e=new WeakMap,t=new WeakMap;r=new WeakMap,a=new WeakMap,n=new WeakMap,i=new WeakMap,Object.defineProperties(globalThis,{global:{enumerable:!1,value:globalThis},$rt:{enumerable:!1,value:new class{dispatchException(e){const t={type:"error",description:""+e};if("object"==typeof e){const r=e.stack;void 0!==r&&(t.stack=r);const a=e.fileName;void 0!==a&&(t.fileName=a);const n=e.lineNumber;void 0!==n&&(t.lineNumber=n,t.columnNumber=1)}_send(JSON.stringify(t),null)}dispatchMessage(e,t){const r=JSON.parse(e);f.dispatch(r,t)}}},rpc:{enumerable:!0,value:{exports:{}}},recv:{enumerable:!0,value(){let e,t;return 1===arguments.length?(e="*",t=arguments[0]):(e=arguments[0],t=arguments[1]),f.subscribe(e,t)}},send:{enumerable:!0,value(e,t=null){const r={type:"send",payload:e};_send(JSON.stringify(r),t)}},ptr:{enumerable:!0,value:e=>new m(e)},NULL:{enumerable:!0,value:new m("0")},NativePointer:{enumerable:!0,value:m},int64:{enumerable:!0,value:e=>new p(e)},Int64:{enumerable:!0,value:p},uint64:{enumerable:!0,value:e=>new v(e)},UInt64:{enumerable:!0,value:v},NativeFunction:{enumerable:!0,value:class extends Function{constructor(r,a,n){return super(),e.set(this,void 0),t.set(this,void 0),this.handle=r,o(this,e,b(a),"f"),o(this,t,n.map(b),"f"),new Proxy(this,{apply:(e,t,r)=>e._invoke(r)})}_invoke(r){const a=r.map(((e,r)=>l(this,t,"f")[r].toNative(e))),n=_invoke(this.handle.$v,...a);return l(this,e,"f").fromNative(n)}}},NativeCallback:{enumerable:!0,value:class extends m{constructor(e,t,l){const s=b(t),u=l.map(b),c=Memory.alloc(Process.pageSize);super(c),r.set(this,void 0),a.set(this,void 0),n.set(this,void 0),i.set(this,void 0),o(this,r,e,"f"),o(this,a,s,"f"),o(this,n,u,"f"),o(this,i,c,"f"),_installNativeCallback(c.$v,this,l.length)}_invoke(e,t,i){const o={returnAddress:t,context:i,threadId:-1,depth:0,errno:-1},s=e.map(((e,t)=>l(this,n,"f")[t].fromNative(e))),u=l(this,r,"f").call(o,...s);return l(this,a,"f").toNative(u)}}},Module:{enumerable:!0,value:{findExportByName:(e,t)=>null,getExportByName(e,t){throw new Error(`unable to find export '${t}'`)}}},ObjC:{enumerable:!0,value:{available:!1}},Swift:{enumerable:!0,value:{available:!1}},Java:{enumerable:!0,value:{available:!1}},console:{enumerable:!0,value:new s},hexdump:{enumerable:!0,value:u}}),Object.defineProperties(Script,{runtime:{enumerable:!0,value:"QJS"},setGlobalAccessHandler:{enumerable:!0,value(e){}}}),Object.defineProperties(Process,{id:{enumerable:!0,value:0},platform:{enumerable:!0,value:"barebone"},codeSigningPolicy:{enumerable:!0,value:"optional"},isDebuggerAttached:{enumerable:!0,value:()=>!0},enumerateModules:{enumerable:!0,value:()=>[{name:"kernel",base:NULL,size:4096,path:"/kernel",enumerateImports:()=>[],enumerateExports:()=>[],enumerateSymbols:()=>[],enumerateRanges:()=>[],findExportByName:()=>null,getExportByName(e){throw new Error(`unable to find export '${e}'`)}}]},setExceptionHandler:{enumerable:!0,value(e){}}});const d={pointer:{fromNative:e=>new m(e),toNative(e){if("object"!=typeof e||null===e)throw new Error("expected a pointer");if(e instanceof m)return e.$v;const t=e.handle;if(void 0===t||!(t instanceof m))throw new Error("expected a pointer");return t.$v}},int:{fromNative:e=>Number(0n!==(0x80000000n&e)?-(0xffffffffn-e+1n):e),toNative(e){if("number"!=typeof e)throw new Error("expected an integer");return BigInt(e)}}};function b(e){const t=d[e];if(void 0===t)throw new Error(`Type ${e} is not yet supported`);return t}
✄
{"version":3,"file":"console.js","names":["hexdump","Console","constructor","_Console_counters","set","this","Map","info","args","sendLogMessage","log","debug","warn","error","count","label","newValue","__classPrivateFieldGet","get","countReset","has","delete","level","values","message","type","payload","map","parseLogArgument","join","_send","JSON","stringify","value","ArrayBuffer","undefined"],"sourceRoot":"/root/frida/subprojects/frida-python/build/subprojects/frida-core/src/barebone/script-runtime.js.p/script-runtime/","sources":["console.ts"],"mappings":"qWAASA,MAAe,sBAElB,MAAOC,QAAbC,cACIC,EAAAC,IAAAC,KAAY,IAAIC,IAmCpB,CAjCIC,QAAQC,GACJC,EAAe,OAAQD,EAC3B,CAEAE,OAAOF,GACHC,EAAe,OAAQD,EAC3B,CAEAG,SAASH,GACLC,EAAe,QAASD,EAC5B,CAEAI,QAAQJ,GACJC,EAAe,UAAWD,EAC9B,CAEAK,SAASL,GACLC,EAAe,QAASD,EAC5B,CAEAM,MAAMC,EAAQ,WACV,MAAMC,GAAYC,EAAAZ,KAAIF,EAAA,KAAWe,IAAIH,IAAU,GAAK,EACpDE,EAAAZ,KAAIF,EAAA,KAAWC,IAAIW,EAAOC,GAC1BX,KAAKK,IAAI,GAAGK,MAAUC,IAC1B,CAEAG,WAAWJ,EAAQ,WACXE,EAAAZ,KAAIF,EAAA,KAAWiB,IAAIL,GACnBE,EAAAZ,KAAIF,EAAA,KAAWkB,OAAON,GAEtBV,KAAKO,KAAK,cAAcG,oBAEhC,EAKJ,SAASN,EAAea,EAAiBC,GACrC,MACMC,EAAU,CACZC,KAAM,MACNH,MAAOA,EACPI,QAJSH,EAAOI,IAAIC,GAAkBC,KAAK,MAM/CC,MAAMC,KAAKC,UAAUR,GAAU,KACnC,CAEA,SAASI,EAAiBK,GACtB,OAAIA,aAAiBC,YACVlC,EAAQiC,QAELE,IAAVF,EACO,YAEG,OAAVA,EACO,OAEJA,CACX,C"}
✄
var e,t=this&&this.__classPrivateFieldGet||function(e,t,n,o){if("a"===n&&!o)throw new TypeError("Private accessor was defined without a getter");if("function"==typeof t?e!==t||!o:!t.has(e))throw new TypeError("Cannot read private member from an object whose class did not declare it");return"m"===n?o:"a"===n?o.call(e):o?o.value:t.get(e)};import{hexdump as n}from"./hexdump.js";export class Console{constructor(){e.set(this,new Map)}info(...e){o("info",e)}log(...e){o("info",e)}debug(...e){o("debug",e)}warn(...e){o("warning",e)}error(...e){o("error",e)}count(n="default"){const o=(t(this,e,"f").get(n)??0)+1;t(this,e,"f").set(n,o),this.log(`${n}: ${o}`)}countReset(n="default"){t(this,e,"f").has(n)?t(this,e,"f").delete(n):this.warn(`Count for "${n}" does not exist`)}}function o(e,t){const n={type:"log",level:e,payload:t.map(r).join(" ")};_send(JSON.stringify(n),null)}function r(e){return e instanceof ArrayBuffer?n(e):void 0===e?"undefined":null===e?"null":e}e=new WeakMap;
✄
{"version":3,"file":"gdb.js","names":["gdb","$gdb"],"sourceRoot":"/root/frida/subprojects/frida-python/build/subprojects/frida-core/src/barebone/script-runtime.js.p/script-runtime/","sources":["gdb.ts"],"mappings":"OAEO,MAAMA,IAAMC"}
✄
export const gdb=$gdb;
✄
{"version":3,"file":"hexdump.js","names":["hexdump","target","options","buffer","defaultStartAddress","NULL","length","ArrayBuffer","undefined","byteLength","Math","min","NativePointer","handle","readByteArray","address","startAddress","offset","startOffset","header","showHeader","ansi","useAnsi","endAddress","add","bytes","Uint8Array","columnPadding","leftColumnWidth","max","toString","resetColor","offsetColor","dataColor","newlineColor","result","push","pad","bufferOffset","asciiChars","lineSize","lineOffset","value","isNewline","hexPair","String","fromCharCode","Array","prototype","apply","trailingSpaceCount","tailOffset","slice","join","str","width","fill","paddingSize","index"],"sourceRoot":"/root/frida/subprojects/frida-python/build/subprojects/frida-core/src/barebone/script-runtime.js.p/script-runtime/","sources":["hexdump.ts"],"mappings":"OAAM,SAAUA,QAAQC,EAA0CC,EAA0B,IACxF,IAAIC,EACAC,EAAsBC,KACtBC,EAASJ,EAAQI,OACjBL,aAAkBM,aAEdD,OADWE,IAAXF,EACSL,EAAOQ,WAEPC,KAAKC,IAAIL,EAAQL,EAAOQ,YACrCN,EAASF,IAEHA,aAAkBW,gBACpBX,EAASA,EAAOY,aACLL,IAAXF,IACAA,EAAS,KACbH,EAASF,EAAOa,cAAcR,GAC9BF,EAAsBH,GAG1B,MACIc,QAASC,EAAeZ,EACxBa,OAAQC,EAAc,EACtBC,OAAQC,GAAa,EACrBC,KAAMC,GAAU,GAChBpB,EACEqB,EAAaP,EAAaQ,IAAIlB,GAE9BmB,EAAQ,IAAIC,WAAWvB,GAEvBwB,EAAgB,KAChBC,EAAkBlB,KAAKmB,IAAIN,EAAWO,SAAS,IAAIxB,OAAQ,GAIjE,IAAIyB,EAAYC,EAAaC,EAAWC,EACpCZ,GACAS,EAAa,OACbC,EAAc,UACdC,EAAY,UACZC,EAAeH,IAEfA,EAAa,GACbC,EAAc,GACdC,EAAY,GACZC,EAAe,IAGnB,MAAMC,EAAmB,GAErBf,GACAe,EAAOC,KACHC,EAAI,WAAYT,EAAiB,KACjCD,EArBU,kDAuBVA,EAtBY,mBAwBZ,MAIR,IAAIV,EAASC,EACb,IAAK,IAAIoB,EAAe,EAAGA,EAAehC,EAAQgC,GAAgB,GAAI,CAC7C,IAAjBA,GACAH,EAAOC,KAAK,MAEhBD,EAAOC,KACHJ,EAAaK,EAAIrB,EAAaQ,IAAIP,GAAQa,SAAS,IAAKF,EAAiB,KAAMG,EAC/EJ,GAGJ,MAAMY,EAAuB,GACvBC,EAAW9B,KAAKC,IAAIL,EAASW,EAAQ,IAE3C,IAAK,IAAIwB,EAAa,EAAGA,IAAeD,EAAUC,IAAc,CAC5D,MAAMC,EAAQjB,EAAMR,KAEd0B,EAAsB,KAAVD,EAEZE,EAAUP,EAAIK,EAAMZ,SAAS,IAAK,EAAG,KACxB,IAAfW,GACAN,EAAOC,KAAK,KAChBD,EAAOC,KACHO,EAAYT,EAAeD,EAC3BW,EACAb,GAGJQ,EAAWH,KACPO,EAAYT,EAAeD,EAC1BS,GAAS,IAAMA,GAAS,IAAOG,OAAOC,aAAaJ,GAAS,IAC7DX,E,CAIR,IAAK,IAAIU,EAAaD,EAAyB,KAAfC,EAAmBA,IAC/CN,EAAOC,KAAK,OACZG,EAAWH,KAAK,KAGpBD,EAAOC,KAAKT,GAEZoB,MAAMC,UAAUZ,KAAKa,MAAMd,EAAQI,E,CAGvC,IAAIW,EAAqB,EACzB,IAAK,IAAIC,EAAahB,EAAO7B,OAAS,EAAG6C,GAAc,GAA4B,MAAvBhB,EAAOgB,GAAqBA,IACpFD,IAGJ,OAAOf,EAAOiB,MAAM,EAAGjB,EAAO7B,OAAS4C,GAAoBG,KAAK,GACpE,CAEA,SAAShB,EAAIiB,EAAaC,EAAeC,GACrC,MAAMrB,EAAmB,GACnBsB,EAAc/C,KAAKmB,IAAI0B,EAAQD,EAAIhD,OAAQ,GACjD,IAAK,IAAIoD,EAAQ,EAAGA,IAAUD,EAAaC,IACvCvB,EAAOC,KAAKoB,GAEhB,OAAOrB,EAAOkB,KAAK,IAAMC,CAC7B"}
✄
export function hexdump(e,n={}){let r,o=NULL,h=n.length;e instanceof ArrayBuffer?(h=void 0===h?e.byteLength:Math.min(h,e.byteLength),r=e):(e instanceof NativePointer||(e=e.handle),void 0===h&&(h=256),r=e.readByteArray(h),o=e);const{address:s=o,offset:a=0,header:i=!0,ansi:l=!1}=n,p=s.add(h),u=new Uint8Array(r),f="  ",d=Math.max(p.toString(16).length,8);let g,c,m,y;l?(g="[0m",c="[0;32m",m="[0;33m",y=g):(g="",c="",m="",y="");const A=[];i&&A.push(t("        ",d," "),f," 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F",f,"0123456789ABCDEF","\n");let x=a;for(let e=0;e<h;e+=16){0!==e&&A.push("\n"),A.push(c,t(s.add(x).toString(16),d,"0"),g,f);const n=[],r=Math.min(h-x,16);for(let e=0;e!==r;e++){const r=u[x++],o=10===r,h=t(r.toString(16),2,"0");0!==e&&A.push(" "),A.push(o?y:m,h,g),n.push(o?y:m,r>=32&&r<=126?String.fromCharCode(r):".",g)}for(let t=r;16!==t;t++)A.push("   "),n.push(" ");A.push(f),Array.prototype.push.apply(A,n)}let B=0;for(let t=A.length-1;t>=0&&" "===A[t];t--)B++;return A.slice(0,A.length-B).join("")}function t(t,e,n){const r=[],o=Math.max(e-t.length,0);for(let t=0;t!==o;t++)r.push(n);return r.join("")+t}
✄
{"version":3,"file":"message-dispatcher.js","names":["MessageDispatcher","constructor","_MessageDispatcher_messages","set","this","_MessageDispatcher_operations","Map","_MessageDispatcher_dispatch","item","message","data","ops","__classPrivateFieldGet","opsForType","handlerType","type","undefined","get","push","complete","shift","length","delete","dispatch","Array","_MessageDispatcher_instances","_MessageDispatcher_handleRpcMessage","call","slice","_MessageDispatcher_dispatchMessages","subscribe","handler","op","MessageRecvOperation","id","operation","params","exports","rpc","method","args","hasOwnProperty","_MessageDispatcher_reply","result","apply","then","value","catch","error","name","stack","e","Object","keys","ArrayBuffer","send","concat","splice","forEach","_MessageRecvOperation_completed","wait","_waitForEvent","_complete","__classPrivateFieldSet"],"sourceRoot":"/root/frida/subprojects/frida-python/build/subprojects/frida-core/src/barebone/script-runtime.js.p/script-runtime/","sources":["message-dispatcher.ts"],"mappings":"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"}
✄
var t,e,s,i,a,r,o,n,c=this&&this.__classPrivateFieldGet||function(t,e,s,i){if("a"===s&&!i)throw new TypeError("Private accessor was defined without a getter");if("function"==typeof e?t!==e||!i:!e.has(t))throw new TypeError("Cannot read private member from an object whose class did not declare it");return"m"===s?i:"a"===s?i.call(t):i?i.value:e.get(t)},h=this&&this.__classPrivateFieldSet||function(t,e,s,i,a){if("m"===i)throw new TypeError("Private method is not writable");if("a"===i&&!a)throw new TypeError("Private accessor was defined without a setter");if("function"==typeof e?t!==e||!a:!e.has(t))throw new TypeError("Cannot write private member to an object whose class did not declare it");return"a"===i?a.call(t,s):a?a.value=s:e.set(t,s),s};export class MessageDispatcher{constructor(){t.add(this),e.set(this,[]),s.set(this,new Map),o.set(this,(t=>{const[i,a]=t,r=c(this,s,"f");let o,n=i.type;if(void 0!==n&&(o=r.get(n)),void 0===o&&(n="*",o=r.get(n)),void 0===o)return void c(this,e,"f").push(t);const h=o.shift();0===o.length&&r.delete(n),h(i,a)}))}dispatch(s,a){s instanceof Array&&"frida:rpc"===s[0]?c(this,t,"m",i).call(this,s[1],s[2],s.slice(3)):(c(this,e,"f").push([s,a]),c(this,t,"m",r).call(this))}subscribe(e,i){const a=new MessageRecvOperation(i),o=c(this,s,"f");let n=o.get(e);return void 0===n&&(n=[],o.set(e,n)),n.push(a.handler),c(this,t,"m",r).call(this),a}}e=new WeakMap,s=new WeakMap,o=new WeakMap,t=new WeakSet,i=function(e,s,i){const r=rpc.exports;if("call"===s){const s=i[0],o=i[1];if(!r.hasOwnProperty(s))return void c(this,t,"m",a).call(this,e,"error",`unable to find method "${s}"`);try{const i=r[s].apply(r,o);"object"==typeof i&&null!==i&&"function"==typeof i.then?i.then((s=>{c(this,t,"m",a).call(this,e,"ok",s)})).catch((s=>{c(this,t,"m",a).call(this,e,"error",s.message,[s.name,s.stack,s])})):c(this,t,"m",a).call(this,e,"ok",i)}catch(s){c(this,t,"m",a).call(this,e,"error",s.message,[s.name,s.stack,s])}}else"list"===s&&c(this,t,"m",a).call(this,e,"ok",Object.keys(r))},a=function(t,e,s,i=[]){s instanceof ArrayBuffer?send(["frida:rpc",t,e,{}].concat(i),s):send(["frida:rpc",t,e,s].concat(i))},r=function(){c(this,e,"f").splice(0).forEach(c(this,o,"f"))};export class MessageRecvOperation{constructor(t){n.set(this,!1),this.handler=t}wait(){for(;!c(this,n,"f");)_waitForEvent()}_complete(t,e){try{this.handler(t,e)}finally{h(this,n,!0,"f")}}}n=new WeakMap;
✄
{"version":3,"file":"primitives.js","names":["gdb","u64Max","ptrSize","BigInt","Process","pointerSize","ptrMax","signBitMask","longIsSixtyFourBitsWide","BNativePointer","constructor","v","this","$v","handle","val","add","rhs","parseBigInt","sub","and","or","xor","shr","shl","not","sign","strip","blend","compare","rawRhs","lhs","equals","toInt32","Number","toUInt32","toString","radix","undefined","toJSON","toMatchPattern","throwNotImplemented","readPointer","writePointer","value","readS8","writeS8","readU8","writeU8","readS16","writeS16","readU16","writeU16","readS32","writeS32","readU32","writeU32","readS64","writeS64","readU64","writeU64","readShort","writeShort","readUShort","writeUShort","readInt","writeInt","readUInt","writeUInt","readLong","writeLong","readULong","writeULong","readFloat","writeFloat","readDouble","writeDouble","readByteArray","length","writeByteArray","readCString","size","readUtf8String","writeUtf8String","readUtf16String","writeUtf16String","readAnsiString","writeAnsiString","BInt64","toNumber","valueOf","BUInt64","Error"],"sourceRoot":"/root/frida/subprojects/frida-python/build/subprojects/frida-core/src/barebone/script-runtime.js.p/script-runtime/","sources":["primitives.ts"],"mappings":"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"}
✄
import{gdb as t}from"./gdb.js";const r=0xffffffffffffffffn,e=BigInt(Process.pointerSize),n=8n===e?r:0xffffffffn,i=1n<<8n*e-1n,s=8n===e;export class BNativePointer{constructor(t){if("object"==typeof t)this.$v="$v"in t?t.$v:t.handle.$v;else{let r=BigInt(t);r<0n&&(r=n-(-r-1n)),this.$v=r}}add(t){return new BNativePointer(this.$v+h(t))}sub(t){return new BNativePointer(this.$v-h(t))}and(t){return new BNativePointer(this.$v&h(t))}or(t){return new BNativePointer(this.$v|h(t))}xor(t){return new BNativePointer(this.$v^h(t))}shr(t){return new BNativePointer(this.$v>>h(t))}shl(t){return new BNativePointer(this.$v<<h(t))}not(){return new BNativePointer(~this.$v)}sign(){return this}strip(){return this}blend(){return this}compare(t){const r=this.$v,e=h(t);return r===e?0:r<e?-1:1}equals(t){return 0===this.compare(t)}toInt32(){const t=this.$v;return Number(0n!==(t&i)?-(n-t+1n):t)}toUInt32(){return Number(this.$v)}toString(t){return void 0===t?"0x"+this.$v.toString(16):this.$v.toString(t)}toJSON(){return"0x"+this.$v.toString(16)}toMatchPattern(){u()}readPointer(){return t.readPointer(this.$v)}writePointer(r){return t.writePointer(this.$v,r),this}readS8(){return t.readS8(this.$v)}writeS8(r){return t.writeS8(this.$v,r),this}readU8(){return t.readU8(this.$v)}writeU8(r){return t.writeU8(this.$v,r),this}readS16(){return t.readS16(this.$v)}writeS16(r){return t.writeS16(this.$v,r),this}readU16(){return t.readU16(this.$v)}writeU16(r){return t.writeU16(this.$v,r),this}readS32(){return t.readS32(this.$v)}writeS32(r){return t.writeS32(this.$v,r),this}readU32(){return t.readU32(this.$v)}writeU32(r){return t.writeU32(this.$v,r),this}readS64(){return t.readS64(this.$v)}writeS64(r){return t.writeS64(this.$v,r),this}readU64(){return t.readU64(this.$v)}writeU64(r){return t.writeU64(this.$v,r),this}readShort(){return this.readS16()}writeShort(t){return this.writeS16(t)}readUShort(){return this.readU16()}writeUShort(t){return this.writeU16(t)}readInt(){return this.readS32()}writeInt(t){return this.writeS32(t)}readUInt(){return this.readU32()}writeUInt(t){return this.writeU32(t)}readLong(){return s?this.readS64():this.readS32()}writeLong(t){return s?this.writeS64(t):this.writeS32(t)}readULong(){return s?this.readU64():this.readU32()}writeULong(t){return s?this.writeU64(t):this.writeU32(t)}readFloat(){return t.readFloat(this.$v)}writeFloat(r){return t.writeFloat(this.$v,r),this}readDouble(){return t.readDouble(this.$v)}writeDouble(r){return t.writeDouble(this.$v,r),this}readByteArray(r){return t.readByteArray(this.$v,r)}writeByteArray(r){return t.writeByteArray(this.$v,r),this}readCString(r){return t.readCString(this.$v,r)}readUtf8String(r){return t.readUtf8String(this.$v,r)}writeUtf8String(r){return t.writeUtf8String(this.$v,r),this}readUtf16String(t){u()}writeUtf16String(t){u()}readAnsiString(t){u()}writeAnsiString(t){u()}}export class BInt64{constructor(t){this.$v="object"==typeof t?t.$v:BigInt(t)}add(t){return new BInt64(this.$v+h(t))}sub(t){return new BInt64(this.$v-h(t))}and(t){return new BInt64(this.$v&h(t))}or(t){return new BInt64(this.$v|h(t))}xor(t){return new BInt64(this.$v^h(t))}shr(t){return new BInt64(this.$v>>h(t))}shl(t){return new BInt64(this.$v<<h(t))}not(){return new BInt64(~this.$v)}compare(t){const r=this.$v,e=h(t);return r===e?0:r<e?-1:1}equals(t){return 0===this.compare(t)}toNumber(){return Number(this.$v)}toString(t){return this.$v.toString(t)}toJSON(){return this.$v.toString()}valueOf(){return Number(this.$v)}}export class BUInt64{constructor(t){if("object"==typeof t)this.$v=t.$v;else{let e=Big
```