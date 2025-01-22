Response:
The user wants to understand the functionality of the `script-runtime.js` file in Frida, specifically focusing on its role in dynamic instrumentation. I need to:

1. **List the functionalities:** Analyze the provided code and identify the core features implemented.
2. **Address binary/kernel interaction:**  If the code interacts with low-level aspects like memory or the kernel, provide examples.
3. **Provide debugging examples:** If the code implements debugging features, show how to replicate them using `lldb` commands or Python scripts.
4. **Illustrate logical reasoning:** If the code involves logical operations, provide hypothetical inputs and expected outputs.
5. **Highlight common user errors:** Identify potential mistakes users might make when interacting with this code or related features.
6. **Explain the user journey:** Describe how a user's actions might lead to the execution of this code.
7. **Provide a summary:**  Concisely summarize the overall function of the `script-runtime.js` file.

Based on the code, it seems like `script-runtime.js` is the core of the Frida script execution environment. It handles:

- **Exception handling:** Capturing and dispatching JavaScript exceptions.
- **Message dispatching:**  Sending and receiving messages between the Frida script and the Frida core.
- **Remote Procedure Calls (RPC):**  Allowing the script to call functions in the target process.
- **Interfacing with native code:** Providing wrappers for native functions and callbacks.
- **Module and symbol resolution:**  Providing ways to find modules and their exports.
- **Basic utilities:** Console logging and memory dumping.
- **Primitive data type handling:**  Wrappers for common native data types.

Now, let's break down each point in more detail and generate the response.## frida/build/subprojects/frida-core/src/barebone/script-runtime.js 功能概览 (第 1 部分)

这个 `script-runtime.js` 文件是 Frida 动态 Instrumentation 工具的核心组成部分，它定义了 JavaScript 脚本在 Frida 环境中运行时的基础框架和关键功能。简单来说，它负责搭建一个让 JavaScript 代码能够与目标进程进行交互的桥梁。

以下是其主要功能的归纳：

1. **基础运行时环境搭建:**
   - 初始化全局对象 (`globalThis`, `global`) 并注入 Frida 特定的运行时对象 (`$rt`).
   - 提供了用于处理 JavaScript 异常的机制 (`dispatchException`)，能够捕获错误信息（包括堆栈信息、文件名、行号等）并通过消息机制发送出去。
   - 实现了简单的消息分发器 (`MessageDispatcher`)，用于在 JavaScript 脚本和 Frida Core 之间传递消息 (`dispatchMessage`)。

2. **消息通信机制:**
   - 实现了 `recv` 函数，允许 JavaScript 脚本订阅特定类型的消息，并注册回调函数来处理接收到的消息。这使得 Frida 脚本可以监听来自 Frida Core 的事件或数据。
   - 实现了 `send` 函数，允许 JavaScript 脚本向 Frida Core 发送消息。
   - 定义了消息的基本结构 (`type`, `payload`)，用于在 JavaScript 和 Native 层之间传递数据。

3. **与 Native 代码交互:**
   - 提供了 `NativePointer` 类，用于表示内存地址，允许 JavaScript 代码操作目标进程的内存。
   - 提供了 `NativeFunction` 类，允许 JavaScript 代码调用目标进程中的函数。
   - 提供了 `NativeCallback` 类，允许在目标进程中创建一个由 JavaScript 代码实现的 Native 回调函数。
   - 提供了处理 64 位整数的类 (`Int64`, `UInt64`)。

4. **模块和符号访问:**
   - 提供了 `Module` 对象，但其 `findExportByName` 方法当前实现始终返回 `null`， `getExportByName` 方法会抛出错误，表示基础的 barebone 环境可能不直接支持完整的模块枚举。

5. **基础工具:**
   - 集成了 `console` 对象，提供了 `log`, `info`, `debug`, `warn`, `error`, `count`, `countReset` 等常用的控制台输出功能。
   - 集成了 `hexdump` 函数，用于以十六进制格式打印内存数据。

6. **其他:**
   - 提供了访问平台相关信息的 `Process` 对象，包括 `id`, `platform`, `codeSigningPolicy`, `isDebuggerAttached` 等属性，以及用于模块枚举的方法（但在此 barebone 环境中返回有限的信息）。
   - 提供了访问不同运行时环境状态的占位符对象 (`ObjC`, `Swift`, `Java`)，目前它们的 `available` 属性都为 `false`。

**与二进制底层，linux内核的交互示例：**

- **`NativePointer` 操作内存:**  `NativePointer` 类允许直接操作目标进程的内存。例如，你可以创建一个 `NativePointer` 对象指向某个内存地址，然后使用其 `read*` 和 `write*` 方法读取或修改该地址的内容。这涉及到直接的内存访问，是与二进制底层交互的核心。

   ```javascript
   // 假设已知目标进程中某个变量的地址为 0x12345678
   const address = ptr("0x12345678");
   const originalValue = address.readInt(); // 读取该地址的 32 位整数值
   console.log("Original value:", originalValue);
   address.writeInt(100); // 将该地址的值修改为 100
   ```

- **`NativeFunction` 调用目标进程函数:** `NativeFunction` 允许调用目标进程中的函数。你需要知道目标函数的地址、返回值类型和参数类型。

   ```javascript
   // 假设目标进程中有一个名为 `my_function` 的函数，其地址为 0x87654321，
   // 返回值为 void，接受一个 int 类型的参数。
   const myFunction = new NativeFunction(ptr("0x87654321"), 'void', ['int']);
   myFunction(42); // 调用目标进程的 my_function，传入参数 42
   ```

   **涉及到 Linux 内核:**  当 Frida Core 处理这些操作时，它会通过操作系统提供的接口（例如 `ptrace` 系统调用）与目标进程进行交互。`NativePointer` 的读写操作和 `NativeFunction` 的调用最终都会转化为对目标进程内存和执行流程的控制，这些控制是由操作系统内核来管理的。

- **`NativeCallback` 创建 Native 回调:**  `NativeCallback` 允许在目标进程中注册一个回调函数，当目标进程执行到特定位置时，会调用这个回调函数，而回调函数的逻辑是由 JavaScript 代码定义的。

   ```javascript
   const myCallback = new NativeCallback(function (arg) {
     console.log("Callback called with argument:", arg);
   }, 'void', ['int']);

   // 假设你需要将这个回调函数注册到目标进程的某个位置，
   // 这通常需要结合 Frida 的其他 API，例如 Interceptor。
   // Interceptor.attach(ptr("目标地址"), {
   //   onEnter: function (args) {
   //     // ... 将 myCallback 的地址传递给目标进程
   //   }
   // });
   ```

   **涉及到 Linux 内核:** 类似地，创建和调用 Native 回调也需要 Frida Core 与操作系统内核交互，以在目标进程的上下文中执行 JavaScript 代码。

**用 lldb 指令或者 lldb python 脚本复刻的调试功能示例：**

由于 `script-runtime.js`  **本身是调试功能的实现**，我们无法直接用 lldb 复刻它的功能。lldb 是一个独立的调试器，而 `script-runtime.js` 是 Frida 内部脚本运行时的核心。

但是，我们可以举例说明如何用 lldb 观察和调试与 `script-runtime.js` 功能相关的操作，例如内存访问和函数调用：

**假设 JavaScript 代码使用 `NativePointer` 读取目标进程内存：**

```javascript
const address = ptr("0x12345678");
const value = address.readInt();
console.log("Value at address:", value);
```

**使用 lldb 观察内存读取：**

1. **附加到目标进程:**  `lldb -p <target_pid>`
2. **设置断点:**  你可能需要在 Frida Core 的代码中设置断点，以观察 `NativePointer` 的读取操作是如何实现的。这需要对 Frida 的内部实现有一定的了解。  一个可能的断点位置是在 Frida Core 处理内存读取请求的函数中。
3. **使用 `memory read` 命令:**  在 lldb 中，可以使用 `memory read` (或简写 `x`) 命令来读取目标进程的内存。

   ```lldb
   (lldb) x/dw 0x12345678  // 读取地址 0x12345678 的一个双字 (dword, 4 字节)
   ```

**假设 JavaScript 代码使用 `NativeFunction` 调用目标进程函数：**

```javascript
const myFunction = new NativeFunction(ptr("0x87654321"), 'void', ['int']);
myFunction(42);
```

**使用 lldb 观察函数调用：**

1. **附加到目标进程:** `lldb -p <target_pid>`
2. **在目标函数入口处设置断点:** `b *0x87654321`
3. **运行程序:**  让 Frida 执行包含函数调用的 JavaScript 代码。
4. **观察断点命中:** 当程序执行到 `myFunction` 的入口点时，lldb 会中断。
5. **查看参数:**  可以使用 lldb 命令查看函数的参数，例如：

   ```lldb
   (lldb) register read  // 查看所有寄存器
   // 或者根据调用约定查看特定寄存器，例如 x86-64 下第一个参数通常在 RDI 寄存器
   (lldb) register read rdi
   ```

**逻辑推理的假设输入与输出：**

例如，在 `dispatchException` 函数中：

**假设输入:**  JavaScript 代码抛出一个带有堆栈信息的错误对象：

```javascript
try {
  throw new Error("Something went wrong");
} catch (e) {
  // ... 错误被捕获并传递给 dispatchException
}
```

**预期输出 (发送给 Frida Core 的消息):**

```json
{
  "type": "error",
  "description": "Error: Something went wrong",
  "stack": "...", // 包含堆栈信息的字符串
  "fileName": "...", // 抛出错误的脚本文件名
  "lineNumber": ..., // 抛出错误的行号
  "columnNumber": 1  // 列号
}
```

**用户或编程常见的使用错误示例：**

- **错误的 `NativeFunction` 参数类型:**  如果在使用 `NativeFunction` 时，提供的参数类型与目标函数实际的参数类型不匹配，可能导致程序崩溃或行为异常。

   ```javascript
   // 假设目标函数需要一个 int 参数，但错误地传递了一个字符串
   const myFunction = new NativeFunction(ptr("0x..."), 'void', ['int']);
   myFunction("hello"); // 错误的使用方式
   ```

- **尝试访问无效的内存地址:**  使用 `NativePointer` 读取或写入无效的内存地址会导致程序崩溃。

   ```javascript
   const badAddress = ptr("0x1"); // 一个很可能无效的地址
   badAddress.readInt(); // 可能导致崩溃
   ```

- **在 `recv` 中注册了不匹配的消息类型:**  如果在 `recv` 中订阅了一个 Frida Core 不会发送的消息类型，或者拼写错误了消息类型，那么回调函数将永远不会被调用。

   ```javascript
   recv('wrongMessageType', function(message) {
       console.log("Received message:", message); // 这段代码可能永远不会执行
   });
   ```

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户编写 Frida 脚本:** 用户编写包含 `NativePointer`, `NativeFunction`, `recv`, `send`, `console.log` 等操作的 JavaScript 代码。
2. **用户使用 Frida CLI 或 API 运行脚本:**  用户通过 `frida` 命令行工具或者 Frida 提供的编程接口 (Python, Node.js 等) 将脚本注入到目标进程中。
3. **Frida Core 加载脚本:** Frida Core 接收到注入脚本的请求，并将 JavaScript 代码传递给内置的 JavaScript 引擎（在这个 barebone 环境中可能是 QuickJS）。
4. **`script-runtime.js` 被加载和执行:**  `script-runtime.js` 提供的运行时环境会被首先加载和执行，初始化全局对象，设置消息分发器等。
5. **用户脚本执行:**  用户编写的 JavaScript 代码开始执行，它会调用 `script-runtime.js` 中提供的 API，例如 `ptr()`, `NativeFunction`, `recv`, `send` 等。
6. **例如，调用 `console.log()`:** 当用户脚本调用 `console.log()` 时，实际上会调用 `script-runtime.js` 中 `console` 对象的 `log` 方法，最终通过消息机制将日志信息发送到 Frida Core，再由 Frida Core 将其输出到用户的控制台。
7. **例如，使用 `NativePointer` 读取内存:** 当用户脚本使用 `ptr("...")` 创建 `NativePointer` 对象并调用其 `readInt()` 方法时，`script-runtime.js` 中的 `BNativePointer` 类会处理这个请求，并调用底层的 Native 代码去读取目标进程的内存。

**总结:**

`script-runtime.js` 是 Frida JavaScript 运行时环境的基础，它定义了 JavaScript 脚本与目标进程进行交互的核心机制，包括消息通信、Native 代码桥接以及基础工具。用户编写的 Frida 脚本依赖于这个文件提供的 API 来实现动态 Instrumentation 功能。

Prompt: 
```
这是目录为frida/build/subprojects/frida-core/src/barebone/script-runtime.js的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第1部分，共2部分，请归纳一下它的功能

"""
📦
5808 /script-runtime/entrypoint.js.map
4457 /script-runtime/entrypoint.js
1290 /script-runtime/console.js.map
978 /script-runtime/console.js
208 /script-runtime/gdb.js.map
22 /script-runtime/gdb.js
2528 /script-runtime/hexdump.js.map
1131 /script-runtime/hexdump.js
3199 /script-runtime/message-dispatcher.js.map
2395 /script-runtime/message-dispatcher.js
6590 /script-runtime/primitives.js.map
4287 /script-runtime/primitives.js
✄
{"version":3,"file":"entrypoint.js","names":["Console","hexdump","MessageDispatcher","BNativePointer","BInt64","BUInt64","messageDispatcher","Error","prepareStackTrace","error","stack","toString","Object","defineProperties","globalThis","global","enumerable","value","$rt","dispatchException","e","message","type","description","undefined","fileName","lineNumber","columnNumber","_send","JSON","stringify","dispatchMessage","json","data","parse","dispatch","rpc","exports","recv","callback","arguments","length","subscribe","send","payload","ptr","v","NULL","NativePointer","int64","Int64","uint64","UInt64","NativeFunction","Function","constructor","address","retType","argTypes","super","_NativeFunction_retType","set","this","_NativeFunction_argTypes","handle","__classPrivateFieldSet","getMarshalerFor","map","Proxy","apply","target","thiz","args","_invoke","nativeArgs","i","__classPrivateFieldGet","toNative","nativeRetval","$v","fromNative","NativeCallback","func","retTypeMarshaler","argTypeMarshalers","code","Memory","alloc","Process","pageSize","_NativeCallback_func","_NativeCallback_retType","_NativeCallback_argTypes","_NativeCallback_code","_installNativeCallback","returnAddress","context","ic","threadId","depth","errno","jsArgs","jsRetval","call","Module","findExportByName","moduleName","exportName","getExportByName","ObjC","available","Swift","Java","console","Script","runtime","setGlobalAccessHandler","handler","id","platform","codeSigningPolicy","isDebuggerAttached","enumerateModules","name","base","size","path","enumerateImports","enumerateExports","enumerateSymbols","enumerateRanges","setExceptionHandler","marshalers","pointer","int","Number","BigInt","t","m"],"sourceRoot":"/root/frida/build/subprojects/frida-core/src/barebone/script-runtime.js.p/script-runtime/","sources":["entrypoint.ts"],"mappings":"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"}
✄
var e,t,r,a,n,i,o=this&&this.__classPrivateFieldSet||function(e,t,r,a,n){if("m"===a)throw new TypeError("Private method is not writable");if("a"===a&&!n)throw new TypeError("Private accessor was defined without a setter");if("function"==typeof t?e!==t||!n:!t.has(e))throw new TypeError("Cannot write private member to an object whose class did not declare it");return"a"===a?n.call(e,r):n?n.value=r:t.set(e,r),r},l=this&&this.__classPrivateFieldGet||function(e,t,r,a){if("a"===r&&!a)throw new TypeError("Private accessor was defined without a getter");if("function"==typeof t?e!==t||!a:!t.has(e))throw new TypeError("Cannot read private member from an object whose class did not declare it");return"m"===r?a:"a"===r?a.call(e):a?a.value:t.get(e)};import{Console as s}from"./console.js";import{hexdump as u}from"./hexdump.js";import{MessageDispatcher as c}from"./message-dispatcher.js";import{BNativePointer as m,BInt64 as p,BUInt64 as v}from"./primitives.js";const f=new c;Error.prepareStackTrace=(e,t)=>e.toString()+"\n"+t;e=new WeakMap,t=new WeakMap;r=new WeakMap,a=new WeakMap,n=new WeakMap,i=new WeakMap,Object.defineProperties(globalThis,{global:{enumerable:!1,value:globalThis},$rt:{enumerable:!1,value:new class{dispatchException(e){const t={type:"error",description:""+e};if("object"==typeof e){const r=e.stack;void 0!==r&&(t.stack=r);const a=e.fileName;void 0!==a&&(t.fileName=a);const n=e.lineNumber;void 0!==n&&(t.lineNumber=n,t.columnNumber=1)}_send(JSON.stringify(t),null)}dispatchMessage(e,t){const r=JSON.parse(e);f.dispatch(r,t)}}},rpc:{enumerable:!0,value:{exports:{}}},recv:{enumerable:!0,value(){let e,t;return 1===arguments.length?(e="*",t=arguments[0]):(e=arguments[0],t=arguments[1]),f.subscribe(e,t)}},send:{enumerable:!0,value(e,t=null){const r={type:"send",payload:e};_send(JSON.stringify(r),t)}},ptr:{enumerable:!0,value:e=>new m(e)},NULL:{enumerable:!0,value:new m("0")},NativePointer:{enumerable:!0,value:m},int64:{enumerable:!0,value:e=>new p(e)},Int64:{enumerable:!0,value:p},uint64:{enumerable:!0,value:e=>new v(e)},UInt64:{enumerable:!0,value:v},NativeFunction:{enumerable:!0,value:class extends Function{constructor(r,a,n){return super(),e.set(this,void 0),t.set(this,void 0),this.handle=r,o(this,e,b(a),"f"),o(this,t,n.map(b),"f"),new Proxy(this,{apply:(e,t,r)=>e._invoke(r)})}_invoke(r){const a=r.map(((e,r)=>l(this,t,"f")[r].toNative(e))),n=_invoke(this.handle.$v,...a);return l(this,e,"f").fromNative(n)}}},NativeCallback:{enumerable:!0,value:class extends m{constructor(e,t,l){const s=b(t),u=l.map(b),c=Memory.alloc(Process.pageSize);super(c),r.set(this,void 0),a.set(this,void 0),n.set(this,void 0),i.set(this,void 0),o(this,r,e,"f"),o(this,a,s,"f"),o(this,n,u,"f"),o(this,i,c,"f"),_installNativeCallback(c.$v,this,l.length)}_invoke(e,t,i){const o={returnAddress:t,context:i,threadId:-1,depth:0,errno:-1},s=e.map(((e,t)=>l(this,n,"f")[t].fromNative(e))),u=l(this,r,"f").call(o,...s);return l(this,a,"f").toNative(u)}}},Module:{enumerable:!0,value:{findExportByName:(e,t)=>null,getExportByName(e,t){throw new Error(`unable to find export '${t}'`)}}},ObjC:{enumerable:!0,value:{available:!1}},Swift:{enumerable:!0,value:{available:!1}},Java:{enumerable:!0,value:{available:!1}},console:{enumerable:!0,value:new s},hexdump:{enumerable:!0,value:u}}),Object.defineProperties(Script,{runtime:{enumerable:!0,value:"QJS"},setGlobalAccessHandler:{enumerable:!0,value(e){}}}),Object.defineProperties(Process,{id:{enumerable:!0,value:0},platform:{enumerable:!0,value:"barebone"},codeSigningPolicy:{enumerable:!0,value:"optional"},isDebuggerAttached:{enumerable:!0,value:()=>!0},enumerateModules:{enumerable:!0,value:()=>[{name:"kernel",base:NULL,size:4096,path:"/kernel",enumerateImports:()=>[],enumerateExports:()=>[],enumerateSymbols:()=>[],enumerateRanges:()=>[],findExportByName:()=>null,getExportByName(e){throw new Error(`unable to find export '${e}'`)}}]},setExceptionHandler:{enumerable:!0,value(e){}}});const d={pointer:{fromNative:e=>new m(e),toNative(e){if("object"!=typeof e||null===e)throw new Error("expected a pointer");if(e instanceof m)return e.$v;const t=e.handle;if(void 0===t||!(t instanceof m))throw new Error("expected a pointer");return t.$v}},int:{fromNative:e=>Number(0n!==(0x80000000n&e)?-(0xffffffffn-e+1n):e),toNative(e){if("number"!=typeof e)throw new Error("expected an integer");return BigInt(e)}}};function b(e){const t=d[e];if(void 0===t)throw new Error(`Type ${e} is not yet supported`);return t}
✄
{"version":3,"file":"console.js","names":["hexdump","Console","constructor","_Console_counters","set","this","Map","info","args","sendLogMessage","log","debug","warn","error","count","label","newValue","__classPrivateFieldGet","get","countReset","has","delete","level","values","message","type","payload","map","parseLogArgument","join","_send","JSON","stringify","value","ArrayBuffer","undefined"],"sourceRoot":"/root/frida/build/subprojects/frida-core/src/barebone/script-runtime.js.p/script-runtime/","sources":["console.ts"],"mappings":"qWAASA,MAAe,sBAElB,MAAOC,QAAbC,cACIC,EAAAC,IAAAC,KAAY,IAAIC,IAmCpB,CAjCIC,QAAQC,GACJC,EAAe,OAAQD,EAC3B,CAEAE,OAAOF,GACHC,EAAe,OAAQD,EAC3B,CAEAG,SAASH,GACLC,EAAe,QAASD,EAC5B,CAEAI,QAAQJ,GACJC,EAAe,UAAWD,EAC9B,CAEAK,SAASL,GACLC,EAAe,QAASD,EAC5B,CAEAM,MAAMC,EAAQ,WACV,MAAMC,GAAYC,EAAAZ,KAAIF,EAAA,KAAWe,IAAIH,IAAU,GAAK,EACpDE,EAAAZ,KAAIF,EAAA,KAAWC,IAAIW,EAAOC,GAC1BX,KAAKK,IAAI,GAAGK,MAAUC,IAC1B,CAEAG,WAAWJ,EAAQ,WACXE,EAAAZ,KAAIF,EAAA,KAAWiB,IAAIL,GACnBE,EAAAZ,KAAIF,EAAA,KAAWkB,OAAON,GAEtBV,KAAKO,KAAK,cAAcG,oBAEhC,EAKJ,SAASN,EAAea,EAAiBC,GACrC,MACMC,EAAU,CACZC,KAAM,MACNH,MAAOA,EACPI,QAJSH,EAAOI,IAAIC,GAAkBC,KAAK,MAM/CC,MAAMC,KAAKC,UAAUR,GAAU,KACnC,CAEA,SAASI,EAAiBK,GACtB,OAAIA,aAAiBC,YACVlC,EAAQiC,QAELE,IAAVF,EACO,YAEG,OAAVA,EACO,OAEJA,CACX,C"}
✄
var e,t=this&&this.__classPrivateFieldGet||function(e,t,n,o){if("a"===n&&!o)throw new TypeError("Private accessor was defined without a getter");if("function"==typeof t?e!==t||!o:!t.has(e))throw new TypeError("Cannot read private member from an object whose class did not declare it");return"m"===n?o:"a"===n?o.call(e):o?o.value:t.get(e)};import{hexdump as n}from"./hexdump.js";export class Console{constructor(){e.set(this,new Map)}info(...e){o("info",e)}log(...e){o("info",e)}debug(...e){o("debug",e)}warn(...e){o("warning",e)}error(...e){o("error",e)}count(n="default"){const o=(t(this,e,"f").get(n)??0)+1;t(this,e,"f").set(n,o),this.log(`${n}: ${o}`)}countReset(n="default"){t(this,e,"f").has(n)?t(this,e,"f").delete(n):this.warn(`Count for "${n}" does not exist`)}}function o(e,t){const n={type:"log",level:e,payload:t.map(r).join(" ")};_send(JSON.stringify(n),null)}function r(e){return e instanceof ArrayBuffer?n(e):void 0===e?"undefined":null===e?"null":e}e=new WeakMap;
✄
{"version":3,"file":"gdb.js","names":["gdb","$gdb"],"sourceRoot":"/root/frida/build/subprojects/frida-core/src/barebone/script-runtime.js.p/script-runtime/","sources":["gdb.ts"],"mappings":"OAEO,MAAMA,IAAMC"}
✄
export const gdb=$gdb;
✄
{"version":3,"file":"hexdump.js","names":["hexdump","target","options","buffer","defaultStartAddress","NULL","length","ArrayBuffer","undefined","byteLength","Math","min","NativePointer","handle","readByteArray","address","startAddress","offset","startOffset","header","showHeader","ansi","useAnsi","endAddress","add","bytes","Uint8Array","columnPadding","leftColumnWidth","max","toString","resetColor","offsetColor","dataColor","newlineColor","result","push","pad","bufferOffset","asciiChars","lineSize","lineOffset","value","isNewline","hexPair","String","fromCharCode","Array","prototype","apply","trailingSpaceCount","tailOffset","slice","join","str","width","fill","paddingSize","index"],"sourceRoot":"/root/frida/build/subprojects/frida-core/src/barebone/script-runtime.js.p/script-runtime/","sources":["hexdump.ts"],"mappings":"OAAM,SAAUA,QAAQC,EAA0CC,EAA0B,IACxF,IAAIC,EACAC,EAAsBC,KACtBC,EAASJ,EAAQI,OACjBL,aAAkBM,aAEdD,OADWE,IAAXF,EACSL,EAAOQ,WAEPC,KAAKC,IAAIL,EAAQL,EAAOQ,YACrCN,EAASF,IAEHA,aAAkBW,gBACpBX,EAASA,EAAOY,aACLL,IAAXF,IACAA,EAAS,KACbH,EAASF,EAAOa,cAAcR,GAC9BF,EAAsBH,GAG1B,MACIc,QAASC,EAAeZ,EACxBa,OAAQC,EAAc,EACtBC,OAAQC,GAAa,EACrBC,KAAMC,GAAU,GAChBpB,EACEqB,EAAaP,EAAaQ,IAAIlB,GAE9BmB,EAAQ,IAAIC,WAAWvB,GAEvBwB,EAAgB,KAChBC,EAAkBlB,KAAKmB,IAAIN,EAAWO,SAAS,IAAIxB,OAAQ,GAIjE,IAAIyB,EAAYC,EAAaC,EAAWC,EACpCZ,GACAS,EAAa,OACbC,EAAc,UACdC,EAAY,UACZC,EAAeH,IAEfA,EAAa,GACbC,EAAc,GACdC,EAAY,GACZC,EAAe,IAGnB,MAAMC,EAAmB,GAErBf,GACAe,EAAOC,KACHC,EAAI,WAAYT,EAAiB,KACjCD,EArBU,kDAuBVA,EAtBY,mBAwBZ,MAIR,IAAIV,EAASC,EACb,IAAK,IAAIoB,EAAe,EAAGA,EAAehC,EAAQgC,GAAgB,GAAI,CAC7C,IAAjBA,GACAH,EAAOC,KAAK,MAEhBD,EAAOC,KACHJ,EAAaK,EAAIrB,EAAaQ,IAAIP,GAAQa,SAAS,IAAKF,EAAiB,KAAMG,EAC/EJ,GAGJ,MAAMY,EAAuB,GACvBC,EAAW9B,KAAKC,IAAIL,EAASW,EAAQ,IAE3C,IAAK,IAAIwB,EAAa,EAAGA,IAAeD,EAAUC,IAAc,CAC5D,MAAMC,EAAQjB,EAAMR,KAEd0B,EAAsB,KAAVD,EAEZE,EAAUP,EAAIK,EAAMZ,SAAS,IAAK,EAAG,KACxB,IAAfW,GACAN,EAAOC,KAAK,KAChBD,EAAOC,KACHO,EAAYT,EAAeD,EAC3BW,EACAb,GAGJQ,EAAWH,KACPO,EAAYT,EAAeD,EAC1BS,GAAS,IAAMA,GAAS,IAAOG,OAAOC,aAAaJ,GAAS,IAC7DX,E,CAIR,IAAK,IAAIU,EAAaD,EAAyB,KAAfC,EAAmBA,IAC/CN,EAAOC,KAAK,OACZG,EAAWH,KAAK,KAGpBD,EAAOC,KAAKT,GAEZoB,MAAMC,UAAUZ,KAAKa,MAAMd,EAAQI,E,CAGvC,IAAIW,EAAqB,EACzB,IAAK,IAAIC,EAAahB,EAAO7B,OAAS,EAAG6C,GAAc,GAA4B,MAAvBhB,EAAOgB,GAAqBA,IACpFD,IAGJ,OAAOf,EAAOiB,MAAM,EAAGjB,EAAO7B,OAAS4C,GAAoBG,KAAK,GACpE,CAEA,SAAShB,EAAIiB,EAAaC,EAAeC,GACrC,MAAMrB,EAAmB,GACnBsB,EAAc/C,KAAKmB,IAAI0B,EAAQD,EAAIhD,OAAQ,GACjD,IAAK,IAAIoD,EAAQ,EAAGA,IAAUD,EAAaC,IACvCvB,EAAOC,KAAKoB,GAEhB,OAAOrB,EAAOkB,KAAK,IAAMC,CAC7B"}
✄
export function hexdump(e,n={}){let r,o=NULL,h=n.length;e instanceof ArrayBuffer?(h=void 0===h?e.byteLength:Math.min(h,e.byteLength),r=e):(e instanceof NativePointer||(e=e.handle),void 0===h&&(h=256),r=e.readByteArray(h),o=e);const{address:s=o,offset:a=0,header:i=!0,ansi:l=!1}=n,p=s.add(h),u=new Uint8Array(r),f="  ",d=Math.max(p.toString(16).length,8);let g,c,m,y;l?(g="[0m",c="[0;32m",m="[0;33m",y=g):(g="",c="",m="",y="");const A=[];i&&A.push(t("        ",d," "),f," 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F",f,"0123456789ABCDEF","\n");let x=a;for(let e=0;e<h;e+=16){0!==e&&A.push("\n"),A.push(c,t(s.add(x).toString(16),d,"0"),g,f);const n=[],r=Math.min(h-x,16);for(let e=0;e!==r;e++){const r=u[x++],o=10===r,h=t(r.toString(16),2,"0");0!==e&&A.push(" "),A.push(o?y:m,h,g),n.push(o?y:m,r>=32&&r<=126?String.fromCharCode(r):".",g)}for(let t=r;16!==t;t++)A.push("   "),n.push(" ");A.push(f),Array.prototype.push.apply(A,n)}let B=0;for(let t=A.length-1;t>=0&&" "===A[t];t--)B++;return A.slice(0,A.length-B).join("")}function t(t,e,n){const r=[],o=Math.max(e-t.length,0);for(let t=0;t!==o;t++)r.push(n);return r.join("")+t}
✄
{"version":3,"file":"message-dispatcher.js","names":["MessageDispatcher","constructor","_MessageDispatcher_messages","set","this","_MessageDispatcher_operations","Map","_MessageDispatcher_dispatch","item","message","data","ops","__classPrivateFieldGet","opsForType","handlerType","type","undefined","get","push","complete","shift","length","delete","dispatch","Array","_MessageDispatcher_instances","_MessageDispatcher_handleRpcMessage","call","slice","_MessageDispatcher_dispatchMessages","subscribe","handler","op","MessageRecvOperation","id","operation","params","exports","rpc","method","args","hasOwnProperty","_MessageDispatcher_reply","result","apply","then","value","catch","error","name","stack","e","Object","keys","ArrayBuffer","send","concat","splice","forEach","_MessageRecvOperation_completed","wait","_waitForEvent","_complete","__classPrivateFieldSet"],"sourceRoot":"/root/frida/build/subprojects/frida-core/src/barebone/script-runtime.js.p/script-runtime/","sources":["message-dispatcher.ts"],"mappings":"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"}
✄
var t,e,s,i,a,r,o,n,c=this&&this.__classPrivateFieldGet||function(t,e,s,i){if("a"===s&&!i)throw new TypeError("Private accessor was defined without a getter");if("function"==typeof e?t!==e||!i:!e.has(t))throw new TypeError("Cannot read private member from an object whose class did not declare it");return"m"===s?i:"a"===s?i.call(t):i?i.value:e.get(t)},h=this&&this.__classPrivateFieldSet||function(t,e,s,i,a){if("m"===i)throw new TypeError("Private method is not writable");if("a"===i&&!a)throw new TypeError("Private accessor was defined without a setter");if("function"==typeof e?t!==e||!a:!e.has(t))throw new TypeError("Cannot write private member to an object whose class did not declare it");return"a"===i?a.call(t,s):a?a.value=s:e.set(t,s),s};export class MessageDispatcher{constructor(){t.add(this),e.set(this,[]),s.set(this,new Map),o.set(this,(t=>{const[i,a]=t,r=c(this,s,"f");let o,n=i.type;if(void 0!==n&&(o=r.get(n)),void 0===o&&(n="*",o=r.get(n)),void 0===o)return void c(this,e,"f").push(t);const h=o.shift();0===o.length&&r.delete(n),h(i,a)}))}dispatch(s,a){s instanceof Array&&"frida:rpc"===s[0]?c(this,t,"m",i).call(this,s[1],s[2],s.slice(3)):(c(this,e,"f").push([s,a]),c(this,t,"m",r).call(this))}subscribe(e,i){const a=new MessageRecvOperation(i),o=c(this,s,"f");let n=o.get(e);return void 0===n&&(n=[],o.set(e,n)),n.push(a.handler),c(this,t,"m",r).call(this),a}}e=new WeakMap,s=new WeakMap,o=new WeakMap,t=new WeakSet,i=function(e,s,i){const r=rpc.exports;if("call"===s){const s=i[0],o=i[1];if(!r.hasOwnProperty(s))return void c(this,t,"m",a).call(this,e,"error",`unable to find method "${s}"`);try{const i=r[s].apply(r,o);"object"==typeof i&&null!==i&&"function"==typeof i.then?i.then((s=>{c(this,t,"m",a).call(this,e,"ok",s)})).catch((s=>{c(this,t,"m",a).call(this,e,"error",s.message,[s.name,s.stack,s])})):c(this,t,"m",a).call(this,e,"ok",i)}catch(s){c(this,t,"m",a).call(this,e,"error",s.message,[s.name,s.stack,s])}}else"list"===s&&c(this,t,"m",a).call(this,e,"ok",Object.keys(r))},a=function(t,e,s,i=[]){s instanceof ArrayBuffer?send(["frida:rpc",t,e,{}].concat(i),s):send(["frida:rpc",t,e,s].concat(i))},r=function(){c(this,e,"f").splice(0).forEach(c(this,o,"f"))};export class MessageRecvOperation{constructor(t){n.set(this,!1),this.handler=t}wait(){for(;!c(this,n,"f");)_waitForEvent()}_complete(t,e){try{this.handler(t,e)}finally{h(this,n,!0,"f")}}}n=new WeakMap;
✄
{"version":3,"file":"primitives.js","names":["gdb","u64Max","ptrSize","BigInt","Process","pointerSize","ptrMax","signBitMask","longIsSixtyFourBitsWide","BNativePointer","constructor","v","this","$v","handle","val","add","rhs","parseBigInt","sub","and","or","xor","shr","shl","not","sign","strip","blend","compare","rawRhs","lhs","equals","toInt32","Number","toUInt32","toString","radix","undefined","toJSON","toMatchPattern","throwNotImplemented","readPointer","writePointer","value","readS8","writeS8","readU8","writeU8","readS16","writeS16","readU16","writeU16","readS32","writeS32","readU32","writeU32","readS64","writeS64","readU64","writeU64","readShort","writeShort","readUShort","writeUShort","readInt","writeInt","readUInt","writeUInt","readLong","writeLong","readULong","writeULong","readFloat","writeFloat","readDouble","writeDouble","readByteArray","length","writeByteArray","readCString","size","readUtf8String","writeUtf8String","readUtf16String","writeUtf16String","readAnsiString","writeAnsiString","BInt64","toNumber","valueOf","BUInt64","Error"],"sourceRoot":"/root/frida/build/subprojects/frida-core/src/barebone/script-runtime.js.p/script-runtime/","sources":["primitives.ts"],"mappings":"cAASA,MAAW,WAEpB,MACMC,EAAS,oBAETC,EAAUC,OAAOC,QAAQC,aACzBC,EAAsB,KAAZJ,EAAkBD,EAJnB,YAKTM,EAAc,IAAkB,GAAVL,EAAgB,GAEtCM,EAAsC,KAAZN,SAE1B,MAAOO,eAGTC,YAAYC,GACR,GAAiB,iBAANA,EAEHC,KAAKC,GADL,OAAQF,EACEA,EAAEE,GAEFF,EAAEG,OAAOD,OAEpB,CACH,IAAIE,EAAMZ,OAAOQ,GACbI,EAAM,KACNA,EAAMT,IAAWS,EAAM,KAE3BH,KAAKC,GAAKE,C,CAElB,CAEAC,IAAIC,GACA,OAAO,IAAIR,eAAeG,KAAKC,GAAKK,EAAYD,GACpD,CAEAE,IAAIF,GACA,OAAO,IAAIR,eAAeG,KAAKC,GAAKK,EAAYD,GACpD,CAEAG,IAAIH,GACA,OAAO,IAAIR,eAAeG,KAAKC,GAAKK,EAAYD,GACpD,CAEAI,GAAGJ,GACC,OAAO,IAAIR,eAAeG,KAAKC,GAAKK,EAAYD,GACpD,CAEAK,IAAIL,GACA,OAAO,IAAIR,eAAeG,KAAKC,GAAKK,EAAYD,GACpD,CAEAM,IAAIN,GACA,OAAO,IAAIR,eAAeG,KAAKC,IAAMK,EAAYD,GACrD,CAEAO,IAAIP,GACA,OAAO,IAAIR,eAAeG,KAAKC,IAAMK,EAAYD,GACrD,CAEAQ,MACI,OAAO,IAAIhB,gBAAgBG,KAAKC,GACpC,CAEAa,OACI,OAAOd,IACX,CAEAe,QACI,OAAOf,IACX,CAEAgB,QACI,OAAOhB,IACX,CAEAiB,QAAQC,GACJ,MAAMC,EAAMnB,KAAKC,GACXI,EAAMC,EAAYY,GACxB,OAAQC,IAAQd,EAAO,EAAMc,EAAMd,GAAQ,EAAI,CACnD,CAEAe,OAAOf,GACH,OAA6B,IAAtBL,KAAKiB,QAAQZ,EACxB,CAEAgB,UACI,MAAMlB,EAAMH,KAAKC,GACjB,OAAOqB,OAAgC,MAAvBnB,EAAMR,KACdD,EAASS,EAAM,IACjBA,EACV,CAEAoB,WACI,OAAOD,OAAOtB,KAAKC,GACvB,CAEAuB,SAASC,GACL,YAAcC,IAAVD,EACO,KAAOzB,KAAKC,GAAGuB,SAAS,IAC5BxB,KAAKC,GAAGuB,SAASC,EAC5B,CAEAE,SACI,MAAO,KAAO3B,KAAKC,GAAGuB,SAAS,GACnC,CAEAI,iBACIC,GACJ,CAEAC,cACI,OAAO1C,EAAI0C,YAAY9B,KAAKC,GAChC,CAEA8B,aAAaC,GAET,OADA5C,EAAI2C,aAAa/B,KAAKC,GAAI+B,GACnBhC,IACX,CAEAiC,SACI,OAAO7C,EAAI6C,OAAOjC,KAAKC,GAC3B,CAEAiC,QAAQF,GAEJ,OADA5C,EAAI8C,QAAQlC,KAAKC,GAAI+B,GACdhC,IACX,CAEAmC,SACI,OAAO/C,EAAI+C,OAAOnC,KAAKC,GAC3B,CAEAmC,QAAQJ,GAEJ,OADA5C,EAAIgD,QAAQpC,KAAKC,GAAI+B,GACdhC,IACX,CAEAqC,UACI,OAAOjD,EAAIiD,QAAQrC,KAAKC,GAC5B,CAEAqC,SAASN,GAEL,OADA5C,EAAIkD,SAAStC,KAAKC,GAAI+B,GACfhC,IACX,CAEAuC,UACI,OAAOnD,EAAImD,QAAQvC,KAAKC,GAC5B,CAEAuC,SAASR,GAEL,OADA5C,EAAIoD,SAASxC,KAAKC,GAAI+B,GACfhC,IACX,CAEAyC,UACI,OAAOrD,EAAIqD,QAAQzC,KAAKC,GAC5B,CAEAyC,SAASV,GAEL,OADA5C,EAAIsD,SAAS1C,KAAKC,GAAI+B,GACfhC,IACX,CAEA2C,UACI,OAAOvD,EAAIuD,QAAQ3C,KAAKC,GAC5B,CAEA2C,SAASZ,GAEL,OADA5C,EAAIwD,SAAS5C,KAAKC,GAAI+B,GACfhC,IACX,CAEA6C,UACI,OAAOzD,EAAIyD,QAAQ7C,KAAKC,GAC5B,CAEA6C,SAASd,GAEL,OADA5C,EAAI0D,SAAS9C,KAAKC,GAAI+B,GACfhC,IACX,CAEA+C,UACI,OAAO3D,EAAI2D,QAAQ/C,KAAKC,GAC5B,CAEA+C,SAAShB,GAEL,OADA5C,EAAI4D,SAAShD,KAAKC,GAAI+B,GACfhC,IACX,CAEAiD,YACI,OAAOjD,KAAKqC,SAChB,CAEAa,WAAWlB,GACP,OAAOhC,KAAKsC,SAASN,EACzB,CAEAmB,aACI,OAAOnD,KAAKuC,SAChB,CAEAa,YAAYpB,GACR,OAAOhC,KAAKwC,SAASR,EACzB,CAEAqB,UACI,OAAOrD,KAAKyC,SAChB,CAEAa,SAAStB,GACL,OAAOhC,KAAK0C,SAASV,EACzB,CAEAuB,WACI,OAAOvD,KAAK2C,SAChB,CAEAa,UAAUxB,GACN,OAAOhC,KAAK4C,SAASZ,EACzB,CAEAyB,WACI,OAAO7D,EAA0BI,KAAK6C,UAAY7C,KAAKyC,SAC3D,CAEAiB,UAAU1B,GACN,OAAOpC,EAA0BI,KAAK8C,SAASd,GAAShC,KAAK0C,SAASV,EAC1E,CAEA2B,YACI,OAAO/D,EAA0BI,KAAK+C,UAAY/C,KAAK2C,SAC3D,CAEAiB,WAAW5B,GACP,OAAOpC,EAA0BI,KAAKgD,SAAShB,GAAShC,KAAK4C,SAASZ,EAC1E,CAEA6B,YACI,OAAOzE,EAAIyE,UAAU7D,KAAKC,GAC9B,CAEA6D,WAAW9B,GAEP,OADA5C,EAAI0E,WAAW9D,KAAKC,GAAI+B,GACjBhC,IACX,CAEA+D,aACI,OAAO3E,EAAI2E,WAAW/D,KAAKC,GAC/B,CAEA+D,YAAYhC,GAER,OADA5C,EAAI4E,YAAYhE,KAAKC,GAAI+B,GAClBhC,IACX,CAEAiE,cAAcC,GACV,OAAO9E,EAAI6E,cAAcjE,KAAKC,GAAIiE,EACtC,CAEAC,eAAenC,GAEX,OADA5C,EAAI+E,eAAenE,KAAKC,GAAI+B,GACrBhC,IACX,CAEAoE,YAAYC,GACR,OAAOjF,EAAIgF,YAAYpE,KAAKC,GAAIoE,EACpC,CAEAC,eAAeD,GACX,OAAOjF,EAAIkF,eAAetE,KAAKC,GAAIoE,EACvC,CAEAE,gBAAgBvC,GAEZ,OADA5C,EAAImF,gBAAgBvE,KAAKC,GAAI+B,GACtBhC,IACX,CAEAwE,gBAAgBN,GACZrC,GACJ,CAEA4C,iBAAiBzC,GACbH,GACJ,CAEA6C,eAAeL,GACXxC,GACJ,CAEA8C,gBAAgB3C,GACZH,GACJ,SASE,MAAO+C,OAGT9E,YAAYC,GAEJC,KAAKC,GADQ,iBAANF,EACGA,EAAEE,GAEFV,OAAOQ,EAEzB,CAEAK,IAAIC,GACA,OAAO,IAAIuE,OAAO5E,KAAKC,GAAKK,EAAYD,GAC5C,CAEAE,IAAIF,GACA,OAAO,IAAIuE,OAAO5E,KAAKC,GAAKK,EAAYD,GAC5C,CAEAG,IAAIH,GACA,OAAO,IAAIuE,OAAO5E,KAAKC,GAAKK,EAAYD,GAC5C,CAEAI,GAAGJ,GACC,OAAO,IAAIuE,OAAO5E,KAAKC,GAAKK,EAAYD,GAC5C,CAEAK,IAAIL,GACA,OAAO,IAAIuE,OAAO5E,KAAKC,GAAKK,EAAYD,GAC5C,CAEAM,IAAIN,GACA,OAAO,IAAIuE,OAAO5E,KAAKC,IAAMK,EAAYD,GAC7C,CAEAO,IAAIP,GACA,OAAO,IAAIuE,OAAO5E,KAAKC,IAAMK,EAAYD,GAC7C,CAEAQ,MACI,OAAO,IAAI+D,QAAQ5E,KAAKC,GAC5B,CAEAgB,QAAQC,GACJ,MAAMC,EAAMnB,KAAKC,GACXI,EAAMC,EAAYY,GACxB,OAAQC,IAAQd,EAAO,EAAMc,EAAMd,GAAQ,EAAI,CACnD,CAEAe,OAAOf,GACH,OAA6B,IAAtBL,KAAKiB,QAAQZ,EACxB,CAEAwE,WACI,OAAOvD,OAAOtB,KAAKC,GACvB,CAEAuB,SAASC,GACL,OAAOzB,KAAKC,GAAGuB,SAASC,EAC5B,CAEAE,SACI,OAAO3B,KAAKC,GAAGuB,UACnB,CAEAsD,UACI,OAAOxD,OAAOtB,KAAKC,GACvB,SAGE,MAAO8E,QAGTjF,YAAYC,GACR,GAAiB,iBAANA,EACPC,KAAKC,GAAKF,EAAEE,OACT,CACH,IAAIE,EAAMZ,OAAOQ,GACbI,EAAM,KACNA,EAAMd,IAAWc,EAAM,KAE3BH,KAAKC,GAAKE,C,CAElB,CAEAC,IAAIC,GACA,OAAO,IAAI0E,QAAQ/E,KAAKC,GAAKK,EAAYD,GAC7C,CAEAE,IAAIF,GACA,OAAO,IAAI0E,QAAQ/E,KAAKC,GAAKK,EAAYD,GAC7C,CAEAG,IAAIH,GACA,OAAO,IAAI0E,QAAQ/E,KAAKC,GAAKK,EAAYD,GAC7C,CAEAI,GAAGJ,GACC,OAAO,IAAI0E,QAAQ/E,KAAKC,GAAKK,EAAYD,GAC7C,CAEAK,IAAIL,GACA,OAAO,IAAI0E,QAAQ/E,KAAKC,GAAKK,EAAYD,GAC7C,CAEAM,IAAIN,GACA,OAAO,IAAI0E,QAAQ/E,KAAKC,IAAMK,EAAYD,GAC9C,CAEAO,IAAIP,GACA,OAAO,IAAI0E,QAAQ/E,KAAKC,IAAMK,EAAYD,GAC9C,CAEAQ,MACI,OAAO,IAAIkE,SAAS/E,KAAKC,GAC7B,CAEAgB,QAAQC,GACJ,MAAMC,EAAMnB,KAAKC,GACXI,EAAMC,EAAYY,GACxB,OAAQC,IAAQd,EAAO,EAAMc,EAAMd,GAAQ,EAAI,CACnD,CAEAe,OAAOf,GACH,OAA6B,IAAtBL,KAAKiB,QAAQZ,EACxB,CAEAwE,WACI,OAAOvD,OAAOtB,KAAKC,GACvB,CAEAuB,SAASC,GACL,OAAOzB,KAAKC,GAAGuB,SAASC,EAC5B,CAEAE,SACI,OAAO3B,KAAKC,GAAGuB,UACnB,CAEAsD,UACI,OAAOxD,OAAOtB,KAAKC,GACvB,EAGJ,SAASK,EAAYP,GACjB,MAAiB,iBAANA,EACH,OAAQA,EACDA,EAAEE,GAEFF,EAAEG,OAAOD,GAGbV,OAAOQ,EAEtB,CAEA,SAAS8B,IACL,MAAM,IAAImD,MAAM,8CACpB"}
✄
import{gdb as t}from"./gdb.js";const r=0xffffffffffffffffn,e=BigInt(Process.pointerSize),n=8n===e?r:0xffffffffn,i=1n<<8n*e-1n,s=8n===e;export class BNativePointer{constructor(t){if("object"==typeof t)this.$v="$v"in t?t.$v:t.handle.$v;else{let r=BigInt(t);r<0n&&(r=n-(-r-1n)),this.$v=r}}add(t){return new BNativePointer(this.$v+h(t))}sub(t){return new BNativePointer(this.$v-h(t))}and(t){return new BNativePointer(this.$v&h(t))}or(t){return new BNativePointer(this.$v|h(t))}xor(t){return new BNativePointer(this.$v^h(t))}shr(t){return new BNativePointer(this.$v>>h(t))}shl(t){return new BNativePointer(this.$v<<h(t))}not(){return new BNativePointer(~this.$v)}sign(){return this}strip(){return this}blend(){return this}compare(t){const r=this.$v,e=h(t);return r===e?0:r<e?-1:1}equals(t){return 0===this.compare(t)}toInt32(){const t=this.$v;return Number(0n!==(t&i)?-(n-t+1n):t)}toUInt32(){return Number(this.$v)}toString(t){return void 0===t?"0x"+this.$v.toString(16):this.$v.toString(t)}toJSON(){return"0x"+this.$v.toString(16)}toMatchPattern(){u()}readPointer(){return t.readPointer(this.$v)}writePointer(r){return t.writePointer(this.$v,r),this}readS8(){return t.readS8(this.$v)}writeS8(r){return t.writeS8(this.$v,r),this}readU8(){return t.readU8(this.$v)}writeU8(r){return t.writeU8(this.$v,r),this}readS16(){return t.readS16(this.$v)}writeS16(r){return t.writeS16(this.$v,r),this}readU16(){return t.readU16(this.$v)}writeU16(r){return t.writeU16(this.$v,r),this}readS32(){return t.readS32(this.$v)}writeS32(r){return t.writeS32(this.$v,r),this}readU32(){return t.readU32(this.$v)}writeU32(r){return t.writeU32(this.$v,r),this}readS64(){return t.readS64(this.$v)}writeS64(r){return t.writeS64(this.$v,r),this}readU64(){return t.readU64(this.$v)}writeU64(r){return t.writeU64(this.$v,r),this}readShort(){return this.readS16()}writeShort(t){return this.writeS16(t)}readUShort(){return this.readU16()}writeUShort(t){return this.writeU16(t)}readInt(){return this.readS32()}writeInt(t){return this.writeS32(t)}readUInt(){return this.readU32()}writeUInt(t){return this.writeU32(t)}readLong(){return s?this.readS64():this.readS32()}writeLong(t){return s?this.writeS64(t):this.writeS32(t)}readULong(){return s?this.readU64():this.readU32()}writeULong(t){return s?this.writeU64(t):this.writeU32(t)}readFloat(){return t.readFloat(this.$v)}writeFloat(r){return t.writeFloat(this.$v,r),this}readDouble(){return t.readDouble(this.$v)}writeDouble(r){return t.writeDouble(this.$v,r),this}readByteArray(r){return t.readByteArray(this.$v,r)}writeByteArray(r){return t.writeByteArray(this.$v,r),this}readCString(r){return t.readCString(this.$v,r)}readUtf8String(r){return t.readUtf8String(this.$v,r)}writeUtf8String(r){return t.writeUtf8String(this.$v,r),this}readUtf16String(t){u()}writeUtf16String(t){u()}readAnsiString(t){u()}writeAnsiString(t){u()}}export class BInt64{constructor(t){this.$v="object"==typeof t?t.$v:BigInt(t)}add(t){return new BInt64(this.$v+h(t))}sub(t){return new BInt64(this.$v-h(t))}and(t){return new BInt64(this.$v&h(t))}or(t){return new BInt64(this.$v|h(t))}xor(t){return new BInt64(this.$v^h(t))}shr(t){return new BInt64(this.$v>>h(t))}shl(t){return new BInt64(this.$v<<h(t))}not(){return new BInt64(~this.$v)}compare(t){const r=this.$v,e=h(t);return r===e?0:r<e?-1:1}equals(t){return 0===this.compare(t)}toNumber(){return Number(this.$v)}toString(t){return this.$v.toString(t)}toJSON(){return this.$v.toString()}valueOf(){return Number(this.$v)}}export class BUInt64{constructor(t){if("object"==typeof t)this.$v=t.$v;else{let e=BigInt(t);e<0n&&(e=r-(-e-1n)),this.$v=e}}add(t){return new BUInt64(this.$v+h(t))}sub(t){return new BUInt64(this.$v-h(t))}and(t){return new BUInt64(this.$
"""


```