Response:
The user wants to understand the functionality of the provided JavaScript code, which appears to be part of Frida's Objective-C bridge. I need to analyze the code and summarize its main features, focusing on its role in dynamic instrumentation and interaction with the Objective-C runtime.

Here's a breakdown of the code's key aspects:

1. **Initialization and API Access:** It initializes by trying to access Frida's native API for Objective-C interaction.
2. **Class and Protocol Registries:** It maintains registries for Objective-C classes and protocols, allowing access to them by name.
3. **Object Representation (ObjCObject):** It defines a JavaScript wrapper (`ObjCObject`) for Objective-C objects, providing access to their properties, methods, and ivars.
4. **Method Swizzling/Hooking:** It implements functionality to replace the implementation of Objective-C methods.
5. **Block Handling:** It provides a way to work with Objective-C blocks.
6. **Proxy Objects:** It allows the creation of proxy objects that can intercept messages.
7. **Dynamic Class and Protocol Creation:** It enables the runtime creation of new Objective-C classes and protocols.
8. **Binding Data to Objects:** It provides a mechanism to associate arbitrary data with Objective-C objects.
9. **Error Handling:** Includes `try...catch` blocks for handling potential errors during initialization and method calls.

Based on this analysis, I can now formulate a summary of its functionalities.这是 `frida/build/subprojects/frida-gum/bindings/gumjs/runtime.bundle.p/out-qjs/objc.js` 文件的第一部分源代码，它是一个用于 Frida 动态 instrumentation tool 的 Objective-C 运行时桥接代码。  该部分代码主要负责以下功能：

1. **初始化和 API 访问:** 代码首先尝试获取 Frida 提供的 Objective-C 运行时 API (`getApi`)。如果获取失败，它会抛出一个错误。这部分是与 Frida 底层二进制交互的起点。

2. **类和协议注册表:**  它维护了两个核心的注册表：`ClassRegistry` 和 `ProtocolRegistry`。
    *   `ClassRegistry` 允许通过名称访问已加载的 Objective-C 类。它会缓存已查找的类，并能动态列出所有已加载的类。
    *   `ProtocolRegistry` 允许通过名称访问已注册的 Objective-C 协议。

3. **Objective-C 对象表示 (`ObjCObject`):**  定义了 JavaScript 对象 `ObjCObject`，用于表示 Objective-C 的对象实例或类对象。它提供了访问 Objective-C 对象属性、方法、所属类、父类、实现的协议以及实例变量（ivars）的能力。

4. **方法替换 (Method Swizzling):**  实现了替换 Objective-C 方法实现的功能。`replaceMethodImplementation` 函数允许修改现有方法的行为。

5. **异步任务调度:** 提供了 `schedule` 函数，允许在指定的 Dispatch Queue 上异步执行 JavaScript 代码。这通常用于在主线程上执行 UI 相关的操作，避免阻塞。

6. **原生回调 (`NativeCallback`):**  `implement` 函数用于创建 `NativeCallback` 对象，可以将 JavaScript 函数转换为 Objective-C 可以调用的函数指针，用于实现 Objective-C 的方法。

7. **选择器 (`selector`):**  提供了 `selector` 函数，用于将字符串转换为 Objective-C 的 `SEL` (选择器) 类型，以及 `selectorAsString` 反向转换。

8. **块 (Block) 处理:**  定义了 `Block` 对象，用于表示和操作 Objective-C 的闭包 (blocks)。

9. **代理对象 (`registerProxy`):** 允许注册一个符合特定协议的代理类，可以拦截并处理发送给它的消息。

10. **动态类注册 (`registerClass`):**  允许在运行时动态创建新的 Objective-C 类，并指定其父类、实现的协议和方法。

11. **动态协议注册 (`registerProtocol`):** 允许在运行时动态创建新的 Objective-C 协议。

12. **对象绑定数据 (`bind`, `unbind`, `getBoundData`):**  提供了将任意 JavaScript 数据与 Objective-C 对象关联起来的能力。

**涉及二进制底层，linux内核的举例说明:**

*   **`getApi()`:**  这个函数会调用 Frida 的 Gum 库，Gum 库本身会与目标进程的内存进行交互，直接操作 Objective-C 运行时的数据结构。这涉及到读取和写入目标进程的内存，属于典型的二进制底层操作。在 Linux 内核层面，这可能涉及到 `ptrace` 系统调用或者 Frida 使用的内核模块来完成内存的读写。
*   **`api.objc_getClassList()`，`api.objc_lookUpClass()` 等:** 这些 `api` 对象的方法是对 Objective-C 运行时 C API 的封装。Frida 的 Gum 库通过直接调用这些 C API 函数与 Objective-C 运行时进行交互。这些 C API 的实现位于操作系统的动态链接库中，最终会转化为底层的机器码执行。
*   **`NativeCallback` 的创建:** 当创建一个 `NativeCallback` 时，Frida 需要在目标进程中分配一块可执行内存，并将 JavaScript 函数的入口地址包装成一个可以被 Objective-C 调用的函数指针。这个过程涉及到内存管理和指令的生成，是典型的底层二进制操作。

**用 lldb 指令或者 lldb python 脚本复刻的源代码所实现调试功能的示例 (如果源代码是调试功能的实现):**

虽然这段代码本身是 Frida 运行时桥接的一部分，并非直接的调试功能实现，但它可以用来构建调试功能。 假设我们要复刻 `ObjCObject` 中获取对象 `$className` 的功能，可以使用 lldb 指令：

```lldb
(lldb) po object_getClassName(0x100008000) // 假设 0x100008000 是一个 Objective-C 对象的地址
```

或者使用 lldb Python 脚本：

```python
import lldb

def get_class_name(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    options = lldb.SBExpressionOptions()
    options.Set ভাষা(lldb.eLanguageTypeObjC_plus_plus)
    expr_result = process.EvaluateExpression(f"(const char *)object_getClassName((id){command})", options)
    if expr_result.IsValid() and expr_result.GetError().Success():
        print(expr_result.GetValue())
    else:
        print(expr_result.GetError())

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f objc_runtime.get_class_name get_objc_classname')
    print("The 'get_objc_classname' command has been created.")

```

然后在 lldb 中使用：

```lldb
(lldb) get_objc_classname 0x100008000
```

这会调用 Objective-C 的运行时函数 `object_getClassName` 来获取指定对象的类名，类似于 `ObjCObject` 的 `$className` 属性的实现。

**逻辑推理的假设输入与输出:**

假设我们调用 `ClassRegistry` 来获取 `NSString` 类：

*   **假设输入:**  调用 `ObjC.classes.NSString`
*   **预期输出:** 返回一个 `ObjCObject` 实例，该实例的 `handle` 属性指向 `NSString` 类的元数据。

**用户或编程常见的使用错误举例说明:**

*   **错误地使用 `registerClass` 注册已存在的类名:** 如果用户尝试使用 `registerClass` 注册一个已经存在的 Objective-C 类名，Frida 会抛出一个错误，因为 Objective-C 运行时不允许重复注册类。

    ```javascript
    // 假设 NSString 已经存在
    ObjC.registerClass({ name: 'NSString', super: ObjC.classes.NSObject, methods: {} });
    // 错误：Unable to register already registered class 'NSString'
    ```

*   **在不正确的线程调用 UI 相关的 Objective-C 方法:**  如果用户在非主线程上直接调用 UIKit 框架中的 UI 更新方法，可能会导致程序崩溃或 UI 行为异常。Frida 的 `schedule` 函数可以帮助避免这个问题，但如果用户直接调用，就会出错。

    ```javascript
    // 错误示例：在非主线程上更新 UILabel 的文本
    var label = ObjC.classes.UILabel.alloc().init();
    label.setText_('New Text'); // 可能导致崩溃或异常
    ```

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **编写 Frida 脚本:** 用户首先会编写一个 Frida 脚本，用于 hook 或 instrument Objective-C 的代码。
2. **引入 Objective-C 桥接:**  在脚本中，用户会通过 `ObjC` 全局对象访问 Objective-C 运行时。 这就意味着 Frida 内部会加载并初始化 `objc.js` 这个模块。
3. **访问类或对象:**  用户可能会使用 `ObjC.classes.NSString` 来获取 `NSString` 类，或者使用 `ObjC.Object(ptr)` 来包装一个 Objective-C 对象指针。 这会触发 `ClassRegistry` 和 `ObjCObject` 的相关代码执行。
4. **调用方法或访问属性:** 用户可能会调用 `ObjC` 对象的 `$className` 属性或调用对象的方法，例如 `NSString` 的 `stringWithUTF8String_`。 这会触发 `ObjCObject` 中方法查找和调用的逻辑。
5. **动态注册类或协议:**  用户可能想要在运行时创建新的 Objective-C 类或协议，这时会调用 `ObjC.registerClass` 或 `ObjC.registerProtocol`。

因此，当用户在 Frida 脚本中与 Objective-C 运行时进行交互时，例如访问类、对象、调用方法、注册新的类或协议时，就会逐步执行 `objc.js` 中的代码。 如果在这些操作中出现错误，例如找不到类、方法调用失败等，就需要根据错误信息和脚本的执行流程来定位问题，而 `objc.js` 的源代码就是理解这些交互过程的关键。

**功能归纳:**

总而言之，`frida/build/subprojects/frida-gum/bindings/gumjs/runtime.bundle.p/out-qjs/objc.js` 的第一部分代码主要提供了 Frida 与 Objective-C 运行时交互的基础设施，包括访问和表示 Objective-C 的类、对象和协议，进行方法替换，处理 Blocks，以及动态创建类和协议等核心功能，为 Frida 用户提供了在运行时动态分析和修改 Objective-C 代码的能力。

Prompt: 
```
这是目录为frida/build/subprojects/frida-gum/bindings/gumjs/runtime.bundle.p/out-qjs/objc.js的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第1部分，共3部分，请归纳一下它的功能

"""
(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
(function (setImmediate){(function (){
const {getApi: getApi, defaultInvocationOptions: defaultInvocationOptions} = require("./lib/api"), fastpaths = require("./lib/fastpaths");

function Runtime() {
  const pointerSize = Process.pointerSize;
  let api = null, apiError = null;
  const realizedClasses = new Set, classRegistry = new ClassRegistry, protocolRegistry = new ProtocolRegistry, replacedMethods = new Map, scheduledWork = new Map;
  let nextId = 1, workCallback = null, NSAutoreleasePool = null;
  const bindings = new Map;
  let readObjectIsa = null;
  const msgSendBySignatureId = new Map, msgSendSuperBySignatureId = new Map;
  let cachedNSString = null, cachedNSStringCtor = null, cachedNSNumber = null, cachedNSNumberCtor = null, singularTypeById = null, modifiers = null;
  try {
    tryInitialize();
  } catch (e) {}
  function tryInitialize() {
    if (null !== api) return !0;
    if (null !== apiError) throw apiError;
    try {
      api = getApi();
    } catch (e) {
      throw apiError = e, e;
    }
    return null !== api;
  }
  function dispose() {
    for (const [e, t] of replacedMethods.entries()) {
      const r = ptr(e), [n, o] = t;
      api.method_getImplementation(r).equals(o) && api.method_setImplementation(r, n);
    }
    replacedMethods.clear();
  }
  function performScheduledWorkItem(e) {
    const t = e.toString(), r = scheduledWork.get(t);
    scheduledWork.delete(t), null === NSAutoreleasePool && (NSAutoreleasePool = classRegistry.NSAutoreleasePool);
    const n = NSAutoreleasePool.alloc().init();
    let o = null;
    try {
      r();
    } catch (e) {
      o = e;
    }
    n.release(), setImmediate(performScheduledWorkCleanup, o);
  }
  function performScheduledWorkCleanup(e) {
    if (Script.unpin(), null !== e) throw e;
  }
  function selector(e) {
    return api.sel_registerName(Memory.allocUtf8String(e));
  }
  function selectorAsString(e) {
    return api.sel_getName(e).readUtf8String();
  }
  Script.bindWeak(this, dispose), Object.defineProperty(this, "available", {
    enumerable: !0,
    get: () => tryInitialize()
  }), Object.defineProperty(this, "api", {
    enumerable: !0,
    get: () => getApi()
  }), Object.defineProperty(this, "classes", {
    enumerable: !0,
    value: classRegistry
  }), Object.defineProperty(this, "protocols", {
    enumerable: !0,
    value: protocolRegistry
  }), Object.defineProperty(this, "Object", {
    enumerable: !0,
    value: ObjCObject
  }), Object.defineProperty(this, "Protocol", {
    enumerable: !0,
    value: ObjCProtocol
  }), Object.defineProperty(this, "Block", {
    enumerable: !0,
    value: Block
  }), Object.defineProperty(this, "mainQueue", {
    enumerable: !0,
    get: () => api._dispatch_main_q
  }), Object.defineProperty(this, "registerProxy", {
    enumerable: !0,
    value: registerProxy
  }), Object.defineProperty(this, "registerClass", {
    enumerable: !0,
    value: registerClass
  }), Object.defineProperty(this, "registerProtocol", {
    enumerable: !0,
    value: registerProtocol
  }), Object.defineProperty(this, "bind", {
    enumerable: !0,
    value: bind
  }), Object.defineProperty(this, "unbind", {
    enumerable: !0,
    value: unbind
  }), Object.defineProperty(this, "getBoundData", {
    enumerable: !0,
    value: getBoundData
  }), Object.defineProperty(this, "enumerateLoadedClasses", {
    enumerable: !0,
    value: enumerateLoadedClasses
  }), Object.defineProperty(this, "enumerateLoadedClassesSync", {
    enumerable: !0,
    value: enumerateLoadedClassesSync
  }), Object.defineProperty(this, "choose", {
    enumerable: !0,
    value: choose
  }), Object.defineProperty(this, "chooseSync", {
    enumerable: !0,
    value(e) {
      const t = [];
      return choose(e, {
        onMatch(e) {
          t.push(e);
        },
        onComplete() {}
      }), t;
    }
  }), this.schedule = function(e, t) {
    const r = ptr(nextId++);
    scheduledWork.set(r.toString(), t), null === workCallback && (workCallback = new NativeCallback(performScheduledWorkItem, "void", [ "pointer" ])), 
    Script.pin(), api.dispatch_async_f(e, r, workCallback);
  }, this.implement = function(e, t) {
    return new NativeCallback(t, e.returnType, e.argumentTypes);
  }, this.selector = selector, this.selectorAsString = selectorAsString;
  const registryBuiltins = new Set([ "prototype", "constructor", "hasOwnProperty", "toJSON", "toString", "valueOf" ]);
  function ClassRegistry() {
    const e = {};
    let t = 0;
    const r = new Proxy(this, {
      has: (e, t) => n(t),
      get(e, t, r) {
        switch (t) {
         case "prototype":
          return e.prototype;

         case "constructor":
          return e.constructor;

         case "hasOwnProperty":
          return n;

         case "toJSON":
          return i;

         case "toString":
          return a;

         case "valueOf":
          return s;

         default:
          const r = o(t);
          return null !== r ? r : void 0;
        }
      },
      set: (e, t, r, n) => !1,
      ownKeys(r) {
        let n = api.objc_getClassList(NULL, 0);
        if (n !== t) {
          const r = Memory.alloc(n * pointerSize);
          n = api.objc_getClassList(r, n);
          for (let t = 0; t !== n; t++) {
            const n = r.add(t * pointerSize).readPointer(), o = api.class_getName(n).readUtf8String();
            e[o] = n;
          }
          t = n;
        }
        return Object.keys(e);
      },
      getOwnPropertyDescriptor: (e, t) => ({
        writable: !1,
        configurable: !0,
        enumerable: !0
      })
    });
    function n(e) {
      return !!registryBuiltins.has(e) || null !== o(e);
    }
    function o(r) {
      let n = e[r];
      if (void 0 === n) {
        if (n = api.objc_lookUpClass(Memory.allocUtf8String(r)), n.isNull()) return null;
        e[r] = n, t++;
      }
      return new ObjCObject(n, void 0, !0);
    }
    function i() {
      return Object.keys(r).reduce((function(e, t) {
        return e[t] = function(e) {
          const t = o(e);
          if (null === t) throw new Error("Unable to find class '" + e + "'");
          return t;
        }(t).toJSON(), e;
      }), {});
    }
    function a() {
      return "ClassRegistry";
    }
    function s() {
      return "ClassRegistry";
    }
    return r;
  }
  function ProtocolRegistry() {
    let e = {}, t = 0;
    const r = new Proxy(this, {
      has: (e, t) => n(t),
      get(e, t, r) {
        switch (t) {
         case "prototype":
          return e.prototype;

         case "constructor":
          return e.constructor;

         case "hasOwnProperty":
          return n;

         case "toJSON":
          return i;

         case "toString":
          return a;

         case "valueOf":
          return s;

         default:
          const r = o(t);
          return null !== r ? r : void 0;
        }
      },
      set: (e, t, r, n) => !1,
      ownKeys(r) {
        const n = Memory.alloc(pointerSize), o = api.objc_copyProtocolList(n);
        try {
          const r = n.readUInt();
          if (r !== t) {
            e = {};
            for (let t = 0; t !== r; t++) {
              const r = o.add(t * pointerSize).readPointer(), n = api.protocol_getName(r).readUtf8String();
              e[n] = r;
            }
            t = r;
          }
        } finally {
          api.free(o);
        }
        return Object.keys(e);
      },
      getOwnPropertyDescriptor: (e, t) => ({
        writable: !1,
        configurable: !0,
        enumerable: !0
      })
    });
    function n(e) {
      return !!registryBuiltins.has(e) || null !== o(e);
    }
    function o(r) {
      let n = e[r];
      if (void 0 === n) {
        if (n = api.objc_getProtocol(Memory.allocUtf8String(r)), n.isNull()) return null;
        e[r] = n, t++;
      }
      return new ObjCProtocol(n);
    }
    function i() {
      return Object.keys(r).reduce((function(t, r) {
        return t[r] = {
          handle: e[r]
        }, t;
      }), {});
    }
    function a() {
      return "ProtocolRegistry";
    }
    function s() {
      return "ProtocolRegistry";
    }
    return r;
  }
  const objCObjectBuiltins = new Set([ "prototype", "constructor", "handle", "hasOwnProperty", "toJSON", "toString", "valueOf", "equals", "$kind", "$super", "$superClass", "$class", "$className", "$moduleName", "$protocols", "$methods", "$ownMethods", "$ivars" ]);
  function ObjCObject(e, t, r, n) {
    let o = null, i = null, a = null, s = null, l = null, c = null, u = null, p = null, d = null, f = null, g = null;
    const h = {};
    let y = null, m = null, b = null;
    if (e = getHandle(e), void 0 === r) {
      const t = api.object_getClass(e), r = t.toString();
      realizedClasses.has(r) || (api.objc_lookUpClass(api.class_getName(t)), realizedClasses.add(r));
    }
    const S = new Proxy(this, {
      has: (e, t) => w(t),
      get(o, d, f) {
        switch (d) {
         case "handle":
          return e;

         case "prototype":
          return o.prototype;

         case "constructor":
          return o.constructor;

         case "hasOwnProperty":
          return w;

         case "toJSON":
          return T;

         case "toString":
         case "valueOf":
          const g = f.description;
          if (void 0 !== g) {
            const e = g.call(f);
            if (null !== e) return e.UTF8String.bind(e);
          }
          return function() {
            return f.$className;
          };

         case "equals":
          return I;

         case "$kind":
          return null === i && (i = N() ? api.class_isMetaClass(e) ? "meta-class" : "class" : "instance"), 
          i;

         case "$super":
          if (null === a) {
            const t = api.class_getSuperclass(v());
            if (t.isNull()) a = [ null ]; else {
              const n = Memory.alloc(2 * pointerSize);
              n.writePointer(e), n.add(pointerSize).writePointer(t), a = [ new ObjCObject(e, void 0, r, n) ];
            }
          }
          return a[0];

         case "$superClass":
          if (null === s) {
            const e = api.class_getSuperclass(v());
            s = e.isNull() ? [ null ] : [ new ObjCObject(e) ];
          }
          return s[0];

         case "$class":
          return null === l && (l = new ObjCObject(api.object_getClass(e), void 0, !0)), l;

         case "$className":
          return null === c && (c = n ? api.class_getName(n.add(pointerSize).readPointer()).readUtf8String() : N() ? api.class_getName(e).readUtf8String() : api.object_getClassName(e).readUtf8String()), 
          c;

         case "$moduleName":
          return null === u && (u = api.class_getImageName(v()).readUtf8String()), u;

         case "$protocols":
          if (null === p) {
            p = {};
            const e = Memory.alloc(pointerSize), t = api.class_copyProtocolList(v(), e);
            if (!t.isNull()) try {
              const r = e.readUInt();
              for (let e = 0; e !== r; e++) {
                const r = new ObjCProtocol(t.add(e * pointerSize).readPointer());
                p[r.name] = r;
              }
            } finally {
              api.free(t);
            }
          }
          return p;

         case "$methods":
          if (null === y) {
            const e = n ? n.add(pointerSize).readPointer() : v(), t = api.object_getClass(e), r = new Set;
            let o = t;
            do {
              for (let e of collectMethodNames(o, "+ ")) r.add(e);
              o = api.class_getSuperclass(o);
            } while (!o.isNull());
            o = e;
            do {
              for (let e of collectMethodNames(o, "- ")) r.add(e);
              o = api.class_getSuperclass(o);
            } while (!o.isNull());
            y = Array.from(r);
          }
          return y;

         case "$ownMethods":
          if (null === m) {
            const e = n ? n.add(pointerSize).readPointer() : v(), t = collectMethodNames(api.object_getClass(e), "+ "), r = collectMethodNames(e, "- ");
            m = t.concat(r);
          }
          return m;

         case "$ivars":
          return null === b && (b = N() ? {} : new ObjCIvars(S, v())), b;

         default:
          if ("symbol" == typeof d) return o[d];
          if (t) {
            const e = j(d);
            if (null === e || !e.implemented) return;
          }
          const h = _(d);
          if (null === h) return;
          return h;
        }
      },
      set: (e, t, r, n) => !1,
      ownKeys(r) {
        if (null === d) if (t) {
          const e = [], t = P();
          Object.keys(t).forEach((function(r) {
            if ("+" !== r[0] && "-" !== r[0]) {
              t[r].implemented && e.push(r);
            }
          })), d = e;
        } else {
          const t = {}, r = {};
          let n = api.object_getClass(e);
          do {
            const e = Memory.alloc(pointerSize), o = api.class_copyMethodList(n, e), i = N() ? "+ " : "- ";
            try {
              const n = e.readUInt();
              for (let e = 0; e !== n; e++) {
                const n = o.add(e * pointerSize).readPointer(), a = api.method_getName(n), s = api.sel_getName(a).readUtf8String();
                if (void 0 !== r[s]) continue;
                r[s] = s;
                const l = jsMethodName(s);
                let c = 2, u = l;
                for (;void 0 !== t[u]; ) c++, u = l + c;
                t[u] = !0;
                const p = i + s;
                if (void 0 === h[p]) {
                  const e = {
                    sel: a,
                    handle: n,
                    wrapper: null
                  };
                  h[p] = e, h[u] = e;
                }
              }
            } finally {
              api.free(o);
            }
            n = api.class_getSuperclass(n);
          } while (!n.isNull());
          d = Object.keys(t);
        }
        return [ "handle" ].concat(d);
      },
      getOwnPropertyDescriptor: (e, t) => ({
        writable: !1,
        configurable: !0,
        enumerable: !0
      })
    });
    return t && (g = N() ? null : _("- respondsToSelector:")), S;
    function w(e) {
      if (objCObjectBuiltins.has(e)) return !0;
      if (t) {
        const t = j(e);
        return !(null === t || !t.implemented);
      }
      return null !== O(e);
    }
    function v() {
      return null === o && (o = N() ? e : api.object_getClass(e)), o;
    }
    function N() {
      return void 0 === r && (r = api.object_isClass ? !!api.object_isClass(e) : !!api.class_isMetaClass(api.object_getClass(e))), 
      r;
    }
    function O(e) {
      let r = h[e];
      if (void 0 !== r) return r;
      const n = function(e) {
        const t = /([+\-])\s(\S+)/.exec(e);
        let r, n;
        null === t ? (n = N() ? "+" : "-", r = objcMethodName(e)) : (n = t[1], r = t[2]);
        const o = [ n, r ].join(" ");
        return [ n, r, o ];
      }(e), o = n[2];
      if (r = h[o], void 0 !== r) return h[e] = r, r;
      const i = n[0], a = n[1], s = selector(a), l = N() ? "+" : "-";
      if (t) {
        const e = j(o);
        null !== e && (r = {
          sel: s,
          types: e.types,
          wrapper: null,
          kind: i
        });
      }
      if (void 0 === r) {
        const e = "+" === i ? api.class_getClassMethod(v(), s) : api.class_getInstanceMethod(v(), s);
        if (e.isNull()) {
          if (N() || "-" !== i || "forwardingTargetForSelector:" === a || "methodSignatureForSelector:" === a) return null;
          let e = S;
          if (!("- forwardingTargetForSelector:" in S)) return null;
          {
            const t = S.forwardingTargetForSelector_(s);
            if (null === t || "instance" !== t.$kind) return null;
            e = t;
          }
          const t = api.class_getInstanceMethod(api.object_getClass(e.handle), s);
          if (t.isNull()) return null;
          let n = api.method_getTypeEncoding(t).readUtf8String();
          if ((null === n || "" === n) && (n = C(e, o), null === n && (n = C(S, o)), null === n)) return null;
          r = {
            sel: s,
            types: n,
            wrapper: null,
            kind: i
          };
        } else r = {
          sel: s,
          handle: e,
          wrapper: null,
          kind: i
        };
      }
      return h[o] = r, h[e] = r, i === l && (h[jsMethodName(a)] = r), r;
    }
    function C(e, t) {
      const r = Object.keys(e.$protocols).map((t => k({}, e.$protocols[t]))).reduce(((e, t) => (Object.assign(e, t), 
      e)), {})[t];
      return void 0 === r ? null : r.types;
    }
    function k(e, t) {
      return void 0 !== t.methods && Object.assign(e, t.methods), void 0 !== t.protocol && k(e, t.protocol), 
      e;
    }
    function j(e) {
      const t = P()[e];
      return void 0 !== t ? t : null;
    }
    function P() {
      if (null === f) {
        const e = {}, r = collectProtocols(t), n = N() ? "+" : "-";
        Object.keys(r).forEach((function(t) {
          const o = r[t].methods;
          Object.keys(o).forEach((function(t) {
            const r = o[t], i = t.substr(2), a = t[0];
            let s = !1, l = !1;
            const c = {
              types: r.types
            };
            Object.defineProperty(c, "implemented", {
              get: () => (s || (l = !!r.required || null !== g && g.call(S, selector(i)), s = !0), 
              l)
            }), e[t] = c, a === n && (e[jsMethodName(i)] = c);
          }));
        })), f = e;
      }
      return f;
    }
    function _(e) {
      const t = O(e);
      if (null === t) return null;
      let r = t.wrapper;
      return null === r && (r = makeMethodInvocationWrapper(t, S, n, defaultInvocationOptions), 
      t.wrapper = r), r;
    }
    function T() {
      return {
        handle: e.toString()
      };
    }
    function I(t) {
      return e.equals(getHandle(t));
    }
  }
  function getReplacementMethodImplementation(e) {
    const t = replacedMethods.get(e.toString());
    if (void 0 === t) return null;
    const [, r] = t;
    return r;
  }
  function replaceMethodImplementation(e, t) {
    const r = e.toString();
    let n;
    const o = replacedMethods.get(r);
    void 0 !== o ? [n] = o : n = api.method_getImplementation(e), t.equals(n) ? replacedMethods.delete(r) : replacedMethods.set(r, [ n, t ]), 
    api.method_setImplementation(e, t);
  }
  function collectMethodNames(e, t) {
    const r = [], n = Memory.alloc(pointerSize), o = api.class_copyMethodList(e, n);
    try {
      const e = n.readUInt();
      for (let n = 0; n !== e; n++) {
        const e = o.add(n * pointerSize).readPointer(), i = api.method_getName(e), a = api.sel_getName(i).readUtf8String();
        r.push(t + a);
      }
    } finally {
      api.free(o);
    }
    return r;
  }
  function ObjCProtocol(e) {
    let t = null, r = null, n = null, o = null;
    function i(t, r, n) {
      const o = api.protocol_copyMethodDescriptionList(e, n.required ? 1 : 0, n.instance ? 1 : 0, r);
      if (!o.isNull()) try {
        const e = r.readUInt();
        for (let r = 0; r !== e; r++) {
          const e = o.add(r * (2 * pointerSize)), i = (n.instance ? "- " : "+ ") + selectorAsString(e.readPointer()), a = e.add(pointerSize).readPointer().readUtf8String();
          t[i] = {
            required: n.required,
            types: a
          };
        }
      } finally {
        api.free(o);
      }
    }
    Object.defineProperty(this, "handle", {
      value: e,
      enumerable: !0
    }), Object.defineProperty(this, "name", {
      get: () => (null === t && (t = api.protocol_getName(e).readUtf8String()), t),
      enumerable: !0
    }), Object.defineProperty(this, "protocols", {
      get() {
        if (null === r) {
          r = {};
          const t = Memory.alloc(pointerSize), n = api.protocol_copyProtocolList(e, t);
          if (!n.isNull()) try {
            const e = t.readUInt();
            for (let t = 0; t !== e; t++) {
              const e = new ObjCProtocol(n.add(t * pointerSize).readPointer());
              r[e.name] = e;
            }
          } finally {
            api.free(n);
          }
        }
        return r;
      },
      enumerable: !0
    }), Object.defineProperty(this, "properties", {
      get() {
        if (null === n) {
          n = {};
          const t = Memory.alloc(pointerSize), r = api.protocol_copyPropertyList(e, t);
          if (!r.isNull()) try {
            const e = t.readUInt();
            for (let o = 0; o !== e; o++) {
              const e = r.add(o * pointerSize).readPointer(), i = api.property_getName(e).readUtf8String(), a = {}, s = api.property_copyAttributeList(e, t);
              if (!s.isNull()) try {
                const e = t.readUInt();
                for (let t = 0; t !== e; t++) {
                  const e = s.add(t * (2 * pointerSize)), r = e.readPointer().readUtf8String(), n = e.add(pointerSize).readPointer().readUtf8String();
                  a[r] = n;
                }
              } finally {
                api.free(s);
              }
              n[i] = a;
            }
          } finally {
            api.free(r);
          }
        }
        return n;
      },
      enumerable: !0
    }), Object.defineProperty(this, "methods", {
      get() {
        if (null === o) {
          o = {};
          const e = Memory.alloc(pointerSize);
          i(o, e, {
            required: !0,
            instance: !1
          }), i(o, e, {
            required: !1,
            instance: !1
          }), i(o, e, {
            required: !0,
            instance: !0
          }), i(o, e, {
            required: !1,
            instance: !0
          });
        }
        return o;
      },
      enumerable: !0
    });
  }
  const objCIvarsBuiltins = new Set([ "prototype", "constructor", "hasOwnProperty", "toJSON", "toString", "valueOf" ]);
  function ObjCIvars(e, t) {
    const r = {};
    let n = null, o = [], i = t;
    do {
      o.unshift(i), i = api.class_getSuperclass(i);
    } while (!i.isNull());
    const a = Memory.alloc(pointerSize);
    o.forEach((e => {
      const t = api.class_copyIvarList(e, a);
      try {
        const e = a.readUInt();
        for (let n = 0; n !== e; n++) {
          const e = t.add(n * pointerSize).readPointer(), o = api.ivar_getName(e).readUtf8String();
          r[o] = [ e, null ];
        }
      } finally {
        api.free(t);
      }
    }));
    const s = new Proxy(this, {
      has: (e, t) => c(t),
      get(e, t, r) {
        switch (t) {
         case "prototype":
          return e.prototype;

         case "constructor":
          return e.constructor;

         case "hasOwnProperty":
          return c;

         case "toJSON":
          return u;

         case "toString":
          return p;

         case "valueOf":
          return d;

         default:
          const r = l(t);
          if (null === r) return;
          return r.get();
        }
      },
      set(e, t, r, n) {
        const o = l(t);
        if (null === o) throw new Error("Unknown ivar");
        return o.set(r), !0;
      },
      ownKeys: e => (null === n && (n = Object.keys(r)), n),
      getOwnPropertyDescriptor: (e, t) => ({
        writable: !0,
        configurable: !0,
        enumerable: !0
      })
    });
    return s;
    function l(t) {
      const n = r[t];
      if (void 0 === n) return null;
      let o = n[1];
      if (null === o) {
        const r = n[0], i = api.ivar_getOffset(r).toInt32(), a = e.handle.add(i), s = parseType(api.ivar_getTypeEncoding(r).readUtf8String()), l = s.fromNative || identityTransform, c = s.toNative || identityTransform;
        let u, p;
        "isa" === t ? (u = readObjectIsa, p = function() {
          throw new Error("Unable to set the isa instance variable");
        }) : (u = s.read, p = s.write), o = {
          get: () => l.call(e, u(a)),
          set(t) {
            p(a, c.call(e, t));
          }
        }, n[1] = o;
      }
      return o;
    }
    function c(e) {
      return !!objCIvarsBuiltins.has(e) || r.hasOwnProperty(e);
    }
    function u() {
      return Object.keys(s).reduce((function(e, t) {
        return e[t] = s[t], e;
      }), {});
    }
    function p() {
      return "ObjCIvars";
    }
    function d() {
      return "ObjCIvars";
    }
  }
  let blockDescriptorAllocSize, blockDescriptorDeclaredSize, blockDescriptorOffsets, blockSize, blockOffsets;
  4 === pointerSize ? (blockDescriptorAllocSize = 16, blockDescriptorDeclaredSize = 20, 
  blockDescriptorOffsets = {
    reserved: 0,
    size: 4,
    rest: 8
  }, blockSize = 20, blockOffsets = {
    isa: 0,
    flags: 4,
    reserved: 8,
    invoke: 12,
    descriptor: 16
  }) : (blockDescriptorAllocSize = 32, blockDescriptorDeclaredSize = 32, blockDescriptorOffsets = {
    reserved: 0,
    size: 8,
    rest: 16
  }, blockSize = 32, blockOffsets = {
    isa: 0,
    flags: 8,
    reserved: 12,
    invoke: 16,
    descriptor: 24
  });
  const BLOCK_HAS_COPY_DISPOSE = 1 << 25, BLOCK_HAS_CTOR = 1 << 26, BLOCK_IS_GLOBAL = 1 << 28, BLOCK_HAS_STRET = 1 << 29, BLOCK_HAS_SIGNATURE = 1 << 30;
  function Block(e, t = defaultInvocationOptions) {
    if (this._options = t, e instanceof NativePointer) {
      const t = e.add(blockOffsets.descriptor).readPointer();
      this.handle = e;
      const r = e.add(blockOffsets.flags).readU32();
      if (r & BLOCK_HAS_SIGNATURE) {
        const e = r & BLOCK_HAS_COPY_DISPOSE ? 2 : 0;
        this.types = t.add(blockDescriptorOffsets.rest + e * pointerSize).readPointer().readCString(), 
        this._signature = parseSignature(this.types);
      } else this._signature = null;
    } else {
      this.declare(e);
      const t = Memory.alloc(blockDescriptorAllocSize + blockSize), r = t.add(blockDescriptorAllocSize), n = Memory.allocUtf8String(this.types);
      t.add(blockDescriptorOffsets.reserved).writeULong(0), t.add(blockDescriptorOffsets.size).writeULong(blockDescriptorDeclaredSize), 
      t.add(blockDescriptorOffsets.rest).writePointer(n), r.add(blockOffsets.isa).writePointer(classRegistry.__NSGlobalBlock__), 
      r.add(blockOffsets.flags).writeU32(BLOCK_HAS_SIGNATURE | BLOCK_IS_GLOBAL), r.add(blockOffsets.reserved).writeU32(0), 
      r.add(blockOffsets.descriptor).writePointer(t), this.handle = r, this._storage = [ t, n ], 
      this.implementation = e.implementation;
    }
  }
  function collectProtocols(e, t) {
    (t = t || {})[e.name] = e;
    const r = e.protocols;
    return Object.keys(r).forEach((function(e) {
      collectProtocols(r[e], t);
    })), t;
  }
  function registerProxy(e) {
    const t = e.protocols || [], r = e.methods || {}, n = e.events || {}, o = new Set(Object.keys(r).filter((e => null !== /([+\-])\s(\S+)/.exec(e))).map((e => e.split(" ")[1]))), i = {
      "- dealloc": function() {
        const e = this.data.target;
        "- release" in e && e.release(), unbind(this.self), this.super.dealloc();
        const t = this.data.events.dealloc;
        void 0 !== t && t.call(this);
      },
      "- respondsToSelector:": function(e) {
        const t = selectorAsString(e);
        return !!o.has(t) || this.data.target.respondsToSelector_(e);
      },
      "- forwardingTargetForSelector:": function(e) {
        const t = this.data.events.forward;
        return void 0 !== t && t.call(this, selectorAsString(e)), this.data.target;
      },
      "- methodSignatureForSelector:": function(e) {
        return this.data.target.methodSignatureForSelector_(e);
      },
      "- forwardInvocation:": function(e) {
        e.invokeWithTarget_(this.data.target);
      }
    };
    for (var a in r) if (r.hasOwnProperty(a)) {
      if (i.hasOwnProperty(a)) throw new Error("The '" + a + "' method is reserved");
      i[a] = r[a];
    }
    const s = registerClass({
      name: e.name,
      super: classRegistry.NSProxy,
      protocols: t,
      methods: i
    });
    return function(e, t) {
      e = e instanceof NativePointer ? new ObjCObject(e) : e, t = t || {};
      const r = s.alloc().autorelease(), o = getBoundData(r);
      for (var i in o.target = "- retain" in e ? e.retain() : e, o.events = n, t) if (t.hasOwnProperty(i)) {
        if (o.hasOwnProperty(i)) throw new Error("The '" + i + "' property is reserved");
        o[i] = t[i];
      }
      this.handle = r.handle;
    };
  }
  function registerClass(e) {
    let t = e.name;
    void 0 === t && (t = makeClassName());
    const r = void 0 !== e.super ? e.super : classRegistry.NSObject, n = e.protocols || [], o = e.methods || {}, i = [], a = api.objc_allocateClassPair(null !== r ? r.handle : NULL, Memory.allocUtf8String(t), ptr("0"));
    if (a.isNull()) throw new Error("Unable to register already registered class '" + t + "'");
    const s = api.object_getClass(a);
    try {
      n.forEach((function(e) {
        api.class_addProtocol(a, e.handle);
      })), Object.keys(o).forEach((function(e) {
        const t = /([+\-])\s(\S+)/.exec(e);
        if (null === t) throw new Error("Invalid method name");
        const l = t[1], c = t[2];
        let u;
        const p = o[e];
        if ("function" == typeof p) {
          let t = null;
          if (e in r) t = r[e].types; else for (let r of n) {
            const n = r.methods[e];
            if (void 0 !== n) {
              t = n.types;
              break;
            }
          }
          if (null === t) throw new Error("Unable to find '" + e + "' in super-class or any of its protocols");
          u = {
            types: t,
            implementation: p
          };
        } else u = p;
        const d = "+" === l ? s : a;
        let f = u.types;
        void 0 === f && (f = unparseSignature(u.retType, [ "+" === l ? "class" : "object", "selector" ].concat(u.argTypes)));
        const g = parseSignature(f), h = new NativeCallback(makeMethodImplementationWrapper(g, u.implementation), g.retType.type, g.argTypes.map((function(e) {
          return e.type;
        })));
        i.push(h), api.class_addMethod(d, selector(c), h, Memory.allocUtf8String(f));
      }));
    } catch (e) {
      throw api.objc_disposeClassPair(a), e;
    }
    return api.objc_registerClassPair(a), a._methodCallbacks = i, Script.bindWeak(a, makeClassDestructor(ptr(a))), 
    new ObjCObject(a);
  }
  function makeClassDestructor(e) {
    return function() {
      api.objc_disposeClassPair(e);
    };
  }
  function registerProtocol(e) {
    let t = e.name;
    void 0 === t && (t = makeProtocolName());
    const r = e.protocols || [], n = e.methods || {};
    r.forEach((function(e) {
      if (!(e instanceof ObjCProtocol)) throw new Error("Expected protocol");
    }));
    const o = Object.keys(n).map((function(e) {
      const t = n[e], r = /([+\-])\s(\S+)/.exec(e);
      if (null === r) throw new Error("Invalid method name");
      const o = r[1], i = r[2];
      let a = t.types;
      return void 0 === a && (a = unparseSignature(t.retType, [ "+" === o ? "class" : "object", "selector" ].concat(t.argTypes))), 
      {
        kind: o,
        name: i,
        types: a,
        optional: t.optional
      };
    })), i = api.objc_allocateProtocol(Memory.allocUtf8String(t));
    if (i.isNull()) throw new Error("Unable to register already registered protocol '" + t + "'");
    return r.forEach((function(e) {
      api.protocol_addProtocol(i, e.handle);
    })), o.forEach((function(e) {
      const t = e.optional ? 0 : 1, r = "-" === e.kind ? 1 : 0;
      api.protocol_addMethodDescription(i, selector(e.name), Memory.allocUtf8String(e.types), t, r);
    })), api.objc_registerProtocol(i), new ObjCProtocol(i);
  }
  function getHandle(e) {
    if (e instanceof NativePointer) return e;
    if ("object" == typeof e && e.hasOwnProperty("handle")) return e.handle;
    throw new Error("Expected NativePointer or ObjC.Object instance");
  }
  function bind(e, t) {
    const r = getHandle(e), n = e instanceof ObjCObject ? e : new ObjCObject(r);
    bindings.set(r.toString(), {
      self: n,
      super: n.$super,
      data: t
    });
  }
  function unbind(e) {
    const t = getHandle(e);
    bindings.delete(t.toString());
  }
  function getBoundData(e) {
    return getBinding(e).data;
  }
  
"""


```