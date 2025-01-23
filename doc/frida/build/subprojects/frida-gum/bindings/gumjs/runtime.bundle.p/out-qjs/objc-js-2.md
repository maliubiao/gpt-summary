Response:
Let's break down the thought process for analyzing the provided JavaScript code snippet for Frida.

**1. Initial Understanding of the Context:**

The prompt clearly states this is a part of Frida, specifically the `objc.js` within the `frida-gum` bindings. This immediately tells me it's related to interacting with Objective-C runtime within a target process. The path `runtime.bundle.p/out-qjs` suggests it's likely a compiled or bundled version for QuickJS, Frida's embedded JavaScript engine.

**2. Deconstructing the Code:**

I'll go through the code section by section, focusing on the core functionalities:

* **Top Section (C Code):**  This is where the heavy lifting happens. I see functions like `collect_classes`, `collect_matches_in_ranges`, and `read_local_memory`. The function signatures and variable types (e.g., `task_t`, `vm_range_t`, `GHashTable`) strongly indicate interaction with the macOS/iOS kernel and Objective-C runtime. The `#ifdef OBJC_ISA_MASK` hints at dealing with Objective-C object pointers and potentially handling different architectures or runtime versions.

* **JavaScript Section (Variable Declarations and `_()` function):**  I see imports like `require("./api")` and `Process`. The `_()` function is crucial. It fetches functions like `objc_getClassList`, `class_getSuperclass`, and `class_getInstanceSize` via `n()`, which is likely the imported API. It then creates a `CModule` instance using the C code. This is a key Frida mechanism for running native code within the JavaScript environment. The `choose` function within the returned object is obviously designed to find Objective-C objects based on certain criteria.

* **`module.exports` Section:** This is the standard way to export functionality in Node.js-style modules. The `get()` function ensures that the initialization logic (`_()`) is only run once (singleton pattern).

* **Browser Compatibility Section (setTimeout/clearTimeout):** This is boilerplate code for making `setTimeout` and `clearTimeout` work in a browser-like environment, which is relevant because Frida often operates within injected processes.

* **`setImmediate`/`clearImmediate` Section:** Another set of polyfills for asynchronous operations.

* **Final Frida Initialization:**  `Frida._objc = require("frida-objc-bridge");` This connects the module to the broader Frida Objective-C bridging infrastructure.

**3. Identifying Key Functions and Their Purpose:**

* **`collect_classes`:**  Collects all loaded Objective-C classes.
* **`collect_matches_in_ranges`:**  Scans memory ranges looking for potential Objective-C objects of specific classes. The size check (`range->size >= instance_size`) is vital.
* **`read_local_memory`:**  In this specific snippet, it's a seemingly no-op function that simply returns the remote address as the local memory. This is a significant point that might be different in other Frida implementations or on other platforms. It suggests this code might be running within the target process's memory space already, or it relies on a lower-level mechanism to handle the memory mapping.
* **`_()` (JavaScript):** Initializes the native Objective-C runtime interaction.
* **`choose` (JavaScript):** The primary function to find instances of Objective-C classes.

**4. Connecting to Core Concepts:**

* **Dynamic Instrumentation:**  The code is explicitly designed for this purpose. It inspects the runtime state of a running process without needing to recompile it.
* **Objective-C Runtime:**  The code heavily relies on understanding the structure of Objective-C objects (isa pointer, instance size).
* **Memory Management:**  Functions like `malloc_get_all_zones` and the memory range scanning are directly related to memory management within the target process.
* **Cross-Platform Considerations:** The `#ifdef OBJC_ISA_MASK` highlights the need to adapt to different architectures.
* **Inter-Process Communication (Implicit):** While not explicitly shown in *this* snippet, the broader Frida framework handles the communication between the Frida agent (running inside the target) and the Frida client (controlling the instrumentation).

**5. Addressing Specific Prompt Points:**

* **Binary/Low-Level:** The C code is the prime example. Accessing memory addresses, dealing with pointers, interacting with kernel data structures (`task_t`, `vm_range_t`).
* **Linux Kernel:**  While the code itself is macOS/iOS specific (due to `task_t`, `mach_task_self_`), the *concept* of scanning process memory is applicable to Linux. Frida on Linux would use different kernel APIs (e.g., `/proc/<pid>/mem`).
* **lldb/Python Scripting:**  This requires thinking about how to replicate the functionality *without* Frida. Reading process memory using `memory read`, inspecting memory at specific addresses, and potentially iterating through memory regions based on OS-specific information. Python scripting could automate this.
* **Logic and Assumptions:** The core logic is finding memory ranges that *look like* instances of a given class based on their isa pointer and size. The assumption is that this is a reliable way to identify objects.
* **User Errors:**  Typos in class names, trying to find classes that aren't loaded, or misinterpreting the results (e.g., assuming a memory region is a valid object when it's not).
* **User Operations:**  The user would typically use Frida's JavaScript API to call functions that eventually lead to this code being executed, such as `ObjC.choose(ClassName, ...)`.

**6. Structuring the Output:**

I'd organize the answer by:

* **Overall Function:** A high-level summary.
* **Detailed Functionality:** Breaking down the C and JavaScript parts.
* **Binary/Kernel Examples:**  Pointing to specific C code lines.
* **lldb/Python Examples:** Providing concrete examples.
* **Assumptions and Logic:** Explaining the underlying principles.
* **User Errors:**  Illustrating common mistakes.
* **User Journey:** Describing how a user would interact with Frida to trigger this code.
* **Summary (Part 3):**  Reiterating the core purpose concisely.

**7. Refinement and Clarity:**

Throughout the process, I'd focus on using precise language and avoiding jargon where possible. I'd provide clear examples and explanations to make the technical details understandable. For instance, instead of just saying "it reads memory," I'd specify "it reads the isa pointer at the beginning of a potential object."

This step-by-step thought process allows me to dissect the code, understand its purpose within the Frida ecosystem, and effectively address all aspects of the prompt.这是对 frida Dynamic instrumentation tool 的源代码文件 `frida/build/subprojects/frida-gum/bindings/gumjs/runtime.bundle.p/out-qjs/objc.js` 的功能归纳总结，作为第 3 部分，它主要负责提供在目标进程中查找 Objective-C 对象的机制。

**整体功能归纳:**

这个文件的核心功能是**动态地在目标进程的内存中查找指定 Objective-C 类的实例对象**。 它利用了 Objective-C 运行时的特性，通过扫描内存区域，检查潜在对象的结构（isa 指针和实例大小）来确定是否为目标类的实例。

**功能拆解与细节:**

1. **C 代码部分 (`ee (classes);` 到 `KERN_SUCCESS;`):**
   - **`collect_classes(task_t task, void * user_data)`:**  此函数（在代码片段中被注释掉，但根据上下文推断存在）负责收集目标进程中所有已加载的 Objective-C 类的信息。它可能使用 Mach 内核 API 来获取已加载的镜像和符号信息，并解析 Objective-C 的类结构。
   - **`collect_matches_in_ranges(task_t task, void * user_data, unsigned type, vm_range_t * ranges, unsigned count)`:** 这是核心查找函数。
     - 它接收一个任务 ( `task_t`，代表目标进程)，用户数据 (`user_data`)，内存区域类型 (`unsigned type`)，以及一组内存区域 (`vm_range_t * ranges`)。
     - 遍历给定的内存区域。
     - 对于每个内存区域，它将区域的起始地址 (`range->address`) 转换为一个潜在的 Objective-C 对象指针 (`candidate`)。
     - **二进制底层交互:** 它直接读取该地址指向的内存内容，假设前几个字节是 isa 指针。
     - **Objective-C 运行时交互:**  它使用 `g_hash_table_lookup` 查找与该 isa 指针对应的类信息（存储在 `ctx->classes` 中），并获取该类的实例大小 (`instance_size`)。
     - **匹配判断:** 如果找到了对应的类信息并且当前内存区域的大小 (`range->size`) 大于等于该类的实例大小，则认为找到了该类的实例，并将其地址添加到匹配结果数组 (`ctx->matches`) 中。
     - **`#ifdef OBJC_ISA_MASK`:** 这段代码处理 isa 指针的掩码。在某些 Objective-C 运行时版本或架构中，isa 指针可能包含额外的元数据，需要通过掩码操作提取出真正的类指针。
   - **`read_local_memory(task_t remote_task, vm_address_t remote_address, vm_size_t size, void ** local_memory)`:**  此函数在当前的代码片段中非常简单，直接将远程地址赋值给本地内存指针。这可能是在特定上下文中优化过的实现，假设 Frida 已经在目标进程的地址空间内运行，可以直接访问内存。在更复杂的场景下，它可能需要使用 Mach API (例如 `vm_read`) 从目标进程读取内存。

2. **JavaScript 代码部分 (`{getApi: n} = require("./api")`, `let t = null;` 到 `module.exports = { get: () => (null === t && (t = _()), t) };`):**
   - **依赖引入:**  引入了 `./api` 模块 (很可能包含了与 Objective-C 运行时交互的底层 API 接口) 和 `Process` 模块 (Frida 提供的进程信息接口)。
   - **单例模式:** 使用 `t` 变量和 `get()` 函数实现了单例模式，确保 `_()` 函数只被执行一次。
   - **`_()` 函数:**
     - **获取 API 函数:** 调用 `n()` (即 `getApi`) 获取与 Objective-C 运行时交互的关键函数，如 `objc_getClassList` (获取类列表), `class_getSuperclass` (获取父类), `class_getInstanceSize` (获取实例大小)。
     - **内存分配:** 使用 `Memory.alloc(4)` 分配一块内存，并写入 `mach_task_self_` 的值。 `mach_task_self_` 是一个 Mach 内核函数，返回当前任务的端口，这里很可能是作为参数传递给 C 代码，用于标识目标进程。
     - **CModule 创建:** 使用 `CModule` 创建一个可以调用 C 代码的模块。将 JavaScript 中获取的 Objective-C API 函数和 `malloc_get_all_zones` (用于获取所有内存区域) 以及 `selfTask` (目标进程的 task 端口) 传递给 C 代码。
     - **NativeFunction 创建:** 使用 `NativeFunction` 创建可以直接调用 C 代码中 `choose` 和 `destroy` 函数的 JavaScript 函数。
   - **`choose(e, n)` 函数:**
     - **参数传递:** 接收一个表示要查找的 Objective-C 类的指针 (`e`) 和一个布尔值 (`n`)，该布尔值可能指示是否包含父类的实例。
     - **调用 C 代码:** 调用 C 代码中的 `choose` 函数，并将类指针、布尔值以及用于接收匹配结果数量的内存地址 (`_`) 传递给它。
     - **结果处理:**  从 `_` 读取匹配结果的数量，然后遍历结果指针数组，将每个匹配到的对象地址读取出来并添加到 JavaScript 的数组 `t` 中。
     - **释放内存:** 最后调用 C 代码中的 `destroy` 函数释放 C 代码中分配的内存。

**与二进制底层、Linux 内核的关联 (尽管此代码主要针对 macOS/iOS):**

- **二进制底层:** 代码直接操作内存地址和指针 (`gconstpointer`, `vm_address_t`)，读取内存内容 (`*(gconstpointer *) candidate`)，这都是典型的二进制底层操作。
- **Linux 内核 (类比):** 虽然代码中使用的是 macOS/iOS 的 Mach 内核 API (`task_t`, `vm_range_t`, `mach_task_self_`), 但在 Linux 上实现类似功能需要使用 Linux 提供的内核接口，例如：
    - **进程表示:**  使用进程 ID (PID) 来标识目标进程。
    - **内存区域获取:**  读取 `/proc/[pid]/maps` 文件来获取目标进程的内存映射信息。
    - **内存读取:** 使用 `ptrace` 系统调用或者 `/proc/[pid]/mem` 文件来读取目标进程的内存。
    - **对象结构:** 需要了解 Linux 上 Objective-C 运行时的对象内存布局。

**用 lldb 指令或者 lldb python 脚本复刻调试功能的示例:**

假设我们要查找 `NSString` 类的实例对象，并且我们已经找到了 `NSString` 类的地址（可以通过符号信息或者其他方式获取，这里假设为 `0x12345678`）。

**lldb 指令示例:**

```lldb
# 假设目标进程的进程 ID 是 123
process attach 123

# 获取目标进程的所有内存映射
memory read --size 4 `(void*)0x$(kern.task.all_image_info_addr)`

# (需要根据实际情况解析内存映射，找到可能包含 Objective-C 对象的区域)

# 假设我们找到了一个可疑的内存地址，例如 0x700000000000
memory read --size 8 0x700000000000  # 读取 isa 指针 (假设 64 位)

# 假设读取到的 isa 指针值为 0x00000001000080a0，我们需要确认这个 isa 指针是否指向 NSString 的类信息

# (可能需要其他方式来验证 isa 指针)

# 如果我们确认了 isa 指针，并且想查看该地址后续的内存，看看是否符合 NSString 的实例大小
# 假设 NSString 的实例大小是 32 字节
memory read --size 32 0x700000000000
```

**lldb Python 脚本示例:**

```python
import lldb

def find_nsstring_instances(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()

    # 假设 NSString 类的地址已知
    nsstring_class_address = 0x12345678

    # 遍历目标进程的内存区域 (简化版本，实际需要更完善的内存映射获取逻辑)
    # 这里假设我们知道一个可能包含对象的区域范围
    start_address = 0x700000000000
    end_address =   0x700000010000

    nsstring_size = 32 # 假设 NSString 的实例大小

    for address in range(start_address, end_address, 8): # 假设 64 位，步长为指针大小
        error = lldb.SBError()
        isa_ptr = process.ReadPointerFromMemory(address, error)
        if error.Success():
            # 简化的匹配逻辑，实际需要更严谨的 isa 指针验证
            if isa_ptr == nsstring_class_address:
                print(f"潜在的 NSString 实例地址: {hex(address)}")
                # 可以进一步读取内存验证大小等信息
                data = process.ReadMemory(address, nsstring_size, error)
                if error.Success():
                    print(f"内存内容: {data.hex()}")

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f objc.find_nsstring_instances find_nsstring')

```

**假设输入与输出 (针对 `choose` 函数):**

假设输入：
- `e`: 指向 `NSString` 类的指针地址 (例如: `0x10abcdef00`)
- `n`: `false` (不包含父类实例)

可能的输出：
- 一个包含 `NSString` 类所有实例对象地址的 JavaScript 数组，例如： `[Ptr("0x7ffee1234560"), Ptr("0x7ffee9876540")]`

**用户或编程常见的使用错误:**

1. **错误的类名或类指针:** 用户可能输入错误的 Objective-C 类名，导致无法找到对应的类信息，`choose` 函数将返回空数组。
2. **目标类未加载:** 如果用户尝试查找的类尚未被目标进程加载，`objc_getClassList` 将不会返回该类的信息，`choose` 函数同样会失败。
3. **内存扫描范围不足:** 如果 Frida 的内存扫描范围设置得太小，可能无法覆盖到目标对象所在的内存区域。
4. **误解结果:** 用户可能会将一些看起来像对象但实际上不是有效 `NSString` 实例的内存区域误认为结果。
5. **权限问题:**  Frida 需要足够的权限才能访问目标进程的内存。如果权限不足，可能导致内存读取失败。

**用户操作如何一步步到达这里作为调试线索:**

1. **编写 Frida 脚本:** 用户编写一个 Frida 脚本，希望找到目标 App 中的 `NSString` 对象。
   ```javascript
   // Frida 脚本
   Java.perform(function() {
       var NSString = ObjC.classes.NSString;
       if (NSString) {
           var instances = ObjC.choose(NSString);
           console.log("找到 NSString 实例:", instances);
       } else {
           console.log("NSString 类未找到");
       }
   });
   ```
2. **运行 Frida 脚本:** 用户使用 Frida CLI 工具将脚本注入到目标 App 进程中：
   ```bash
   frida -U -f com.example.myapp -l your_script.js
   ```
3. **Frida 工作原理:**
   - Frida 客户端 (CLI 工具) 连接到目标设备上的 Frida 服务。
   - Frida 服务将 Frida agent (包含 GumJS 运行时) 注入到目标 App 进程中。
   - 用户的 JavaScript 脚本在 GumJS 运行时环境中执行。
   - 当脚本执行到 `ObjC.choose(NSString)` 时，Frida 的 Objective-C bridge 会调用 `frida-objc-bridge` 模块 (对应于这里的 `objc.js`)。
   - `objc.js` 中的 `get()` 方法被调用，初始化查找机制。
   - `choose()` 方法被调用，它会调用底层的 C 代码来扫描内存，查找 `NSString` 的实例。

**总结 (第 3 部分功能归纳):**

作为 Frida Objective-C bridge 的一部分， `objc.js` 文件 (尤其是这里分析的代码片段) 的核心功能是**在目标进程的内存中动态查找指定 Objective-C 类的实例对象**。 它通过利用 Objective-C 运行时的特性，扫描内存区域，检查潜在对象的 isa 指针和实例大小来实现这一目标，为 Frida 提供了强大的动态分析和调试能力。

### 提示词
```
这是目录为frida/build/subprojects/frida-gum/bindings/gumjs/runtime.bundle.p/out-qjs/objc.js的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```javascript
ee (classes);\n}\n\nstatic void\ncollect_matches_in_ranges (task_t task,\n                           void * user_data,\n                           unsigned type,\n                           vm_range_t * ranges,\n                           unsigned count)\n{\n  ChooseContext * ctx = user_data;\n  GHashTable * classes = ctx->classes;\n  unsigned i;\n\n  for (i = 0; i != count; i++)\n  {\n    const vm_range_t * range = &ranges[i];\n    gconstpointer candidate = GSIZE_TO_POINTER (range->address);\n    gconstpointer isa;\n    guint instance_size;\n\n    isa = *(gconstpointer *) candidate;\n#ifdef OBJC_ISA_MASK\n    isa = GSIZE_TO_POINTER (GPOINTER_TO_SIZE (isa) & OBJC_ISA_MASK);\n#endif\n\n    instance_size = GPOINTER_TO_UINT (g_hash_table_lookup (classes, isa));\n    if (instance_size != 0 && range->size >= instance_size)\n    {\n      g_array_append_val (ctx->matches, candidate);\n    }\n  }\n}\n\nstatic kern_return_t\nread_local_memory (task_t remote_task,\n                   vm_address_t remote_address,\n                   vm_size_t size,\n                   void ** local_memory)\n{\n  *local_memory = (void *) remote_address;\n\n  return KERN_SUCCESS;\n}\n", {getApi: n} = require("./api"), {pointerSize: s} = Process;

let t = null;

function _() {
  const {objc_getClassList: t, class_getSuperclass: _, class_getInstanceSize: a} = n(), o = Memory.alloc(4);
  o.writeU32(Module.getExportByName(null, "mach_task_self_").readU32());
  const r = new CModule(e, {
    objc_getClassList: t,
    class_getSuperclass: _,
    class_getInstanceSize: a,
    malloc_get_all_zones: Module.getExportByName("/usr/lib/system/libsystem_malloc.dylib", "malloc_get_all_zones"),
    selfTask: o
  }), c = new NativeFunction(r.choose, "pointer", [ "pointer", "bool", "pointer" ]), l = new NativeFunction(r.destroy, "void", [ "pointer" ]);
  return {
    handle: r,
    choose(e, n) {
      const t = [], _ = Memory.alloc(4), a = c(e, n ? 1 : 0, _);
      try {
        const e = _.readU32();
        for (let n = 0; n !== e; n++) t.push(a.add(n * s).readPointer());
      } finally {
        l(a);
      }
      return t;
    }
  };
}

module.exports = {
  get: () => (null === t && (t = _()), t)
};

},{"./api":2}],4:[function(require,module,exports){
var t, e, n = module.exports = {};

function r() {
  throw new Error("setTimeout has not been defined");
}

function o() {
  throw new Error("clearTimeout has not been defined");
}

function i(e) {
  if (t === setTimeout) return setTimeout(e, 0);
  if ((t === r || !t) && setTimeout) return t = setTimeout, setTimeout(e, 0);
  try {
    return t(e, 0);
  } catch (n) {
    try {
      return t.call(null, e, 0);
    } catch (n) {
      return t.call(this, e, 0);
    }
  }
}

function u(t) {
  if (e === clearTimeout) return clearTimeout(t);
  if ((e === o || !e) && clearTimeout) return e = clearTimeout, clearTimeout(t);
  try {
    return e(t);
  } catch (n) {
    try {
      return e.call(null, t);
    } catch (n) {
      return e.call(this, t);
    }
  }
}

!function() {
  try {
    t = "function" == typeof setTimeout ? setTimeout : r;
  } catch (e) {
    t = r;
  }
  try {
    e = "function" == typeof clearTimeout ? clearTimeout : o;
  } catch (t) {
    e = o;
  }
}();

var c, s = [], l = !1, a = -1;

function f() {
  l && c && (l = !1, c.length ? s = c.concat(s) : a = -1, s.length && h());
}

function h() {
  if (!l) {
    var t = i(f);
    l = !0;
    for (var e = s.length; e; ) {
      for (c = s, s = []; ++a < e; ) c && c[a].run();
      a = -1, e = s.length;
    }
    c = null, l = !1, u(t);
  }
}

function m(t, e) {
  this.fun = t, this.array = e;
}

function p() {}

n.nextTick = function(t) {
  var e = new Array(arguments.length - 1);
  if (arguments.length > 1) for (var n = 1; n < arguments.length; n++) e[n - 1] = arguments[n];
  s.push(new m(t, e)), 1 !== s.length || l || i(h);
}, m.prototype.run = function() {
  this.fun.apply(null, this.array);
}, n.title = "browser", n.browser = !0, n.env = {}, n.argv = [], n.version = "", 
n.versions = {}, n.on = p, n.addListener = p, n.once = p, n.off = p, n.removeListener = p, 
n.removeAllListeners = p, n.emit = p, n.prependListener = p, n.prependOnceListener = p, 
n.listeners = function(t) {
  return [];
}, n.binding = function(t) {
  throw new Error("process.binding is not supported");
}, n.cwd = function() {
  return "/";
}, n.chdir = function(t) {
  throw new Error("process.chdir is not supported");
}, n.umask = function() {
  return 0;
};

},{}],5:[function(require,module,exports){
(function (setImmediate,clearImmediate){(function (){
var e = require("process/browser.js").nextTick, t = Function.prototype.apply, o = Array.prototype.slice, i = {}, n = 0;

function r(e, t) {
  this._id = e, this._clearFn = t;
}

exports.setTimeout = function() {
  return new r(t.call(setTimeout, window, arguments), clearTimeout);
}, exports.setInterval = function() {
  return new r(t.call(setInterval, window, arguments), clearInterval);
}, exports.clearTimeout = exports.clearInterval = function(e) {
  e.close();
}, r.prototype.unref = r.prototype.ref = function() {}, r.prototype.close = function() {
  this._clearFn.call(window, this._id);
}, exports.enroll = function(e, t) {
  clearTimeout(e._idleTimeoutId), e._idleTimeout = t;
}, exports.unenroll = function(e) {
  clearTimeout(e._idleTimeoutId), e._idleTimeout = -1;
}, exports._unrefActive = exports.active = function(e) {
  clearTimeout(e._idleTimeoutId);
  var t = e._idleTimeout;
  t >= 0 && (e._idleTimeoutId = setTimeout((function() {
    e._onTimeout && e._onTimeout();
  }), t));
}, exports.setImmediate = "function" == typeof setImmediate ? setImmediate : function(t) {
  var r = n++, l = !(arguments.length < 2) && o.call(arguments, 1);
  return i[r] = !0, e((function() {
    i[r] && (l ? t.apply(null, l) : t.call(null), exports.clearImmediate(r));
  })), r;
}, exports.clearImmediate = "function" == typeof clearImmediate ? clearImmediate : function(e) {
  delete i[e];
};

}).call(this)}).call(this,require("timers").setImmediate,require("timers").clearImmediate)

},{"process/browser.js":4,"timers":5}],6:[function(require,module,exports){
Frida._objc = require("frida-objc-bridge");

},{"frida-objc-bridge":1}]},{},[6])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJub2RlX21vZHVsZXMvZnJpZGEtb2JqYy1icmlkZ2UvaW5kZXguanMiLCJub2RlX21vZHVsZXMvZnJpZGEtb2JqYy1icmlkZ2UvbGliL2FwaS5qcyIsIm5vZGVfbW9kdWxlcy9mcmlkYS1vYmpjLWJyaWRnZS9saWIvZmFzdHBhdGhzLmpzIiwibm9kZV9tb2R1bGVzL3Byb2Nlc3MvYnJvd3Nlci5qcyIsIm5vZGVfbW9kdWxlcy90aW1lcnMtYnJvd3NlcmlmeS9tYWluLmpzIiwicnVudGltZS9vYmpjLmpzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBOztBQ0FBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7OztBQ3ZwREE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDOUhBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNoQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDaEdBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOzs7QUNqQ0E7QUFDQTtBQUNBIiwiZmlsZSI6ImdlbmVyYXRlZC5qcyIsInNvdXJjZVJvb3QiOiIifQ==
```