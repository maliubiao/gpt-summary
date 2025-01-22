Response:
My thought process for analyzing the `swift.js` code and generating the detailed explanation involved the following steps:

1. **Initial Code Scan and Keyword Identification:** I first scanned the code for keywords and patterns that suggest functionality. I looked for:
    * `exports`: Indicates what parts of the code are intended for external use.
    * `class`: Defines blueprints for objects, hinting at data structures and behaviors.
    * `function`:  Basic building blocks of code, suggesting actions and computations.
    * `WeakMap`:  Implies managing object associations without preventing garbage collection, often used for private data.
    * `NativeFunction`:  A clear indicator of interfacing with native (non-JavaScript) code.
    * `Memory.alloc`, `Memory.patchCode`:  Direct interaction with memory, pointing towards low-level operations.
    * `Process.pointerSize`:  Suggests awareness of system architecture (32-bit or 64-bit).
    * `Arm64Writer`:  Specifically targeting ARM64 architecture, likely for code manipulation.
    * `Interceptor.attach`: A Frida-specific function for hooking and observing function calls.
    * `readValue`, `readPointer`, `readCString`, `readInt`, etc.: Methods for reading different data types from memory.
    * Demangling related functions (`getDemangledSymbol`, `parseSwiftMethodSignature`):  Indicates working with Swift-specific constructs.
    * References to metadata (`TargetMetadata`, `TargetClassMetadata`, etc.):  Strongly suggests dealing with Swift's type system.
    * Protocol related terms (`Protocol`, `ProtocolComposition`): More Swift-specific concepts.

2. **Module and Class Identification:** I identified the main classes and their roles:
    * `S`: A simple queue implementation.
    * `A` (renamed to `SwiftcallNativeFunction`): The core of the native function wrapping, handling argument marshalling, native call execution, and return value handling.
    * `SwiftInterceptor`:  The mechanism for intercepting and observing Swift function calls.
    * Various classes in the latter part of the code (`Type`, `Class`, `Struct`, `Enum`, `Protocol`, `ProtocolComposition`, `RuntimeInstance`, `ValueInstance`, `StructValue`, `EnumValue`, `ObjectInstance`): These clearly represent Swift's type system within the Frida environment.
    * `Registry`, `SwiftModule`:  Structures for managing and organizing Swift types.

3. **Focusing on Key Functionality:**  I homed in on the most complex and important parts of the code, particularly the `SwiftcallNativeFunction` class and the `SwiftInterceptor`.

4. **Analyzing `SwiftcallNativeFunction`:**  I broke down its constructor and `call` method:
    * **Constructor:**  I noticed the use of `WeakMap` for private members. The logic involving `Memory.alloc`, `Memory.patchCode`, and `Arm64Writer` stood out as the core of the dynamic trampoline creation for calling native Swift functions. I analyzed the ARM64 writing code to understand how arguments and return values are handled.
    * **`call` method:** This method seems responsible for invoking the dynamically generated trampoline. The argument processing logic (handling arrays and `moveValueToBuffer`) was important.

5. **Analyzing `SwiftInterceptor`:** I focused on the `attach` method:
    * It uses Frida's `Interceptor.attach` to hook Swift functions.
    * It leverages the demangling and signature parsing functions to understand the function's arguments and return types.
    * It demonstrates how to handle both direct and indirect return values, as well as different argument passing mechanisms (direct vs. existential containers).

6. **Connecting to Underlying Concepts:**  I started linking the code's actions to lower-level concepts:
    * **Binary Level:** The `Arm64Writer` directly manipulates machine code. The handling of registers (`x15`, `x29`, `x30`, etc.) is architecture-specific. The trampoline creation itself is a binary-level technique.
    * **Linux Kernel (Indirectly):** While not directly interacting with the kernel in *this specific file*, Frida as a tool relies heavily on kernel-level features for process injection, code injection, and memory access. The `NativeFunction` abstraction hides some of this complexity.
    * **Swift Runtime:** The code extensively interacts with Swift's runtime metadata to understand type layouts, method signatures, and calling conventions.

7. **Inferring Use Cases and Potential Errors:**  Based on the functionality, I considered how developers would use this code and what mistakes they might make:
    * **Incorrect Type Information:**  Providing wrong argument types or return types when creating a `SwiftcallNativeFunction`.
    * **Memory Management:** Potential issues if `moveValueToBuffer` or the trampoline logic has errors.
    * **Understanding Swift Calling Conventions:** Developers need to understand how Swift passes arguments and returns values to use this correctly.

8. **Constructing GDB/Python Examples (Conceptual):** I thought about how to replicate the functionality using GDB or Frida's Python API. Since the core is dynamic code generation, direct GDB replication would be very involved. Frida's Python API would be more suitable, allowing direct memory manipulation and function interception.

9. **Structuring the Explanation:**  I organized my findings into logical sections, addressing each part of the prompt: functionality, low-level details, debugging examples, assumptions, common errors, and user journey. I used clear headings and bullet points for readability.

10. **Refinement and Iteration:** I reviewed my initial analysis and added more detail and clarity where needed. For instance, I elaborated on the purpose of the trampoline and the different return value scenarios. I also made sure to explain the significance of concepts like "existential containers."

This iterative process of scanning, identifying key components, analyzing functionality, connecting to lower-level concepts, and considering usage patterns allowed me to build a comprehensive explanation of the `swift.js` code. The focus was on understanding *what* the code does and *why* it does it that way, especially in the context of dynamic instrumentation and interacting with native Swift code.这是 frida 动态插桩工具的源代码文件 `swift.js` 的第二部分，主要功能是提供在 JavaScript 中调用原生 Swift 函数的能力，并提供了一些用于处理 Swift 类型和内存的辅助工具。

**归纳一下它的功能：**

1. **创建可调用的原生 Swift 函数 (`SwiftcallNativeFunction` 类):**
   - 允许 JavaScript 代码像调用普通 JavaScript 函数一样调用原生的 Swift 函数。
   - 自动处理 Swift 函数的参数和返回值，包括基本类型、结构体、枚举以及更复杂的类型如协议类型。
   - 内部通过动态生成机器码（trampoline）来实现跨语言调用。

2. **Swift 函数拦截 (`SwiftInterceptor`):**
   - 提供了 `attach` 方法，用于拦截 (hook) 原生的 Swift 函数调用。
   - 在函数调用前后执行自定义的 JavaScript 代码 (onEnter, onLeave)。
   - 可以访问和修改函数的参数和返回值。

3. **处理 Swift 类型 (`Type`, `Class`, `Struct`, `Enum`, `Protocol`, `ProtocolComposition` 等类):**
   - 对 Swift 的类、结构体、枚举和协议等类型进行了抽象和表示。
   - 提供了获取类型信息（如字段、方法、一致性）的能力。
   - 允许在 JavaScript 中创建和操作 Swift 类型的实例。

4. **处理 Swift 内存 (`RuntimeInstance`, `ValueInstance`, `StructValue`, `EnumValue`, `ObjectInstance`):**
   - 提供了对 Swift 对象和值类型实例的抽象。
   - 允许读取和写入 Swift 实例的内存。
   - 针对不同的 Swift 类型（类、结构体、枚举）提供了特定的处理方式。

5. **辅助函数:**
   - `makeSwiftNativeFunction`:  创建原生 Swift 函数的 JavaScript 可调用包装器。
   - `shouldPassIndirectly`:  判断 Swift 类型是否应该通过间接方式（指针）传递。
   - `readValue`:  从 `NativePointer` 读取指定类型的数值。

**与二进制底层、Linux 内核相关的举例说明：**

* **二进制底层 (动态生成机器码):**
    - `SwiftcallNativeFunction` 类的构造函数中使用了 `Memory.patchCode` 和 `Arm64Writer`。
    - `Arm64Writer` 用于生成 ARM64 架构的机器码指令，创建一个小的“trampoline”代码段。
    - 这个 trampoline 的作用是设置正确的寄存器状态（例如，加载函数地址、参数地址），然后跳转到实际的 Swift 函数执行。
    - 例如，`r.putLdrRegAddress("x14", e)` 将 Swift 函数的地址加载到 `x14` 寄存器。`r.putBlrRegNoAuth("x14")` 执行无身份验证的分支链接到 `x14` 寄存器指向的地址，即调用 Swift 函数。
    - 代码中还处理了返回值的情况，根据返回值的大小和类型，可能会将返回值存储到指定的内存地址，并通过寄存器传递。

* **Linux 内核 (间接相关):**
    - 虽然这段代码本身没有直接的 Linux 内核系统调用，但 Frida 作为工具的底层机制涉及到进程注入、代码注入和内存管理，这些都依赖于 Linux 内核提供的功能。
    - 例如，`Interceptor.attach` 的实现需要操作系统级别的机制来修改目标进程的内存，以便在函数执行前后插入我们自定义的代码。
    - `Memory.alloc` 等内存操作最终也会委托给操作系统内核的内存管理模块。

**用 gdb 指令或 gdb python 脚本复刻调试功能的示例：**

假设我们要复刻 `SwiftInterceptor.attach` 的部分功能，即在 Swift 函数入口处设置断点并查看参数。

**使用 GDB 指令：**

1. **找到 Swift 函数的地址:**  你需要先找到你要 hook 的 Swift 函数的地址。可以使用 `frida` 的 `Module.getExportByName()` 或者分析符号表来获取。 假设函数名为 `_TFC4Test4MyClass4myFuncfT_T_`，地址为 `0x12345678`.

2. **设置断点:**
   ```gdb
   break *0x12345678
   ```

3. **查看寄存器 (参数):** Swift 的函数参数通常会通过寄存器传递（尤其是在 ARM64 架构上）。你需要了解 Swift 的调用约定来确定参数存储在哪些寄存器中。通常，前几个参数会放在 `x0`, `x1`, `x2` 等寄存器中。
   ```gdb
   run
   info registers x0 x1 x2
   ```

4. **查看内存 (如果参数是指针):** 如果参数是通过指针传递的，你需要读取指针指向的内存。
   ```gdb
   x/gx $x0  // 假设第一个参数的指针在 x0 中
   ```

**使用 GDB Python 脚本：**

```python
import gdb

class SwiftEnterBreakpoint(gdb.Breakpoint):
    def __init__(self, spec):
        super().__init__(spec)

    def stop(self):
        print("Hit Swift function at {}".format(self.location))
        # 假设前三个参数在 x0, x1, x2 中
        x0 = gdb.parse_and_eval("$x0")
        x1 = gdb.parse_and_eval("$x1")
        x2 = gdb.parse_and_eval("$x2")
        print("Register x0: {}".format(x0))
        print("Register x1: {}".format(x1))
        print("Register x2: {}".format(x2))

        # 如果参数是指针，可以读取内存
        try:
            if x0 != 0:
                memory = gdb.inferiors()[0].read_memory(x0, 8) # 读取 8 字节
                print("Memory at x0: {}".format(memory))
        except:
            pass
        return False # 继续执行

SwiftEnterBreakpoint("*0x12345678") # 替换为实际地址
```

将这段 Python 代码保存为 `.py` 文件，然后在 GDB 中使用 `source your_script.py` 加载，然后 `run` 就可以在 Swift 函数入口处中断并打印寄存器值。

**逻辑推理的假设输入与输出 (针对 `shouldPassIndirectly` 函数):**

* **假设输入:**  一个 `TargetMetadata` 对象，代表一个 Swift 类型。
* **逻辑:** `shouldPassIndirectly` 函数检查类型的 `getValueWitnesses().flags.isBitwiseTakable` 属性。
* **假设输出:**
    * 如果 `isBitwiseTakable` 为 `true`，则输出 `false` (表示可以直接传递)。
    * 如果 `isBitwiseTakable` 为 `false`，则输出 `true` (表示应该间接传递)。

**用户或编程常见的使用错误举例说明：**

1. **`SwiftcallNativeFunction` 参数类型不匹配:**
   - **错误:**  在 JavaScript 中调用 `SwiftcallNativeFunction` 时，传递的参数类型与 Swift 函数期望的类型不一致。
   - **例子:** Swift 函数期望一个 `Int`，但在 JavaScript 中传递了一个字符串。
   - **后果:**  可能导致类型转换错误、内存访问错误，甚至程序崩溃。

2. **尝试 hook 不存在的 Swift 函数:**
   - **错误:**  使用 `SwiftInterceptor.attach` 尝试 hook 一个不存在的 Swift 函数，或者使用了错误的函数签名。
   - **后果:**  `Interceptor.attach` 可能会抛出异常，或者 hook 失败，你的 `onEnter` 和 `onLeave` 回调不会被执行。

3. **在 `onEnter` 或 `onLeave` 中错误地修改参数或返回值:**
   - **错误:**  在 `SwiftInterceptor` 的回调函数中，不理解 Swift 的内存布局或调用约定，错误地修改了参数的内存，或者返回了错误类型的值。
   - **后果:**  可能导致 Swift 函数执行异常，或者返回意想不到的结果，破坏程序状态。

4. **忘记处理协议类型 (`ProtocolComposition`):**
   - **错误:**  当 Swift 函数的参数或返回值是协议类型时，没有正确使用 `ProtocolComposition` 或相关的方法来处理 existential container。
   - **后果:**  可能无法正确读取或传递协议类型的值。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户想要在 Frida 中 hook 一个 Swift 函数:** 用户首先会编写 Frida 脚本，使用 `SwiftInterceptor.attach` 方法，并提供目标 Swift 函数的名称或地址以及 `onEnter` 和/或 `onLeave` 回调函数。

2. **Frida 解析 Swift 函数签名:** 当 `SwiftInterceptor.attach` 被调用时，Frida 会尝试解析给定的 Swift 函数的签名 (demangle)，并确定其参数和返回值的类型。这涉及到调用 `getDemangledSymbol` 和 `parseSwiftMethodSignature` 等函数。

3. **Frida 创建 Interceptor:** Frida 内部会创建一个 `Interceptor` 对象，并将其附加到目标 Swift 函数的入口点。

4. **目标 Swift 函数被调用:** 当目标 Swift 函数在程序执行过程中被调用时，`Interceptor` 会捕获到这次调用，并执行 `SwiftInterceptor.attach` 中指定的 `onEnter` 回调。

5. **`onEnter` 执行参数处理:** 在 `onEnter` 回调中，用户可以访问 `this.context` 来获取函数的参数值。`swift.js` 中的代码会根据参数的类型（例如，是否是协议类型）进行不同的处理。

6. **目标 Swift 函数执行:** `onEnter` 执行完毕后，目标 Swift 函数会继续执行。

7. **`onLeave` 执行返回值处理:** 当目标 Swift 函数执行完毕并返回时，`Interceptor` 会执行 `SwiftInterceptor.attach` 中指定的 `onLeave` 回调。用户可以在 `onLeave` 中访问和修改返回值。

8. **Frida 返回结果给用户脚本:**  `onLeave` 执行完毕后，Frida 将控制权返回给用户的 Frida 脚本。

**作为调试线索，当用户遇到问题时，可以按照以下步骤进行排查：**

1. **检查函数名称或地址是否正确:**  确保传递给 `SwiftInterceptor.attach` 的函数名称或地址是正确的，可以使用 Frida 的 `Module.getExportByName()` 来验证。

2. **检查 `onEnter` 和 `onLeave` 回调是否被执行:**  在回调函数中添加 `console.log` 语句来确认它们是否被触发。

3. **打印参数和返回值的类型和值:**  在回调函数中打印 `this.context` 中的寄存器值，以及尝试读取参数内存的值，来确认参数是否正确传递。

4. **查看 Frida 抛出的错误信息:**  Frida 可能会抛出异常，提供关于 hook 失败或类型错误的线索。

5. **使用 Frida 的 `rpc` 功能进行更细粒度的调试:**  可以将一些辅助函数或变量暴露给 Frida 客户端，以便在运行时检查状态。

总而言之，这段代码是 Frida 动态插桩工具中用于桥接 JavaScript 和原生 Swift 代码的关键部分，它提供了强大的功能来分析、监控和修改 Swift 程序的运行时行为。理解其内部机制对于进行高级的 Frida 开发至关重要。

Prompt: 
```
这是目录为frida/build/subprojects/frida-gum/bindings/gumjs/runtime.bundle.p/out-qjs/swift.js的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用gdb指令或者gdb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第2部分，共3部分，请归纳一下它的功能

"""
TypeLayout().stride);
}

function x(e) {
  return !e.getValueWitnesses().flags.isBitwiseTakable;
}

exports.makeSwiftNativeFunction = m, exports.shouldPassIndirectly = x;

class S {
  constructor() {
    e.set(this, {}), t.set(this, 0);
  }
  get length() {
    return Object.keys(u(this, e, "f")).length - u(this, t, "f");
  }
  enqueue(t) {
    const r = Object.keys(u(this, e, "f")).length;
    u(this, e, "f")[r] = t;
  }
  dequeue() {
    var r, s;
    if (0 === Object.keys(u(this, e, "f")).length) return;
    return u(this, e, "f")[(c(this, t, (s = u(this, t, "f"), r = s++, s), "f"), r)];
  }
  resetCursor() {
    c(this, t, 0, "f");
  }
  toJSON() {
    return u(this, e, "f");
  }
}

e = new WeakMap, t = new WeakMap;

class A {
  constructor(e, t, l, f, d) {
    let h;
    r.set(this, void 0), s.set(this, void 0), i.set(this, void 0), n.set(this, void 0), 
    a.set(this, void 0), o.set(this, void 0), this.wrapper = (...e) => {
      u(this, r, "f").resetCursor(), e = e.map((e => {
        if (Array.isArray(e) && e.length > 4) {
          const t = u(this, r, "f").dequeue();
          return (0, g.moveValueToBuffer)(e, t), t;
        }
        return e;
      })).flat();
      if (u(this, o, "f")(...e), 0 === u(this, i, "f")) return;
      const t = [];
      if (!Array.isArray(u(this, s, "f"))) return u(this, n, "f").readValue(u(this, s, "f"));
      for (let e = 0, r = 0; e < u(this, i, "f"); e += 8, r++) {
        const i = u(this, s, "f")[r];
        t.push(u(this, n, "f").add(e).readValue(i));
      }
      return t;
    }, c(this, r, new S, "f"), l = l.map((e => {
      if (Array.isArray(e) && e.length > 4) {
        const t = Memory.alloc(Process.pointerSize * e.length);
        return u(this, r, "f").enqueue(t), "pointer";
      }
      return e;
    })).flat(), c(this, s, t, "f"), Array.isArray(t) ? (c(this, i, Process.pointerSize * t.length, "f"), 
    c(this, n, Memory.alloc(u(this, i, "f")), "f"), t.length > 4 && (h = u(this, n, "f"))) : "void" === t ? c(this, i, 0, "f") : (c(this, i, Process.pointerSize, "f"), 
    c(this, n, Memory.alloc(u(this, i, "f")), "f")), c(this, a, Memory.alloc(2 * Process.pointerSize), "f");
    const p = w.allocateTrampoline(76);
    Memory.patchCode(p, 76, (t => {
      const r = new Arm64Writer(t, {
        pc: p
      });
      if (r.putLdrRegAddress("x15", u(this, a, "f")), r.putStpRegRegRegOffset("x29", "x30", "x15", 0, "post-adjust"), 
      void 0 !== f && r.putLdrRegAddress("x20", f), void 0 !== d && r.putLdrRegAddress("x21", d), 
      void 0 !== h && r.putLdrRegAddress("x8", h), r.putLdrRegAddress("x14", e), r.putBlrRegNoAuth("x14"), 
      void 0 === h && u(this, i, "f") > 0) {
        r.putLdrRegAddress("x15", u(this, n, "f"));
        let e = 0, t = 0;
        for (;t < u(this, i, "f"); e++, t += 8) {
          const s = `x${e}`;
          r.putStrRegRegOffset(s, "x15", t);
        }
      }
      r.putLdrRegAddress("x15", u(this, a, "f")), r.putLdpRegRegRegOffset("x29", "x30", "x15", 0, "post-adjust"), 
      r.putRet(), r.flush();
    })), c(this, o, new NativeFunction(p, "pointer", l), "f");
  }
  call(...e) {
    return this.wrapper(e);
  }
}

exports.SwiftcallNativeFunction = A, r = new WeakMap, s = new WeakMap, i = new WeakMap, 
n = new WeakMap, a = new WeakMap, o = new WeakMap, NativePointer.prototype.readValue = function(e) {
  switch (e) {
   case "pointer":
    return this.readPointer();

   case "string":
    return this.readCString();

   case "int":
    return this.readInt();

   case "uint":
    return this.readUInt();

   case "long":
    return this.readLong();

   case "ulong":
    return this.readULong();

   case "int8":
    return this.readS8();

   case "uint8":
    return this.readU8();

   case "int16":
    return this.readS16();

   case "uint16":
    return this.readU16();

   case "int32":
    return this.readS32();

   case "uint32":
    return this.readU32();

   case "int64":
    return this.readS64();

   case "uint64":
    return this.readU64();

   default:
    throw new Error(`Unimplemented type: ${e}`);
  }
};

},{"../abi/metadata":1,"../abi/metadatavalues":2,"../runtime/existentialcontainer":14,"./buffer":6,"./macho":9,"./types":12}],8:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: !0
}), exports.SwiftInterceptor = void 0;

const e = require("../abi/metadatavalues"), t = require("./buffer"), n = require("./callingconvention"), o = require("./macho"), r = require("./symbols"), s = require("./types");

var i;

function a(e) {
  return e.indexOf("&") > -1 || (0, o.findProtocolDescriptor)(e);
}

function c(e, t, n) {
  const o = [];
  for (let r = t; r != n; r++) o.push(e[r]);
  return o;
}

!function(i) {
  i.attach = function(i, u) {
    const l = (0, o.getDemangledSymbol)(i), d = (0, r.parseSwiftMethodSignature)(l);
    let f, p;
    return void 0 !== u.onLeave && (p = function(e) {
      const r = d.retTypeName;
      let i;
      if (a(r)) {
        const e = s.ProtocolComposition.fromSignature(r), o = e.sizeofExistentialContainer;
        let a;
        if (o <= n.MAX_LOADABLE_SIZE) {
          const e = (0, t.sizeInQWordsRounded)(o), n = [];
          for (let t = 0; t != e; t++) n.push(this.context[`x${t}`]);
          a = (0, t.makeBufferFromValue)(n);
        } else a = f;
        i = s.ValueInstance.fromExistentialContainer(a, e);
      } else {
        const r = (0, o.untypedMetadataFor)(d.retTypeName);
        if (r.isClassObject()) i = new s.ObjectInstance(e); else {
          if (r.getTypeLayout().stride <= n.MAX_LOADABLE_SIZE && !(0, n.shouldPassIndirectly)(r)) {
            const e = (0, t.sizeInQWordsRounded)(r.getTypeLayout().stride), n = [];
            for (let t = 0; t < e; t++) n.push(this.context[`x${t}`]);
            i = s.ValueInstance.fromRaw(n, r);
          } else i = s.ValueInstance.fromCopy(f, r);
        }
      }
      u.onLeave.bind(this)(i);
    }), Interceptor.attach(i, {
      onEnter: function(r) {
        if (f = this.context[n.INDRIECT_RETURN_REGISTER], void 0 !== u.onEnter) {
          const i = [];
          let l, f = 0;
          for (const u of d.argTypeNames) {
            if (a(u)) {
              const e = s.ProtocolComposition.fromSignature(u), o = e.sizeofExistentialContainer;
              let a;
              if (o <= n.MAX_LOADABLE_SIZE) {
                const e = (0, t.sizeInQWordsRounded)(o), n = c(r, f, f + e);
                a = (0, t.makeBufferFromValue)(n), f += e;
              } else a = r[f++];
              l = s.ValueInstance.fromExistentialContainer(a, e), i.push(l);
              continue;
            }
            const d = (0, o.untypedMetadataFor)(u);
            if (d.isClassObject()) l = new s.ObjectInstance(r[f++]); else {
              const n = (0, t.sizeInQWordsRounded)(d.getTypeLayout().stride), o = d.getKind(), i = c(r, f, f + n);
              if (o === e.MetadataKind.Struct) {
                const e = d;
                l = new s.StructValue(e, {
                  raw: i
                });
              } else {
                if (o !== e.MetadataKind.Enum) throw new Error("Unhandled metadata kind: " + o);
                {
                  const e = d;
                  l = new s.EnumValue(e, {
                    raw: i
                  });
                }
              }
              f += n;
            }
            i.push(l);
          }
          u.onEnter.bind(this)(i);
        }
      },
      onLeave: p
    });
  };
}(i = exports.SwiftInterceptor || (exports.SwiftInterceptor = {}));

},{"../abi/metadatavalues":2,"./buffer":6,"./callingconvention":7,"./macho":9,"./symbols":11,"./types":12}],9:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: !0
}), exports.getDemangledSymbol = exports.findDemangledSymbol = exports.getProtocolDescriptor = exports.findProtocolDescriptor = exports.getAllProtocolDescriptors = exports.getProtocolConformancesFor = exports.metadataFor = exports.untypedMetadataFor = exports.getAllFullTypeData = void 0;

const e = require("../abi/metadata"), t = require("../abi/metadatavalues"), o = require("./api"), r = require("../basic/relativepointer"), n = require("./symbols"), i = new ModuleMap, s = {}, c = {}, a = new Map;

if ("arm64" === Process.arch && "darwin" === Process.platform) {
  for (const e of i.values()) {
    for (const t of D(e)) c[t.getFullTypeName()] = {
      descriptor: t,
      conformances: {}
    };
    for (const t of v(e)) s[t.getFullProtocolName()] = t;
  }
  for (const e of i.values()) P(e);
}

function l() {
  return Object.values(c);
}

function d(t) {
  const o = c[t];
  if (void 0 === o) throw new Error("Type not found: " + t);
  if (void 0 !== o.metadata) return c[t].metadata;
  const r = o.descriptor.getAccessFunction().call(), n = e.TargetMetadata.from(r);
  return c[t].metadata = n, n;
}

function f(e, t) {
  const o = c[e];
  if (void 0 === o) throw new Error("Type not found: " + e);
  if (void 0 !== o.metadata) return c[e].metadata;
  const r = new t(o.descriptor.getAccessFunction().call());
  return c[e].metadata = r, r;
}

function u(e) {
  const t = c[e];
  if (void 0 === t) throw new Error("Type not found: " + e);
  return t.conformances;
}

function p() {
  return Object.values(s);
}

function m(e) {
  return s[e];
}

function g(e) {
  const t = s[e];
  if (void 0 === t) throw new Error(`Can't find protocol descriptor for: "${e}"`);
  return t;
}

function D(o) {
  const n = [], i = w(o), s = i.size / r.RelativeDirectPointer.sizeOf;
  for (let o = 0; o < s; o++) {
    const s = i.vmAddress.add(o * r.RelativeDirectPointer.sizeOf), c = r.RelativeDirectPointer.From(s).get(), a = new e.TargetTypeContextDescriptor(c);
    if (a.isGeneric()) continue;
    let l;
    switch (a.getKind()) {
     case t.ContextDescriptorKind.Class:
      l = new e.TargetClassDescriptor(c);
      break;

     case t.ContextDescriptorKind.Struct:
      l = new e.TargetStructDescriptor(c);
      break;

     case t.ContextDescriptorKind.Enum:
      l = new e.TargetEnumDescriptor(c);
      break;

     default:
      continue;
    }
    n.push(l);
  }
  return n;
}

function v(t) {
  const o = [], n = x(t), i = n.size / r.RelativeDirectPointer.sizeOf;
  for (let t = 0; t < i; t++) {
    const i = n.vmAddress.add(t * r.RelativeDirectPointer.sizeOf), s = r.RelativeDirectPointer.From(i).get(), c = new e.TargetProtocolDescriptor(s);
    o.push(c);
  }
  return o;
}

function P(o) {
  const i = y(o), s = i.size / r.RelativeDirectPointer.sizeOf;
  for (let o = 0; o < s; o++) {
    const s = i.vmAddress.add(o * r.RelativeDirectPointer.sizeOf), a = r.RelativeDirectPointer.From(s).get(), l = new e.TargetProtocolConformanceDescriptor(a), d = l.getTypeDescriptor(), f = new e.TargetTypeContextDescriptor(d);
    if (null === d || f.isGeneric() || f.getKind() === t.ContextDescriptorKind.Protocol) continue;
    const u = c[f.getFullTypeName()];
    if (void 0 !== u) if (l.protocol.isNull()) {
      const e = (0, n.demangledSymbolFromAddress)(a), t = (0, n.findProtocolNameInConformanceDescriptor)(e);
      if (null === t) {
        console.warn(`Failed to parse protocol name from conformance descriptor '${e}'. Please file a bug.`);
        continue;
      }
      u.conformances[t] = {
        protocol: null,
        witnessTable: null
      };
    } else {
      const t = new e.TargetProtocolDescriptor(l.protocol);
      u.conformances[t.name] = {
        protocol: t,
        witnessTable: l.witnessTablePattern
      };
    }
  }
}

function w(e) {
  return T(e, "__swift5_types");
}

function x(e) {
  return T(e, "__swift5_protos");
}

function y(e) {
  return T(e, "__swift5_proto");
}

function T(e, t, r = "__TEXT") {
  const n = e.base, i = Memory.allocUtf8String(r), s = Memory.allocUtf8String(t), c = Memory.alloc(Process.pointerSize);
  return {
    vmAddress: (0, o.getPrivateAPI)().getsectiondata(n, i, s, c),
    size: c.readU32()
  };
}

function b(e) {
  if (null === i.find(e)) return;
  const t = e.toString(), o = a.get(t);
  if (void 0 !== o) return o;
  const r = (0, n.demangledSymbolFromAddress)(e);
  return void 0 !== r ? (a.set(t, r), r) : void 0;
}

function F(e) {
  const t = b(e);
  if (void 0 === t) throw new Error("Can't find symbol at " + e.toString());
  return t;
}

exports.getAllFullTypeData = l, exports.untypedMetadataFor = d, exports.metadataFor = f, 
exports.getProtocolConformancesFor = u, exports.getAllProtocolDescriptors = p, exports.findProtocolDescriptor = m, 
exports.getProtocolDescriptor = g, exports.findDemangledSymbol = b, exports.getDemangledSymbol = F;

},{"../abi/metadata":1,"../abi/metadatavalues":2,"../basic/relativepointer":3,"./api":5,"./symbols":11}],10:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: !0
}), exports.SwiftModule = exports.Registry = void 0;

const s = require("../abi/metadatavalues"), t = require("./macho"), e = require("./types");

class o {
  constructor() {
    this.modules = {}, this.classes = {}, this.structs = {}, this.enums = {}, this.protocols = {}, 
    this.cachedTypes = {};
    for (const o of (0, t.getAllFullTypeData)()) {
      const t = o.descriptor, r = o.conformances;
      switch (o.descriptor.getKind()) {
       case s.ContextDescriptorKind.Class:
        {
          const s = new e.Class(t, r);
          this.classes[s.$name] = s, this.getModule(s.$moduleName).addClass(s);
          break;
        }

       case s.ContextDescriptorKind.Struct:
        {
          const s = new e.Struct(t, r);
          this.structs[s.$name] = s, this.getModule(s.$moduleName).addStruct(s);
          break;
        }

       case s.ContextDescriptorKind.Enum:
        {
          const s = new e.Enum(t, r);
          this.enums[s.$name] = s, this.getModule(s.$moduleName).addEnum(s);
          break;
        }
      }
    }
    for (const s of (0, t.getAllProtocolDescriptors)()) {
      const t = new e.Protocol(s);
      this.protocols[s.name] = t, this.getModule(t.moduleName).addProtocol(t);
    }
  }
  static shared() {
    return void 0 === o.sharedInstance && (o.sharedInstance = new o), o.sharedInstance;
  }
  getModule(s) {
    if (s in this.modules) return this.modules[s];
    const t = new r(s);
    return this.modules[s] = t, t;
  }
}

exports.Registry = o;

class r {
  constructor(s) {
    this.name = s, this.classes = {}, this.structs = {}, this.enums = {}, this.protocols = {};
  }
  addClass(s) {
    this.classes[s.$name] = s;
  }
  addStruct(s) {
    this.structs[s.$name] = s;
  }
  addEnum(s) {
    this.enums[s.$name] = s;
  }
  addProtocol(s) {
    this.protocols[s.name] = s;
  }
  toJSON() {
    return {
      classes: Object.keys(this.classes).length,
      structs: Object.keys(this.structs).length,
      enums: Object.keys(this.enums).length,
      protocols: Object.keys(this.protocols).length
    };
  }
}

exports.SwiftModule = r;

},{"../abi/metadatavalues":2,"./macho":9,"./types":12}],11:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: !0
}), exports.findProtocolNameInConformanceDescriptor = exports.getSymbolicator = exports.tryParseSwiftAccessorSignature = exports.parseSwiftAccessorSignature = exports.tryParseSwiftMethodSignature = exports.parseSwiftMethodSignature = exports.tryDemangleSymbol = exports.demangledSymbolFromAddress = void 0;

const t = require("../lib/api"), e = 0x8000000000000000, r = new Map;

let o = null;

function n(r) {
  const o = (0, t.getPrivateAPI)(), n = o.CSSymbolicatorGetSymbolWithAddressAtTime(f(), r, e);
  if (o.CSIsNull(n)) return;
  const i = o.CSSymbolGetMangledName(n).readCString();
  return null !== i ? s(i) : void 0;
}

function s(e) {
  if (!i(e)) return;
  const o = r.get(e);
  if (void 0 !== o) return o;
  const n = (0, t.getApi)();
  try {
    const t = Memory.allocUtf8String(e), o = n.swift_demangle(t, e.length, ptr(0), ptr(0), 0).readUtf8String();
    return r.set(e, o), o;
  } catch (t) {
    return;
  }
}

function i(t) {
  if (0 == t.length) return !1;
  const e = [ "_T0", "$S", "_$S", "$s", "_$s" ];
  for (const r of e) if (t.startsWith(r)) return !0;
  return !1;
}

function a(t) {
  const e = /(\w+): ([\w.]+)(?:, )*|\(([\w.]+)\)/g, r = /([a-zA-Z_]\w+)(<.+>)*\(.*\) -> ([\w.]+(?: & [\w.]+)*|\([\w.]*\))$/g.exec(t);
  if (null === r) throw new Error("Couldn't parse function with signature: " + t);
  const o = r[1], n = r[3] || "void";
  if (void 0 === o) throw new Error("Couldn't parse function with signature: " + t);
  const s = [], i = [];
  let a;
  for (;null !== (a = e.exec(t)); ) {
    const t = a[3];
    void 0 !== t ? (s.push(""), i.push(t)) : (s.push(a[1]), i.push(a[2]));
  }
  if (s.length !== i.length) throw new Error("Couldn't parse function with signature: " + t);
  let c = o;
  return s.length > 0 && (c += "$" + s.join("_") + "_"), {
    methodName: o,
    argNames: s,
    argTypeNames: i,
    retTypeName: n,
    jsSignature: c
  };
}

function c(t) {
  try {
    return a(t);
  } catch (t) {
    return;
  }
}

function u(t) {
  const e = /(\w+).(getter|setter) : ([\w.]+)$/g.exec(t);
  if (null === e) throw new Error("Couldn't parse accessor signature " + t);
  const r = e[2];
  if ("getter" !== r && "setter" !== r) throw new Error("Couldn't parse accessor signature " + t);
  return {
    accessorType: r,
    memberName: e[1],
    memberTypeName: e[3]
  };
}

function l(t) {
  try {
    return u(t);
  } catch (t) {
    return;
  }
}

function f() {
  if (null !== o) return o;
  const e = (0, t.getPrivateAPI)();
  let r = e.CSSymbolicatorCreateWithPid(Process.id);
  if (e.CSIsNull(r) && (r = e.CSSymbolicatorCreateWithTask(e.mach_task_self()), e.CSIsNull(r))) throw new Error("Failed to create symbolicator");
  return o = r, Script.bindWeak(o, p), r;
}

function S(t) {
  const e = /protocol conformance descriptor for \S+ : \S+\.(\S+) in \S+/g.exec(t);
  return null === e ? null : e[1];
}

function p() {
  (0, t.getPrivateAPI)().CSRelease(o);
}

exports.demangledSymbolFromAddress = n, exports.tryDemangleSymbol = s, exports.parseSwiftMethodSignature = a, 
exports.tryParseSwiftMethodSignature = c, exports.parseSwiftAccessorSignature = u, 
exports.tryParseSwiftAccessorSignature = l, exports.getSymbolicator = f, exports.findProtocolNameInConformanceDescriptor = S;

},{"../lib/api":5}],12:[function(require,module,exports){
"use strict";

var e, t, a, r = this && this.__classPrivateFieldSet || function(e, t, a, r, s) {
  if ("m" === r) throw new TypeError("Private method is not writable");
  if ("a" === r && !s) throw new TypeError("Private accessor was defined without a setter");
  if ("function" == typeof t ? e !== t || !s : !t.has(e)) throw new TypeError("Cannot write private member to an object whose class did not declare it");
  return "a" === r ? s.call(e, a) : s ? s.value = a : t.set(e, a), a;
}, s = this && this.__classPrivateFieldGet || function(e, t, a, r) {
  if ("a" === a && !r) throw new TypeError("Private accessor was defined without a getter");
  if ("function" == typeof t ? e !== t || !r : !t.has(e)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
  return "m" === a ? r : "a" === a ? r.call(e) : r ? r.value : t.get(e);
};

Object.defineProperty(exports, "__esModule", {
  value: !0
}), exports.ObjectInstance = exports.EnumValue = exports.StructValue = exports.ValueInstance = exports.RuntimeInstance = exports.ProtocolComposition = exports.Protocol = exports.Enum = exports.Struct = exports.Class = exports.Type = void 0;

const i = require("../abi/metadata"), o = require("../abi/metadatavalues"), n = require("../lib/symbols"), d = require("./callingconvention"), l = require("../runtime/heapobject"), c = require("./buffer"), u = require("./macho"), h = require("../reflection/records"), m = require("../basic/relativepointer"), p = require("../runtime/existentialcontainer");

class f {
  constructor(e, t, a) {
    this.kind = e, this.descriptor = t, this.$conformances = a, this.$name = t.name, 
    this.$fields = x(t), this.$moduleName = t.getModuleContext().name;
  }
  get $metadataPointer() {
    return this.$metadata.handle;
  }
  toJSON() {
    return {
      $fields: this.$fields,
      $conformances: Object.keys(this.$conformances)
    };
  }
}

exports.Type = f;

class g extends f {
  constructor(e, t) {
    super("Class", e, t), this.$methods = N(e);
    for (const e of this.$methods) if ("Init" === e.type) {
      const t = (0, n.tryParseSwiftMethodSignature)(e.name);
      if (void 0 === t) continue;
      Object.defineProperty(this, t.jsSignature, {
        configurable: !0,
        get() {
          const a = t.argTypeNames.map((e => (0, u.untypedMetadataFor)(e))), r = (0, d.makeSwiftNativeFunction)(e.address, this.$metadata, a, this.$metadataPointer);
          return Object.defineProperty(this, t.jsSignature, {
            configurable: !0,
            value: r
          }), r;
        }
      });
    }
  }
  get $metadata() {
    return (0, u.metadataFor)(this.descriptor.getFullTypeName(), i.TargetClassMetadata);
  }
  toJSON() {
    const e = super.toJSON();
    return Object.assign(e, {
      $methods: this.$methods
    });
  }
}

exports.Class = g;

class w extends f {
  constructor(e, t) {
    super("Struct", e, t);
  }
  get $metadata() {
    return (0, u.metadataFor)(this.descriptor.getFullTypeName(), i.TargetStructMetadata);
  }
}

exports.Struct = w;

class y extends f {
  constructor(e, t) {
    if (super("Enum", e, t), void 0 !== this.$fields) for (const [t, a] of this.$fields.entries()) {
      const r = t;
      if (e.isPayloadTag(r)) {
        const e = e => {
          if (void 0 === e) throw new Error("Case requires an associated value");
          return new S(this.$metadata, {
            tag: r,
            payload: e
          });
        };
        Object.defineProperty(this, a.name, {
          configurable: !1,
          enumerable: !0,
          value: e,
          writable: !1
        });
      } else Object.defineProperty(this, a.name, {
        configurable: !0,
        enumerable: !0,
        get: () => {
          const e = new S(this.$metadata, {
            tag: r
          });
          return Object.defineProperty(this, a.name, {
            value: e
          }), e;
        }
      });
    }
  }
  get $metadata() {
    return (0, u.metadataFor)(this.descriptor.getFullTypeName(), i.TargetEnumMetadata);
  }
}

exports.Enum = y;

class b {
  constructor(e) {
    this.descriptor = e, this.name = e.name, this.numRequirements = e.numRequirements, 
    this.isClassOnly = e.getProtocolContextDescriptorFlags().getClassConstraint() == o.ProtocolClassConstraint.Class, 
    this.moduleName = e.getModuleContext().name;
  }
  toJSON() {
    return {
      numRequirements: this.descriptor.numRequirements,
      isClassOnly: this.isClassOnly
    };
  }
}

exports.Protocol = b;

class v {
  constructor(...e) {
    this.protocols = [ ...e ], this.numProtocols = e.length, this.isClassOnly = !1;
    for (const t of e) if (t.isClassOnly) {
      this.isClassOnly = !0;
      break;
    }
  }
  get sizeofExistentialContainer() {
    return (this.isClassOnly ? 1 * Process.pointerSize : 4 * Process.pointerSize) + Process.pointerSize * this.numProtocols;
  }
  static fromSignature(e) {
    const t = [], a = e.split("&").map((e => e.trim()));
    for (const e of a) {
      const a = (0, u.getProtocolDescriptor)(e), r = new b(a);
      t.push(r);
    }
    return new v(...t);
  }
}

exports.ProtocolComposition = v;

class $ {
  equals(e) {
    return this.handle.equals(e.handle);
  }
  toJSON() {
    return {
      handle: this.handle
    };
  }
  static fromAdopted(e, t) {
    return t.getKind() === o.MetadataKind.Class ? new M(e) : C.fromAdopted(e, t);
  }
  static fromExistentialContainer(e, t) {
    if (t.isClassOnly) {
      const a = p.ClassExistentialContainer.makeFromRaw(e, t.numProtocols);
      return new M(a.value);
    }
    {
      const a = p.TargetOpaqueExistentialContainer.makeFromRaw(e, t.numProtocols), r = a.type;
      if (r.isClassObject()) return new M(a.buffer.privateData.readPointer());
      {
        const e = a.projectValue();
        return C.fromCopy(e, r);
      }
    }
  }
}

exports.RuntimeInstance = $;

class C extends $ {
  static fromCopy(e, t) {
    const a = Memory.alloc(t.getTypeLayout().stride);
    return t.vw_initializeWithCopy(a, e), t.getKind() === o.MetadataKind.Struct ? new P(t, {
      handle: a
    }) : new S(t, {
      handle: a
    });
  }
  static fromAdopted(e, t) {
    const a = t.getKind();
    if (a === o.MetadataKind.Struct) return new P(t, {
      handle: e
    });
    if (a === o.MetadataKind.Enum) return new S(t, {
      handle: e
    });
    throw new Error("Non-value kind: " + a);
  }
  static fromRaw(e, t) {
    const a = t.getKind();
    if (a === o.MetadataKind.Struct) return new P(t, {
      raw: e
    });
    if (a === o.MetadataKind.Enum) return new S(t, {
      raw: e
    });
    throw new Error("Non-value kind: " + a);
  }
}

exports.ValueInstance = C;

class P {
  constructor(e, t) {
    if (void 0 === t.handle && void 0 === t.raw) throw new Error("Either a handle or raw fields must be provided");
    this.$metadata = e instanceof w ? e.$metadata : e, this.handle = t.handle || (0, 
    c.makeBufferFromValue)(t.raw);
  }
  equals(e) {
    return this.handle.equals(e.handle);
  }
  toJSON() {
    return {
      handle: this.handle
    };
  }
}

exports.StructValue = P;

class S {
  constructor(a, s) {
    e.set(this, void 0), t.set(this, void 0), this.$metadata = a instanceof y ? a.$metadata : a, 
    this.descriptor = this.$metadata.getDescription();
    const o = x(this.descriptor);
    if (void 0 === s.tag && void 0 === s.handle && void 0 === s.raw) throw new Error("Either a tag, handle or raw fields must be provided");
    if (void 0 !== s.tag) {
      const a = s.tag, i = s.payload, n = this.$metadata.getTypeLayout().stride, d = n < Process.pointerSize ? Process.pointerSize : n;
      if (this.handle = Memory.alloc(d), void 0 === a || a >= this.descriptor.getNumCases()) throw new Error("Invalid tag for an enum of this type");
      if (this.descriptor.isPayloadTag(a)) {
        if (void 0 === i) throw new Error("Payload must be provided for this tag");
        const e = o[a].typeName;
        if (i.$metadata.getFullTypeName() !== e) throw new Error("Payload must be of type " + e);
        i instanceof M ? (this.handle.writePointer(i.handle), r(this, t, i, "f")) : (r(this, t, C.fromAdopted(this.handle, i.$metadata), "f"), 
        this.$metadata.vw_initializeWithCopy(this.handle, i.handle));
      }
      this.$metadata.vw_destructiveInjectEnumTag(this.handle, a), r(this, e, a, "f");
    } else {
      this.handle = s.handle || (0, c.makeBufferFromValue)(s.raw);
      const a = this.$metadata.vw_getEnumTag(this.handle);
      let n;
      if (a >= this.descriptor.getNumCases()) throw new Error("Invalid pointer for an enum of this type");
      if (this.descriptor.isPayloadTag(a)) {
        const e = o[a].typeName, t = (0, u.metadataFor)(e, i.TargetValueMetadata);
        n = $.fromAdopted(this.handle, t);
      }
      r(this, e, a, "f"), r(this, t, n, "f");
    }
  }
  get $tag() {
    return s(this, e, "f");
  }
  get $payload() {
    return s(this, t, "f");
  }
  equals(e) {
    let t = !1;
    return void 0 !== this.$tag && void 0 !== e.$tag && (t = this.$tag === e.$tag), 
    void 0 !== this.$payload && void 0 !== e.$payload && t && (t = this.$payload.handle.equals(e.$payload.handle)), 
    t;
  }
  toJSON() {
    return {
      handle: this.handle,
      $tag: s(this, e, "f"),
      $payload: s(this, t, "f")
    };
  }
}

exports.EnumValue = S, e = new WeakMap, t = new WeakMap;

class M extends $ {
  constructor(e) {
    super(), this.handle = e, a.set(this, void 0), r(this, a, new l.HeapObject(e), "f"), 
    this.$metadata = s(this, a, "f").getMetadata(i.TargetClassMetadata);
    const t = this.$metadata.getDescription();
    for (const e of N(t)) switch (e.type) {
     case "Getter":
      {
        const t = (0, n.parseSwiftAccessorSignature)(e.name), a = (0, u.untypedMetadataFor)(t.memberTypeName), r = (0, 
        d.makeSwiftNativeFunction)(e.address, a, [], this.handle);
        Object.defineProperty(this, t.memberName, {
          configurable: !0,
          enumerable: !0,
          get: r
        });
        break;
      }

     case "Setter":
      {
        const t = (0, n.parseSwiftAccessorSignature)(e.name), a = (0, u.untypedMetadataFor)(t.memberTypeName), r = (0, 
        d.makeSwiftNativeFunction)(e.address, "void", [ a ], this.handle);
        Object.defineProperty(this, t.memberName, {
          configurable: !0,
          enumerable: !0,
          set: r
        });
        break;
      }

     case "Method":
      {
        const t = (0, n.parseSwiftMethodSignature)(e.name), a = "()" === t.retTypeName ? "void" : (0, 
        u.untypedMetadataFor)(t.retTypeName), r = t.argTypeNames.map((e => (0, u.untypedMetadataFor)(e))), s = (0, 
        d.makeSwiftNativeFunction)(e.address, a, r, this.handle);
        Object.defineProperty(this, t.jsSignature, {
          configurable: !0,
          enumerable: !0,
          value: s
        });
        break;
      }
    }
  }
}

function x(e) {
  const t = [];
  if (!e.isReflectable()) return;
  const a = new h.FieldDescriptor(e.fields.get());
  if (0 === a.numFields) return;
  const r = a.getFields();
  for (const e of r) t.push({
    name: e.fieldName,
    typeName: null === e.mangledTypeName ? void 0 : T(e.mangledTypeName.get()),
    isVar: e.isVar
  });
  return t;
}

function N(e) {
  const t = [];
  for (const a of e.getMethodDescriptors()) {
    const e = a.impl.get(), r = (0, u.findDemangledSymbol)(e), s = a.flags.getKind();
    let i;
    switch (s) {
     case o.MethodDescriptorKind.Init:
      i = "Init";
      break;

     case o.MethodDescriptorKind.Getter:
      i = "Getter";
      break;

     case o.MethodDescriptorKind.Setter:
      i = "Setter";
      break;

     case o.MethodDescriptorKind.ReadCoroutine:
      i = "ReadCoroutine";
      break;

     case o.MethodDescriptorKind.ModifyCoroutine:
      i = "ModifyCoroutine";
      break;

     case o.MethodDescriptorKind.Method:
      i = "Method";
      break;

     default:
      throw new Error(`Invalid method descriptor kind: ${s}`);
    }
    t.push({
      address: e,
      name: r,
      type: i
    });
  }
  return t;
}

function T(e) {
  let t = e, a = t.readU8(), r = null;
  for (;0 !== a; ) {
    if (a >= 1 && a <= 23) {
      if (t = t.add(1), 1 === a) r = new i.TargetTypeContextDescriptor(m.RelativeDirectPointer.From(t).get()); else if (2 === a) {
        let e = m.RelativeDirectPointer.From(t).get().readPointer();
        e = e.and(8796093022207), r = new i.TargetTypeContextDescriptor(e);
      }
      break;
    }
    if (a >= 24 && a <= 31) throw new Error("UNIMPLEMENTED 0x18 - 0x1F");
    t = t.add(1), a = t.readU8();
  }
  return null !== r ? r.name : (0, n.tryDemangleSymbol)("_$s" + e.readCString());
}

exports.ObjectInstance = M, a = new WeakMap;

},{"../abi/metadata":1,"../abi/metadatavalues":2,"../basic/relativepointer":3,"../lib/symbols":11,"../reflection/records":13,"../runtime/existentialcontainer":14,"../runtime/heapobject":15,"./buffer":6,"./callingconvention":7,"./macho":9}],13:[function(require,module,exports){
"use strict";

var e, t, r, i, s = this && this.__classPrivateFieldGet || function(e, t, r, i) {
  if ("a" === r && !i) throw new TypeError("Private accessor was defined without a getter");
  if ("function" == typeof t ? e !== t || !i : !t.has(e)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
  return "m" === r ? i : "a" === r ? i.call(e) : i ? i.value : t.get(e);
}, a = this && this.__classPrivateFieldSet || function(e, t, r, i, s) {
  if ("m" === i) throw new TypeError("Private method is not writable");
  if ("a" === i && !s) throw new TypeError("Private accessor was defined without a setter");
  if ("function" == typeof t ? e !== t || !s : !t.has(e)) throw new TypeError("Cannot write private member to an object whose class did not declare it");
  return "a" === i ? s.call(e, r) : s ? s.value = r : t.set(e, r), r;
};

Object.defineProperty(exports, "__esModule", {
  value: !0
}), exports.FieldDescriptor = void 0;

const n = require("../basic/relativepointer");

class o {
  constructor(t) {
    this.handle = t, e.set(this, void 0);
  }
  getFieldRecordBuffer() {
    return this.handle.add(o.SIZE);
  }
  get numFields() {
    return void 0 !== s(this, e, "f") || a(this, e, this.handle.add(o.OFFSETOF_NUMFIELDS).readU32(), "f"), 
    s(th
"""


```