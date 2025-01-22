Response:
Let's break down the thought process for analyzing this Frida/GumJS/ObjC source code.

**1. Initial Understanding and Context:**

* **Keywords:** "frida", "Dynamic instrumentation tool", "objc.js", "runtime.bundle.p", "out-qjs". These immediately tell us this is a JavaScript file within Frida, specifically for interacting with Objective-C runtime. The `out-qjs` suggests it's likely processed by a JavaScript engine like QuickJS for the target environment. "runtime.bundle.p" hints at a packaged set of runtime functionalities.
* **File Path:**  `frida/build/subprojects/frida-gum/bindings/gumjs/runtime.bundle.p/out-qjs/objc.js` gives us the architectural layering: Frida core -> Gum (instrumentation engine) -> JavaScript bindings -> Runtime support for ObjC.
* **"Part 2 of 3":** This implies it's not a complete module on its own and relies on other parts.

**2. High-Level Function Identification (Skimming):**

Read through the function definitions and their names. Look for recurring patterns and keywords:

* `getBinding`:  Likely related to associating JavaScript objects with native Objective-C objects.
* `enumerateLoadedClasses`, `enumerateLoadedClassesSync`:  Clearly about discovering loaded Objective-C classes. The "Sync" version suggests a blocking operation.
* `choose`:  Seems to select or filter specific Objective-C objects based on class.
* `makeMethodInvocationWrapper`, `makeMethodImplementationWrapper`, `makeBlockInvocationWrapper`, `makeBlockImplementationWrapper`: These are crucial. "Wrapper" suggests creating intermediary functions to handle calls between JS and ObjC. "Invocation" likely means calling existing ObjC methods/blocks, while "Implementation" means providing a new JS implementation for an ObjC method/block.
* `rawFridaType`, `makeClassName`, `makeProtocolName`, `objcMethodName`, `jsMethodName`: Utility functions for type conversion and naming.
* `Block.prototype.implementation`, `Block.prototype.declare`, `Block.prototype._getSignature`:  Extending the functionality of a `Block` object, related to its execution.
* `readObjectIsa`:  A low-level function dealing with the "isa" pointer (object's class). The architecture-specific masking (`isaMasks`) confirms this is about low-level ObjC object layout.
* `getMsgSendImpl`, `getMsgSendSuperImpl`, `resolveMsgSendImpl`, `makeMsgSendImpl`: These are about the core of Objective-C message sending (`objc_msgSend`). The "Super" variants handle calls to the superclass.
* `typeFitsInRegisters`, `sizeOfTypeOnX64`: Optimization details related to how arguments and return values are passed on specific architectures.
* `unparseSignature`, `parseSignature`, `parseType`, `readType`, `readNumber`, `readUntil`, etc.:  Functions for handling Objective-C type encodings (signatures). This is key to interoperability.
* `arrayType`, `structType`, `unionType`:  Specific handlers for complex data types in signatures.
* `qualifierById`, `parseQualifiers`, `idByAlias`, `typeIdFromAlias`: More signature-related utilities.
* `fromNativeId`, `toNativeId`, `fromNativeBlock`, `toNativeBlock`, `toNativeObjectArray`: Conversion functions between JS and native ObjC types.
* `identityTransform`, `align`: Basic utilities.
* `modifiers`, `singularTypeById`: Data structures defining type encodings.

**3. Functional Grouping and Deduction:**

Group the identified functions by their apparent purpose:

* **Object Binding:** `getBinding`
* **Class Enumeration:** `enumerateLoadedClasses`, `enumerateLoadedClassesSync`
* **Object Selection:** `choose`
* **Method/Block Wrapping (Invocation/Implementation):**  The `make...Wrapper` functions.
* **Naming/Type Conversion:** `rawFridaType`, `makeClassName`, `makeProtocolName`, `objcMethodName`, `jsMethodName`
* **Block Handling:**  `Block.prototype` extensions.
* **Low-Level Object Access:** `readObjectIsa`
* **Message Sending:** `getMsgSendImpl`, `getMsgSendSuperImpl`, etc.
* **Type Signature Handling:** `unparseSignature`, `parseSignature`, `parseType`, etc.
* **Type Conversion (JS <-> Native):** `fromNativeId`, `toNativeId`, etc.
* **Internal Utilities:** `identityTransform`, `align`
* **Type Definitions:** `modifiers`, `singularTypeById`

From these groupings, we can start to deduce the overall functionality. The code appears to provide a bridge between JavaScript and the Objective-C runtime, allowing JS code to:

* Inspect and interact with existing Objective-C objects and classes.
* Call methods on Objective-C objects.
* Provide custom implementations for Objective-C methods and blocks.

**4. Identifying Low-Level Aspects:**

Look for direct interaction with memory and OS concepts:

* **`readObjectIsa`:** Directly reads memory (`readPointer`) and performs bitwise operations (`and`) to get the class pointer. This is very low-level. The `isaMasks` variable explicitly depends on the architecture.
* **`objc_msgSend` related functions:**  `objc_msgSend` is the fundamental function for sending messages in Objective-C. The code directly uses NativeFunction to interface with these core runtime functions.
* **Pointer manipulation:**  The extensive use of `Pointer`, `Memory`, `Memory.alloc`, `readPointer`, `writePointer`, `add` indicates direct memory manipulation.
* **`enumerateLoadedClasses`:** Uses `api.objc_getClassList` which is a direct call to an Objective-C runtime function to get the list of loaded classes. It also allocates memory using `Memory.alloc`.
* **Type Signatures:**  The parsing of type signatures directly reflects the low-level encoding used by the Objective-C runtime to describe method arguments and return types.

**5. Considering Debugging and Errors:**

* **Debugging Focus:** The "wrapper" functions are prime targets for debugging, as they are the bridges where things can go wrong in terms of argument passing, return value handling, and method resolution.
* **Common Errors:** Mismatched types between JS and ObjC are a likely source of errors. Incorrect selectors or class names would cause issues with method lookup. Memory management errors (though less directly visible here) could be a concern in more complex interactions.

**6. Thinking About User Interaction (How to reach this code):**

Consider how a Frida user would end up executing this code:

* **`ObjC.choose(...)`:** This function directly calls the `choose` function in the script.
* **Hooking Methods:** When a user hooks an Objective-C method using Frida, the `makeMethodInvocationWrapper` and `makeMethodImplementationWrapper` functions are used to create the necessary JS-side wrappers.
* **Creating Blocks:**  If a user creates or interacts with Objective-C blocks, the `Block` prototype extensions and the `makeBlock...Wrapper` functions are involved.
* **Enumerating Classes:** Explicitly calling `ObjC.enumerateLoadedClasses()` or `ObjC.enumerateLoadedClassesSync()`.

**7. Structuring the Answer:**

Organize the findings into the requested sections:

* **Functionality:** Start with a high-level summary, then detail the purpose of each functional group.
* **Low-Level Aspects:** Provide specific examples with explanations.
* **LLDB Examples:**  Focus on how you could achieve similar inspection or manipulation using LLDB, especially around `objc_msgSend` and memory access. Python scripting within LLDB would be even more powerful.
* **Logic/Assumptions:**  Illustrate with simple input/output examples for key functions.
* **Common Errors:** Describe typical user mistakes.
* **User Steps:** Outline the common Frida API calls that lead to the execution of this code.
* **Summary:**  Concisely reiterate the main purpose.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  "This is just about calling ObjC methods."  **Correction:**  It's much broader, encompassing class enumeration, creating new implementations, and low-level memory interaction.
* **Initial thought:** "The type signature stuff is just boilerplate." **Correction:** It's essential for correct argument and return value marshaling between JS and ObjC. Understanding the encoding is crucial.
* **Focus on direct code execution:** While the code itself doesn't *directly* execute arbitrary binary or kernel code, it facilitates the *instrumentation* of code that does. The interaction with `objc_msgSend` is a key entry point for intercepting and modifying native execution.

By following these steps, iterating through the code, and connecting the pieces, we can arrive at a comprehensive understanding of the `objc.js` file's role within Frida.好的，让我们来分析一下 `frida/build/subprojects/frida-gum/bindings/gumjs/runtime.bundle.p/out-qjs/objc.js` 这个文件的功能。

**功能归纳：**

这个文件是 Frida 用于在 JavaScript 中与 Objective-C 运行时交互的核心组件。它提供了以下关键功能：

1. **Objective-C 对象绑定:**
   -  管理 JavaScript 对象和原生 Objective-C 对象的关联。
   -  `getBinding(e)`:  根据 Objective-C 对象的句柄（handle）获取或创建一个与之绑定的 JavaScript 对象。它维护一个 `bindings` 映射来跟踪这些关联。如果 JavaScript 端没有对应的绑定，它会创建一个新的 `ObjCObject` 实例，并将其 `self` 属性指向该 Objective-C 对象，`super` 属性指向其父类。

2. **类枚举:**
   -  允许 JavaScript 代码枚举已加载的 Objective-C 类。
   -  `enumerateLoadedClasses(...e)`:  遍历所有已加载的 Objective-C 类，并对匹配的类名执行回调函数 `r.onMatch`。它可以选择性地基于 `ModuleMap` 进行过滤。
   -  `enumerateLoadedClassesSync(e = {})`:  `enumerateLoadedClasses` 的同步版本，返回一个包含类名和其所属路径的对象。

3. **对象选择:**
   -  提供一种机制来选择特定类的实例。
   -  `choose(e, t)`:  查找指定 Objective-C 类（或其子类）的所有实例，并对每个实例执行回调函数 `t.onMatch`。

4. **方法调用和实现包装:**
   -  创建 JavaScript 函数来调用 Objective-C 的方法。
   -  `makeMethodInvocationWrapper(method, owner, superSpecifier, invocationOptions)`:  为 Objective-C 方法创建一个 JavaScript 包装器，允许从 JavaScript 中调用该方法。它处理参数的转换，并使用 `objc_msgSend` 或 `objc_msgSendSuper` 进行实际调用。
   -  `makeMethodImplementationWrapper(signature, implementation)`:  为 Objective-C 方法的实现创建一个 JavaScript 包装器，允许用 JavaScript 代码替换原生方法的实现。

5. **Block 调用和实现包装:**
   -  处理 Objective-C 的 Block (闭包)。
   -  `makeBlockInvocationWrapper(block, signature, implementation)`:  为 Objective-C Block 创建一个 JavaScript 包装器，以便从 JavaScript 中调用 Block。
   -  `makeBlockImplementationWrapper(block, signature, implementation)`:  为 Objective-C Block 的实现创建一个 JavaScript 包装器，允许用 JavaScript 代码替换原生 Block 的实现。

6. **类型处理和转换:**
   -  负责 Objective-C 和 JavaScript 之间的数据类型转换。
   -  `parseSignature(e)` 和相关的函数 (`parseType`, `readType`, 等):  解析 Objective-C 方法和 Block 的类型签名，以便正确地进行参数和返回值的转换。
   -  `fromNativeId`, `toNativeId`, `fromNativeBlock`, `toNativeBlock`:  在原生 Objective-C 类型和 JavaScript 类型之间进行转换的函数。

7. **底层消息发送:**
   -  直接与 Objective-C 的消息发送机制交互。
   -  `getMsgSendImpl(e, t)` 和 `getMsgSendSuperImpl(e, t)`:  获取用于发送消息的 `objc_msgSend` 或 `objc_msgSendSuper` 函数的 NativeFunction 实例。这涉及到处理不同的函数签名和参数传递方式。

8. **类和协议命名:**
   -  提供生成唯一类名和协议名的辅助函数。
   -  `makeClassName()`, `makeProtocolName()`:  生成在运行时创建匿名类或协议时使用的唯一名称。

9. **方法名转换:**
   -  在 Objective-C 和 JavaScript 的方法命名约定之间进行转换。
   -  `objcMethodName(e)`:  将 JavaScript 风格的方法名（用下划线分隔参数）转换为 Objective-C 风格（用冒号分隔）。
   -  `jsMethodName(e)`:  将 Objective-C 风格的方法名转换为 JavaScript 友好的名称。

**涉及二进制底层和 Linux 内核（间接）：**

虽然这个 JavaScript 文件本身没有直接的 Linux 内核代码，但它深深地依赖于 Objective-C 运行时，而 Objective-C 运行时是操作系统底层的一部分。Frida 通过 Gum (一个动态检测引擎) 与目标进程交互，Gum 负责与操作系统进行交互，包括：

* **内存操作:**  `Memory.alloc`, `readPointer`, `writePointer` 等函数直接操作目标进程的内存空间。例如，`enumerateLoadedClasses` 中使用 `Memory.alloc` 来分配内存存储类列表。
* **函数调用:**  `NativeFunction` 用于调用目标进程中的原生函数，例如 `objc_getClassList`, `objc_msgSend` 等。这些函数是 Objective-C 运行时库的一部分，在操作系统底层执行。
* **进程和线程管理 (间接):** 虽然代码中没有显式的进程/线程操作，但 Frida 本身需要管理与目标进程的交互。例如，`dispatch_async_f` 函数用于在主线程异步执行任务。
* **地址空间布局 (间接):**  枚举加载的类需要理解目标进程的内存布局。`readObjectIsa` 函数读取对象的 `isa` 指针，这是对象在内存中的第一个成员，指向其所属的类。

**举例说明：**

* **二进制底层 (内存操作):** `readObjectIsa` 函数直接读取 Objective-C 对象的 `isa` 指针，这是一个指向类元数据的内存地址。不同的 CPU 架构下，`isa` 指针的掩码可能不同 (`isaMasks`)，用于提取实际的类指针。

   ```javascript
   const isaMasks = {
     x64: "0x7ffffffffff8",
     arm64: "0xffffffff8"
   };
   const rawMask = isaMasks[Process.arch];
   if (void 0 !== rawMask) {
     const e = ptr(rawMask);
     readObjectIsa = function(t) {
       return t.readPointer().and(e);
     };
   }
   ```

   在 LLDB 中，你可以使用类似的命令来读取对象的 `isa` 指针：

   ```lldb
   (lldb) x/gx <object_address>  // 读取对象地址的内容 (假设是 64 位架构)
   ```

   然后，你可能需要手动应用掩码来获取类指针。

* **Linux 内核 (通过 Objective-C 运行时):**  当调用 `api.objc_getClassList(c, l)` 时，Frida 实际上是在目标进程中调用了 Objective-C 运行时的函数。Objective-C 运行时会与操作系统内核交互来获取当前加载的类的信息。虽然 JavaScript 代码没有直接的系统调用，但它通过 Frida 提供的接口间接地使用了操作系统提供的功能。

**LLDB 指令或 Python 脚本复刻调试功能示例：**

假设我们要复刻 `enumerateLoadedClassesSync` 的部分功能，即获取所有已加载的 Objective-C 类名。

**LLDB 指令：**

```lldb
// 获取 objc_getClassList 函数的地址
(lldb) image lookup -n objc_getClassList

// 调用 objc_getClassList 获取类的数量
(lldb) p (int)objc_getClassList(0, 0)
// 假设返回值为 100

// 分配内存来存储类指针 (假设是 64 位架构)
(lldb) expr void *$classes = malloc(sizeof(void *) * 100)

// 再次调用 objc_getClassList 来填充分配的内存
(lldb) p (int)objc_getClassList($classes, 100)

// 循环遍历内存，读取类指针并获取类名
(lldb) expr for (int i = 0; i < 100; ++i) { char *name = (char *)class_getName(((void **)$classes)[i]); if (name) printf("%s\n", name); }

// 清理内存
(lldb) expr free($classes)
```

**LLDB Python 脚本：**

```python
import lldb

def get_loaded_classes():
    debugger = lldb.debugger
    command_interpreter = debugger.GetCommandInterpreter()

    # 获取 objc_getClassList 函数地址
    result = lldb.SBCommandReturnObject()
    command_interpreter.HandleCommand("image lookup -n objc_getClassList", result)
    if not result.Success():
        print("Error finding objc_getClassList")
        return

    output = result.GetOutput()
    # 解析输出获取函数地址 (这里需要根据实际输出格式进行解析)
    # 假设解析出的地址是 objc_getClassList_addr

    # 调用 objc_getClassList 获取类的数量
    command_interpreter.HandleCommand("p (int)objc_getClassList(0, 0)", result)
    if not result.Success():
        print("Error getting class count")
        return
    class_count = int(result.GetOutput().split('=')[-1].strip())

    # 分配内存
    process = debugger.GetSelectedTarget().GetProcess()
    classes_memory = process.AllocateMemory(class_count * process.GetAddressByteSize(), lldb.SBError())
    if not classes_memory.IsValid():
        print("Error allocating memory")
        return

    # 调用 objc_getClassList 填充内存
    command_interpreter.HandleCommand(f"p (int)objc_getClassList(0x{classes_memory.GetLoadAddress():x}, {class_count})", result)
    if not result.Success():
        print("Error getting class list")
        process.DeallocateMemory(classes_memory)
        return

    loaded_classes = []
    for i in range(class_count):
        class_ptr_addr = classes_memory.GetLoadAddress() + i * process.GetAddressByteSize()
        error = lldb.SBError()
        class_ptr = process.ReadPointerFromMemory(class_ptr_addr, error)
        if error.Success() and class_ptr != 0:
            command_interpreter.HandleCommand(f"p (char *)class_getName(0x{class_ptr:x})", result)
            if result.Success():
                class_name = result.GetOutput().split('=')[-1].strip().strip('"')
                loaded_classes.append(class_name)

    process.DeallocateMemory(classes_memory)
    return loaded_classes

# 调用脚本
if __name__ == '__main__':
    classes = get_loaded_classes()
    if classes:
        for class_name in classes:
            print(class_name)
```

**假设输入与输出 (逻辑推理):**

假设我们调用 `getBinding` 函数，并传入一个 Objective-C 对象的句柄 `0x100080000`，并且这个句柄之前没有被绑定过。

**假设输入:**

```javascript
getBinding(ptr("0x100080000"))
```

**预期输出:**

```javascript
{
  self: ObjCObject { handle: "0x100080000" },
  super: ObjCObject { handle: "<父类对象的句柄>" }, // 父类对象的句柄需要运行时才能确定
  data: {}
}
```

**用户或编程常见的使用错误：**

1. **类型不匹配:**  在调用 Objective-C 方法时，如果 JavaScript 传递的参数类型与 Objective-C 方法期望的参数类型不符，会导致运行时错误或崩溃。例如，传递一个 JavaScript 字符串给一个期望 `NSInteger` 的 Objective-C 方法。

   ```javascript
   // 假设某个 Objective-C 方法期望一个 NSInteger
   ObjC.classes.MyClass.someMethod_(123); // 正确
   ObjC.classes.MyClass.someMethod_("abc"); // 错误：类型不匹配
   ```

2. **选择器错误:**  如果方法名（选择器）拼写错误或不正确，会导致找不到方法。

   ```javascript
   // 假设 MyClass 有一个方法叫做 "doSomething"
   ObjC.classes.MyClass.doSomething(); // 正确

   ObjC.classes.MyClass.dosomething(); // 错误：选择器拼写错误
   ```

3. **尝试访问未加载的类或对象:**  如果尝试访问尚未加载到内存中的类或对象，会导致错误。

   ```javascript
   // 假设 AnotherClass 还没有被加载
   const anotherClass = ObjC.classes.AnotherClass; // 可能会抛出异常
   ```

4. **错误地处理 Block:**  如果 Block 的签名声明不正确，或者在 JavaScript 中使用 Block 的方式不正确，会导致错误。

   ```javascript
   // 假设 Objective-C 方法期望一个接受一个字符串参数的 Block
   someObject.someMethodWithBlock_(new ObjC.Block({ types: ['void', 'object'] }, function(str) {
     console.log(str);
   }));
   ```
   如果 `types` 定义不正确，例如缺少参数类型，则可能导致运行时错误。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户启动 Frida 并连接到目标进程。**
2. **用户编写 Frida 脚本，尝试与 Objective-C 代码交互。**
3. **用户可能使用 `ObjC.classes.XXX` 来获取 Objective-C 类。** 这会导致在内部调用 `getBinding` 或相关函数来创建 JavaScript 代理对象。
4. **用户可能使用 `ObjC.classes.XXX.YYY()` 来调用 Objective-C 方法。** 这会导致调用 `makeMethodInvocationWrapper` 来创建方法调用包装器，并最终执行 `objc_msgSend`。
5. **用户可能使用 `ObjC.choose('类名')` 来枚举特定类的实例。** 这会直接调用 `choose` 函数。
6. **用户可能使用 `ObjC.schedule(block)` 或类似的方式与 Objective-C 的 Block 交互。** 这会触发 Block 相关的包装器函数。
7. **如果脚本中存在类型转换或方法查找错误，或者尝试访问未加载的类，就可能在这个 `objc.js` 文件中的代码中抛出异常或产生错误。** Frida 的错误报告会指向这个文件中的特定行。

**归纳一下它的功能 (第2部分)：**

总而言之，`frida/build/subprojects/frida-gum/bindings/gumjs/runtime.bundle.p/out-qjs/objc.js` 的主要功能是 **作为 Frida 在 JavaScript 环境中操作和与 Objective-C 运行时交互的桥梁**。它提供了核心机制来：

* **映射和管理 Objective-C 对象和 JavaScript 对象的对应关系。**
* **枚举和选择已加载的 Objective-C 类和对象。**
* **动态地创建 JavaScript 包装器来调用和替换 Objective-C 方法和 Block 的实现。**
* **处理 Objective-C 和 JavaScript 之间的数据类型转换。**
* **在底层与 Objective-C 的消息发送机制交互。**

这个文件是 Frida 实现动态 Objective-C 代码检测和修改的关键组成部分。

Prompt: 
```
这是目录为frida/build/subprojects/frida-gum/bindings/gumjs/runtime.bundle.p/out-qjs/objc.js的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第2部分，共3部分，请归纳一下它的功能

"""
function getBinding(e) {
    const t = getHandle(e), r = t.toString();
    let n = bindings.get(r);
    if (void 0 === n) {
      const o = e instanceof ObjCObject ? e : new ObjCObject(t);
      n = {
        self: o,
        super: o.$super,
        data: {}
      }, bindings.set(r, n);
    }
    return n;
  }
  function enumerateLoadedClasses(...e) {
    const t = new ModuleMap;
    let r, n, o = !1;
    if (1 === e.length) r = e[0]; else {
      r = e[1];
      n = e[0].ownedBy;
    }
    void 0 === n && (n = t, o = !0);
    const i = api.class_getName, a = r.onMatch.bind(r), s = (8 === pointerSize ? 8 : 11) * pointerSize, l = api.objc_getClassList(NULL, 0), c = Memory.alloc(l * pointerSize);
    api.objc_getClassList(c, l);
    for (let e = 0; e !== l; e++) {
      const r = c.add(e * pointerSize).readPointer(), l = i(r);
      let u = null, p = n.findPath(l);
      if (null === p && (o || null === t.findPath(l))) {
        u = l.readCString();
        if (-1 !== u.indexOf(".")) {
          const e = r.add(s).readPointer();
          p = n.findPath(e);
        }
      }
      null !== p && (null === u && (u = l.readUtf8String()), a(u, p));
    }
    r.onComplete();
  }
  function enumerateLoadedClassesSync(e = {}) {
    const t = {};
    return enumerateLoadedClasses(e, {
      onMatch(e, r) {
        let n = t[r];
        void 0 === n && (n = [], t[r] = n), n.push(e);
      },
      onComplete() {}
    }), t;
  }
  function choose(e, t) {
    let r = e, n = !0;
    if (e instanceof ObjCObject || "object" != typeof e || (r = e.class, e.hasOwnProperty("subclasses") && (n = e.subclasses)), 
    !(r instanceof ObjCObject) || "class" !== r.$kind && "meta-class" !== r.$kind) throw new Error("Expected an ObjC.Object for a class or meta-class");
    const o = fastpaths.get().choose(r, n).map((e => new ObjCObject(e)));
    for (const e of o) {
      if ("stop" === t.onMatch(e)) break;
    }
    t.onComplete();
  }
  function makeMethodInvocationWrapper(method, owner, superSpecifier, invocationOptions) {
    const sel = method.sel;
    let handle = method.handle, types;
    void 0 === handle ? (handle = null, types = method.types) : types = api.method_getTypeEncoding(handle).readUtf8String();
    const signature = parseSignature(types), retType = signature.retType, argTypes = signature.argTypes.slice(2), objc_msgSend = superSpecifier ? getMsgSendSuperImpl(signature, invocationOptions) : getMsgSendImpl(signature, invocationOptions), argVariableNames = argTypes.map((function(e, t) {
      return "a" + (t + 1);
    })), callArgs = [ superSpecifier ? "superSpecifier" : "this", "sel" ].concat(argTypes.map((function(e, t) {
      return e.toNative ? "argTypes[" + t + "].toNative.call(this, " + argVariableNames[t] + ")" : argVariableNames[t];
    })));
    let returnCaptureLeft, returnCaptureRight;
    "void" === retType.type ? (returnCaptureLeft = "", returnCaptureRight = "") : retType.fromNative ? (returnCaptureLeft = "return retType.fromNative.call(this, ", 
    returnCaptureRight = ")") : (returnCaptureLeft = "return ", returnCaptureRight = "");
    const m = eval("var m = function (" + argVariableNames.join(", ") + ") { " + returnCaptureLeft + "objc_msgSend(" + callArgs.join(", ") + ")" + returnCaptureRight + "; }; m;");
    function getMethodHandle() {
      if (null === handle) {
        if ("instance" === owner.$kind) {
          let e = owner;
          do {
            if (!("- forwardingTargetForSelector:" in e)) break;
            {
              const t = e.forwardingTargetForSelector_(sel);
              if (null === t) break;
              if ("instance" !== t.$kind) break;
              const r = api.class_getInstanceMethod(t.$class.handle, sel);
              r.isNull() ? e = t : handle = r;
            }
          } while (null === handle);
        }
        if (null === handle) throw new Error("Unable to find method handle of proxied function");
      }
      return handle;
    }
    return Object.defineProperty(m, "handle", {
      enumerable: !0,
      get: getMethodHandle
    }), m.selector = sel, Object.defineProperty(m, "implementation", {
      enumerable: !0,
      get() {
        const e = getMethodHandle(), t = new NativeFunction(api.method_getImplementation(e), m.returnType, m.argumentTypes, invocationOptions), r = getReplacementMethodImplementation(e);
        return null !== r && (t._callback = r), t;
      },
      set(e) {
        replaceMethodImplementation(getMethodHandle(), e);
      }
    }), m.returnType = retType.type, m.argumentTypes = signature.argTypes.map((e => e.type)), 
    m.types = types, Object.defineProperty(m, "symbol", {
      enumerable: !0,
      get: () => `${method.kind}[${owner.$className} ${selectorAsString(sel)}]`
    }), m.clone = function(e) {
      return makeMethodInvocationWrapper(method, owner, superSpecifier, e);
    }, m;
  }
  function makeMethodImplementationWrapper(signature, implementation) {
    const retType = signature.retType, argTypes = signature.argTypes, argVariableNames = argTypes.map((function(e, t) {
      return 0 === t ? "handle" : 1 === t ? "sel" : "a" + (t - 1);
    })), callArgs = argTypes.slice(2).map((function(e, t) {
      const r = argVariableNames[2 + t];
      return e.fromNative ? "argTypes[" + (2 + t) + "].fromNative.call(self, " + r + ")" : r;
    }));
    let returnCaptureLeft, returnCaptureRight;
    "void" === retType.type ? (returnCaptureLeft = "", returnCaptureRight = "") : retType.toNative ? (returnCaptureLeft = "return retType.toNative.call(self, ", 
    returnCaptureRight = ")") : (returnCaptureLeft = "return ", returnCaptureRight = "");
    const m = eval("var m = function (" + argVariableNames.join(", ") + ") { var binding = getBinding(handle);var self = binding.self;" + returnCaptureLeft + "implementation.call(binding" + (callArgs.length > 0 ? ", " : "") + callArgs.join(", ") + ")" + returnCaptureRight + "; }; m;");
    return m;
  }
  function makeBlockInvocationWrapper(block, signature, implementation) {
    const retType = signature.retType, argTypes = signature.argTypes.slice(1), argVariableNames = argTypes.map((function(e, t) {
      return "a" + (t + 1);
    })), callArgs = argTypes.map((function(e, t) {
      return e.toNative ? "argTypes[" + t + "].toNative.call(this, " + argVariableNames[t] + ")" : argVariableNames[t];
    }));
    let returnCaptureLeft, returnCaptureRight;
    "void" === retType.type ? (returnCaptureLeft = "", returnCaptureRight = "") : retType.fromNative ? (returnCaptureLeft = "return retType.fromNative.call(this, ", 
    returnCaptureRight = ")") : (returnCaptureLeft = "return ", returnCaptureRight = "");
    const f = eval("var f = function (" + argVariableNames.join(", ") + ") { " + returnCaptureLeft + "implementation(this" + (callArgs.length > 0 ? ", " : "") + callArgs.join(", ") + ")" + returnCaptureRight + "; }; f;");
    return f.bind(block);
  }
  function makeBlockImplementationWrapper(block, signature, implementation) {
    const retType = signature.retType, argTypes = signature.argTypes, argVariableNames = argTypes.map((function(e, t) {
      return 0 === t ? "handle" : "a" + t;
    })), callArgs = argTypes.slice(1).map((function(e, t) {
      const r = argVariableNames[1 + t];
      return e.fromNative ? "argTypes[" + (1 + t) + "].fromNative.call(this, " + r + ")" : r;
    }));
    let returnCaptureLeft, returnCaptureRight;
    "void" === retType.type ? (returnCaptureLeft = "", returnCaptureRight = "") : retType.toNative ? (returnCaptureLeft = "return retType.toNative.call(this, ", 
    returnCaptureRight = ")") : (returnCaptureLeft = "return ", returnCaptureRight = "");
    const f = eval("var f = function (" + argVariableNames.join(", ") + ") { if (!this.handle.equals(handle))this.handle = handle;" + returnCaptureLeft + "implementation.call(block" + (callArgs.length > 0 ? ", " : "") + callArgs.join(", ") + ")" + returnCaptureRight + "; }; f;");
    return f.bind(block);
  }
  function rawFridaType(e) {
    return "object" === e ? "pointer" : e;
  }
  function makeClassName() {
    for (let e = 1; ;e++) {
      const t = "FridaAnonymousClass" + e;
      if (!(t in classRegistry)) return t;
    }
  }
  function makeProtocolName() {
    for (let e = 1; ;e++) {
      const t = "FridaAnonymousProtocol" + e;
      if (!(t in protocolRegistry)) return t;
    }
  }
  function objcMethodName(e) {
    return e.replace(/_/g, ":");
  }
  function jsMethodName(e) {
    let t = e.replace(/:/g, "_");
    return objCObjectBuiltins.has(t) && (t += "2"), t;
  }
  Object.defineProperties(Block.prototype, {
    implementation: {
      enumerable: !0,
      get() {
        const e = this.handle.add(blockOffsets.invoke).readPointer().strip(), t = this._getSignature();
        return makeBlockInvocationWrapper(this, t, new NativeFunction(e.sign(), t.retType.type, t.argTypes.map((function(e) {
          return e.type;
        })), this._options));
      },
      set(e) {
        const t = this._getSignature(), r = new NativeCallback(makeBlockImplementationWrapper(this, t, e), t.retType.type, t.argTypes.map((function(e) {
          return e.type;
        })));
        this._callback = r;
        const n = this.handle.add(blockOffsets.invoke), o = Memory.queryProtection(n), i = o.includes("w");
        i || Memory.protect(n, Process.pointerSize, "rw-"), n.writePointer(r.strip().sign("ia", n)), 
        i || Memory.protect(n, Process.pointerSize, o);
      }
    },
    declare: {
      value(e) {
        let t = e.types;
        void 0 === t && (t = unparseSignature(e.retType, [ "block" ].concat(e.argTypes))), 
        this.types = t, this._signature = parseSignature(t);
      }
    },
    _getSignature: {
      value() {
        const e = this._signature;
        if (null === e) throw new Error("block is missing signature; call declare()");
        return e;
      }
    }
  });
  const isaMasks = {
    x64: "0x7ffffffffff8",
    arm64: "0xffffffff8"
  }, rawMask = isaMasks[Process.arch];
  if (void 0 !== rawMask) {
    const e = ptr(rawMask);
    readObjectIsa = function(t) {
      return t.readPointer().and(e);
    };
  } else readObjectIsa = function(e) {
    return e.readPointer();
  };
  function getMsgSendImpl(e, t) {
    return resolveMsgSendImpl(msgSendBySignatureId, e, t, !1);
  }
  function getMsgSendSuperImpl(e, t) {
    return resolveMsgSendImpl(msgSendSuperBySignatureId, e, t, !0);
  }
  function resolveMsgSendImpl(e, t, r, n) {
    if (r !== defaultInvocationOptions) return makeMsgSendImpl(t, r, n);
    const {id: o} = t;
    let i = e.get(o);
    return void 0 === i && (i = makeMsgSendImpl(t, r, n), e.set(o, i)), i;
  }
  function makeMsgSendImpl(e, t, r) {
    const n = e.retType.type, o = e.argTypes.map((function(e) {
      return e.type;
    })), i = [ "objc_msgSend" ];
    r && i.push("Super");
    n instanceof Array && !typeFitsInRegisters(n) ? i.push("_stret") : "float" !== n && "double" !== n || i.push("_fpret");
    const a = i.join("");
    return new NativeFunction(api[a], n, o, t);
  }
  function typeFitsInRegisters(e) {
    if ("x64" !== Process.arch) return !1;
    return sizeOfTypeOnX64(e) <= 16;
  }
  function sizeOfTypeOnX64(e) {
    if (e instanceof Array) return e.reduce(((e, t) => e + sizeOfTypeOnX64(t)), 0);
    switch (e) {
     case "bool":
     case "char":
     case "uchar":
      return 1;

     case "int16":
     case "uint16":
      return 2;

     case "int":
     case "int32":
     case "uint":
     case "uint32":
     case "float":
      return 4;

     default:
      return 8;
    }
  }
  function unparseSignature(e, t) {
    const r = typeIdFromAlias(e), n = t.map(typeIdFromAlias), o = n.map((e => singularTypeById[e].size)), i = o.reduce(((e, t) => e + t), 0);
    let a = 0;
    return r + i + n.map(((e, t) => {
      const r = e + a;
      return a += o[t], r;
    })).join("");
  }
  function parseSignature(e) {
    const t = [ e, 0 ];
    parseQualifiers(t);
    const r = readType(t);
    readNumber(t);
    const n = [];
    let o = JSON.stringify(r.type);
    for (;dataAvailable(t); ) {
      parseQualifiers(t);
      const e = readType(t);
      readNumber(t), n.push(e), o += JSON.stringify(e.type);
    }
    return {
      id: o,
      retType: r,
      argTypes: n
    };
  }
  function parseType(e) {
    return readType([ e, 0 ]);
  }
  function readType(e) {
    let t = readChar(e);
    if ("@" === t) {
      let r = peekChar(e);
      "?" === r ? (t += r, skipChar(e)) : '"' === r && (skipChar(e), readUntil('"', e));
    } else if ("^" === t) {
      let r = peekChar(e);
      "@" === r && (t += r, skipChar(e));
    }
    const r = singularTypeById[t];
    if (void 0 !== r) return r;
    if ("[" === t) {
      const t = readNumber(e), r = readType(e);
      return skipChar(e), arrayType(t, r);
    }
    if ("{" === t) {
      if (!tokenExistsAhead("=", "}", e)) return readUntil("}", e), structType([]);
      readUntil("=", e);
      const t = [];
      let r;
      for (;"}" !== (r = peekChar(e)); ) '"' === r && (skipChar(e), readUntil('"', e)), 
      t.push(readType(e));
      return skipChar(e), structType(t);
    }
    if ("(" === t) {
      readUntil("=", e);
      const t = [];
      for (;")" !== peekChar(e); ) t.push(readType(e));
      return skipChar(e), unionType(t);
    }
    if ("b" === t) return readNumber(e), singularTypeById.i;
    if ("^" === t) return readType(e), singularTypeById["?"];
    if (modifiers.has(t)) return readType(e);
    throw new Error("Unable to handle type " + t);
  }
  function readNumber(e) {
    let t = "";
    for (;dataAvailable(e); ) {
      const r = peekChar(e), n = r.charCodeAt(0);
      if (!(n >= 48 && n <= 57)) break;
      t += r, skipChar(e);
    }
    return parseInt(t);
  }
  function readUntil(e, t) {
    const r = t[0], n = t[1], o = r.indexOf(e, n);
    if (-1 === o) throw new Error("Expected token '" + e + "' not found");
    const i = r.substring(n, o);
    return t[1] = o + 1, i;
  }
  function readChar(e) {
    return e[0][e[1]++];
  }
  function peekChar(e) {
    return e[0][e[1]];
  }
  function tokenExistsAhead(e, t, r) {
    const [n, o] = r, i = n.indexOf(e, o);
    if (-1 === i) return !1;
    const a = n.indexOf(t, o);
    if (-1 === a) throw new Error("Expected to find terminator: " + t);
    return i < a;
  }
  function skipChar(e) {
    e[1]++;
  }
  function dataAvailable(e) {
    return e[1] !== e[0].length;
  }
  const qualifierById = {
    r: "const",
    n: "in",
    N: "inout",
    o: "out",
    O: "bycopy",
    R: "byref",
    V: "oneway"
  };
  function parseQualifiers(e) {
    const t = [];
    for (;;) {
      const r = qualifierById[peekChar(e)];
      if (void 0 === r) break;
      t.push(r), skipChar(e);
    }
    return t;
  }
  const idByAlias = {
    char: "c",
    int: "i",
    int16: "s",
    int32: "i",
    int64: "q",
    uchar: "C",
    uint: "I",
    uint16: "S",
    uint32: "I",
    uint64: "Q",
    float: "f",
    double: "d",
    bool: "B",
    void: "v",
    string: "*",
    object: "@",
    block: "@?",
    class: "#",
    selector: ":",
    pointer: "^v"
  };
  function typeIdFromAlias(e) {
    if ("object" == typeof e && null !== e) return `@"${e.type}"`;
    const t = idByAlias[e];
    if (void 0 === t) throw new Error("No known encoding for type " + e);
    return t;
  }
  const fromNativeId = function(e) {
    return e.isNull() ? null : e.toString(16) === this.handle.toString(16) ? this : new ObjCObject(e);
  }, toNativeId = function(e) {
    if (null === e) return NULL;
    const t = typeof e;
    return "string" === t ? (null === cachedNSStringCtor && (cachedNSString = classRegistry.NSString, 
    cachedNSStringCtor = cachedNSString.stringWithUTF8String_), cachedNSStringCtor.call(cachedNSString, Memory.allocUtf8String(e))) : "number" === t ? (null === cachedNSNumberCtor && (cachedNSNumber = classRegistry.NSNumber, 
    cachedNSNumberCtor = cachedNSNumber.numberWithDouble_), cachedNSNumberCtor.call(cachedNSNumber, e)) : e;
  }, fromNativeBlock = function(e) {
    return e.isNull() ? null : e.toString(16) === this.handle.toString(16) ? this : new Block(e);
  }, toNativeBlock = function(e) {
    return null !== e ? e : NULL;
  }, toNativeObjectArray = function(e) {
    if (e instanceof Array) {
      const t = e.length, r = Memory.alloc(t * pointerSize);
      for (let n = 0; n !== t; n++) r.add(n * pointerSize).writePointer(toNativeId(e[n]));
      return r;
    }
    return e;
  };
  function arrayType(e, t) {
    return {
      type: "pointer",
      read(r) {
        const n = [], o = t.size;
        for (let i = 0; i !== e; i++) n.push(t.read(r.add(i * o)));
        return n;
      },
      write(e, r) {
        const n = t.size;
        r.forEach(((r, o) => {
          t.write(e.add(o * n), r);
        }));
      }
    };
  }
  function structType(e) {
    let t, r;
    if (e.some((function(e) {
      return !!e.fromNative;
    }))) {
      const r = e.map((function(e) {
        return e.fromNative ? e.fromNative : identityTransform;
      }));
      t = function(e) {
        return e.map((function(e, t) {
          return r[t].call(this, e);
        }));
      };
    } else t = identityTransform;
    if (e.some((function(e) {
      return !!e.toNative;
    }))) {
      const t = e.map((function(e) {
        return e.toNative ? e.toNative : identityTransform;
      }));
      r = function(e) {
        return e.map((function(e, r) {
          return t[r].call(this, e);
        }));
      };
    } else r = identityTransform;
    const [n, o] = e.reduce((function(e, t) {
      const [r, n] = e, {size: o} = t, i = align(r, o);
      return n.push(i), [ i + o, n ];
    }), [ 0, [] ]);
    return {
      type: e.map((e => e.type)),
      size: n,
      read: t => e.map(((e, r) => e.read(t.add(o[r])))),
      write(t, r) {
        r.forEach(((r, n) => {
          e[n].write(t.add(o[n]), r);
        }));
      },
      fromNative: t,
      toNative: r
    };
  }
  function unionType(e) {
    const t = e.reduce((function(e, t) {
      return t.size > e.size ? t : e;
    }), e[0]);
    let r, n;
    if (t.fromNative) {
      const e = t.fromNative;
      r = function(t) {
        return e.call(this, t[0]);
      };
    } else r = function(e) {
      return e[0];
    };
    if (t.toNative) {
      const e = t.toNative;
      n = function(t) {
        return [ e.call(this, t) ];
      };
    } else n = function(e) {
      return [ e ];
    };
    return {
      type: [ t.type ],
      size: t.size,
      read: t.read,
      write: t.write,
      fromNative: r,
      toNative: n
    };
  }
  const longBits = 8 == pointerSize && "windows" !== Process.platform ? 64 : 32;
  function identityTransform(e) {
    return e;
  }
  function align(e, t) {
    const r = e % t;
    return 0 === r ? e : e + (t - r);
  }
  modifiers = new Set([ "j", "A", "r", "n", "N", "o", "O", "R", "V", "+" ]), singularTypeById = {
    c: {
      type: "char",
      size: 1,
      read: e => e.readS8(),
      write: (e, t) => {
        e.writeS8(t);
      },
      toNative: e => "boolean" == typeof e ? e ? 1 : 0 : e
    },
    i: {
      type: "int",
      size: 4,
      read: e => e.readInt(),
      write: (e, t) => {
        e.writeInt(t);
      }
    },
    s: {
      type: "int16",
      size: 2,
      read: e => e.readS16(),
      write: (e, t) => {
        e.writeS16(t);
      }
    },
    l: {
      type: "int32",
      size: 4,
      read: e => e.readS32(),
      write: (e, t) => {
        e.writeS32(t);
      }
    },
    q: {
      type: "int64",
      size: 8,
      read: e => e.readS64(),
      write: (e, t) => {
        e.writeS64(t);
      }
    },
    C: {
      type: "uchar",
      size: 1,
      read: e => e.readU8(),
      write: (e, t) => {
        e.writeU8(t);
      }
    },
    I: {
      type: "uint",
      size: 4,
      read: e => e.readUInt(),
      write: (e, t) => {
        e.writeUInt(t);
      }
    },
    S: {
      type: "uint16",
      size: 2,
      read: e => e.readU16(),
      write: (e, t) => {
        e.writeU16(t);
      }
    },
    L: {
      type: "uint" + longBits,
      size: longBits / 8,
      read: e => e.readULong(),
      write: (e, t) => {
        e.writeULong(t);
      }
    },
    Q: {
      type: "uint64",
      size: 8,
      read: e => e.readU64(),
      write: (e, t) => {
        e.writeU64(t);
      }
    },
    f: {
      type: "float",
      size: 4,
      read: e => e.readFloat(),
      write: (e, t) => {
        e.writeFloat(t);
      }
    },
    d: {
      type: "double",
      size: 8,
      read: e => e.readDouble(),
      write: (e, t) => {
        e.writeDouble(t);
      }
    },
    B: {
      type: "bool",
      size: 1,
      read: e => e.readU8(),
      write: (e, t) => {
        e.writeU8(t);
      },
      fromNative: e => !!e,
      toNative: e => e ? 1 : 0
    },
    v: {
      type: "void",
      size: 0
    },
    "*": {
      type: "pointer",
      size: pointerSize,
      read: e => e.readPointer(),
      write: (e, t) => {
        e.writePointer(t);
      },
      fromNative: e => e.readUtf8String()
    },
    "@": {
      type: "pointer",
      size: pointerSize,
      read: e => e.readPointer(),
      write: (e, t) => {
        e.writePointer(t);
      },
      fromNative: fromNativeId,
      toNative: toNativeId
    },
    "@?": {
      type: "pointer",
      size: pointerSize,
      read: e => e.readPointer(),
      write: (e, t) => {
        e.writePointer(t);
      },
      fromNative: fromNativeBlock,
      toNative: toNativeBlock
    },
    "^@": {
      type: "pointer",
      size: pointerSize,
      read: e => e.readPointer(),
      write: (e, t) => {
        e.writePointer(t);
      },
      toNative: toNativeObjectArray
    },
    "^v": {
      type: "pointer",
      size: pointerSize,
      read: e => e.readPointer(),
      write: (e, t) => {
        e.writePointer(t);
      }
    },
    "#": {
      type: "pointer",
      size: pointerSize,
      read: e => e.readPointer(),
      write: (e, t) => {
        e.writePointer(t);
      },
      fromNative: fromNativeId,
      toNative: toNativeId
    },
    ":": {
      type: "pointer",
      size: pointerSize,
      read: e => e.readPointer(),
      write: (e, t) => {
        e.writePointer(t);
      }
    },
    "?": {
      type: "pointer",
      size: pointerSize,
      read: e => e.readPointer(),
      write: (e, t) => {
        e.writePointer(t);
      }
    }
  };
}

module.exports = new Runtime;

}).call(this)}).call(this,require("timers").setImmediate)

},{"./lib/api":2,"./lib/fastpaths":3,"timers":5}],2:[function(require,module,exports){
let o = null;

const e = {
  exceptions: "propagate"
};

function t() {
  if (null !== o) return o;
  const t = {};
  let n = 0;
  return [ {
    module: "libsystem_malloc.dylib",
    functions: {
      free: [ "void", [ "pointer" ] ]
    }
  }, {
    module: "libobjc.A.dylib",
    functions: {
      objc_msgSend: function(o) {
        this.objc_msgSend = o;
      },
      objc_msgSend_stret: function(o) {
        this.objc_msgSend_stret = o;
      },
      objc_msgSend_fpret: function(o) {
        this.objc_msgSend_fpret = o;
      },
      objc_msgSendSuper: function(o) {
        this.objc_msgSendSuper = o;
      },
      objc_msgSendSuper_stret: function(o) {
        this.objc_msgSendSuper_stret = o;
      },
      objc_msgSendSuper_fpret: function(o) {
        this.objc_msgSendSuper_fpret = o;
      },
      objc_getClassList: [ "int", [ "pointer", "int" ] ],
      objc_lookUpClass: [ "pointer", [ "pointer" ] ],
      objc_allocateClassPair: [ "pointer", [ "pointer", "pointer", "pointer" ] ],
      objc_disposeClassPair: [ "void", [ "pointer" ] ],
      objc_registerClassPair: [ "void", [ "pointer" ] ],
      class_isMetaClass: [ "bool", [ "pointer" ] ],
      class_getName: [ "pointer", [ "pointer" ] ],
      class_getImageName: [ "pointer", [ "pointer" ] ],
      class_copyProtocolList: [ "pointer", [ "pointer", "pointer" ] ],
      class_copyMethodList: [ "pointer", [ "pointer", "pointer" ] ],
      class_getClassMethod: [ "pointer", [ "pointer", "pointer" ] ],
      class_getInstanceMethod: [ "pointer", [ "pointer", "pointer" ] ],
      class_getSuperclass: [ "pointer", [ "pointer" ] ],
      class_addProtocol: [ "bool", [ "pointer", "pointer" ] ],
      class_addMethod: [ "bool", [ "pointer", "pointer", "pointer", "pointer" ] ],
      class_copyIvarList: [ "pointer", [ "pointer", "pointer" ] ],
      objc_getProtocol: [ "pointer", [ "pointer" ] ],
      objc_copyProtocolList: [ "pointer", [ "pointer" ] ],
      objc_allocateProtocol: [ "pointer", [ "pointer" ] ],
      objc_registerProtocol: [ "void", [ "pointer" ] ],
      protocol_getName: [ "pointer", [ "pointer" ] ],
      protocol_copyMethodDescriptionList: [ "pointer", [ "pointer", "bool", "bool", "pointer" ] ],
      protocol_copyPropertyList: [ "pointer", [ "pointer", "pointer" ] ],
      protocol_copyProtocolList: [ "pointer", [ "pointer", "pointer" ] ],
      protocol_addProtocol: [ "void", [ "pointer", "pointer" ] ],
      protocol_addMethodDescription: [ "void", [ "pointer", "pointer", "pointer", "bool", "bool" ] ],
      ivar_getName: [ "pointer", [ "pointer" ] ],
      ivar_getTypeEncoding: [ "pointer", [ "pointer" ] ],
      ivar_getOffset: [ "pointer", [ "pointer" ] ],
      object_isClass: [ "bool", [ "pointer" ] ],
      object_getClass: [ "pointer", [ "pointer" ] ],
      object_getClassName: [ "pointer", [ "pointer" ] ],
      method_getName: [ "pointer", [ "pointer" ] ],
      method_getTypeEncoding: [ "pointer", [ "pointer" ] ],
      method_getImplementation: [ "pointer", [ "pointer" ] ],
      method_setImplementation: [ "pointer", [ "pointer", "pointer" ] ],
      property_getName: [ "pointer", [ "pointer" ] ],
      property_copyAttributeList: [ "pointer", [ "pointer", "pointer" ] ],
      sel_getName: [ "pointer", [ "pointer" ] ],
      sel_registerName: [ "pointer", [ "pointer" ] ],
      class_getInstanceSize: [ "pointer", [ "pointer" ] ]
    },
    optionals: {
      objc_msgSend_stret: "ABI",
      objc_msgSend_fpret: "ABI",
      objc_msgSendSuper_stret: "ABI",
      objc_msgSendSuper_fpret: "ABI",
      object_isClass: "iOS8"
    }
  }, {
    module: "libdispatch.dylib",
    functions: {
      dispatch_async_f: [ "void", [ "pointer", "pointer", "pointer" ] ]
    },
    variables: {
      _dispatch_main_q: function(o) {
        this._dispatch_main_q = o;
      }
    }
  } ].forEach((function(o) {
    const i = "libobjc.A.dylib" === o.module, r = o.functions || {}, p = o.variables || {}, s = o.optionals || {};
    n += Object.keys(r).length + Object.keys(p).length;
    const c = Module.enumerateExportsSync(o.module).reduce((function(o, e) {
      return o[e.name] = e, o;
    }), {});
    Object.keys(r).forEach((function(o) {
      const p = c[o];
      if (void 0 !== p && "function" === p.type) {
        const s = r[o];
        "function" == typeof s ? (s.call(t, p.address), i && s.call(t, p.address)) : (t[o] = new NativeFunction(p.address, s[0], s[1], e), 
        i && (t[o] = t[o])), n--;
      } else {
        s[o] && n--;
      }
    })), Object.keys(p).forEach((function(o) {
      const e = c[o];
      if (void 0 !== e && "variable" === e.type) {
        p[o].call(t, e.address), n--;
      }
    }));
  })), 0 === n && (t.objc_msgSend_stret || (t.objc_msgSend_stret = t.objc_msgSend), 
  t.objc_msgSend_fpret || (t.objc_msgSend_fpret = t.objc_msgSend), t.objc_msgSendSuper_stret || (t.objc_msgSendSuper_stret = t.objc_msgSendSuper), 
  t.objc_msgSendSuper_fpret || (t.objc_msgSendSuper_fpret = t.objc_msgSendSuper), 
  o = t), o;
}

module.exports = {
  getApi: t,
  defaultInvocationOptions: e
};

},{}],3:[function(require,module,exports){
const e = "#include <glib.h>\n#include <ptrauth.h>\n\n#define KERN_SUCCESS 0\n#define MALLOC_PTR_IN_USE_RANGE_TYPE 1\n#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8\n# define OBJC_ISA_MASK 0x7ffffffffff8ULL\n#elif defined (HAVE_ARM64)\n# define OBJC_ISA_MASK 0xffffffff8ULL\n#endif\n\ntypedef struct _ChooseContext ChooseContext;\n\ntypedef struct _malloc_zone_t malloc_zone_t;\ntypedef struct _malloc_introspection_t malloc_introspection_t;\ntypedef struct _vm_range_t vm_range_t;\n\ntypedef gpointer Class;\ntypedef int kern_return_t;\ntypedef guint mach_port_t;\ntypedef mach_port_t task_t;\ntypedef guintptr vm_offset_t;\ntypedef guintptr vm_size_t;\ntypedef vm_offset_t vm_address_t;\n\nstruct _ChooseContext\n{\n  GHashTable * classes;\n  GArray * matches;\n};\n\nstruct _malloc_zone_t\n{\n  void * reserved1;\n  void * reserved2;\n  size_t (* size) (struct _malloc_zone_t * zone, const void * ptr);\n  void * (* malloc) (struct _malloc_zone_t * zone, size_t size);\n  void * (* calloc) (struct _malloc_zone_t * zone, size_t num_items, size_t size);\n  void * (* valloc) (struct _malloc_zone_t * zone, size_t size);\n  void (* free) (struct _malloc_zone_t * zone, void * ptr);\n  void * (* realloc) (struct _malloc_zone_t * zone, void * ptr, size_t size);\n  void (* destroy) (struct _malloc_zone_t * zone);\n  const char * zone_name;\n\n  unsigned (* batch_malloc) (struct _malloc_zone_t * zone, size_t size, void ** results, unsigned num_requested);\n  void (* batch_free) (struct _malloc_zone_t * zone, void ** to_be_freed, unsigned num_to_be_freed);\n\n  malloc_introspection_t * introspect;\n};\n\ntypedef kern_return_t (* memory_reader_t) (task_t remote_task, vm_address_t remote_address, vm_size_t size, void ** local_memory);\ntypedef void (* vm_range_recorder_t) (task_t task, void * user_data, unsigned type, vm_range_t * ranges, unsigned count);\ntypedef kern_return_t (* enumerator_func) (task_t task, void * user_data, unsigned type_mask, vm_address_t zone_address, memory_reader_t reader,\n      vm_range_recorder_t recorder);\n\nstruct _malloc_introspection_t\n{\n  enumerator_func enumerator;\n};\n\nstruct _vm_range_t\n{\n  vm_address_t address;\n  vm_size_t size;\n};\n\nextern int objc_getClassList (Class * buffer, int buffer_count);\nextern Class class_getSuperclass (Class cls);\nextern size_t class_getInstanceSize (Class cls);\nextern kern_return_t malloc_get_all_zones (task_t task, memory_reader_t reader, vm_address_t ** addresses, unsigned * count);\n\nstatic void collect_subclasses (Class klass, GHashTable * result);\nstatic void collect_matches_in_ranges (task_t task, void * user_data, unsigned type, vm_range_t * ranges, unsigned count);\nstatic kern_return_t read_local_memory (task_t remote_task, vm_address_t remote_address, vm_size_t size, void ** local_memory);\n\nextern mach_port_t selfTask;\n\ngpointer *\nchoose (Class * klass,\n        gboolean consider_subclasses,\n        guint * count)\n{\n  ChooseContext ctx;\n  GHashTable * classes;\n  vm_address_t * malloc_zone_addresses;\n  unsigned malloc_zone_count, i;\n\n  classes = g_hash_table_new_full (NULL, NULL, NULL, NULL);\n  ctx.classes = classes;\n  ctx.matches = g_array_new (FALSE, FALSE, sizeof (gpointer));\n  if (consider_subclasses)\n    collect_subclasses (klass, classes);\n  else\n    g_hash_table_insert (classes, klass, GSIZE_TO_POINTER (class_getInstanceSize (klass)));\n\n  malloc_zone_count = 0;\n  malloc_get_all_zones (selfTask, read_local_memory, &malloc_zone_addresses, &malloc_zone_count);\n\n  for (i = 0; i != malloc_zone_count; i++)\n  {\n    vm_address_t zone_address = malloc_zone_addresses[i];\n    malloc_zone_t * zone = (malloc_zone_t *) zone_address;\n    enumerator_func enumerator;\n\n    if (zone != NULL && zone->introspect != NULL &&\n        (enumerator = (ptrauth_strip (zone->introspect, ptrauth_key_asda))->enumerator) != NULL)\n    {\n      enumerator = ptrauth_sign_unauthenticated (\n          ptrauth_strip (enumerator, ptrauth_key_asia),\n          ptrauth_key_asia, 0);\n\n      enumerator (selfTask, &ctx, MALLOC_PTR_IN_USE_RANGE_TYPE, zone_address, read_local_memory,\n          collect_matches_in_ranges);\n    }\n  }\n\n  g_hash_table_unref (classes);\n\n  *count = ctx.matches->len;\n\n  return (gpointer *) g_array_free (ctx.matches, FALSE);\n}\n\nvoid\ndestroy (gpointer mem)\n{\n  g_free (mem);\n}\n\nstatic void\ncollect_subclasses (Class klass,\n                    GHashTable * result)\n{\n  Class * classes;\n  int count, i;\n\n  count = objc_getClassList (NULL, 0);\n  classes = g_malloc (count * sizeof (gpointer));\n  count = objc_getClassList (classes, count);\n\n  for (i = 0; i != count; i++)\n  {\n    Class candidate = classes[i];\n    Class c;\n\n    c = candidate;\n    do\n    {\n      if (c == klass)\n      {\n        g_hash_table_insert (result, candidate, GSIZE_TO_POINTER (class_getInstanceSize (candidate)));\n        break;\n      }\n\n      c = class_getSuperclass (c);\n    }\n    while (c != NULL);\n  }\n\n  g_fr
"""


```