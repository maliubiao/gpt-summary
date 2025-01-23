Response:
Let's break down the thought process for analyzing this Frida Swift bridge code snippet.

**1. Understanding the Request:**

The core request is to analyze a specific file (`swift.js`) within the Frida framework related to Swift dynamic instrumentation. Key requirements are:

* **Functionality:** What does this code do?
* **Low-level/Kernel Interaction:** Does it touch binary, Linux kernel, etc.?  Provide examples.
* **Debugging:** How can this functionality be replicated with LLDB?
* **Logic/Assumptions:**  Are there logical inferences or assumptions in the code?
* **Common Errors:** What mistakes might users make?
* **User Path:** How does a user end up using this code?
* **Summary:** A concise overview of its purpose.

**2. Initial Code Scan and Keyword Identification:**

I'd first quickly scan the code for recognizable keywords and patterns:

* **`require(...)`:**  Indicates dependencies on other modules within the Frida Swift bridge. This is a crucial starting point for understanding the code's context. Specifically, `frida-swift-bridge` points to the core of this integration.
* **`exports.`:**  Marks what this module makes available for use by other parts of the Frida system.
* **Class definitions (`class ...`)**:  Suggests object-oriented programming and likely represents specific Swift concepts. The names are highly informative (e.g., `FieldDescriptor`, `TargetOpaqueExistentialContainer`, `ClassExistentialContainer`, `HeapObject`).
* **`WeakMap`:**  Used for private members in JavaScript classes.
* **`OFFSETOF_...` and `SIZE`:**  Strong indicators of interacting with binary data structures, as these define the layout of objects in memory.
* **Bitwise operations (`&`, `|`, `~`)**:  Further reinforces interaction with low-level binary representations, likely for flags and masks.
* **`readU32()`, `readPointer()`, `readUtf8String()`, `writePointer()`:** Direct evidence of memory manipulation.
* **`Process.pointerSize`, `Memory.alloc()`:** Frida-specific APIs for accessing process information and allocating memory.

**3. Deciphering the Classes and Their Relationships:**

Based on the class names and their properties, I'd start forming a mental model of the Swift reflection/introspection process:

* **`FieldDescriptor`:**  Clearly describes a field within a Swift object. It holds information like flags, mangled type name, and field name. The "mangled type name" hints at how Swift encodes type information.
* **`TargetOpaqueExistentialContainer` and `ClassExistentialContainer`:**  These seem to represent ways Swift handles existential types (protocols) and class types at runtime. The "container" aspect suggests they hold metadata and possibly the actual object data. The "opaque" part might mean the underlying type isn't always known statically.
* **`HeapObject`:**  A fundamental building block representing an object allocated on the heap. It holds a pointer to the object's metadata.

The dependencies revealed by `require()` are also important:

* `../abi/metadata`: Deals with the structure of Swift metadata.
* `./heapobject`:  The `HeapObject` class itself.
* `./basic/relativepointer`:  Handles pointers that are relative to some base address.

**4. Connecting to Low-Level Concepts:**

The presence of `OFFSETOF_...`, `SIZE`, and memory read/write operations immediately screams "binary layout."  I'd think:

* **Binary Structure of Swift Objects:** This code is likely interacting with the in-memory representation of Swift objects, reading metadata and field information.
* **Metadata:** Swift uses metadata to describe types and objects at runtime, enabling features like reflection.
* **Heap Allocation:** `Memory.alloc()` and `HeapObject` directly relate to how objects are allocated in memory.
* **Pointers:** The code heavily uses pointers to navigate memory and access different parts of objects and metadata.

**5. Considering Debugging (LLDB):**

Given the memory manipulation, LLDB comes to mind for replicating the functionality. I'd consider how to:

* **Examine Memory:**  Use `memory read` or `x` in LLDB to inspect the raw bytes at specific addresses.
* **Interpret Pointers:**  Dereference pointers to see what they point to.
* **Follow Metadata Structures:**  Use knowledge of the Swift metadata layout (which this code implicitly reveals) to interpret the raw bytes. This might involve reading sequences of pointers and integers.
* **Python Scripting:**  For more complex tasks, LLDB's Python scripting capabilities are essential for automating memory reads and interpreting structures.

**6. Inferring Logic and Potential Errors:**

* **Assumptions:** The code assumes a certain layout of Swift metadata, which might change between Swift versions. This is a crucial assumption to note.
* **User Errors:** Incorrectly calculating offsets, misinterpreting flags, or attempting to access memory that isn't valid are all potential pitfalls.

**7. Tracing the User Path:**

To understand how a user reaches this code, I'd think about the broader Frida use case for Swift:

* **Dynamic Analysis of iOS/macOS Apps:**  Frida is used to inspect and modify running applications.
* **Hooking Swift Functions:**  Users might want to intercept Swift method calls or access object properties.
* **Reflection/Introspection:** To do this effectively, Frida needs to be able to understand the structure of Swift objects, which is where this `swift.js` comes in.

**8. Structuring the Answer:**

Finally, I'd organize my findings into the requested sections: functionality, low-level details, LLDB examples, logic/assumptions, errors, user path, and summary. Using code snippets and clear explanations is key. Since this is "Part 3," I'd focus on summarizing the overall functionality gleaned from the code.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "Maybe this is about calling Swift functions."  **Correction:** While Frida *can* call Swift functions, this specific code focuses more on inspecting existing Swift objects and their metadata.
* **Initial thought:** "The LLDB examples need to be very specific." **Refinement:**  Provide general LLDB commands and explain the *process* of replicating the functionality, as the exact memory addresses will vary. Highlight the use of Python scripting for complex tasks.
* **Initial thought:** "Just list the classes." **Refinement:** Explain the *purpose* of each class and how they relate to Swift concepts. The names are a big clue.

By following this systematic approach, combining code analysis with knowledge of Frida, Swift internals, and debugging techniques, I can arrive at a comprehensive and accurate explanation of the provided code snippet.这是 frida 动态插桩工具中用于处理 Swift 语言特性的一个模块。它主要负责在运行时检查和解析 Swift 对象的结构和元数据信息。让我们分解一下它的功能：

**功能归纳:**

该代码的主要功能是提供在 Frida 中运行时自省 Swift 对象的能力。它定义了一些类，用于表示 Swift 元数据中的特定结构，例如字段描述符和存在类型容器。这使得 Frida 能够动态地了解 Swift 对象的布局、类型信息和属性。

**更详细的功能分解:**

1. **`FieldDescriptor` 类:**  用于描述 Swift 对象中的一个字段（属性）。
    * 它能获取字段的标志（`flags`），例如是否是 `indirect case` 或 `var`。
    * 它能获取字段的 `mangledTypeName`，即 Swift 类型名称的编码形式。
    * 它能获取字段的 `fieldName`，即字段的名称。
    * 通过标志位 `isIndirectCase` 和 `isVar` 提供对字段特性的判断。

2. **`TargetOpaqueExistentialContainer` 和 `ClassExistentialContainer` 类:** 用于处理 Swift 的存在类型（协议）容器和类类型容器。
    * 它们允许访问容器中存储的类型信息（`type`）。
    * 它们可以获取存储实际值的缓冲区（`buffer` 或 `value`）。
    * `TargetOpaqueExistentialContainer` 能够判断值是否内联存储 (`isValueInline`)，并投影出实际的值 (`projectValue`)。
    * 它们可以获取 witness table 的地址，witness table 是 Swift 中实现协议一致性的关键。

3. **`HeapObject` 类:**  表示堆上分配的 Swift 对象。
    * 它提供了一个方法 `getMetadata()` 来获取对象的元数据信息。

**涉及的二进制底层和 Linux 内核 (假设在 Linux 环境下运行):**

* **二进制底层:**
    * **内存布局解析:** 代码通过读取特定偏移量 (`OFFSETOF_...`) 的内存来解析 Swift 对象和元数据的二进制结构。例如，`FieldDescriptor.OFFSETOF_FLAGS` 定义了字段描述符中标志位在内存中的偏移量。这直接与 Swift 编译器生成的二进制文件的结构相关。
    * **指针操作:** 代码中大量使用了指针 (`handle`) 和指针运算 (`add()`) 来遍历内存中的数据结构。这反映了在底层，Swift 对象和元数据是通过指针相互关联的。
    * **字节读取:** 使用 `readU32()`, `readPointer()`, `readUtf8String()` 等方法从内存中读取不同类型的数据，这些都是直接的二进制数据操作。

* **Linux 内核 (间接):**
    * **进程内存管理:**  Frida 需要与目标进程交互，读取其内存空间。这涉及到 Linux 内核提供的进程间通信和内存管理机制，例如 `ptrace` 系统调用（Frida 可能会使用它或类似的机制）。虽然这段代码本身没有直接调用内核 API，但其运行依赖于 Frida 框架提供的与内核交互的能力。
    * **动态链接器/加载器:** 当 Swift 代码在运行时被加载时，Linux 内核的动态链接器负责加载必要的库和进行符号解析。这段代码中使用的元数据结构是在编译和链接阶段确定的，并在运行时由加载器加载到内存中。

**举例说明:**

假设我们有一个 Swift 类 `MyClass`，它有一个 `Int` 类型的属性 `myField`。

```swift
class MyClass {
    var myField: Int = 10
}
```

当 Frida 连接到运行该 Swift 代码的进程后，`swift.js` 中的代码可以执行以下操作：

1. **定位 `MyClass` 对象的实例:**  Frida 用户可能会通过其他 Frida 功能（例如，查找特定类型的对象）获取到 `MyClass` 实例在内存中的地址。

2. **使用 `HeapObject` 获取元数据:**  `new HeapObject(instanceAddress).getMetadata(TargetClassMetadata)` 可以获取到 `MyClass` 的元数据。

3. **遍历字段:**  从类元数据中可以找到字段描述符的列表。`FieldDescriptor` 类可以解析 `myField` 属性的描述符。
    * `fieldDescriptor.fieldName` 可能返回 "myField"。
    * `fieldDescriptor.mangledTypeName` 可能返回 "Si" (Swift 中 `Int` 的编码)。

4. **访问属性值:**  通过结合对象的地址和 `myField` 的偏移量（这可能需要进一步解析元数据或使用其他 Frida 功能），可以读取到 `myField` 的值 10。

**用 lldb 指令或 lldb python 脚本复刻调试功能的示例:**

假设我们已经通过某种方式找到了 `MyClass` 实例的地址 `0x100008000` 和 `myField` 字段描述符的地址 `0x100009000`。

**lldb 指令示例:**

```lldb
# 读取 MyClass 实例的内存 (假设前 8 字节是 metadata 指针，接下来的 8 字节是 myField 的值)
(lldb) x/2xg 0x100008000

# 读取 FieldDescriptor 的内存 (假设 numFields 在偏移 12)
(lldb) x/xw 0x100009000+12

# 读取 mangledTypeName 指针 (假设在偏移 4)
(lldb) x/xg 0x100009000+4
(lldb) memory read `(long)($0)`  # 假设上一个命令的结果存储在 $0 寄存器中，读取指针指向的字符串

# 读取 fieldName 指针 (假设在偏移 8)
(lldb) x/xg 0x100009000+8
(lldb) memory read `(long)($0)`
```

**lldb Python 脚本示例:**

```python
import lldb

def read_field_descriptor(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()

    field_descriptor_addr = int(command, 16)

    flags_addr = field_descriptor_addr + 0
    flags = process.ReadUnsignedFromMemory(flags_addr, 4)
    print(f"Flags: {flags}")

    mangled_type_name_ptr_addr = field_descriptor_addr + 4
    mangled_type_name_ptr = process.ReadPointerFromMemory(mangled_type_name_ptr_addr)
    if mangled_type_name_ptr:
        error = lldb.SBError()
        mangled_type_name = process.ReadCStringFromMemory(mangled_type_name_ptr, 256, error)
        if mangled_type_name:
            print(f"Mangled Type Name: {mangled_type_name}")
        else:
            print(f"Error reading mangled type name: {error}")

    field_name_ptr_addr = field_descriptor_addr + 8
    field_name_ptr = process.ReadPointerFromMemory(field_name_ptr_addr)
    if field_name_ptr:
        error = lldb.SBError()
        field_name = process.ReadCStringFromMemory(field_name_ptr, 256, error)
        if field_name:
            print(f"Field Name: {field_name}")
        else:
            print(f"Error reading field name: {error}")

# 在 lldb 中使用： script read_field_descriptor 0x100009000
```

这些示例演示了如何使用 lldb 直接读取内存，并根据 `swift.js` 中定义的偏移量来解析 `FieldDescriptor` 的信息。

**逻辑推理的假设输入与输出:**

假设输入一个 `FieldDescriptor` 对象的内存地址，例如 `0x10000a000`。

**假设输入:** `fieldDescriptorAddress = 0x10000a000`

**可能的输出 (取决于该地址内存中的实际数据):**

```
Flags: 0
Mangled Type Name: Si
Field Name: myField
```

或者如果 `isIndirectCase` 为真：

```
Flags: 1
Mangled Type Name: Optional<String>
Field Name: anotherField
```

**用户或编程常见的使用错误:**

1. **错误的偏移量:** 用户可能会错误地估计或计算内存偏移量，导致读取到错误的数据或程序崩溃。例如，如果 `FieldDescriptor.OFFSETOF_FLAGS` 的值在某个 Swift 版本中发生变化，而用户仍然使用旧的偏移量，就会得到错误的标志信息。

2. **无效的内存地址:**  传递给构造函数或方法无效的内存地址会导致程序崩溃或读取到未定义的行为。这可能是由于目标对象或元数据被释放，或者地址计算错误。

3. **假设特定的 Swift 版本:** 代码的正确运行可能依赖于特定的 Swift 版本和 ABI (应用程序二进制接口)。不同版本的 Swift 可能有不同的元数据布局。如果 Frida 版本与目标应用程序的 Swift 版本不兼容，这段代码可能无法正确解析数据。

4. **不理解 Mangled Type Name:**  用户可能不理解 Swift 的类型编码规则，导致无法正确解释 `mangledTypeName` 字段。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **Frida 连接到目标进程:**  用户首先使用 Frida CLI 或 API 连接到正在运行的 iOS 或 macOS 应用程序。

2. **查找 Swift 对象:**  用户可能使用 Frida 的 `ObjC.choose()` 或自定义脚本来枚举和查找特定类型的 Swift 对象实例。他们可能基于某些条件（例如，对象的属性值）来定位目标对象。

3. **访问对象属性或进行方法拦截:**  为了理解对象的内部状态或修改其行为，用户可能尝试访问对象的属性。对于 Swift 对象，Frida 需要理解其内存布局。

4. **`swift.js` 参与元数据解析:**  当 Frida 尝试访问 Swift 对象的属性时，底层的 Frida Gum 引擎会调用 `swift.js` 中的代码来解析对象的元数据，确定属性的类型和偏移量。

5. **调试 `swift.js` 或相关逻辑:**  如果用户在访问 Swift 对象属性时遇到问题（例如，获取到错误的值或遇到错误），他们可能会查看 Frida 的源代码，包括 `swift.js`，以了解元数据解析的逻辑，并尝试找出问题所在。他们可能会在 Frida 脚本中使用 `console.log` 或类似的调试方法来输出 `swift.js` 中间变量的值，以便理解解析过程。

**总结 `swift.js` 的功能:**

`swift.js` 在 Frida 框架中扮演着关键的角色，它提供了运行时自省 Swift 对象结构的能力。通过定义 `FieldDescriptor` 和存在类型容器等类，它能够解析 Swift 对象的元数据，包括字段信息、类型信息和 witness table。这使得 Frida 能够动态地理解 Swift 代码的内部结构，为用户进行动态分析、hooking 和逆向工程提供了基础。它依赖于对 Swift 编译器生成的二进制结构的理解和对内存布局的解析。

### 提示词
```
这是目录为frida/build/subprojects/frida-gum/bindings/gumjs/runtime.bundle.p/out-qjs/swift.js的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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
is, e, "f");
  }
  getFields() {
    const e = [];
    let t, r = this.getFieldRecordBuffer();
    for (let i = 0; i < this.numFields; i++) t = new d(r), e.push(t), r = r.add(d.SIZE);
    return e;
  }
}

exports.FieldDescriptor = o, e = new WeakMap, o.SIZE = 16, o.OFFSETOF_NUMFIELDS = 12;

class d {
  constructor(e) {
    this.handle = e, t.set(this, void 0), r.set(this, void 0), i.set(this, void 0);
  }
  get flags() {
    return void 0 !== s(this, t, "f") || a(this, t, this.handle.add(d.OFFSETOF_FLAGS).readU32(), "f"), 
    s(this, t, "f");
  }
  get mangledTypeName() {
    return void 0 !== s(this, r, "f") || a(this, r, n.RelativeDirectPointer.From(this.handle.add(d.OFFSETOF_MANGLED_TYPE_NAME)), "f"), 
    s(this, r, "f");
  }
  get fieldName() {
    return void 0 !== s(this, i, "f") || a(this, i, n.RelativeDirectPointer.From(this.handle.add(d.OFFSETOF_FIELD_NAME)).get().readUtf8String(), "f"), 
    s(this, i, "f");
  }
  get isIndirectCase() {
    return !!(this.flags & h.IsIndirectCase);
  }
  get isVar() {
    return !!(this.flags & h.IsVar);
  }
}

var h;

t = new WeakMap, r = new WeakMap, i = new WeakMap, d.SIZE = 12, d.OFFSETOF_FLAGS = 0, 
d.OFFSETOF_MANGLED_TYPE_NAME = 4, d.OFFSETOF_FIELD_NAME = 8, function(e) {
  e[e.IsIndirectCase = 1] = "IsIndirectCase", e[e.IsVar = 2] = "IsVar";
}(h || (h = {}));

},{"../basic/relativepointer":3}],14:[function(require,module,exports){
"use strict";

var e, t, s, r = this && this.__classPrivateFieldSet || function(e, t, s, r, a) {
  if ("m" === r) throw new TypeError("Private method is not writable");
  if ("a" === r && !a) throw new TypeError("Private accessor was defined without a setter");
  if ("function" == typeof t ? e !== t || !a : !t.has(e)) throw new TypeError("Cannot write private member to an object whose class did not declare it");
  return "a" === r ? a.call(e, s) : a ? a.value = s : t.set(e, s), s;
}, a = this && this.__classPrivateFieldGet || function(e, t, s, r) {
  if ("a" === s && !r) throw new TypeError("Private accessor was defined without a getter");
  if ("function" == typeof t ? e !== t || !r : !t.has(e)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
  return "m" === s ? r : "a" === s ? r.call(e) : r ? r.value : t.get(e);
};

Object.defineProperty(exports, "__esModule", {
  value: !0
}), exports.ClassExistentialContainer = exports.TargetOpaqueExistentialContainer = void 0;

const i = require("../abi/metadata"), n = require("./heapobject");

class o {
  constructor(s, r) {
    this.handle = s, this.numWitnessTables = r, e.set(this, void 0), t.set(this, void 0);
  }
  static alloc(e) {
    const t = o.INITIAL_SIZE + e * Process.pointerSize, s = Memory.alloc(t);
    return new o(s, e);
  }
  static makeFromRaw(e, s) {
    const a = new o(e, s), n = e.add(o.OFFSETOF.type).readPointer(), l = new i.TargetValueMetadata(n);
    return r(a, t, l.isClassObject() ? new i.TargetClassMetadata(n) : l, "f"), a;
  }
  set type(e) {
    this.handle.add(o.OFFSETOF.type).writePointer(e.handle), r(this, t, e, "f");
  }
  get buffer() {
    return void 0 === a(this, e, "f") && r(this, e, new i.TargetValueBuffer(this.handle), "f"), 
    a(this, e, "f");
  }
  get type() {
    return a(this, t, "f");
  }
  getWitnessTables() {
    return this.handle.add(o.OFFSETOF.wintessTable);
  }
  isValueInline() {
    return this.type.getValueWitnesses().isValueInline();
  }
  projectValue() {
    const e = this.type.getValueWitnesses();
    if (e.isValueInline()) return this.buffer.privateData;
    const t = this.buffer.privateData.readPointer(), s = e.getAlignmentMask(), r = n.HeapObject.SIZEOF + s & ~s;
    return t.add(r);
  }
  get sizeof() {
    return o.INITIAL_SIZE + this.numWitnessTables * Process.pointerSize;
  }
}

exports.TargetOpaqueExistentialContainer = o, e = new WeakMap, t = new WeakMap, 
o.INITIAL_SIZE = 4 * Process.pointerSize, o.OFFSETOF = {
  buffer: 0,
  type: 3 * Process.pointerSize,
  wintessTable: 4 * Process.pointerSize
};

class l {
  constructor(e, t) {
    this.handle = e, this.numWitnessTables = t, s.set(this, void 0);
  }
  static alloc(e) {
    const t = l.INITIAL_SIZE + e * Process.pointerSize, s = Memory.alloc(t);
    return new l(s, e);
  }
  static makeFromRaw(e, t) {
    const a = new l(e, t);
    return r(a, s, e.add(l.OFFSETOF.value).readPointer(), "f"), a;
  }
  get value() {
    return a(this, s, "f");
  }
  set value(e) {
    this.handle.add(l.OFFSETOF.value).writePointer(e), r(this, s, e, "f");
  }
  getWitnessTables() {
    return this.handle.add(l.OFFSETOF.witnessTables);
  }
  get sizeof() {
    return l.INITIAL_SIZE + this.numWitnessTables * Process.pointerSize;
  }
}

exports.ClassExistentialContainer = l, s = new WeakMap, l.INITIAL_SIZE = Process.pointerSize, 
l.OFFSETOF = {
  value: 0,
  witnessTables: Process.pointerSize
};

},{"../abi/metadata":1,"./heapobject":15}],15:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: !0
}), exports.BoxPair = exports.HeapObject = void 0;

class e {
  constructor(e) {
    this.handle = e;
  }
  getMetadata(e) {
    return new e(this.handle.readPointer());
  }
}

exports.HeapObject = e, e.SIZEOF = 2 * Process.pointerSize;

class t {
  constructor(t) {
    this.object = new e(t[0]), this.buffer = t[1];
  }
}

exports.BoxPair = t;

},{}],16:[function(require,module,exports){
Frida._swift = require("frida-swift-bridge");

},{"frida-swift-bridge":4}]},{},[16])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJub2RlX21vZHVsZXMvZnJpZGEtc3dpZnQtYnJpZGdlL2Rpc3QvYWJpL21ldGFkYXRhLmpzIiwibm9kZV9tb2R1bGVzL2ZyaWRhLXN3aWZ0LWJyaWRnZS9kaXN0L2FiaS9tZXRhZGF0YXZhbHVlcy5qcyIsIm5vZGVfbW9kdWxlcy9mcmlkYS1zd2lmdC1icmlkZ2UvZGlzdC9iYXNpYy9yZWxhdGl2ZXBvaW50ZXIuanMiLCJub2RlX21vZHVsZXMvZnJpZGEtc3dpZnQtYnJpZGdlL2Rpc3QvaW5kZXguanMiLCJub2RlX21vZHVsZXMvZnJpZGEtc3dpZnQtYnJpZGdlL2Rpc3QvbGliL2FwaS5qcyIsIm5vZGVfbW9kdWxlcy9mcmlkYS1zd2lmdC1icmlkZ2UvZGlzdC9saWIvYnVmZmVyLmpzIiwibm9kZV9tb2R1bGVzL2ZyaWRhLXN3aWZ0LWJyaWRnZS9kaXN0L2xpYi9jYWxsaW5nY29udmVudGlvbi5qcyIsIm5vZGVfbW9kdWxlcy9mcmlkYS1zd2lmdC1icmlkZ2UvZGlzdC9saWIvaW50ZXJjZXB0b3IuanMiLCJub2RlX21vZHVsZXMvZnJpZGEtc3dpZnQtYnJpZGdlL2Rpc3QvbGliL21hY2hvLmpzIiwibm9kZV9tb2R1bGVzL2ZyaWRhLXN3aWZ0LWJyaWRnZS9kaXN0L2xpYi9yZWdpc3RyeS5qcyIsIm5vZGVfbW9kdWxlcy9mcmlkYS1zd2lmdC1icmlkZ2UvZGlzdC9saWIvc3ltYm9scy5qcyIsIm5vZGVfbW9kdWxlcy9mcmlkYS1zd2lmdC1icmlkZ2UvZGlzdC9saWIvdHlwZXMuanMiLCJub2RlX21vZHVsZXMvZnJpZGEtc3dpZnQtYnJpZGdlL2Rpc3QvcmVmbGVjdGlvbi9yZWNvcmRzLmpzIiwibm9kZV9tb2R1bGVzL2ZyaWRhLXN3aWZ0LWJyaWRnZS9kaXN0L3J1bnRpbWUvZXhpc3RlbnRpYWxjb250YWluZXIuanMiLCJub2RlX21vZHVsZXMvZnJpZGEtc3dpZnQtYnJpZGdlL2Rpc3QvcnVudGltZS9oZWFwb2JqZWN0LmpzIiwicnVudGltZS9zd2lmdC5qcyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTtBQ0FBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUMxZUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ3RJQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNwQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUNyRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQ3pFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDaENBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUMzUEE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUMzRkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQzlKQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNqRkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQzNHQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ3paQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ3RFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNoR0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDeEJBO0FBQ0E7QUFDQSIsImZpbGUiOiJnZW5lcmF0ZWQuanMiLCJzb3VyY2VSb290IjoiIn0=
```