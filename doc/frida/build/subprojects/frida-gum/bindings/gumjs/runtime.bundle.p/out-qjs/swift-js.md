Response:
The user wants a summary of the functionality of the provided Javascript code, which appears to be related to inspecting the structure of Swift types and metadata within the Frida dynamic instrumentation framework.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core purpose:** The code is located in `frida/build/subprojects/frida-gum/bindings/gumjs/runtime.bundle.p/out-qjs/swift.js`. The path suggests it's part of Frida's GumJS bindings and deals with Swift runtime aspects. The filename `swift.js` reinforces this.

2. **Scan for key classes and functions:** Look for exported classes and their methods. The code defines classes like `TargetValueBuffer`, `TargetMetadata`, `TargetClassMetadata`, `TargetStructMetadata`, `TargetEnumMetadata`, `TargetProtocolDescriptor`, etc. These names strongly suggest they are representations of Swift's type system components.

3. **Analyze class relationships and methods:**  Notice the inheritance structure (e.g., `x extends P`, `N extends P`). Examine the methods within each class. Methods like `getKind`, `getDescription`, `getValueWitnesses`, `getTypeLayout`, `getFullTypeName`, `getModuleContext`, `getVTableDescriptor`, `getMethodDescriptors`, etc., hint at inspecting type properties and relationships.

4. **Look for interactions with Frida APIs:** Identify usage of `Process.pointerSize`, `NativeFunction`, `Memory.alloc`, and references to modules like `libswiftCore.dylib`. This confirms the code's role in interacting with the Swift runtime within a Frida environment.

5. **Infer functionality from class names and methods:**
    * `TargetValueBuffer`: Likely deals with raw memory representation of Swift values.
    * `TargetMetadata`: The base class for Swift metadata, providing general information.
    * `TargetClassMetadata`, `TargetStructMetadata`, `TargetEnumMetadata`: Specific classes for inspecting class, struct, and enum metadata respectively.
    * `TargetProtocolDescriptor`:  For inspecting Swift protocol definitions.
    * `TargetContextDescriptor`, `TargetModuleContextDescriptor`, `TargetTypeContextDescriptor`:  Related to the hierarchical context of Swift types (module, type).
    * Classes with "Descriptor" in their name likely describe the structure of the corresponding metadata.
    * Classes with "Metadata" likely represent instances of that metadata in memory.
    * Classes with "WitnessTable" likely handle the witness tables used for protocol conformance.

6. **Identify key data structures and concepts:**  The code mentions "metadata kind," "value witnesses," "type layout," "vtable," "protocols," "conformances." These are fundamental concepts in the Swift runtime.

7. **Recognize potential debugging and inspection use cases:** The ability to extract type names, sizes, layouts, and method information suggests the code is used for runtime inspection and analysis of Swift code.

8. **Consider potential user interaction:**  While the code itself isn't directly user-facing, it would likely be used within a larger Frida script. The comments hint at retrieving metadata for specific Swift objects or types.

9. **Structure the summary:** Organize the findings into logical categories, such as core functionality, specific type inspection, and potential use cases. Use clear and concise language.

10. **Review and refine:** Ensure the summary accurately reflects the code's capabilities based on the analysis. Check for any missed details or areas needing clarification.

By following these steps, the generated summary effectively captures the essence of the provided Swift metadata inspection code within the Frida framework.这是一个Frida动态 instrumentation工具的源代码文件，用于在运行时检查和解析Swift编程语言的元数据信息。

**功能归纳 (第1部分涵盖的功能):**

该文件的主要功能是定义了一系列 JavaScript 类，这些类映射了 Swift 运行时环境中的各种元数据结构。通过这些类，Frida 可以理解和访问 Swift 对象的类型信息、内存布局、以及与协议 (Protocols) 相关的特性。

具体来说，第1部分主要集中在以下几个方面：

1. **基础元数据表示：** 定义了 `TargetValueBuffer` 和 `TargetMetadata` 类，它们是表示 Swift 值的缓冲区和基础元数据的抽象。 `TargetMetadata` 类能够判断元数据的具体类型（类、结构体、枚举）。

2. **具体类型元数据解析：**  定义了 `TargetClassMetadata`、`TargetStructMetadata` 和 `TargetEnumMetadata` 这三个子类，分别用于解析 Swift 类、结构体和枚举的元数据信息。这些类能够提取出类型的描述信息。

3. **值见证表 (Value Witness Table) 的处理：**  定义了 `EnumValueWitnessTable` 类和相关的 `y` 类。值见证表描述了如何操作特定类型的值，例如复制、销毁等。 `EnumValueWitnessTable` 特别针对枚举类型，提供了获取枚举标签和注入枚举标签的功能。

4. **上下文描述符 (Context Descriptor) 的处理：** 定义了 `TargetContextDescriptor`、`TargetModuleContextDescriptor` 和 `TargetTypeContextDescriptor`。 这些类用于表示 Swift 代码的组织结构，包括模块、类型等上下文信息。 通过这些类可以获取类型的完整名称和所属模块。

5. **类特有的元数据解析：** `TargetClassDescriptor` 类继承自 `TargetTypeContextDescriptor`，专门用于解析 Swift 类的特定元数据，例如虚函数表 (VTable)。  它可以判断类是否具有 VTable，并能解析 VTable 中的方法描述符。

6. **结构体和枚举特有的元数据解析：** `TargetStructDescriptor` 和 `TargetEnumDescriptor` 类分别用于解析结构体和枚举的特定元数据，例如结构体的字段数量和偏移量，枚举的有效载荷情况和空状态数量。

7. **协议描述符 (Protocol Descriptor) 的处理：**  定义了 `TargetProtocolDescriptor` 类，用于解析 Swift 协议的元数据信息，例如协议的名称和需求数量。

8. **协议一致性描述符 (Protocol Conformance Descriptor) 的处理：** 定义了 `TargetProtocolConformanceDescriptor` 类，用于表示一个类型如何遵循一个协议。 它可以获取协议本身和类型描述符。

9. **辅助类和枚举：** 定义了一些辅助类和枚举，例如 `TargetValueWitnessFlags`、`MetadataKind`、`ContextDescriptorKind` 等，用于表示元数据中的标志位和类型信息。

**总结来说，该文件是 Frida 中用于理解 Swift 类型系统和元数据的重要组成部分。它定义了用于解析各种 Swift 运行时元数据结构的 JavaScript 类，使得 Frida 能够在运行时自省 Swift 代码的结构和行为。**

在后续的部分中，很可能会继续深入探讨如何利用这些类来获取更详细的 Swift 运行时信息，例如对象的属性、方法调用等。

### 提示词
```
这是目录为frida/build/subprojects/frida-gum/bindings/gumjs/runtime.bundle.p/out-qjs/swift.js的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用gdb指令或者gdb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```javascript
(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
"use strict";

var e, t, s, i, r, a, n, o, d, h, F, l, c, T, u, E, p, g, O, S, f, _, v = this && this.__classPrivateFieldSet || function(e, t, s, i, r) {
  if ("m" === i) throw new TypeError("Private method is not writable");
  if ("a" === i && !r) throw new TypeError("Private accessor was defined without a setter");
  if ("function" == typeof t ? e !== t || !r : !t.has(e)) throw new TypeError("Cannot write private member to an object whose class did not declare it");
  return "a" === i ? r.call(e, s) : r ? r.value = s : t.set(e, s), s;
}, C = this && this.__classPrivateFieldGet || function(e, t, s, i) {
  if ("a" === s && !i) throw new TypeError("Private accessor was defined without a getter");
  if ("function" == typeof t ? e !== t || !i : !t.has(e)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
  return "m" === s ? i : "a" === s ? i.call(e) : i ? i.value : t.get(e);
};

Object.defineProperty(exports, "__esModule", {
  value: !0
}), exports.TargetProtocolConformanceDescriptor = exports.TargetProtocolDescriptor = exports.TargetEnumDescriptor = exports.TargetStructDescriptor = exports.TargetClassDescriptor = exports.TargetTypeContextDescriptor = exports.TargetModuleContextDescriptor = exports.TargetContextDescriptor = exports.EnumValueWitnessTable = exports.TargetEnumMetadata = exports.TargetStructMetadata = exports.TargetClassMetadata = exports.TargetValueMetadata = exports.TargetMetadata = exports.TargetValueBuffer = void 0;

const D = require("./metadatavalues"), M = require("../basic/relativepointer"), m = require("../runtime/heapobject"), w = require("../lib/api");

class I {
  constructor(e) {
    this.privateData = e;
  }
}

exports.TargetValueBuffer = I;

class P {
  constructor(t) {
    this.handle = t, e.set(this, void 0), v(this, e, this.handle.add(P.OFFSETOF_KIND).readU32(), "f");
  }
  getKind() {
    return (0, D.getEnumeratedMetadataKind)(C(this, e, "f"));
  }
  isClassObject() {
    return this.getKind() == D.MetadataKind.Class;
  }
  getValueWitnesses() {
    const e = this.getKind();
    if (e !== D.MetadataKind.Enum && e !== D.MetadataKind.Struct) throw new Error(`Kind does not have a VWT: ${e}`);
    const t = this.handle.sub(Process.pointerSize).readPointer();
    return new y(t);
  }
  getTypeLayout() {
    const e = this.getValueWitnesses();
    return {
      size: e.size,
      stride: e.stride,
      flags: e.flags.data,
      extraInhabitantCount: e.extraInhabitantCount
    };
  }
  vw_initializeWithCopy(e, t) {
    return this.getValueWitnesses().initializeWithCopy(e, t, this.handle);
  }
  vw_getEnumTag(e) {
    return this.getValueWitnesses().asEVWT().getEnumTag(e);
  }
  vw_destructiveInjectEnumTag(e, t) {
    return this.getValueWitnesses().asEVWT().destructiveInjectEnumTag(e, t);
  }
  allocateBoxForExistentialIn(e) {
    if (this.getValueWitnesses().isValueInline()) return e.privateData;
    const t = (0, w.getApi)(), s = new m.BoxPair(t.swift_allocBox(this.handle));
    return e.privateData.writePointer(s.object.handle), s.buffer;
  }
  getFullTypeName() {
    return this.getDescription().getFullTypeName();
  }
  static from(e) {
    switch (new x(e).getKind()) {
     case D.MetadataKind.Class:
      return new N(e);

     case D.MetadataKind.Struct:
      return new A(e);

     case D.MetadataKind.Enum:
      return new R(e);

     default:
      throw new Error("Unknown metadata kind");
    }
  }
  toJSON() {
    return {
      handle: this.handle,
      name: this.getFullTypeName()
    };
  }
}

exports.TargetMetadata = P, e = new WeakMap, P.OFFSETOF_KIND = 0;

class x extends P {
  constructor() {
    super(...arguments), t.set(this, void 0);
  }
  get description() {
    return void 0 === C(this, t, "f") && v(this, t, this.handle.add(x.OFFSETOF_DESCRIPTION).readPointer(), "f"), 
    C(this, t, "f");
  }
  getDescription() {
    return new L(this.description);
  }
}

exports.TargetValueMetadata = x, t = new WeakMap, x.OFFSETOF_DESCRIPTION = Process.pointerSize;

class N extends P {
  constructor() {
    super(...arguments), s.set(this, void 0);
  }
  get description() {
    return void 0 === C(this, s, "f") && v(this, s, this.handle.add(N.OFFSTETOF_DESCRIPTION).readPointer(), "f"), 
    C(this, s, "f");
  }
  getDescription() {
    return new K(this.description);
  }
}

exports.TargetClassMetadata = N, s = new WeakMap, N.OFFSTETOF_DESCRIPTION = 8 * Process.pointerSize;

class A extends x {
  getDescription() {
    return new G(this.description);
  }
}

exports.TargetStructMetadata = A;

class R extends x {
  getDescription() {
    return new B(this.description);
  }
}

exports.TargetEnumMetadata = R;

class y {
  constructor(e) {
    this.handle = e;
    const t = this.handle.add(y.OFFSETOF_INTIALIZE_WITH_COPY).readPointer(), s = new NativeFunction(t, "pointer", [ "pointer", "pointer", "pointer" ]);
    this.initializeWithCopy = (e, t, i) => s(e, t, i), this.size = this.getSize(), this.stride = this.getStride(), 
    this.flags = this.getFlags(), this.extraInhabitantCount = this.getExtraInhabitantCount();
  }
  isValueInline() {
    return this.flags.isInlineStorage;
  }
  getSize() {
    return this.handle.add(y.OFFSETOF_SIZE).readU64().toNumber();
  }
  getStride() {
    return this.handle.add(y.OFFSETOF_STRIDE).readU64().toNumber();
  }
  getAlignmentMask() {
    return this.flags.getAlignmentMask();
  }
  getFlags() {
    const e = this.handle.add(y.OFFSETOF_FLAGS).readU32();
    return new D.TargetValueWitnessFlags(e);
  }
  getExtraInhabitantCount() {
    return this.handle.add(y.OFFSETOF_EXTRA_INHABITANT_COUNT).readU32();
  }
  asEVWT() {
    return new W(this.handle);
  }
}

y.OFFSETOF_INTIALIZE_WITH_COPY = 16, y.OFFSETOF_SIZE = 64, y.OFFSETOF_STRIDE = 72, 
y.OFFSETOF_FLAGS = 80, y.OFFSETOF_EXTRA_INHABITANT_COUNT = 84;

class W extends y {
  constructor(e) {
    super(e);
    let t = this.handle.add(W.OFFSETOF_GET_ENUM_TAG).readPointer();
    const s = new NativeFunction(t, "uint32", [ "pointer", "pointer" ]);
    this.getEnumTag = e => s(e, this.handle), t = this.handle.add(W.OFFSETOF_DESTRUCTIVE_INJECT_ENUM_TAG).readPointer();
    const i = new NativeFunction(t, "void", [ "pointer", "uint32", "pointer" ]);
    this.destructiveInjectEnumTag = (e, t) => i(e, t, this.handle);
  }
}

exports.EnumValueWitnessTable = W, W.OFFSETOF_GET_ENUM_TAG = 88, W.OFFSETOF_DESTRUCTIVE_INJECT_ENUM_TAG = 104;

class b {
  constructor(e) {
    this.handle = e, i.set(this, void 0), r.set(this, void 0);
  }
  get flags() {
    if (null != C(this, i, "f")) return C(this, i, "f");
    const e = this.handle.add(b.OFFSETOF_FLAGS).readU32();
    return new Z(e);
  }
  get parent() {
    return void 0 !== C(this, r, "f") || v(this, r, M.RelativeIndirectablePointer.From(this.handle.add(b.OFFSETOF_PARENT)), "f"), 
    C(this, r, "f");
  }
  isGeneric() {
    return this.flags.isGeneric();
  }
  getKind() {
    return this.flags.getKind();
  }
  getModuleContext() {
    let e = new V(this.parent.get());
    for (;e.flags.getKind() !== D.ContextDescriptorKind.Module; ) e = new V(e.parent.get());
    return e;
  }
}

exports.TargetContextDescriptor = b, i = new WeakMap, r = new WeakMap, b.OFFSETOF_FLAGS = 0, 
b.OFFSETOF_PARENT = 4;

class V extends b {
  constructor() {
    super(...arguments), a.set(this, void 0);
  }
  get name() {
    if (void 0 !== C(this, a, "f")) return C(this, a, "f");
    const e = this.handle.add(V.OFFSETOF_NAME), t = M.RelativeDirectPointer.From(e).get();
    return v(this, a, t.readCString(), "f"), C(this, a, "f");
  }
}

exports.TargetModuleContextDescriptor = V, a = new WeakMap, V.OFFSETOF_NAME = 8;

class U extends b {
  constructor() {
    super(...arguments), n.set(this, void 0), o.set(this, void 0), d.set(this, void 0);
  }
  getTypeContextDescriptorFlags() {
    return new D.TypeContextDescriptorFlags(this.flags.getKindSpecificFlags());
  }
  get name() {
    if (void 0 !== C(this, n, "f")) return C(this, n, "f");
    const e = M.RelativeDirectPointer.From(this.handle.add(U.OFFSETOF_NAME)).get();
    return v(this, n, e.readUtf8String(), "f"), C(this, n, "f");
  }
  get accessFunctionPointer() {
    return void 0 !== C(this, o, "f") ? C(this, o, "f") : M.RelativeDirectPointer.From(this.handle.add(U.OFFSETOF_ACCESS_FUNCTION_PTR)).get();
  }
  get fields() {
    return void 0 !== C(this, d, "f") ? C(this, d, "f") : M.RelativeDirectPointer.From(this.handle.add(U.OFFSETOF_FIELDS));
  }
  isReflectable() {
    return null !== this.fields;
  }
  getAccessFunction() {
    return new NativeFunction(this.accessFunctionPointer, "pointer", []);
  }
  getFullTypeName() {
    return `${this.getModuleContext().name}.${this.name}`;
  }
}

exports.TargetTypeContextDescriptor = U, n = new WeakMap, o = new WeakMap, d = new WeakMap, 
U.OFFSETOF_NAME = 8, U.OFFSETOF_ACCESS_FUNCTION_PTR = 12, U.OFFSETOF_FIELDS = 16;

class L extends U {}

class K extends U {
  hasVTable() {
    return this.getTypeContextDescriptorFlags().class_hasVTable();
  }
  hasResilientSuperClass() {
    return this.getTypeContextDescriptorFlags().class_hasResilientSuperClass();
  }
  hasOverrideTable() {
    return this.getTypeContextDescriptorFlags().class_hasOverrideTable();
  }
  hasSingletonMetadataInitialization() {
    return this.getTypeContextDescriptorFlags().hasSingletonMetadataInitialization();
  }
  hasForeignMetadataInitialization() {
    return this.getTypeContextDescriptorFlags().hasForeignMetadataInitialization();
  }
  getVTableDescriptor() {
    if (!this.hasVTable()) return null;
    const e = this.handle.add(K.OFFSETOF_TARGET_VTABLE_DESCRIPTOR_HEADER);
    return new k(e);
  }
  getMethodDescriptors() {
    const e = [];
    if (!this.hasVTable() || this.isGeneric() || this.hasResilientSuperClass() || this.hasOverrideTable() || this.hasSingletonMetadataInitialization() || this.hasForeignMetadataInitialization()) return e;
    const t = this.getVTableDescriptor().vtableSize;
    let s = this.handle.add(K.OFFSETOF_METHOD_DESCRIPTORS);
    const i = s.add(t * z.sizeof);
    for (;!s.equals(i); s = s.add(z.sizeof)) {
      const t = new z(s);
      null !== t.impl && e.push(t);
    }
    return e;
  }
}

exports.TargetClassDescriptor = K, K.OFFSETOF_TARGET_VTABLE_DESCRIPTOR_HEADER = 44, 
K.OFFSETOF_METHOD_DESCRIPTORS = 52;

class k {
  constructor(e) {
    this.handle = e, h.set(this, void 0);
  }
  get vtableSize() {
    return void 0 !== C(this, h, "f") ? C(this, h, "f") : this.handle.add(k.OFFSETOF_VTABLE_SIZE).readU32();
  }
}

h = new WeakMap, k.OFFSETOF_VTABLE_OFFSET = 0, k.OFFSETOF_VTABLE_SIZE = 4;

class z {
  constructor(e) {
    this.handle = e, F.set(this, void 0), l.set(this, void 0);
  }
  get flags() {
    if (void 0 !== C(this, F, "f")) return C(this, F, "f");
    const e = this.handle.add(z.OFFSETOF_FLAGS).readU32();
    return new D.MethodDescriptorFlags(e);
  }
  get impl() {
    if (void 0 !== C(this, l, "f")) return C(this, l, "f");
    const e = this.handle.add(z.OFFSETOF_IMPL);
    return M.RelativeDirectPointer.From(e);
  }
}

F = new WeakMap, l = new WeakMap, z.OFFSETOF_FLAGS = 0, z.OFFSETOF_IMPL = 4, z.sizeof = 8;

class G extends U {
  constructor() {
    super(...arguments), c.set(this, void 0), T.set(this, void 0);
  }
  hasFieldOffsetVector() {
    return 0 !== this.fieldOffsetVectorOffset;
  }
  get numFields() {
    return void 0 !== C(this, c, "f") ? C(this, c, "f") : this.handle.add(G.OFFSETOF_NUM_FIELDS).readU32();
  }
  get fieldOffsetVectorOffset() {
    return void 0 !== C(this, T, "f") ? C(this, T, "f") : this.handle.add(G.OFFSETOF_FIELD_OFFSET_VECTOR_OFFSET).readU32();
  }
}

exports.TargetStructDescriptor = G, c = new WeakMap, T = new WeakMap, G.OFFSETOF_NUM_FIELDS = 24, 
G.OFFSETOF_FIELD_OFFSET_VECTOR_OFFSET = 28;

class B extends U {
  constructor() {
    super(...arguments), u.set(this, void 0), E.set(this, void 0);
  }
  get numPayloadCasesAndPayloaadSizeOffset() {
    if (void 0 === C(this, u, "f")) {
      const e = this.handle.add(B.OFFSETOF_NUM_PAYLOAD_CASES_AND_PAYLOAD_SIZE_OFFSET).readU32();
      v(this, u, e, "f");
    }
    return C(this, u, "f");
  }
  get numEmptyCases() {
    return void 0 === C(this, E, "f") && v(this, E, this.handle.add(B.OFFSETOF_NUM_EMPTY_CASES).readU32(), "f"), 
    C(this, E, "f");
  }
  getNumPayloadCases() {
    return 16777215 & this.numPayloadCasesAndPayloaadSizeOffset;
  }
  getNumEmptyCases() {
    return this.numEmptyCases;
  }
  getNumCases() {
    return this.getNumPayloadCases() + this.numEmptyCases;
  }
  isPayloadTag(e) {
    return this.getNumCases() > 0 && e < this.getNumPayloadCases();
  }
}

exports.TargetEnumDescriptor = B, u = new WeakMap, E = new WeakMap, B.OFFSETOF_NUM_PAYLOAD_CASES_AND_PAYLOAD_SIZE_OFFSET = 20, 
B.OFFSETOF_NUM_EMPTY_CASES = 24;

class j extends b {
  constructor(e) {
    super(e), p.set(this, void 0), g.set(this, void 0);
  }
  get name() {
    if (void 0 === C(this, p, "f")) {
      const e = M.RelativeDirectPointer.From(this.handle.add(j.OFFSETOF_NAME)).get();
      v(this, p, e.readCString(), "f");
    }
    return C(this, p, "f");
  }
  get numRequirements() {
    if (void 0 === C(this, g, "f")) {
      const e = this.handle.add(j.OFFSETOF_NUM_REQUIREMENTS);
      v(this, g, e.readU32(), "f");
    }
    return C(this, g, "f");
  }
  getProtocolContextDescriptorFlags() {
    return new D.ProtocolContextDescriptorFlags(this.flags.getKindSpecificFlags());
  }
  getFullProtocolName() {
    return this.getModuleContext().name + "." + this.name;
  }
}

exports.TargetProtocolDescriptor = j, p = new WeakMap, g = new WeakMap, j.OFFSETOF_NAME = 8, 
j.OFFSETOF_NUM_REQUIREMENTS = 16;

class Y {
  constructor(e) {
    this.handle = e;
  }
  getTypeDescriptor(e) {
    let t = null;
    switch (e) {
     case D.TypeReferenceKind.DirectTypeDescriptor:
      t = M.RelativeDirectPointer.From(this.handle).get();
      break;

     case D.TypeReferenceKind.IndirectTypeDescriptor:
      t = M.RelativeDirectPointer.From(this.handle).get(), t = t.readPointer();

     case D.TypeReferenceKind.DirectObjCClassName:
     case D.TypeReferenceKind.IndirectObjCClass:
    }
    return t;
  }
}

class H {
  constructor(e) {
    this.handle = e, O.set(this, void 0), S.set(this, void 0), f.set(this, void 0), 
    _.set(this, void 0);
  }
  get protocol() {
    return void 0 === C(this, O, "f") && v(this, O, M.RelativeIndirectablePointer.From(this.handle.add(H.OFFSETOF_PROTOTCOL)).get(), "f"), 
    C(this, O, "f");
  }
  get typeRef() {
    if (void 0 === C(this, S, "f")) {
      const e = this.handle.add(H.OFFSETOF_TYPE_REF);
      v(this, S, new Y(e), "f");
    }
    return C(this, S, "f");
  }
  get witnessTablePattern() {
    if (void 0 === C(this, f, "f")) {
      const e = M.RelativeDirectPointer.From(this.handle.add(H.OFFSTEOF_WITNESS_TABLE_PATTERN));
      v(this, f, e ? e.get() : null, "f");
    }
    return C(this, f, "f");
  }
  get flags() {
    if (void 0 === C(this, _, "f")) {
      const e = this.handle.add(H.OFFSETOF_FLAGS);
      v(this, _, new D.ConformanceFlags(e.readU32()), "f");
    }
    return C(this, _, "f");
  }
  getTypeKind() {
    return this.flags.getTypeReferenceKind();
  }
  getTypeDescriptor() {
    return this.typeRef.getTypeDescriptor(this.getTypeKind());
  }
}

exports.TargetProtocolConformanceDescriptor = H, O = new WeakMap, S = new WeakMap, 
f = new WeakMap, _ = new WeakMap, H.OFFSETOF_PROTOTCOL = 0, H.OFFSETOF_TYPE_REF = 4, 
H.OFFSTEOF_WITNESS_TABLE_PATTERN = 8, H.OFFSETOF_FLAGS = 12, H.OFFSETOF_WITNESS_TABLE_PATTERN = 16;

class Z {
  constructor(e) {
    this.value = e;
  }
  getKind() {
    return 31 & this.value;
  }
  isGeneric() {
    return !!(128 & this.value);
  }
  getIntValue() {
    return this.value;
  }
  getKindSpecificFlags() {
    return this.value >>> 16 & 65535;
  }
}

},{"../basic/relativepointer":3,"../lib/api":5,"../runtime/heapobject":15,"./metadatavalues":2}],2:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: !0
}), exports.ProtocolContextDescriptorFlags = exports.ProtocolClassConstraint = exports.ConformanceFlags = exports.TypeReferenceKind = exports.MethodDescriptorFlags = exports.MethodDescriptorKind = exports.TypeContextDescriptorFlags = exports.ContextDescriptorKind = exports.getEnumeratedMetadataKind = exports.MetadataKind = exports.TargetValueWitnessFlags = exports.NumWords_ValueBuffer = void 0, 
exports.NumWords_ValueBuffer = 3;

const t = 512;

var e, a, s, i, n, r, o, l, d;

!function(t) {
  t[t.AlignmentMask = 255] = "AlignmentMask", t[t.IsNonPOD = 65536] = "IsNonPOD", 
  t[t.IsNonInline = 131072] = "IsNonInline", t[t.HasSpareBits = 524288] = "HasSpareBits", 
  t[t.IsNonBitwiseTakable = 1048576] = "IsNonBitwiseTakable", t[t.HasEnumWitnesses = 2097152] = "HasEnumWitnesses", 
  t[t.Incomplete = 4194304] = "Incomplete";
}(e || (e = {}));

class c {
  constructor(t) {
    this.data = t;
  }
  get isInlineStorage() {
    return !(this.data & e.IsNonInline);
  }
  get isPOD() {
    return !(this.data & e.IsNonPOD);
  }
  get isBitwiseTakable() {
    return !(this.data & e.IsNonBitwiseTakable);
  }
  getAlignmentMask() {
    return this.data & e.AlignmentMask;
  }
}

function u(t) {
  return t > a.LastEnumerated ? a.Class : t;
}

exports.TargetValueWitnessFlags = c, function(t) {
  t[t.Class = 0] = "Class", t[t.Struct = 512] = "Struct", t[t.Enum = 513] = "Enum", 
  t[t.LastEnumerated = 2047] = "LastEnumerated";
}(a = exports.MetadataKind || (exports.MetadataKind = {})), exports.getEnumeratedMetadataKind = u, 
function(t) {
  t[t.Module = 0] = "Module", t[t.Extension = 1] = "Extension", t[t.Anonymous = 2] = "Anonymous", 
  t[t.Protocol = 3] = "Protocol", t[t.OpaqueType = 4] = "OpaqueType", t[t.TypeFirst = 16] = "TypeFirst", 
  t[t.Class = 16] = "Class", t[t.Struct = 17] = "Struct", t[t.Enum = 18] = "Enum";
}(s = exports.ContextDescriptorKind || (exports.ContextDescriptorKind = {})), function(t) {
  t[t.MetadataInitialization = 0] = "MetadataInitialization", t[t.MetadataInitialization_width = 2] = "MetadataInitialization_width", 
  t[t.Class_ResilientSuperclassReferenceKind = 9] = "Class_ResilientSuperclassReferenceKind", 
  t[t.Class_HasResilientSuperclass = 13] = "Class_HasResilientSuperclass", t[t.Class_HasOverrideTable = 14] = "Class_HasOverrideTable", 
  t[t.Class_HasVTable = 15] = "Class_HasVTable";
}(i || (i = {})), function(t) {
  t[t.NoMetadataInitialization = 0] = "NoMetadataInitialization", t[t.SingletonMetadataInitialization = 1] = "SingletonMetadataInitialization", 
  t[t.ForeignMetadataInitialization = 2] = "ForeignMetadataInitialization";
}(n || (n = {}));

class p {
  constructor(t) {
    this.value = t;
  }
  class_hasVTable() {
    return !!(this.value & 1 << i.Class_HasVTable);
  }
  class_hasResilientSuperClass() {
    return !!(this.value & 1 << i.Class_HasResilientSuperclass);
  }
  class_hasOverrideTable() {
    return !!(this.value & 1 << i.Class_HasOverrideTable);
  }
  getMetadataInitialization() {
    return C(this.value, i.MetadataInitialization, i.MetadataInitialization_width);
  }
  hasSingletonMetadataInitialization() {
    return this.getMetadataInitialization() === n.SingletonMetadataInitialization;
  }
  hasForeignMetadataInitialization() {
    return this.getMetadataInitialization() === n.ForeignMetadataInitialization;
  }
}

function C(t, e, a) {
  return t >>> e & ~(-1 << a);
}

exports.TypeContextDescriptorFlags = p, function(t) {
  t[t.Method = 0] = "Method", t[t.Init = 1] = "Init", t[t.Getter = 2] = "Getter", 
  t[t.Setter = 3] = "Setter", t[t.ModifyCoroutine = 4] = "ModifyCoroutine", t[t.ReadCoroutine = 5] = "ReadCoroutine";
}(r = exports.MethodDescriptorKind || (exports.MethodDescriptorKind = {}));

class M {
  constructor(t) {
    this.value = t;
  }
  getKind() {
    return this.value & M.KindMask;
  }
}

exports.MethodDescriptorFlags = M, M.KindMask = 15, function(t) {
  t[t.DirectTypeDescriptor = 0] = "DirectTypeDescriptor", t[t.IndirectTypeDescriptor = 1] = "IndirectTypeDescriptor", 
  t[t.DirectObjCClassName = 2] = "DirectObjCClassName", t[t.IndirectObjCClass = 3] = "IndirectObjCClass";
}(o = exports.TypeReferenceKind || (exports.TypeReferenceKind = {})), function(t) {
  t[t.TypeMetadataKindMask = 56] = "TypeMetadataKindMask", t[t.TypeMetadataKindShift = 3] = "TypeMetadataKindShift";
}(l || (l = {}));

class I {
  constructor(t) {
    this.value = t;
  }
  getTypeReferenceKind() {
    return (this.value & l.TypeMetadataKindMask) >> l.TypeMetadataKindShift;
  }
}

exports.ConformanceFlags = I;

class h {}

exports.ProtocolClassConstraint = h, h.Class = !1, h.Any = !0, function(t) {
  t[t.HasClassConstratint = 0] = "HasClassConstratint", t[t.HasClassConstratint_width = 1] = "HasClassConstratint_width";
}(d || (d = {}));

class x {
  constructor(t) {
    this.bits = t;
  }
  getClassConstraint() {
    return !!(this.bits & 1 << d.HasClassConstratint);
  }
}

exports.ProtocolContextDescriptorFlags = x;

},{}],3:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: !0
}), exports.RelativeIndirectablePointer = exports.RelativeDirectPointer = void 0;

class e {
  constructor(e, t) {
    this.handle = e, this.offset = t;
  }
  static From(t) {
    const r = t.readS32();
    return 0 === r ? null : new e(t, r);
  }
  get() {
    return this.handle.add(this.offset);
  }
}

exports.RelativeDirectPointer = e, e.sizeOf = 4;

class t {
  constructor(e, t) {
    this.handle = e, this.offset = t;
  }
  static From(e) {
    const r = e.readS32();
    return 0 === r ? null : new t(e, r);
  }
  get() {
    const e = this.handle.add(-2 & this.offset);
    return 1 & this.offset ? e.readPointer() : e;
  }
}

exports.RelativeIndirectablePointer = t;

},{}],4:[function(require,module,exports){
"use strict";

var t, e, r = this && this.__classPrivateFieldGet || function(t, e, r, i) {
  if ("a" === r && !i) throw new TypeError("Private accessor was defined without a getter");
  if ("function" == typeof e ? t !== e || !i : !e.has(t)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
  return "m" === r ? i : "a" === r ? i.call(t) : i ? i.value : e.get(t);
}, i = this && this.__classPrivateFieldSet || function(t, e, r, i, s) {
  if ("m" === i) throw new TypeError("Private method is not writable");
  if ("a" === i && !s) throw new TypeError("Private accessor was defined without a setter");
  if ("function" == typeof e ? t !== e || !s : !e.has(t)) throw new TypeError("Cannot write private member to an object whose class did not declare it");
  return "a" === i ? s.call(t, r) : s ? s.value = r : e.set(t, r), r;
};

const s = require("./lib/api"), o = require("./lib/types"), n = require("./lib/callingconvention"), a = require("./lib/registry"), c = require("./lib/interceptor"), l = require("./lib/symbols");

class u {
  constructor() {
    t.set(this, null), e.set(this, null), this.Object = o.ObjectInstance, this.Struct = o.StructValue, 
    this.Enum = o.EnumValue, this.ProtocolComposition = o.ProtocolComposition, this.Interceptor = c.SwiftInterceptor;
    try {
      this.tryInitialize();
    } catch (t) {}
  }
  get available() {
    try {
      return this.tryInitialize();
    } catch (t) {
      return !1;
    }
  }
  get api() {
    return r(this, t, "f");
  }
  get modules() {
    return a.Registry.shared().modules;
  }
  get classes() {
    return a.Registry.shared().classes;
  }
  get structs() {
    return a.Registry.shared().structs;
  }
  get enums() {
    return a.Registry.shared().enums;
  }
  get protocols() {
    return a.Registry.shared().protocols;
  }
  NativeFunction(t, e, r, i, s) {
    function a(t) {
      return t instanceof o.Type ? t.$metadata : t instanceof o.Protocol ? new o.ProtocolComposition(t) : t;
    }
    const c = a(e), l = r.map((t => a(t)));
    return (0, n.makeSwiftNativeFunction)(t, c, l, i, s);
  }
  tryInitialize() {
    if (null !== r(this, t, "f")) return !0;
    if (null !== r(this, e, "f")) throw r(this, e, "f");
    try {
      i(this, t, (0, s.getApi)(), "f"), (0, s.getPrivateAPI)(), (0, l.getSymbolicator)();
    } catch (t) {
      throw i(this, e, t, "f"), t;
    }
    return null !== r(this, t, "f");
  }
}

t = new WeakMap, e = new WeakMap, module.exports = new u;

},{"./lib/api":5,"./lib/callingconvention":7,"./lib/interceptor":8,"./lib/registry":10,"./lib/symbols":11,"./lib/types":12}],5:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: !0
}), exports.getPrivateAPI = exports.getApi = void 0;

const e = [ "pointer", "pointer" ];

let o = null, t = null;

function i() {
  if ("arm64" !== Process.arch || "darwin" !== Process.platform) throw new Error("Only arm64(e) Darwin is currently supported");
  if (null !== o) return o;
  o = n([ {
    module: "libswiftCore.dylib",
    functions: {
      swift_demangle: [ "pointer", [ "pointer", "size_t", "pointer", "pointer", "int32" ] ]
    }
  } ]);
  const e = n([ {
    module: "libswiftCore.dylib",
    functions: {
      swift_allocBox: [ [ "pointer", "pointer" ], [ "pointer" ] ]
    }
  } ]);
  return o = Object.assign(o, e), o;
}

function r() {
  if (null !== t) return t;
  if (Module.ensureInitialized("CoreFoundation"), null === Process.findModuleByName("CoreSymbolication")) try {
    Module.load("/System/Library/PrivateFrameworks/CoreSymbolication.framework/CoreSymbolication");
  } catch (e) {
    Module.load("/System/Library/PrivateFrameworks/CoreSymbolication.framework/Versions/A/CoreSymbolication");
  }
  return t = n([ {
    module: "libmacho.dylib",
    functions: {
      getsectiondata: [ "pointer", [ "pointer", "pointer", "pointer", "pointer" ] ]
    }
  }, {
    module: "CoreSymbolication",
    functions: {
      CSSymbolicatorCreateWithPid: [ e, [ "int" ] ],
      CSSymbolicatorCreateWithTask: [ e, [ "uint" ] ],
      CSSymbolicatorGetSymbolWithAddressAtTime: [ e, [ e, "pointer", "uint64" ] ],
      CSIsNull: [ "bool", [ e ] ],
      CSSymbolGetMangledName: [ "pointer", [ e ] ],
      CSRelease: [ "void", [ e ] ]
    }
  }, {
    module: "libsystem_kernel.dylib",
    functions: {
      mach_task_self: [ "uint", [] ]
    }
  } ]), t;
}

function n(e) {
  const o = {};
  for (const t of e) {
    const e = Process.getModuleByName(t.module);
    Module.ensureInitialized(e.name);
    for (const [i, [r, n]] of Object.entries(t.functions)) {
      const t = e.getExportByName(i);
      o[i] = new NativeFunction(t, r, n);
    }
  }
  return o;
}

exports.getApi = i, exports.getPrivateAPI = r;

},{}],6:[function(require,module,exports){
"use strict";

function e(e) {
  Array.isArray(e) || (e = [ e ]);
  const r = Process.pointerSize * e.length, o = Memory.alloc(r);
  for (let t = 0, s = 0; s < r; t++, s += Process.pointerSize) {
    const r = e[t], n = o.add(s);
    r instanceof NativePointer ? n.writePointer(r) : n.writeU64(r);
  }
  return o;
}

function r(e, r) {
  const o = [];
  for (let t = 0; t < r; t += 8) o.push(e.add(t).readU64());
  return o;
}

function o(e, r) {
  const o = Process.pointerSize * e.length;
  for (let t = 0, s = 0; s < o; t++, s += Process.pointerSize) r.add(s).writeU64(e[t]);
}

function t(e) {
  return (e = e < 8 ? 8 : e) / 8;
}

Object.defineProperty(exports, "__esModule", {
  value: !0
}), exports.sizeInQWordsRounded = exports.moveValueToBuffer = exports.makeValueFromBuffer = exports.makeBufferFromValue = void 0, 
exports.makeBufferFromValue = e, exports.makeValueFromBuffer = r, exports.moveValueToBuffer = o, 
exports.sizeInQWordsRounded = t;

},{}],7:[function(require,module,exports){
"use strict";

var e, t, r, s, i, n, a, o, u = this && this.__classPrivateFieldGet || function(e, t, r, s) {
  if ("a" === r && !s) throw new TypeError("Private accessor was defined without a getter");
  if ("function" == typeof t ? e !== t || !s : !t.has(e)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
  return "m" === r ? s : "a" === r ? s.call(e) : s ? s.value : t.get(e);
}, c = this && this.__classPrivateFieldSet || function(e, t, r, s, i) {
  if ("m" === s) throw new TypeError("Private method is not writable");
  if ("a" === s && !i) throw new TypeError("Private accessor was defined without a setter");
  if ("function" == typeof t ? e !== t || !i : !t.has(e)) throw new TypeError("Cannot write private member to an object whose class did not declare it");
  return "a" === s ? i.call(e, r) : i ? i.value = r : t.set(e, r), r;
};

Object.defineProperty(exports, "__esModule", {
  value: !0
}), exports.SwiftcallNativeFunction = exports.shouldPassIndirectly = exports.makeSwiftNativeFunction = exports.INDRIECT_RETURN_REGISTER = exports.MAX_LOADABLE_SIZE = void 0;

const l = require("./types"), f = require("../abi/metadata"), d = require("../runtime/existentialcontainer"), h = require("./macho"), p = require("../abi/metadatavalues"), g = require("./buffer");

exports.MAX_LOADABLE_SIZE = 4 * Process.pointerSize, exports.INDRIECT_RETURN_REGISTER = "x8";

class w {
  static get currentPage() {
    return w.pages[w.pages.length - 1];
  }
  static _initialize() {
    w.pages = [ Memory.alloc(Process.pageSize) ], w.currentSlot = w.currentPage;
  }
  static allocateTrampoline(e) {
    void 0 === w.pages && w._initialize();
    let t = w.currentPage;
    const r = t.add(Process.pageSize);
    w.currentSlot.add(e).compare(r) > 0 && (t = Memory.alloc(Process.pageSize), w.pages.push(t));
    const s = w.currentSlot;
    return w.currentSlot = w.currentSlot.add(e), s;
  }
}

function m(e, t, r, s, i) {
  const n = r.map((e => y(e))), a = y(t), o = new A(e, a, n, s).wrapper;
  return Object.assign((function(...e) {
    const s = [];
    for (const [t, i] of e.entries()) {
      const e = r[t];
      if ("string" == typeof e || Array.isArray(e)) {
        s.push(i);
        continue;
      }
      if (e instanceof f.TargetMetadata) {
        s.push(v(i));
        continue;
      }
      const n = e, a = i.$metadata;
      let o;
      if (n.isClassOnly) o = d.ClassExistentialContainer.alloc(n.numProtocols), o.value = i.handle; else if (o = d.TargetOpaqueExistentialContainer.alloc(n.numProtocols), 
      o.type = a, a.isClassObject()) o.buffer.privateData.writePointer(i.handle); else {
        const e = a.allocateBoxForExistentialIn(o.buffer);
        a.vw_initializeWithCopy(e, i.handle);
      }
      const u = o.getWitnessTables();
      for (const [e, t] of n.protocols.entries()) {
        const r = a.getFullTypeName(), s = (0, h.getProtocolConformancesFor)(r)[t.name];
        if (void 0 === s) throw new Error(`Type ${r} does not conform to protocol ${t.name}`);
        const i = s.witnessTable;
        u.add(e * Process.pointerSize).writePointer(i);
      }
      s.push(v(o));
    }
    const i = o(...s);
    if ("string" == typeof t || Array.isArray(t)) return i;
    if (t instanceof f.TargetMetadata) switch (t.getKind()) {
     case p.MetadataKind.Struct:
      return new l.StructValue(t, {
        raw: i
      });

     case p.MetadataKind.Enum:
      return new l.EnumValue(t, {
        raw: i
      });

     case p.MetadataKind.Class:
      return new l.ObjectInstance(i);

     default:
      throw new Error("Unimplemented kind: " + t.getKind());
    }
    const n = (0, g.makeBufferFromValue)(i);
    return l.ValueInstance.fromExistentialContainer(n, t);
  }), {
    address: e
  });
}

function y(e) {
  if ("string" == typeof e || Array.isArray(e)) return e;
  if (e instanceof l.ProtocolComposition) {
    const t = Array(e.numProtocols).fill("pointer");
    return e.isClassOnly ? [ "pointer", ...t ] : [ "pointer", "pointer", "pointer", "pointer", ...t ];
  }
  if (e.getKind() === p.MetadataKind.Class || x(e)) return "pointer";
  let t = e.getTypeLayout().stride / 8;
  return t = t > 1 ? t : 1, Array(t).fill("uint64");
}

function v(e) {
  if (e instanceof l.ObjectInstance) return e.handle;
  if (e instanceof d.TargetOpaqueExistentialContainer) return (0, g.makeValueFromBuffer)(e.handle, e.sizeof);
  if (e instanceof d.ClassExistentialContainer) {
    const t = e, r = [];
    for (let e = 0; e != t.sizeof; e += 8) r.push(t.handle.add(e).readPointer());
    return r;
  }
  return x(e.$metadata) ? e.handle : (0, g.makeValueFromBuffer)(e.handle, e.$metadata.get
```