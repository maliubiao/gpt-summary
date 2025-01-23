Response: Let's break down the thought process for analyzing the C++ code and generating the summary and JavaScript example.

1. **Understand the Goal:** The request asks for a summary of the C++ file's functionality and a JavaScript example illustrating its connection to JavaScript. This means I need to identify the core purpose of the code and how it facilitates the interaction between WebAssembly and JavaScript within V8.

2. **High-Level Overview (Skimming the Code):**  I'll quickly skim the code, looking for keywords and patterns that suggest the file's role. I see things like `WasmGraphAssembler`, `Node*`, `simplified_`, `machine()`, `Allocate`, `LoadFromObject`, `StoreToObject`, `Map`, `FixedArray`, `JSFunction`, `WasmGC`, etc. These immediately point towards compiler infrastructure for WebAssembly, specifically related to generating an intermediate representation (likely a graph) for optimization and code generation.

3. **Identify the Core Class:** The name `WasmGraphAssembler` is the most prominent clue. The term "assembler" suggests it's involved in building something, and "graph" hints at a graph-based intermediate representation. The "Wasm" prefix clearly indicates it's related to WebAssembly.

4. **Analyze Key Methods and Concepts:** Now, I'll delve deeper into the code, focusing on the most common and important methods:

    * **`Branch`:**  A fundamental control flow operation in compilers. This confirms it's building a control flow graph.
    * **`Allocate`:**  Memory allocation, necessary for creating objects in the Wasm heap.
    * **`LoadFromObject`, `StoreToObject`:**  Accessing fields of objects. This is crucial for interacting with Wasm memory and JavaScript objects. The `ObjectAccess` parameter reinforces this idea of controlled access.
    * **`LoadMap`, `StoreMap`, `LoadInstanceType`:**  Operations related to object metadata (maps), essential for V8's object model and type checking.
    * **`LoadFixedArray...`, `StoreFixedArray...`:** Operations on fixed-size arrays, a common data structure.
    * **`LoadJSArrayElements`:**  Specifically interacting with JavaScript arrays. This is a strong indicator of the bridge between Wasm and JS.
    * **`FieldOffset`, `WasmArrayElementOffset`:**  Calculating memory offsets for accessing Wasm data structures.
    * **`WasmTypeCheck`, `WasmTypeCast`:**  Type-related operations for Wasm's type system.
    * **`Null`, `IsNull`, `IsNotNull`, `AssertNotNull`:** Handling null values in Wasm.
    * **`WasmAnyConvertExtern`, `WasmExternConvertAny`:**  Conversion between Wasm's `anyref`/`externref` types and JavaScript values. This is a *key* connection point.
    * **`StructGet`, `StructSet`, `ArrayGet`, `ArraySet`, `ArrayLength`:** Operations on Wasm GC (Garbage Collected) objects (structs and arrays).
    * **Methods involving "TrustedPointer", "ProtectedPointer", "Sandboxed":** These suggest security features and handling of pointers that might cross isolation boundaries.

5. **Identify Relationships to JavaScript:** The presence of methods like `LoadJSArrayElements`, `LoadContextFromJSFunction`, `LoadFunctionDataFromJSFunction`, and especially `WasmAnyConvertExtern` and `WasmExternConvertAny` clearly indicates the code is involved in the interaction between Wasm and JavaScript. The conversion methods are the most direct link.

6. **Formulate the Summary:** Based on the analysis, I can now summarize the file's purpose: it provides a set of building blocks for generating the intermediate representation (a graph) of WebAssembly code within the V8 JavaScript engine's compiler. This involves operations for memory management, object access, control flow, type checking, and crucially, interaction with JavaScript objects.

7. **Construct the JavaScript Example:** To illustrate the connection, I need a JavaScript scenario where Wasm interacts with JS. The `WasmAnyConvertExtern` and `WasmExternConvertAny` methods are the perfect fit.

    * **Scenario:**  Wasm needs to receive a JavaScript value and potentially pass a Wasm value back to JavaScript.
    * **JavaScript Side:**  Create a JavaScript function that calls a Wasm function, passing a JS value. Also, potentially have the Wasm function return a value.
    * **Wasm Side (Conceptual):** The `WasmGraphAssembler` would generate code using `WasmAnyConvertExtern` when the Wasm function receives the JavaScript value and `WasmExternConvertAny` when it returns a value to JavaScript.

8. **Refine the Example and Explanation:** Make the JavaScript example clear and concise. Explain how the C++ functions (`WasmAnyConvertExtern`, `WasmExternConvertAny`) are the underlying mechanisms that enable the seamless passing of values between JavaScript and WebAssembly, handling the necessary type conversions and representations. Highlight that this happens *under the hood* during the compilation process.

9. **Review and Verify:** Read through the summary and example to ensure they are accurate, well-explained, and directly address the prompt's requirements. Make sure the JavaScript code is valid and the explanation correctly connects the C++ functionality to the JS behavior. For example, I initially might have focused too much on low-level memory operations, but the request specifically asked about the *JavaScript* connection, so emphasizing the conversion functions is crucial.

This iterative process of skimming, deep-diving into key parts, identifying connections, and then summarizing and illustrating helps to accurately understand and explain the functionality of the given C++ code in relation to JavaScript.
这个C++源代码文件 `wasm-graph-assembler.cc` 定义了一个名为 `WasmGraphAssembler` 的类，其主要功能是 **构建 WebAssembly 代码的图表示**，用于 V8 JavaScript 引擎的编译器进行优化和代码生成。

更具体地说，`WasmGraphAssembler` 提供了一系列方法，用于在 V8 的 **TurboFan 图形中间表示 (IR)** 中创建和连接节点，这些节点代表了 WebAssembly 操作。  它充当了一个方便的接口，隐藏了直接操作 TurboFan 图的复杂性，使得 WebAssembly 编译器的开发者能够更容易地生成正确的图结构。

以下是 `WasmGraphAssembler` 的一些关键功能点：

* **基本图操作:**  提供创建分支 (`Branch`)、控制流节点等基本图结构的方法。
* **类型转换:** 提供了 WebAssembly 中常见的类型转换操作，例如整数类型之间的转换 (`BuildTruncateIntPtrToInt32`, `BuildChangeInt32ToIntPtr` 等)，以及与 Smi (Small Integer) 之间的转换 (`BuildChangeInt32ToSmi`, `BuildChangeSmiToInt32`).
* **内存操作:** 提供了分配内存 (`Allocate`)、从对象加载数据 (`LoadFromObject`, `LoadImmutableFromObject`) 和存储数据到对象 (`StoreToObject`, `InitializeImmutableInObject`) 的方法。这些方法考虑了内存屏障等细节。
* **对象访问:**  提供了访问 V8 堆中各种对象 (如 `Map`, `FixedArray`, `JSFunction`, `WasmGC` 对象等) 属性的方法。这些方法封装了访问对象内部结构所需的偏移量计算和类型信息。
* **Wasm 特有操作:**  提供了与 WebAssembly 特性相关的操作，例如：
    * **Wasm GC (垃圾回收) 对象操作:**  例如获取和设置结构体字段 (`StructGet`, `StructSet`)，以及数组元素 (`ArrayGet`, `ArraySet`, `ArrayLength`)。
    * **类型检查和转换:**  提供了 Wasm 的类型检查 (`WasmTypeCheck`, `WasmTypeCheckAbstract`) 和类型转换 (`WasmTypeCast`, `WasmTypeCastAbstract`) 操作。
    * **`anyref` 和 `externref` 转换:** 提供了 `WasmAnyConvertExtern` 和 `WasmExternConvertAny`，用于在 WebAssembly 的引用类型和 JavaScript 值之间进行转换。
* **字符串操作:**  提供了加载字符串长度 (`LoadStringLength`) 和获取 UTF-16 表示 (`StringAsWtf16`) 的方法。
* **辅助函数:**  提供了一些用于处理特定类型对象或执行常见任务的辅助函数，例如检查是否为 Smi (`IsSmi`)。

**与 JavaScript 的关系及 JavaScript 示例**

`WasmGraphAssembler` 的功能与 JavaScript 的互操作性密切相关。  当 WebAssembly 代码需要与 JavaScript 代码交互时，例如调用 JavaScript 函数或访问 JavaScript 对象，`WasmGraphAssembler` 用于构建相应的图节点来实现这些操作。

特别是 `WasmAnyConvertExtern` 和 `WasmExternConvertAny` 这两个方法是连接 WebAssembly 和 JavaScript 的关键桥梁：

* **`WasmAnyConvertExtern(Node* object)`:**  当 WebAssembly 代码接收一个 JavaScript 值（在 WebAssembly 中表示为 `anyref` 或 `externref`）时，这个方法用于生成将 JavaScript 值转换为 WebAssembly 外部引用的图节点。
* **`WasmExternConvertAny(Node* object)`:**  当 WebAssembly 代码需要将一个 WebAssembly 外部引用（可能指向一个 JavaScript 对象）传递给 JavaScript 时，这个方法用于生成将 WebAssembly 外部引用转换回 JavaScript 值的图节点。

**JavaScript 示例：**

假设我们有以下 WebAssembly 代码：

```wat
(module
  (import "env" "js_add" (func $js_add (param externref i32) (result i32)))
  (func (export "wasm_add_one") (param $x i32) (result i32)
    local.get $x
    i32.const 1
    call $js_add
  )
)
```

以及对应的 JavaScript 代码：

```javascript
const importObject = {
  env: {
    js_add: (jsValue, wasmValue) => {
      console.log("Received JavaScript value:", jsValue);
      return wasmValue + 1;
    },
  },
};

WebAssembly.instantiateStreaming(fetch('module.wasm'), importObject)
  .then(result => {
    const wasmInstance = result.instance;
    const result = wasmInstance.exports.wasm_add_one(5);
    console.log("Result from WASM:", result);
  });
```

在这个例子中：

1. **Wasm 调用 JavaScript:**  WebAssembly 函数 `wasm_add_one` 调用了导入的 JavaScript 函数 `js_add`。
2. **传递 JavaScript 值:** 虽然在这个简单的例子中传递的是一个 `i32`，但如果 `js_add` 的签名是 `(param externref i32)`，那么从 JavaScript 传递的任何 JavaScript 对象都会被转换为 `externref` 传递给 WebAssembly。  在 V8 的编译器中，当生成 `call $js_add` 的代码时，`WasmGraphAssembler` 可能会使用 `WasmAnyConvertExtern` 来处理从 JavaScript 传递过来的 `externref` 参数。
3. **返回 JavaScript 值 (隐含):** JavaScript 函数 `js_add` 返回一个 `i32`。 如果 JavaScript 函数返回的是一个 JavaScript 对象，那么当这个值返回到 WebAssembly 的调用点时，`WasmGraphAssembler` 可能会使用 `WasmExternConvertAny` 来处理将 JavaScript 对象转换回 WebAssembly 可以理解的 `externref`。

虽然在这个具体的例子中没有直接展示 `WasmAnyConvertExtern` 或 `WasmExternConvertAny` 的使用，但它们在更复杂的场景中至关重要，尤其是在 WebAssembly 和 JavaScript 之间传递对象引用时。 `WasmGraphAssembler` 负责构建图节点，确保这些跨语言的调用能够正确地进行，包括必要的类型转换和表示转换。

总而言之，`wasm-graph-assembler.cc` 中定义的 `WasmGraphAssembler` 类是 V8 编译 WebAssembly 代码的关键组件，它提供了一组抽象的接口，用于构建代表 WebAssembly 操作的 TurboFan 图节点，并特别处理了与 JavaScript 互操作相关的操作。

### 提示词
```
这是目录为v8/src/compiler/wasm-graph-assembler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/wasm-graph-assembler.h"

#include "src/common/globals.h"
#include "src/compiler/access-builder.h"
#include "src/compiler/diamond.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/wasm-compiler-definitions.h"
#include "src/objects/string.h"
#include "src/wasm/object-access.h"
#include "src/wasm/wasm-objects.h"

namespace v8::internal::compiler {

// static
CallDescriptor* GetBuiltinCallDescriptor(Builtin name, Zone* zone,
                                         StubCallMode stub_mode,
                                         bool needs_frame_state,
                                         Operator::Properties properties) {
  CallInterfaceDescriptor interface_descriptor =
      Builtins::CallInterfaceDescriptorFor(name);
  return Linkage::GetStubCallDescriptor(
      zone,                                           // zone
      interface_descriptor,                           // descriptor
      interface_descriptor.GetStackParameterCount(),  // stack parameter count
      needs_frame_state ? CallDescriptor::kNeedsFrameState
                        : CallDescriptor::kNoFlags,  // flags
      properties,                                    // properties
      stub_mode);                                    // stub call mode
}

// static
ObjectAccess ObjectAccessForGCStores(wasm::ValueType type) {
  return ObjectAccess(
      MachineType::TypeForRepresentation(type.machine_representation(),
                                         !type.is_packed()),
      type.is_reference() ? kFullWriteBarrier : kNoWriteBarrier);
}

// Sets {true_node} and {false_node} to their corresponding Branch outputs.
// Returns the Branch node. Does not change control().
Node* WasmGraphAssembler::Branch(Node* cond, Node** true_node,
                                 Node** false_node, BranchHint hint) {
  DCHECK_NOT_NULL(cond);
  Node* branch =
      graph()->NewNode(mcgraph()->common()->Branch(hint), cond, control());
  *true_node = graph()->NewNode(mcgraph()->common()->IfTrue(), branch);
  *false_node = graph()->NewNode(mcgraph()->common()->IfFalse(), branch);
  return branch;
}

Node* WasmGraphAssembler::BuildTruncateIntPtrToInt32(Node* value) {
  return mcgraph()->machine()->Is64() ? TruncateInt64ToInt32(value) : value;
}

Node* WasmGraphAssembler::BuildChangeInt32ToIntPtr(Node* value) {
  return mcgraph()->machine()->Is64() ? ChangeInt32ToInt64(value) : value;
}

Node* WasmGraphAssembler::BuildChangeIntPtrToInt64(Node* value) {
  return mcgraph()->machine()->Is32() ? ChangeInt32ToInt64(value) : value;
}

Node* WasmGraphAssembler::BuildChangeUint32ToUintPtr(Node* node) {
  if (mcgraph()->machine()->Is32()) return node;
  // Fold instances of ChangeUint32ToUint64(IntConstant) directly.
  Uint32Matcher matcher(node);
  if (matcher.HasResolvedValue()) {
    uintptr_t value = matcher.ResolvedValue();
    return mcgraph()->IntPtrConstant(base::bit_cast<intptr_t>(value));
  }
  return ChangeUint32ToUint64(node);
}

Node* WasmGraphAssembler::BuildSmiShiftBitsConstant() {
  return IntPtrConstant(kSmiShiftSize + kSmiTagSize);
}

Node* WasmGraphAssembler::BuildSmiShiftBitsConstant32() {
  return Int32Constant(kSmiShiftSize + kSmiTagSize);
}

Node* WasmGraphAssembler::BuildChangeInt32ToSmi(Node* value) {
  // With pointer compression, only the lower 32 bits are used.
  return COMPRESS_POINTERS_BOOL ? BitcastWord32ToWord64(Word32Shl(
                                      value, BuildSmiShiftBitsConstant32()))
                                : WordShl(BuildChangeInt32ToIntPtr(value),
                                          BuildSmiShiftBitsConstant());
}

Node* WasmGraphAssembler::BuildChangeUint31ToSmi(Node* value) {
  return COMPRESS_POINTERS_BOOL
             ? Word32Shl(value, BuildSmiShiftBitsConstant32())
             : WordShl(BuildChangeUint32ToUintPtr(value),
                       BuildSmiShiftBitsConstant());
}

Node* WasmGraphAssembler::BuildChangeSmiToInt32(Node* value) {
  return COMPRESS_POINTERS_BOOL
             ? Word32Sar(value, BuildSmiShiftBitsConstant32())
             : BuildTruncateIntPtrToInt32(
                   WordSar(value, BuildSmiShiftBitsConstant()));
}

Node* WasmGraphAssembler::BuildConvertUint32ToSmiWithSaturation(
    Node* value, uint32_t maxval) {
  DCHECK(Smi::IsValid(maxval));
  Node* max = mcgraph()->Uint32Constant(maxval);
  Node* check = Uint32LessThanOrEqual(value, max);
  Node* valsmi = BuildChangeUint31ToSmi(value);
  Node* maxsmi = NumberConstant(maxval);
  Diamond d(graph(), mcgraph()->common(), check, BranchHint::kTrue);
  d.Chain(control());
  return d.Phi(MachineRepresentation::kTagged, valsmi, maxsmi);
}

Node* WasmGraphAssembler::BuildChangeSmiToIntPtr(Node* value) {
  return COMPRESS_POINTERS_BOOL ? BuildChangeInt32ToIntPtr(Word32Sar(
                                      value, BuildSmiShiftBitsConstant32()))
                                : WordSar(value, BuildSmiShiftBitsConstant());
}

// Helper functions for dealing with HeapObjects.
// Rule of thumb: if access to a given field in an object is required in
// at least two places, put a helper function here.

Node* WasmGraphAssembler::Allocate(int size) {
  return Allocate(Int32Constant(size));
}

Node* WasmGraphAssembler::Allocate(Node* size) {
  return AddNode(graph()->NewNode(
      simplified_.AllocateRaw(Type::Any(), AllocationType::kYoung), size,
      effect(), control()));
}

Node* WasmGraphAssembler::LoadFromObject(MachineType type, Node* base,
                                         Node* offset) {
  return AddNode(graph()->NewNode(
      simplified_.LoadFromObject(ObjectAccess(type, kNoWriteBarrier)), base,
      offset, effect(), control()));
}

Node* WasmGraphAssembler::LoadProtectedPointerFromObject(Node* object,
                                                         Node* offset) {
  return LoadFromObject(V8_ENABLE_SANDBOX_BOOL ? MachineType::ProtectedPointer()
                                               : MachineType::AnyTagged(),
                        object, offset);
}

Node* WasmGraphAssembler::LoadImmutableProtectedPointerFromObject(
    Node* object, Node* offset) {
  return LoadImmutableFromObject(V8_ENABLE_SANDBOX_BOOL
                                     ? MachineType::ProtectedPointer()
                                     : MachineType::AnyTagged(),
                                 object, offset);
}

Node* WasmGraphAssembler::LoadImmutableFromObject(MachineType type, Node* base,
                                                  Node* offset) {
  return AddNode(graph()->NewNode(
      simplified_.LoadImmutableFromObject(ObjectAccess(type, kNoWriteBarrier)),
      base, offset, effect(), control()));
}

Node* WasmGraphAssembler::LoadImmutable(LoadRepresentation rep, Node* base,
                                        Node* offset) {
  return AddNode(
      graph()->NewNode(mcgraph()->machine()->LoadImmutable(rep), base, offset));
}

Node* WasmGraphAssembler::StoreToObject(ObjectAccess access, Node* base,
                                        Node* offset, Node* value) {
  return AddNode(graph()->NewNode(simplified_.StoreToObject(access), base,
                                  offset, value, effect(), control()));
}

Node* WasmGraphAssembler::InitializeImmutableInObject(ObjectAccess access,
                                                      Node* base, Node* offset,
                                                      Node* value) {
  return AddNode(
      graph()->NewNode(simplified_.InitializeImmutableInObject(access), base,
                       offset, value, effect(), control()));
}

Node* WasmGraphAssembler::BuildDecodeSandboxedExternalPointer(
    Node* handle, ExternalPointerTag tag, Node* isolate_root) {
#if V8_ENABLE_SANDBOX
  Node* index = Word32Shr(handle, Int32Constant(kExternalPointerIndexShift));
  Node* offset = ChangeUint32ToUint64(
      Word32Shl(index, Int32Constant(kExternalPointerTableEntrySizeLog2)));
  Node* table;
  if (IsSharedExternalPointerType(tag)) {
    Node* table_address =
        Load(MachineType::Pointer(), isolate_root,
             IsolateData::shared_external_pointer_table_offset());
    table = Load(MachineType::Pointer(), table_address,
                 Internals::kExternalPointerTableBasePointerOffset);
  } else {
    table = Load(MachineType::Pointer(), isolate_root,
                 IsolateData::external_pointer_table_offset() +
                     Internals::kExternalPointerTableBasePointerOffset);
  }
  Node* decoded_ptr = Load(MachineType::Pointer(), table, offset);
  return WordAnd(decoded_ptr, IntPtrConstant(~tag));
#else
  UNREACHABLE();
#endif  // V8_ENABLE_SANDBOX
}

Node* WasmGraphAssembler::BuildDecodeTrustedPointer(Node* handle,
                                                    IndirectPointerTag tag) {
#if V8_ENABLE_SANDBOX
  Node* index = Word32Shr(handle, Int32Constant(kTrustedPointerHandleShift));
  Node* offset = ChangeUint32ToUint64(
      Word32Shl(index, Int32Constant(kTrustedPointerTableEntrySizeLog2)));
  Node* table = Load(MachineType::Pointer(), LoadRootRegister(),
                     IsolateData::trusted_pointer_table_offset() +
                         Internals::kTrustedPointerTableBasePointerOffset);
  Node* decoded_ptr = Load(MachineType::Pointer(), table, offset);
  // Untag the pointer and remove the marking bit in one operation.
  decoded_ptr = WordAnd(decoded_ptr,
                        IntPtrConstant(~(tag | kTrustedPointerTableMarkBit)));
  // We have to change the type of the result value to Tagged, so if the value
  // gets spilled on the stack, it will get processed by the GC.
  decoded_ptr = BitcastWordToTagged(decoded_ptr);
  return decoded_ptr;
#else
  UNREACHABLE();
#endif  // V8_ENABLE_SANDBOX
}

Node* WasmGraphAssembler::BuildLoadExternalPointerFromObject(
    Node* object, int field_offset, ExternalPointerTag tag,
    Node* isolate_root) {
#ifdef V8_ENABLE_SANDBOX
  DCHECK_NE(tag, kExternalPointerNullTag);
  Node* handle = LoadFromObject(MachineType::Uint32(), object,
                                wasm::ObjectAccess::ToTagged(field_offset));
  return BuildDecodeSandboxedExternalPointer(handle, tag, isolate_root);
#else
  return LoadFromObject(MachineType::Pointer(), object,
                        wasm::ObjectAccess::ToTagged(field_offset));
#endif  // V8_ENABLE_SANDBOX
}

Node* WasmGraphAssembler::IsSmi(Node* object) {
  if (COMPRESS_POINTERS_BOOL) {
    return Word32Equal(Word32And(object, Int32Constant(kSmiTagMask)),
                       Int32Constant(kSmiTag));
  } else {
    return WordEqual(WordAnd(object, IntPtrConstant(kSmiTagMask)),
                     IntPtrConstant(kSmiTag));
  }
}

// Maps and their contents.
Node* WasmGraphAssembler::LoadMap(Node* object) {
  Node* map_word =
      LoadImmutableFromObject(MachineType::TaggedPointer(), object,
                              HeapObject::kMapOffset - kHeapObjectTag);
#ifdef V8_MAP_PACKING
  return UnpackMapWord(map_word);
#else
  return map_word;
#endif
}

void WasmGraphAssembler::StoreMap(Node* heap_object, Node* map) {
  ObjectAccess access(MachineType::TaggedPointer(), kMapWriteBarrier);
#ifdef V8_MAP_PACKING
  map = PackMapWord(TNode<Map>::UncheckedCast(map));
#endif
  InitializeImmutableInObject(access, heap_object,
                              HeapObject::kMapOffset - kHeapObjectTag, map);
}

Node* WasmGraphAssembler::LoadInstanceType(Node* map) {
  return LoadImmutableFromObject(
      MachineType::Uint16(), map,
      wasm::ObjectAccess::ToTagged(Map::kInstanceTypeOffset));
}
Node* WasmGraphAssembler::LoadWasmTypeInfo(Node* map) {
  int offset = Map::kConstructorOrBackPointerOrNativeContextOffset;
  return LoadImmutableFromObject(MachineType::TaggedPointer(), map,
                                 wasm::ObjectAccess::ToTagged(offset));
}

// FixedArrays.

Node* WasmGraphAssembler::LoadFixedArrayLengthAsSmi(Node* fixed_array) {
  return LoadImmutableFromObject(
      MachineType::TaggedSigned(), fixed_array,
      wasm::ObjectAccess::ToTagged(offsetof(FixedArray, length_)));
}

Node* WasmGraphAssembler::LoadFixedArrayElement(Node* fixed_array,
                                                Node* index_intptr,
                                                MachineType type) {
  DCHECK(IsSubtype(type.representation(), MachineRepresentation::kTagged));
  Node* offset = IntAdd(IntMul(index_intptr, IntPtrConstant(kTaggedSize)),
                        IntPtrConstant(wasm::ObjectAccess::ToTagged(
                            OFFSET_OF_DATA_START(FixedArray))));
  return LoadFromObject(type, fixed_array, offset);
}

Node* WasmGraphAssembler::LoadWeakFixedArrayElement(Node* fixed_array,
                                                    Node* index_intptr) {
  Node* offset = IntAdd(IntMul(index_intptr, IntPtrConstant(kTaggedSize)),
                        IntPtrConstant(wasm::ObjectAccess::ToTagged(
                            OFFSET_OF_DATA_START(WeakFixedArray))));
  return LoadFromObject(MachineType::AnyTagged(), fixed_array, offset);
}

Node* WasmGraphAssembler::LoadImmutableFixedArrayElement(Node* fixed_array,
                                                         Node* index_intptr,
                                                         MachineType type) {
  Node* offset = IntAdd(IntMul(index_intptr, IntPtrConstant(kTaggedSize)),
                        IntPtrConstant(wasm::ObjectAccess::ToTagged(
                            OFFSET_OF_DATA_START(FixedArray))));
  return LoadImmutableFromObject(type, fixed_array, offset);
}

Node* WasmGraphAssembler::LoadFixedArrayElement(Node* array, int index,
                                                MachineType type) {
  return LoadFromObject(
      type, array, wasm::ObjectAccess::ElementOffsetInTaggedFixedArray(index));
}

Node* WasmGraphAssembler::LoadProtectedFixedArrayElement(Node* array,
                                                         int index) {
  return LoadProtectedPointerFromObject(
      array, wasm::ObjectAccess::ElementOffsetInProtectedFixedArray(index));
}

Node* WasmGraphAssembler::LoadProtectedFixedArrayElement(Node* array,
                                                         Node* index_intptr) {
  Node* offset = IntAdd(WordShl(index_intptr, IntPtrConstant(kTaggedSizeLog2)),
                        IntPtrConstant(wasm::ObjectAccess::ToTagged(
                            OFFSET_OF_DATA_START(ProtectedFixedArray))));
  return LoadProtectedPointerFromObject(array, offset);
}

Node* WasmGraphAssembler::LoadByteArrayElement(Node* byte_array,
                                               Node* index_intptr,
                                               MachineType type) {
  int element_size = ElementSizeInBytes(type.representation());
  Node* offset = IntAdd(IntMul(index_intptr, IntPtrConstant(element_size)),
                        IntPtrConstant(wasm::ObjectAccess::ToTagged(
                            OFFSET_OF_DATA_START(ByteArray))));
  return LoadFromObject(type, byte_array, offset);
}

Node* WasmGraphAssembler::LoadImmutableTrustedPointerFromObject(
    Node* object, int field_offset, IndirectPointerTag tag) {
  Node* offset = IntPtrConstant(field_offset);
#ifdef V8_ENABLE_SANDBOX
  Node* handle = LoadImmutableFromObject(MachineType::Uint32(), object, offset);
  return BuildDecodeTrustedPointer(handle, tag);
#else
  return LoadImmutableFromObject(MachineType::TaggedPointer(), object, offset);
#endif
}

Node* WasmGraphAssembler::LoadTrustedPointerFromObject(Node* object,
                                                       int field_offset,
                                                       IndirectPointerTag tag) {
  Node* offset = IntPtrConstant(field_offset);
#ifdef V8_ENABLE_SANDBOX
  Node* handle = LoadFromObject(MachineType::Uint32(), object, offset);
  return BuildDecodeTrustedPointer(handle, tag);
#else
  return LoadFromObject(MachineType::TaggedPointer(), object, offset);
#endif
}

std::pair<Node*, Node*>
WasmGraphAssembler::LoadTrustedPointerFromObjectTrapOnNull(
    Node* object, int field_offset, IndirectPointerTag tag) {
  Node* offset = IntPtrConstant(field_offset);
#ifdef V8_ENABLE_SANDBOX
  Node* handle = LoadTrapOnNull(MachineType::Uint32(), object, offset);
  return {handle, BuildDecodeTrustedPointer(handle, tag)};
#else
  Node* value = LoadTrapOnNull(MachineType::TaggedPointer(), object, offset);
  return {value, value};
#endif
}

Node* WasmGraphAssembler::StoreFixedArrayElement(Node* array, int index,
                                                 Node* value,
                                                 ObjectAccess access) {
  return StoreToObject(
      access, array, wasm::ObjectAccess::ElementOffsetInTaggedFixedArray(index),
      value);
}

// Functions, SharedFunctionInfos, FunctionData.

Node* WasmGraphAssembler::LoadSharedFunctionInfo(Node* js_function) {
  return LoadImmutableFromObject(
      MachineType::TaggedPointer(), js_function,
      wasm::ObjectAccess::SharedFunctionInfoOffsetInTaggedJSFunction());
}
Node* WasmGraphAssembler::LoadContextFromJSFunction(Node* js_function) {
  return LoadFromObject(MachineType::TaggedPointer(), js_function,
                        wasm::ObjectAccess::ContextOffsetInTaggedJSFunction());
}

Node* WasmGraphAssembler::LoadFunctionDataFromJSFunction(Node* js_function) {
  Node* shared = LoadSharedFunctionInfo(js_function);
  return LoadImmutableTrustedPointerFromObject(
      shared,
      wasm::ObjectAccess::ToTagged(
          SharedFunctionInfo::kTrustedFunctionDataOffset),
      kWasmFunctionDataIndirectPointerTag);
}

Node* WasmGraphAssembler::LoadExportedFunctionIndexAsSmi(
    Node* exported_function_data) {
  return LoadImmutableFromObject(
      MachineType::TaggedSigned(), exported_function_data,
      wasm::ObjectAccess::ToTagged(
          WasmExportedFunctionData::kFunctionIndexOffset));
}
Node* WasmGraphAssembler::LoadExportedFunctionInstanceData(
    Node* exported_function_data) {
  return LoadImmutableProtectedPointerFromObject(
      exported_function_data,
      wasm::ObjectAccess::ToTagged(
          WasmExportedFunctionData::kProtectedInstanceDataOffset));
}

// JavaScript objects.

Node* WasmGraphAssembler::LoadJSArrayElements(Node* js_array) {
  return LoadFromObject(
      MachineType::AnyTagged(), js_array,
      wasm::ObjectAccess::ToTagged(JSObject::kElementsOffset));
}

// WasmGC objects.

Node* WasmGraphAssembler::FieldOffset(const wasm::StructType* type,
                                      uint32_t field_index) {
  return IntPtrConstant(wasm::ObjectAccess::ToTagged(
      WasmStruct::kHeaderSize + type->field_offset(field_index)));
}

Node* WasmGraphAssembler::WasmArrayElementOffset(Node* index,
                                                 wasm::ValueType element_type) {
  Node* index_intptr =
      mcgraph()->machine()->Is64() ? ChangeInt32ToInt64(index) : index;
  return IntAdd(
      IntPtrConstant(wasm::ObjectAccess::ToTagged(WasmArray::kHeaderSize)),
      IntMul(index_intptr, IntPtrConstant(element_type.value_kind_size())));
}

Node* WasmGraphAssembler::IsDataRefMap(Node* map) {
  Node* instance_type = LoadInstanceType(map);
  // We're going to test a range of WasmObject instance types with a single
  // unsigned comparison.
  Node* comparison_value =
      Int32Sub(instance_type, Int32Constant(FIRST_WASM_OBJECT_TYPE));
  return Uint32LessThanOrEqual(
      comparison_value,
      Int32Constant(LAST_WASM_OBJECT_TYPE - FIRST_WASM_OBJECT_TYPE));
}

Node* WasmGraphAssembler::WasmTypeCheck(Node* object, Node* rtt,
                                        WasmTypeCheckConfig config) {
  return AddNode(graph()->NewNode(simplified_.WasmTypeCheck(config), object,
                                  rtt, effect(), control()));
}

Node* WasmGraphAssembler::WasmTypeCheckAbstract(Node* object,
                                                WasmTypeCheckConfig config) {
  return AddNode(graph()->NewNode(simplified_.WasmTypeCheckAbstract(config),
                                  object, effect(), control()));
}

Node* WasmGraphAssembler::WasmTypeCast(Node* object, Node* rtt,
                                       WasmTypeCheckConfig config) {
  return AddNode(graph()->NewNode(simplified_.WasmTypeCast(config), object, rtt,
                                  effect(), control()));
}

Node* WasmGraphAssembler::WasmTypeCastAbstract(Node* object,
                                               WasmTypeCheckConfig config) {
  return AddNode(graph()->NewNode(simplified_.WasmTypeCastAbstract(config),
                                  object, effect(), control()));
}

Node* WasmGraphAssembler::Null(wasm::ValueType type) {
  return AddNode(graph()->NewNode(simplified_.Null(type)));
}

Node* WasmGraphAssembler::IsNull(Node* object, wasm::ValueType type) {
  return AddNode(graph()->NewNode(simplified_.IsNull(type), object, control()));
}

Node* WasmGraphAssembler::IsNotNull(Node* object, wasm::ValueType type) {
  return AddNode(
      graph()->NewNode(simplified_.IsNotNull(type), object, control()));
}

Node* WasmGraphAssembler::AssertNotNull(Node* object, wasm::ValueType type,
                                        TrapId trap_id) {
  return AddNode(graph()->NewNode(simplified_.AssertNotNull(type, trap_id),
                                  object, effect(), control()));
}

Node* WasmGraphAssembler::WasmAnyConvertExtern(Node* object) {
  return AddNode(graph()->NewNode(simplified_.WasmAnyConvertExtern(), object,
                                  effect(), control()));
}

Node* WasmGraphAssembler::WasmExternConvertAny(Node* object) {
  return AddNode(graph()->NewNode(simplified_.WasmExternConvertAny(), object,
                                  effect(), control()));
}

Node* WasmGraphAssembler::StructGet(Node* object, const wasm::StructType* type,
                                    int field_index, bool is_signed,
                                    CheckForNull null_check) {
  return AddNode(graph()->NewNode(
      simplified_.WasmStructGet(type, field_index, is_signed, null_check),
      object, effect(), control()));
}

void WasmGraphAssembler::StructSet(Node* object, Node* value,
                                   const wasm::StructType* type,
                                   int field_index, CheckForNull null_check) {
  AddNode(
      graph()->NewNode(simplified_.WasmStructSet(type, field_index, null_check),
                       object, value, effect(), control()));
}

Node* WasmGraphAssembler::ArrayGet(Node* array, Node* index,
                                   const wasm::ArrayType* type,
                                   bool is_signed) {
  return AddNode(graph()->NewNode(simplified_.WasmArrayGet(type, is_signed),
                                  array, index, effect(), control()));
}

void WasmGraphAssembler::ArraySet(Node* array, Node* index, Node* value,
                                  const wasm::ArrayType* type) {
  AddNode(graph()->NewNode(simplified_.WasmArraySet(type), array, index, value,
                           effect(), control()));
}

Node* WasmGraphAssembler::ArrayLength(Node* array, CheckForNull null_check) {
  return AddNode(graph()->NewNode(simplified_.WasmArrayLength(null_check),
                                  array, effect(), control()));
}

void WasmGraphAssembler::ArrayInitializeLength(Node* array, Node* length) {
  AddNode(graph()->NewNode(simplified_.WasmArrayInitializeLength(), array,
                           length, effect(), control()));
}

Node* WasmGraphAssembler::LoadStringLength(Node* string) {
  return LoadImmutableFromObject(
      MachineType::Int32(), string,
      wasm::ObjectAccess::ToTagged(AccessBuilder::ForStringLength().offset));
}

Node* WasmGraphAssembler::StringAsWtf16(Node* string) {
  return AddNode(graph()->NewNode(simplified_.StringAsWtf16(), string, effect(),
                                  control()));
}

Node* WasmGraphAssembler::StringPrepareForGetCodeunit(Node* string) {
  return AddNode(graph()->NewNode(simplified_.StringPrepareForGetCodeunit(),
                                  string, effect(), control()));
}

Node* WasmGraphAssembler::LoadTrustedDataFromInstanceObject(
    Node* instance_object) {
  return LoadImmutableTrustedPointerFromObject(
      instance_object,
      wasm::ObjectAccess::ToTagged(WasmInstanceObject::kTrustedDataOffset),
      kWasmTrustedInstanceDataIndirectPointerTag);
}

// Generic HeapObject helpers.

Node* WasmGraphAssembler::HasInstanceType(Node* heap_object,
                                          InstanceType type) {
  Node* map = LoadMap(heap_object);
  Node* instance_type = LoadInstanceType(map);
  return Word32Equal(instance_type, Int32Constant(type));
}

}  // namespace v8::internal::compiler
```