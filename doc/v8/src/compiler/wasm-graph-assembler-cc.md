Response:
Let's break down the thought process for analyzing this C++ code and generating the explanation.

1. **Understand the Goal:** The request asks for a functional overview of the `wasm-graph-assembler.cc` file within the V8 JavaScript engine. It also specifies to cover aspects like Torque (if applicable), JavaScript relevance, logical reasoning with examples, and common programming errors.

2. **Initial Code Scan and Key Observations:**
   - **Header Inclusion:** The `#include` directives point to core V8 compiler components (`access-builder.h`, `diamond.h`, `node-matchers.h`, `wasm-compiler-definitions.h`) and object representations (`string.h`, `wasm-objects.h`). This immediately suggests the file is involved in the compilation process for WebAssembly.
   - **Namespace:** The code is within `v8::internal::compiler`, confirming its compiler-related role.
   - **Class Definition:** The core of the file is the `WasmGraphAssembler` class. The name "GraphAssembler" strongly suggests it's responsible for constructing some kind of graph representation, likely the intermediate representation used by the compiler. "Wasm" clearly ties it to WebAssembly.
   - **Method Categories:**  A quick skim reveals groups of methods:
     - Static utility functions (`GetBuiltinCallDescriptor`, `ObjectAccessForGCStores`).
     - Basic control flow (`Branch`).
     - Integer manipulation and type conversions (`BuildTruncateIntPtrToInt32`, `BuildChangeInt32ToIntPtr`, etc.).
     - Smi (Small Integer) handling.
     - Heap object manipulation (allocation, loading, storing).
     - Sandboxed pointer handling (external and trusted pointers).
     - Map and InstanceType operations.
     - FixedArray, ByteArray operations.
     - Function-related operations (SFI, FunctionData).
     - JavaScript object interaction.
     - WasmGC (Garbage Collection) specific operations (Struct, Array, RTT).
     - String operations.
     - Instance object interaction.
     - Generic HeapObject checks.

3. **Inferring Functionality Based on Method Names:**  This is crucial. Even without deep understanding of every V8 internal, the method names are highly descriptive:
   - `Allocate`: Memory allocation.
   - `LoadFromObject`, `StoreToObject`: Accessing object properties.
   - `BuildDecodeSandboxedExternalPointer`, `BuildDecodeTrustedPointer`:  Handling pointers in a sandboxed environment.
   - `LoadMap`, `LoadInstanceType`: Operations related to object structure and type information.
   - `LoadFixedArrayElement`, `StoreFixedArrayElement`: Array manipulation.
   - `LoadSharedFunctionInfo`, `LoadFunctionDataFromJSFunction`:  Accessing function metadata.
   - `WasmTypeCheck`, `WasmTypeCast`: Performing type checks and casts specific to WebAssembly.
   - `StructGet`, `StructSet`, `ArrayGet`, `ArraySet`, `ArrayLength`: Operations on WasmGC structures and arrays.

4. **Connecting to Compilation:**  Knowing this is a "GraphAssembler," the methods are likely used during the compilation process to build the intermediate representation. For example, when the compiler encounters a WebAssembly instruction to load a value from memory, it might use `LoadFromObject` or a related function to create a corresponding node in the graph.

5. **Addressing Specific Questions from the Prompt:**

   - **Functionality Summary:**  Based on the method categories and names, summarize the core functionalities: building the compiler graph for WebAssembly, handling type conversions, managing memory and object access (especially in a sandboxed context), and providing specific operations for WasmGC features.

   - **Torque:** The prompt asks about `.tq` files. A quick search or prior knowledge about V8's build system would reveal that `.tq` files are related to Torque, V8's type system and code generation language. Since the file ends in `.cc`, it's standard C++, not Torque.

   - **JavaScript Relationship:** Consider how WebAssembly interacts with JavaScript. Key areas:
     - Calling JavaScript functions from WebAssembly and vice versa. The `GetBuiltinCallDescriptor` method hints at this.
     - Manipulating JavaScript objects from WebAssembly (and potentially the other way around). Methods like `LoadJSArrayElements` are relevant.
     - Type conversions between JavaScript and WebAssembly values.
     - **Example:** Devise a simple JavaScript/WebAssembly interaction to illustrate these points. A simple function call demonstrates the concept clearly.

   - **Code Logic Reasoning:**  Choose a relatively straightforward method with conditional logic. `Branch` is a good example.
     - **Input:**  Describe the inputs (`cond`, `true_node`, `false_node`).
     - **Process:** Explain how the `Branch` node is created and how the `IfTrue` and `IfFalse` nodes are derived.
     - **Output:** Describe how the `true_node` and `false_node` pointers are updated.
     - **Example:** Provide concrete node names (even if abstract) to make it clearer.

   - **Common Programming Errors:** Think about the potential pitfalls when working with low-level operations like memory access and type conversions:
     - **Incorrect type assumptions:**  Using the wrong `MachineType` for loading/storing.
     - **Incorrect offsets:**  Accessing memory at the wrong location within an object.
     - **Missing null checks:**  Dereferencing null pointers (though V8 might have its own mechanisms for handling this).
     - **Sandbox violations:** Trying to access memory outside the allowed sandbox boundaries (more relevant in sandboxed environments).
     - **Example:** Create simple, illustrative code snippets in C++ (or even pseudocode) demonstrating these errors. Keep the examples concise and focus on the core issue.

6. **Structuring the Explanation:** Organize the information logically with clear headings and bullet points. Start with a high-level overview and then delve into specifics. Address each part of the prompt directly. Use formatting (like bold text and code blocks) to improve readability.

7. **Refinement and Review:**  Read through the generated explanation. Are there any ambiguities?  Is the language clear and concise? Are the examples helpful?  Are all the prompt's questions addressed? For instance, initially, I might have focused too much on the low-level graph operations. Reviewing the prompt would remind me to explicitly connect it to JavaScript and WebAssembly interaction. Ensure the examples are accurate and easy to understand.

By following these steps, systematically analyzing the code, and focusing on the key aspects requested in the prompt, you can generate a comprehensive and informative explanation like the example provided.
好的，让我们来分析一下 `v8/src/compiler/wasm-graph-assembler.cc` 这个 V8 源代码文件。

**功能概述:**

`v8/src/compiler/wasm-graph-assembler.cc` 文件定义了 `WasmGraphAssembler` 类，这个类的主要功能是在 V8 的编译管道中，特别是针对 WebAssembly 模块的编译过程中，用于**构建中间表示（IR）图**。这个图是由各种节点组成的，这些节点代表了 WebAssembly 代码的操作和控制流。

更具体地说，`WasmGraphAssembler` 提供了一系列方法，用于：

1. **创建和连接图节点:**  它封装了 V8 编译器中创建各种图节点的操作，例如算术运算、内存访问、控制流分支、函数调用等。这使得在编译 WebAssembly 代码时，可以方便地构建出代表其语义的图结构。

2. **处理 WebAssembly 特定的操作:**  它包含了一些专门用于处理 WebAssembly 特性的方法，例如：
   - **WasmGC (WebAssembly Garbage Collection) 相关操作:**  如 `StructGet`, `StructSet`, `ArrayGet`, `ArraySet`, `WasmTypeCheck`, `WasmTypeCast` 等，用于操作 WebAssembly 的结构体和数组，进行类型检查和转换。
   - **内存访问:**  提供了安全的内存访问方法，考虑到 WebAssembly 的线性内存模型。
   - **函数调用:**  封装了调用内置函数和 WebAssembly 函数的逻辑。
   - **类型转换:**  提供了在不同数据类型之间进行转换的方法。

3. **与 V8 基础设施集成:**  `WasmGraphAssembler` 使用了 V8 编译器提供的各种工具和数据结构，例如 `Node`、`Graph`、`CommonOperatorBuilder`、`MachineOperatorBuilder`、`SimplifiedOperatorBuilder` 等，确保构建的图能够被后续的编译阶段处理。

4. **处理沙箱环境:**  该文件包含一些针对 V8 沙箱环境的代码，例如处理外部指针和受信任指针，确保 WebAssembly 代码在沙箱内的安全执行。

5. **处理 Smi (Small Integer):**  提供了一些用于处理 V8 中 Smi 类型的便捷方法，Smi 是 V8 中一种高效表示小整数的方式。

**关于文件后缀 `.tq`:**

根据你的描述，如果 `v8/src/compiler/wasm-graph-assembler.cc` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。 Torque 是 V8 自研的一种用于定义内部函数和类型的领域特定语言。然而，该文件以 `.cc` 结尾，表明它是一个标准的 C++ 源代码文件。因此，**`v8/src/compiler/wasm-graph-assembler.cc` 不是一个 Torque 文件。**

**与 JavaScript 的关系:**

WebAssembly 的一个主要目标就是与 JavaScript 无缝集成。`WasmGraphAssembler` 在编译 WebAssembly 代码时，需要处理与 JavaScript 交互的场景。以下是一些关联：

1. **调用 JavaScript 内置函数:** WebAssembly 代码可以调用 JavaScript 提供的内置函数（例如 `console.log`）。`WasmGraphAssembler` 中 `GetBuiltinCallDescriptor` 方法用于获取调用这些内置函数所需的描述符。

2. **操作 JavaScript 对象:** WebAssembly 可以访问和操作 JavaScript 对象。`WasmGraphAssembler` 提供了加载和存储 JavaScript 对象属性的方法，例如 `LoadJSArrayElements`。

3. **类型转换:** 在 WebAssembly 和 JavaScript 之间传递数据时，可能需要进行类型转换。`WasmGraphAssembler` 中可能包含一些处理这些转换的逻辑。

**JavaScript 示例:**

假设有一个 WebAssembly 模块，它需要调用 JavaScript 的 `console.log` 函数来打印一个数字。编译这个 WebAssembly 模块时，`WasmGraphAssembler` 会生成一个表示函数调用的节点。

虽然我们不能直接看到 `WasmGraphAssembler` 生成的图结构，但可以想象它会包含类似以下的操作：

```
// 伪代码，表示 WasmGraphAssembler 可能生成的图节点
builtin_call = CreateBuiltinCall(ConsoleLogDescriptor); // 调用 console.log 的描述符
argument = LoadLocalVariable(0); // 加载 WebAssembly 函数的第一个参数
AddArgumentToCall(builtin_call, argument);
Call(builtin_call);
```

在 JavaScript 方面，你可能会有这样的代码：

```javascript
const wasmCode = new Uint8Array([
  // ... WebAssembly 字节码，包含调用 console.log 的指令 ...
]);

const wasmModule = new WebAssembly.Module(wasmCode);
const wasmInstance = new WebAssembly.Instance(wasmModule, {
  // 导入的对象，可能包含 console 对象
  console: { log: console.log }
});

wasmInstance.exports.myWasmFunction(42); // 调用 WebAssembly 函数
```

在这个例子中，当 V8 编译 `myWasmFunction` 时，`WasmGraphAssembler` 会识别出对 `console.log` 的调用，并生成相应的图节点。

**代码逻辑推理 (假设输入与输出):**

考虑 `WasmGraphAssembler::Branch` 方法，它用于创建条件分支节点。

**假设输入:**

- `cond`: 一个表示条件的 `Node*`，例如一个比较操作的结果。
- `true_node`: 一个 `Node**`，用于存储分支为真时的控制流节点。
- `false_node`: 一个 `Node**`，用于存储分支为假时的控制流节点。
- `hint`: 一个 `BranchHint`，表示分支预测的提示。

**代码逻辑:**

1. 创建一个新的 `Branch` 节点，并将条件 `cond` 和当前的控制流节点 `control()` 作为输入。
2. 创建一个新的 `IfTrue` 节点，其输入是刚刚创建的 `Branch` 节点。
3. 创建一个新的 `IfFalse` 节点，其输入也是刚刚创建的 `Branch` 节点。
4. 将 `IfTrue` 节点的地址赋值给 `*true_node`。
5. 将 `IfFalse` 节点的地址赋值给 `*false_node`。
6. 返回创建的 `Branch` 节点。

**假设输出:**

- `true_node` 指向一个新的 `IfTrue` 节点。
- `false_node` 指向一个新的 `IfFalse` 节点。
- 返回值是新创建的 `Branch` 节点。

**用户常见的编程错误 (可能与此类代码相关):**

虽然用户通常不会直接编写或修改 `wasm-graph-assembler.cc`，但在理解其功能后，可以联想到一些在 WebAssembly 或底层编程中常见的错误：

1. **错误的内存访问:**  在 WebAssembly 中，尝试访问超出线性内存范围的地址会导致错误。如果编译器在构建图的过程中，由于某种原因生成了错误的内存访问节点（例如，使用了错误的偏移量），就可能导致运行时错误。

   **例子 (假设的 WebAssembly 代码):**

   ```wat
   (module
     (memory (export "mem") 1)
     (func (export "store_oob")
       i32.const 65536  ;; 内存大小是 65536 字节 (1页)
       i32.const 42
       i32.store
     )
   )
   ```

   这段 WebAssembly 代码尝试在内存范围之外存储一个值，这会导致运行时错误。编译器在处理 `i32.store` 指令时，需要生成相应的内存存储节点，如果计算出的地址超出范围，就会有问题。

2. **类型不匹配:**  WebAssembly 是一种强类型语言。如果编译器生成的图节点尝试对类型不匹配的数据进行操作，也会导致错误。

   **例子 (假设的 WebAssembly 代码):**

   ```wat
   (module
     (func (export "type_mismatch") (result i32)
       f64.const 3.14
       i32.reinterpret_f64  ;; 将 f64 重新解释为 i32
     )
   )
   ```

   这段代码尝试将一个 64 位浮点数重新解释为 32 位整数，这可能会导致数据丢失或未定义的行为。编译器需要正确处理这种类型转换。

3. **不正确的函数调用:**  如果编译器在构建函数调用图节点时，使用了错误的调用签名或参数，会导致链接错误或运行时错误。

4. **忽视沙箱限制:**  在 V8 的沙箱环境中，WebAssembly 代码对某些操作有限制。如果编译器生成的图节点违反了这些限制（例如，尝试直接访问外部内存而没有经过适当的包装），就会导致安全问题。

总结来说，`v8/src/compiler/wasm-graph-assembler.cc` 是 V8 编译 WebAssembly 代码的核心组件，负责将 WebAssembly 的操作转化为编译器可以理解和优化的图结构。理解其功能有助于深入了解 V8 如何处理 WebAssembly 代码。

### 提示词
```
这是目录为v8/src/compiler/wasm-graph-assembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/wasm-graph-assembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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