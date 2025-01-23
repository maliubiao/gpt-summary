Response:
Let's break down the thought process for analyzing the `WasmGraphAssembler.h` file.

1. **Understand the Context:** The filename `v8/src/compiler/wasm-graph-assembler.h` immediately tells us this is part of the V8 JavaScript engine's compiler, specifically for WebAssembly. The `.h` extension indicates a header file, likely containing class declarations and inline function definitions.

2. **Initial Scan for Purpose:**  Reading the initial comments and the class name `WasmGraphAssembler` suggests its purpose is to help construct a *graph* representation of WebAssembly code during the compilation process. The term "assembler" implies it deals with low-level operations and code generation concepts.

3. **Key Includes:**  The `#include` directives are crucial:
    * `"src/compiler/graph-assembler.h"`: This signals that `WasmGraphAssembler` *inherits* from `GraphAssembler`. This means it builds upon existing graph assembly functionality. We should investigate what `GraphAssembler` does if we want a deeper understanding.
    * `"src/wasm/wasm-code-manager.h"`: This indicates interaction with the WebAssembly-specific parts of V8, likely related to managing compiled WebAssembly code.

4. **Conditional Compilation:** The `#if !V8_ENABLE_WEBASSEMBLY` block is important. It confirms this code is only relevant when WebAssembly support is enabled in V8.

5. **Namespace:** The code is within `v8::internal::compiler`, reinforcing its role within the V8 compiler's internal structure.

6. **Function Breakdown (High-Level):** Now, go through the public methods of the `WasmGraphAssembler` class and try to categorize their functionalities:
    * **Calling Builtins:**  `CallBuiltinThroughJumptable`, `GetBuiltinPointerTarget`, `CallBuiltin`, `CallBuiltinWithFrameState`. These methods clearly deal with calling predefined functions or routines (builtins). The "jumptable" variant suggests optimization techniques.
    * **Control Flow:** `Branch`. This is a fundamental control flow construct.
    * **Constants:** `NumberConstant`, `SmiConstant`. These create constant values within the graph.
    * **Graph Manipulation:** `MergeControlToEnd`. This suggests ways to connect different parts of the graph.
    * **Numeric Conversions:**  A set of `Build...` methods related to converting between different integer and pointer types. This is common in low-level code generation.
    * **Heap Object Manipulation:**  `Allocate`, `LoadFromObject`, `StoreToObject`, etc. These methods are central to interacting with objects allocated on the V8 heap. Pay attention to terms like "protected pointer," "immutable," and "trusted pointer," which hint at security or optimization strategies.
    * **Data Structure Access:** Methods for accessing elements of `FixedArray` and `ByteArray`.
    * **Function-Related Operations:** Methods for loading information about functions (`SharedFunctionInfo`, `FunctionData`).
    * **JavaScript Interop (Possible):**  `LoadJSArrayElements`. This suggests interaction between WebAssembly and JavaScript.
    * **WasmGC (Garbage Collection) Specifics:**  Methods related to `StructType`, `ArrayType`, `RTT` (Runtime Type Information), type checking (`WasmTypeCheck`, `WasmTypeCast`), and `Null` values. These are specific to the WebAssembly Garbage Collection proposal.
    * **String Operations:** `LoadStringLength`, `StringAsWtf16`.
    * **Generic Helpers:** `HasInstanceType`, `TrapIf`, `TrapUnless`, `LoadTrustedDataFromInstanceObject`. These provide general utility.
    * **Simplified Operations:** `simplified()`. This refers to the `SimplifiedOperatorBuilder`, which is part of V8's internal representation.

7. **Identify Key Concepts and Relationships:**
    * **Graph Assembler:** The base class is central. Understand that `WasmGraphAssembler` adds WebAssembly-specific features.
    * **Nodes:** The methods generally return `Node*`. This confirms the graph-based representation.
    * **Machine Types:**  `MachineType` appears frequently, indicating operations at the machine level (e.g., word size, integer types).
    * **Object Access:**  The `ObjectAccess` struct is used for memory access, likely controlling write barriers for garbage collection.
    * **Builtins:**  Understanding what builtins are (predefined functions) is essential.
    * **Frame States:** The mention of `frame_state` is related to debugging and exception handling.

8. **Address Specific Instructions (as per the prompt):**
    * **Functionality Listing:** Systematically list the categories of functions identified in step 6.
    * **Torque Check:**  Look for the `.tq` extension. It's not present, so the answer is straightforward.
    * **JavaScript Relationship:** Focus on methods that hint at interaction (e.g., `LoadJSArrayElements`). Think about scenarios where WebAssembly might interact with JavaScript arrays.
    * **Code Logic Reasoning:** Select a simple method (like `SmiConstant`) and demonstrate its behavior with an example. Choose inputs and expected outputs.
    * **Common Programming Errors:** Consider typical errors when working with memory, types, or indices, and relate them to the methods provided (e.g., out-of-bounds access with array methods, null pointer dereferences with methods that have `CheckForNull`).

9. **Refine and Organize:** Structure the answer logically, using headings and bullet points for clarity. Provide concise explanations for each functional area.

10. **Review and Verify:** Read through the answer to ensure accuracy and completeness. Check if all parts of the prompt have been addressed. For example, double-check the assumptions made for the code logic reasoning.

By following these steps, you can systematically analyze a complex source code file like `WasmGraphAssembler.h` and extract meaningful information about its purpose and functionality. The key is to start with the high-level context and gradually delve into the details of the class methods and their interactions.
## 功能列举

`v8/src/compiler/wasm-graph-assembler.h` 定义了一个名为 `WasmGraphAssembler` 的 C++ 类。这个类的主要功能是 **在 V8 编译 WebAssembly 代码的过程中，构建中间表示 (IR) 图 (也称为 Sea of Nodes 图)**。 它继承自 `GraphAssembler`，并针对 WebAssembly 的特性进行了扩展。

以下是 `WasmGraphAssembler` 的主要功能点：

**1. 构建调用 Builtin 函数的节点:**

*   `CallBuiltinThroughJumptable`:  创建一个通过跳转表调用内置函数的节点。这种方式通常用于优化，因为它可以使用更短的指令。
*   `GetBuiltinPointerTarget`: 获取内置函数的指针目标，通常用于直接调用。
*   `CallBuiltin`: 创建一个直接调用内置函数的节点。
*   `CallBuiltinWithFrameState`: 创建一个调用内置函数的节点，并包含当前的帧状态信息，用于调试和异常处理。

**2. 创建常量节点:**

*   `NumberConstant`: 创建一个表示双精度浮点数常量的节点。
*   `SmiConstant`: 创建一个表示小整数 (Smi) 常量的节点。

**3. 控制流操作:**

*   `Branch`: 创建一个分支节点，根据条件跳转到不同的控制流路径。

**4. 图操作:**

*   `MergeControlToEnd`: 将控制流合并到当前图的末尾。

**5. 数值类型转换:**

*   提供一系列 `Build...` 函数，用于在不同的整数和指针类型之间进行转换，例如 `BuildTruncateIntPtrToInt32`、`BuildChangeInt32ToIntPtr` 等。

**6. 堆对象操作:**

*   `Allocate`:  分配指定大小的堆内存。
*   `LoadFromObject`: 从堆对象中加载指定类型的字段。
*   `LoadProtectedPointerFromObject`, `LoadImmutableProtectedPointerFromObject`, `LoadImmutableFromObject`:  加载受保护或不可变的指针或值。这些通常涉及安全性和优化。
*   `StoreToObject`: 将值存储到堆对象的指定字段。
*   `InitializeImmutableInObject`: 初始化堆对象中不可变的字段。
*   `BuildDecodeSandboxedExternalPointer`, `BuildLoadExternalPointerFromObject`: 处理外部指针，可能涉及到安全沙箱。
*   `LoadImmutableTrustedPointerFromObject`, `LoadTrustedPointerFromObject`, `LoadTrustedPointerFromObjectTrapOnNull`, `BuildDecodeTrustedPointer`:  处理可信指针，可能用于优化和内部结构访问。
*   `IsSmi`:  检查一个节点是否表示 Smi (小整数)。

**7. Map 和 InstanceType 操作:**

*   `LoadMap`: 加载对象的 Map (描述对象结构和类型的元数据)。
*   `StoreMap`: 存储对象的 Map。
*   `LoadInstanceType`: 加载 Map 的 InstanceType，用于区分不同类型的对象。
*   `LoadWasmTypeInfo`: 加载 WebAssembly 特定的类型信息。

**8. FixedArray 操作:**

*   `LoadFixedArrayLengthAsSmi`: 加载固定数组的长度。
*   `LoadFixedArrayElement`, `LoadImmutableFixedArrayElement`: 加载固定数组的元素。
*   `StoreFixedArrayElement`: 存储固定数组的元素。
*   `LoadWeakFixedArrayElement`: 加载弱引用的固定数组元素。

**9. Function 相关操作:**

*   `LoadSharedFunctionInfo`: 加载 JavaScript 函数的共享信息。
*   `LoadContextFromJSFunction`: 加载 JavaScript 函数的上下文。
*   `LoadFunctionDataFromJSFunction`: 加载 JavaScript 函数的数据。
*   `LoadExportedFunctionIndexAsSmi`, `LoadExportedFunctionInstanceData`: 加载导出的 WebAssembly 函数的相关信息。

**10. JavaScript 对象操作:**

*   `LoadJSArrayElements`: 加载 JavaScript 数组的元素。

**11. WebAssembly GC 对象操作 (与 WebAssembly 垃圾回收相关):**

*   `FieldOffset`: 获取 WebAssembly 结构体字段的偏移量。
*   `WasmArrayElementOffset`: 获取 WebAssembly 数组元素的偏移量。
*   `IsDataRefMap`: 检查一个 Map 是否是 DataRef 的 Map。
*   `WasmTypeCheck`, `WasmTypeCheckAbstract`, `WasmTypeCast`, `WasmTypeCastAbstract`: 执行 WebAssembly 类型检查和类型转换。
*   `Null`: 创建一个 WebAssembly null 值的节点。
*   `IsNull`, `IsNotNull`: 检查一个值是否为 null。
*   `AssertNotNull`: 断言一个值不为 null，如果为 null 则触发 trap。
*   `WasmAnyConvertExtern`, `WasmExternConvertAny`: 在 WebAssembly 的 `anyref` 和 `externref` 类型之间进行转换。
*   `StructGet`, `StructSet`: 获取和设置 WebAssembly 结构体的字段。
*   `ArrayGet`, `ArraySet`: 获取和设置 WebAssembly 数组的元素。
*   `ArrayLength`: 获取 WebAssembly 数组的长度。
*   `ArrayInitializeLength`: 初始化 WebAssembly 数组的长度。

**12. 字符串操作:**

*   `LoadStringLength`: 加载字符串的长度。
*   `StringAsWtf16`: 将字符串转换为 WTF-16 编码。
*   `StringPrepareForGetCodeunit`: 为获取字符串的代码单元做准备。

**13. 通用辅助函数:**

*   `HasInstanceType`: 检查堆对象是否具有特定的 InstanceType。
*   `TrapIf`, `TrapUnless`: 根据条件触发 WebAssembly trap (类似异常)。
*   `LoadTrustedDataFromInstanceObject`: 加载实例对象的可信数据。
*   `simplified()`: 返回一个 `SimplifiedOperatorBuilder`，用于构建简化图。

## 关于 .tq 结尾

如果 `v8/src/compiler/wasm-graph-assembler.h` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。 Torque 是一种 V8 使用的领域特定语言，用于生成高效的 C++ 代码，特别是用于实现内置函数和运行时功能。

由于该文件以 `.h` 结尾，它是一个标准的 C++ 头文件。

## 与 JavaScript 的关系 (通过 WebAssembly)

`WasmGraphAssembler` 本身并不直接操作 JavaScript 对象。它的作用是在编译 WebAssembly 代码的过程中构建图。然而，WebAssembly 经常需要与 JavaScript 互操作，例如：

*   **调用 JavaScript 函数:** WebAssembly 可以通过导入的函数调用 JavaScript 代码。`CallBuiltin` 等方法可能会用于生成调用特定 V8 内置函数的节点，这些内置函数可能涉及到 WebAssembly 调用 JavaScript 的机制。
*   **访问 JavaScript 对象:** WebAssembly 可以通过 `externref` 类型持有对 JavaScript 对象的引用。 `LoadJSArrayElements` 等方法表明，编译后的 WebAssembly 代码可能需要访问 JavaScript 数组的内部结构。
*   **类型转换:**  WebAssembly 的类型需要与 JavaScript 的类型进行转换。 `WasmAnyConvertExtern` 和 `WasmExternConvertAny`  用于处理 `anyref` (可以持有任何 JavaScript 对象) 和 `externref` (外部引用) 之间的转换，这是 WebAssembly 与 JavaScript 互操作的关键部分。

**JavaScript 示例 (概念性):**

假设你在 WebAssembly 中有一个函数，它接收一个 JavaScript 数组作为参数，并需要读取数组的长度：

```javascript
// JavaScript 代码
const jsArray = [1, 2, 3, 4, 5];

// 假设这是编译后的 WebAssembly 代码的逻辑 (通过 WasmGraphAssembler 构建)
function wasmFunction(arrayRef) { // arrayRef 是对 jsArray 的引用 (externref)
  // ...
  // 使用 WasmGraphAssembler 生成的节点，从 arrayRef 中加载 JavaScript 数组的元素
  const elements = loadJSArrayElements(arrayRef);
  // ...
  // 获取数组的长度 (可能涉及其他 WasmGraphAssembler 方法)
  const length = elements.length;
  // ...
  return length;
}

wasmFunction(jsArray);
```

在这个概念性的例子中，`WasmGraphAssembler` 会负责生成 `loadJSArrayElements` 操作对应的节点，以便在 WebAssembly 代码中访问 JavaScript 数组的内部结构。

## 代码逻辑推理 (假设输入与输出)

**示例方法:** `SmiConstant(Tagged_t value)`

**假设输入:**  `value = 5` (假设 `Tagged_t` 可以隐式转换为整数)

**代码逻辑:**

1. `Internals::IntegralToSmi(static_cast<int>(value))`：将整数 `5` 转换为 Smi 表示。在 V8 中，Smi 通常是通过将整数左移一位并设置最低位为 0 来实现的。例如，如果指针大小是 64 位，那么 `5` 可能被表示为 `0x000000000000000a`。
2. 根据指针大小 (`kTaggedSize`)：
    *   如果 `kTaggedSize == kInt32Size` (32位系统)：将 Smi 值截断为 32 位整数，并创建一个 `Int32Constant` 节点。
    *   如果 `kTaggedSize != kInt32Size` (64位系统)：将 Smi 值转换为 64 位整数，并创建一个 `Int64Constant` 节点。

**假设输出 (64位系统):** 一个表示 64 位整数常量 `0x000000000000000a` 的 `Node*`。

**示例方法:** `Branch(Node* cond, Node** true_node, Node** false_node, BranchHint hint)`

**假设输入:**

*   `cond`: 指向一个表示布尔条件的 `Node*` (例如，比较操作的结果)。
*   `true_node`: 一个指向 `Node*` 的指针，用于存储分支为真的目标节点。
*   `false_node`: 一个指向 `Node*` 的指针，用于存储分支为假的目标节点。
*   `hint`: 一个 `BranchHint` 枚举值，可能用于优化器。

**代码逻辑:**

1. 创建一个新的 `Branch` 节点，将 `cond` 作为输入。
2. 获取 `Branch` 节点的两个输出：一个表示条件为真时的控制流，另一个表示条件为假时的控制流。
3. 将真分支的输出节点地址赋值给 `*true_node`。
4. 将假分支的输出节点地址赋值给 `*false_node`。
5. 返回新创建的 `Branch` 节点的指针。

**假设输出:**

*   返回一个指向新创建的 `Branch` 节点的 `Node*`。
*   `*true_node` 将指向 `Branch` 节点表示真分支的输出节点。
*   `*false_node` 将指向 `Branch` 节点表示假分支的输出节点。

## 用户常见的编程错误 (与 `WasmGraphAssembler` 相关的概念)

虽然开发者通常不直接使用 `WasmGraphAssembler`，但理解其背后的概念可以帮助理解 WebAssembly 编译和 V8 的内部工作原理，从而避免与这些概念相关的错误。

**1. 类型错误 (与 `LoadFromObject`, `StoreToObject` 等相关):**

*   **错误:** 假设对象的某个字段是某种类型，但实际上是另一种类型。例如，尝试将一个字符串加载为整数。
*   **C++ 示例 (模拟概念):**

    ```c++
    struct MyObject {
        int value;
    };

    MyObject obj;
    obj.value = 10;

    // 错误地尝试将 int 加载为 double
    double wrong_value = static_cast<double>(obj.value); // 这在 C++ 中可行，但在底层表示上可能不一致

    // 在 WasmGraphAssembler 的上下文中，会因为类型不匹配导致编译错误或运行时错误。
    ```

**2. 内存访问错误 (与 `LoadFixedArrayElement`, `StoreFixedArrayElement` 等相关):**

*   **错误:** 尝试访问数组或对象的越界索引。
*   **WebAssembly 示例:**  如果 WebAssembly 代码尝试访问超出数组边界的元素，V8 的运行时系统会检测到并抛出错误。 `WasmGraphAssembler` 生成的代码会进行边界检查。

**3. 空指针解引用 (与需要 `CheckForNull` 的方法相关):**

*   **错误:** 在没有检查指针是否为空的情况下尝试访问指针指向的内存。
*   **WebAssembly 示例:** 如果 WebAssembly 代码尝试访问一个 null `externref` 指向的对象，会导致运行时错误。 `WasmGraphAssembler` 提供的 `AssertNotNull` 等方法可以用来显式地进行空值检查。

**4. 不正确的类型转换 (与 `Build...` 系列的转换函数相关):**

*   **错误:** 在不同的数值类型之间进行不正确的转换，导致数据丢失或精度问题。
*   **C++ 示例 (模拟概念):**

    ```c++
    int large_int = 1000000000;
    short small_int = static_cast<short>(large_int); // 数据溢出
    ```

**5. 对不可变数据的修改 (与 `InitializeImmutableInObject` 等相关):**

*   **错误:** 尝试修改被声明为不可变的数据。
*   **V8 内部:**  `WasmGraphAssembler` 生成的代码会确保对不可变对象的写入操作受到限制，以维护程序的正确性和优化机会。

理解 `WasmGraphAssembler` 的功能有助于开发者理解 V8 如何处理 WebAssembly 代码，并有助于调试与类型、内存访问和数据完整性相关的 WebAssembly 错误。

### 提示词
```
这是目录为v8/src/compiler/wasm-graph-assembler.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/wasm-graph-assembler.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if !V8_ENABLE_WEBASSEMBLY
#error This header should only be included if WebAssembly is enabled.
#endif  // !V8_ENABLE_WEBASSEMBLY

#ifndef V8_COMPILER_WASM_GRAPH_ASSEMBLER_H_
#define V8_COMPILER_WASM_GRAPH_ASSEMBLER_H_

#include "src/compiler/graph-assembler.h"
#include "src/wasm/wasm-code-manager.h"

namespace v8 {
namespace internal {
namespace compiler {

CallDescriptor* GetBuiltinCallDescriptor(
    Builtin name, Zone* zone, StubCallMode stub_mode,
    bool needs_frame_state = false,
    Operator::Properties properties = Operator::kNoProperties);

ObjectAccess ObjectAccessForGCStores(wasm::ValueType type);

class WasmGraphAssembler : public GraphAssembler {
 public:
  WasmGraphAssembler(MachineGraph* mcgraph, Zone* zone)
      : GraphAssembler(mcgraph, zone, BranchSemantics::kMachine),
        simplified_(zone) {}

  // While CallBuiltin() translates to a direct call to the address of the
  // builtin, CallBuiltinThroughJumptable instead jumps to a slot in a jump
  // table that then calls the builtin. As the jump table is "close" to the
  // generated code, this is encoded as a near call resulting in the instruction
  // being shorter than a direct call to the builtin.
  template <typename... Args>
  Node* CallBuiltinThroughJumptable(Builtin builtin,
                                    Operator::Properties properties,
                                    Args... args) {
    auto* call_descriptor = GetBuiltinCallDescriptor(
        builtin, temp_zone(), StubCallMode::kCallWasmRuntimeStub, false,
        properties);
    // A direct call to a wasm runtime stub defined in this module.
    // Just encode the stub index. This will be patched at relocation.
    Node* call_target = mcgraph()->RelocatableWasmBuiltinCallTarget(builtin);
    return Call(call_descriptor, call_target, args...);
  }

  Node* GetBuiltinPointerTarget(Builtin builtin) {
    static_assert(std::is_same<Smi, BuiltinPtr>(), "BuiltinPtr must be Smi");
    return NumberConstant(static_cast<int>(builtin));
  }

  template <typename... Args>
  Node* CallBuiltin(Builtin name, Operator::Properties properties,
                    Args... args) {
    return CallBuiltinImpl(name, false, properties, args...);
  }

  template <typename... Args>
  Node* CallBuiltinWithFrameState(Builtin name, Operator::Properties properties,
                                  Node* frame_state, Args... args) {
    DCHECK_EQ(frame_state->opcode(), IrOpcode::kFrameState);
    return CallBuiltinImpl(name, true, properties, frame_state, args...);
  }

  // Sets {true_node} and {false_node} to their corresponding Branch outputs.
  // Returns the Branch node. Does not change control().
  Node* Branch(Node* cond, Node** true_node, Node** false_node,
               BranchHint hint);

  Node* NumberConstant(double value) {
    return graph()->NewNode(mcgraph()->common()->NumberConstant(value));
  }

  Node* SmiConstant(Tagged_t value) {
    Address tagged_value = Internals::IntegralToSmi(static_cast<int>(value));
    return kTaggedSize == kInt32Size
               ? Int32Constant(static_cast<int32_t>(tagged_value))
               : Int64Constant(static_cast<int64_t>(tagged_value));
  }

  void MergeControlToEnd(Node* control) {
    NodeProperties::MergeControlToEnd(graph(), common(), control);
  }

  // Numeric conversions
  Node* BuildTruncateIntPtrToInt32(Node* value);

  Node* BuildChangeInt32ToIntPtr(Node* value);

  Node* BuildChangeIntPtrToInt64(Node* value);

  Node* BuildChangeUint32ToUintPtr(Node* node);

  Node* BuildSmiShiftBitsConstant();

  Node* BuildSmiShiftBitsConstant32();

  Node* BuildChangeInt32ToSmi(Node* value);

  Node* BuildChangeUint31ToSmi(Node* value);

  Node* BuildChangeSmiToInt32(Node* value);

  Node* BuildConvertUint32ToSmiWithSaturation(Node* value, uint32_t maxval);

  Node* BuildChangeSmiToIntPtr(Node* value);

  // Helper functions for dealing with HeapObjects.
  // Rule of thumb: if access to a given field in an object is required in
  // at least two places, put a helper function here.

  Node* Allocate(int size);

  Node* Allocate(Node* size);

  Node* LoadFromObject(MachineType type, Node* base, Node* offset);

  Node* LoadFromObject(MachineType type, Node* base, int offset) {
    return LoadFromObject(type, base, IntPtrConstant(offset));
  }

  Node* LoadProtectedPointerFromObject(Node* object, Node* offset);
  Node* LoadProtectedPointerFromObject(Node* object, int offset) {
    return LoadProtectedPointerFromObject(object, IntPtrConstant(offset));
  }

  Node* LoadImmutableProtectedPointerFromObject(Node* object, Node* offset);
  Node* LoadImmutableProtectedPointerFromObject(Node* object, int offset) {
    return LoadImmutableProtectedPointerFromObject(object,
                                                   IntPtrConstant(offset));
  }

  Node* LoadImmutableFromObject(MachineType type, Node* base, Node* offset);

  Node* LoadImmutableFromObject(MachineType type, Node* base, int offset) {
    return LoadImmutableFromObject(type, base, IntPtrConstant(offset));
  }

  Node* LoadImmutable(LoadRepresentation rep, Node* base, Node* offset);

  Node* LoadImmutable(LoadRepresentation rep, Node* base, int offset) {
    return LoadImmutable(rep, base, IntPtrConstant(offset));
  }

  Node* StoreToObject(ObjectAccess access, Node* base, Node* offset,
                      Node* value);

  Node* StoreToObject(ObjectAccess access, Node* base, int offset,
                      Node* value) {
    return StoreToObject(access, base, IntPtrConstant(offset), value);
  }

  Node* InitializeImmutableInObject(ObjectAccess access, Node* base,
                                    Node* offset, Node* value);

  Node* InitializeImmutableInObject(ObjectAccess access, Node* base, int offset,
                                    Node* value) {
    return InitializeImmutableInObject(access, base, IntPtrConstant(offset),
                                       value);
  }

  Node* BuildDecodeSandboxedExternalPointer(Node* handle,
                                            ExternalPointerTag tag,
                                            Node* isolate_root);
  Node* BuildLoadExternalPointerFromObject(Node* object, int offset,
                                           ExternalPointerTag tag,
                                           Node* isolate_root);

  Node* BuildLoadExternalPointerFromObject(Node* object, int offset,
                                           Node* index, ExternalPointerTag tag,
                                           Node* isolate_root);

  Node* LoadImmutableTrustedPointerFromObject(Node* object, int offset,
                                              IndirectPointerTag tag);
  Node* LoadTrustedPointerFromObject(Node* object, int offset,
                                     IndirectPointerTag tag);
  // Returns the load node (where the source position for the trap needs to be
  // set by the caller) and the result.
  std::pair<Node*, Node*> LoadTrustedPointerFromObjectTrapOnNull(
      Node* object, int offset, IndirectPointerTag tag);
  Node* BuildDecodeTrustedPointer(Node* handle, IndirectPointerTag tag);

  Node* IsSmi(Node* object);

  // Maps and their contents.

  Node* LoadMap(Node* object);

  void StoreMap(Node* heap_object, Node* map);

  Node* LoadInstanceType(Node* map);

  Node* LoadWasmTypeInfo(Node* map);

  // FixedArrays.

  Node* LoadFixedArrayLengthAsSmi(Node* fixed_array);

  Node* LoadFixedArrayElement(Node* fixed_array, Node* index_intptr,
                              MachineType type = MachineType::AnyTagged());

  Node* LoadImmutableFixedArrayElement(
      Node* fixed_array, Node* index_intptr,
      MachineType type = MachineType::AnyTagged());

  Node* LoadFixedArrayElement(Node* array, int index, MachineType type);

  Node* LoadFixedArrayElementSmi(Node* array, int index) {
    return LoadFixedArrayElement(array, index, MachineType::TaggedSigned());
  }

  Node* LoadFixedArrayElementPtr(Node* array, int index) {
    return LoadFixedArrayElement(array, index, MachineType::TaggedPointer());
  }

  Node* LoadFixedArrayElementAny(Node* array, int index) {
    return LoadFixedArrayElement(array, index, MachineType::AnyTagged());
  }

  Node* LoadProtectedFixedArrayElement(Node* array, int index);
  Node* LoadProtectedFixedArrayElement(Node* array, Node* index_intptr);

  Node* LoadByteArrayElement(Node* byte_array, Node* index_intptr,
                             MachineType type);

  Node* StoreFixedArrayElement(Node* array, int index, Node* value,
                               ObjectAccess access);

  Node* StoreFixedArrayElementSmi(Node* array, int index, Node* value) {
    return StoreFixedArrayElement(
        array, index, value,
        ObjectAccess(MachineType::TaggedSigned(), kNoWriteBarrier));
  }

  Node* StoreFixedArrayElementAny(Node* array, int index, Node* value) {
    return StoreFixedArrayElement(
        array, index, value,
        ObjectAccess(MachineType::AnyTagged(), kFullWriteBarrier));
  }

  Node* LoadWeakFixedArrayElement(Node* fixed_array, Node* index_intptr);

  // Functions, SharedFunctionInfos, FunctionData.

  Node* LoadSharedFunctionInfo(Node* js_function);

  Node* LoadContextFromJSFunction(Node* js_function);

  Node* LoadFunctionDataFromJSFunction(Node* js_function);

  Node* LoadExportedFunctionIndexAsSmi(Node* exported_function_data);

  Node* LoadExportedFunctionInstanceData(Node* exported_function_data);

  // JavaScript objects.

  Node* LoadJSArrayElements(Node* js_array);

  // WasmGC objects.

  Node* FieldOffset(const wasm::StructType* type, uint32_t field_index);

  Node* WasmArrayElementOffset(Node* index, wasm::ValueType element_type);

  Node* IsDataRefMap(Node* map);

  Node* WasmTypeCheck(Node* object, Node* rtt, WasmTypeCheckConfig config);
  Node* WasmTypeCheckAbstract(Node* object, WasmTypeCheckConfig config);

  Node* WasmTypeCast(Node* object, Node* rtt, WasmTypeCheckConfig config);
  Node* WasmTypeCastAbstract(Node* object, WasmTypeCheckConfig config);

  Node* Null(wasm::ValueType type);

  Node* IsNull(Node* object, wasm::ValueType type);

  Node* IsNotNull(Node* object, wasm::ValueType type);

  Node* AssertNotNull(Node* object, wasm::ValueType type, TrapId trap_id);

  Node* WasmAnyConvertExtern(Node* object);

  Node* WasmExternConvertAny(Node* object);

  Node* StructGet(Node* object, const wasm::StructType* type, int field_index,
                  bool is_signed, CheckForNull null_check);

  void StructSet(Node* object, Node* value, const wasm::StructType* type,
                 int field_index, CheckForNull null_check);

  Node* ArrayGet(Node* array, Node* index, const wasm::ArrayType* type,
                 bool is_signed);

  void ArraySet(Node* array, Node* index, Node* value,
                const wasm::ArrayType* type);

  Node* ArrayLength(Node* array, CheckForNull null_check);

  void ArrayInitializeLength(Node* array, Node* length);

  Node* LoadStringLength(Node* string);

  Node* StringAsWtf16(Node* string);

  Node* StringPrepareForGetCodeunit(Node* string);

  // Generic helpers.

  Node* HasInstanceType(Node* heap_object, InstanceType type);

  void TrapIf(Node* condition, TrapId reason) {
    // Initially wasm traps don't have a FrameState.
    const bool has_frame_state = false;
    AddNode(
        graph()->NewNode(mcgraph()->common()->TrapIf(reason, has_frame_state),
                         condition, effect(), control()));
  }

  void TrapUnless(Node* condition, TrapId reason) {
    // Initially wasm traps don't have a FrameState.
    const bool has_frame_state = false;
    AddNode(graph()->NewNode(
        mcgraph()->common()->TrapUnless(reason, has_frame_state), condition,
        effect(), control()));
  }

  Node* LoadTrustedDataFromInstanceObject(Node* instance_object);

  SimplifiedOperatorBuilder* simplified() override { return &simplified_; }

 private:
  template <typename... Args>
  Node* CallBuiltinImpl(Builtin name, bool needs_frame_state,
                        Operator::Properties properties, Args... args) {
    auto* call_descriptor = GetBuiltinCallDescriptor(
        name, temp_zone(), StubCallMode::kCallBuiltinPointer, needs_frame_state,
        properties);
    Node* call_target = GetBuiltinPointerTarget(name);
    return Call(call_descriptor, call_target, args...);
  }

  SimplifiedOperatorBuilder simplified_;
};

}  // namespace compiler
}  // namespace internal
}  // namespace v8

#endif  // V8_COMPILER_WASM_GRAPH_ASSEMBLER_H_
```