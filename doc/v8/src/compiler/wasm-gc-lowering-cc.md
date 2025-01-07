Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

**1. Initial Understanding and Goals:**

The request asks for a functional summary of a V8 source file (`wasm-gc-lowering.cc`). It also includes specific points to address, like:

* File extension implication (not applicable here).
* Relationship to JavaScript (important).
* Code logic inference (requiring assumptions).
* Common programming errors it might address.
* Overall function summarization (the main goal).

**2. High-Level Analysis (Skimming the Code):**

The first step is to quickly skim the code to get a general idea of its purpose. Keywords like `WasmGCLowering`, `Reduce`, `IrOpcode`, and names like `WasmTypeCheck`, `WasmStructGet`, `WasmArraySet` immediately stand out. The inclusion of `#include "src/wasm/..."` strongly suggests this code deals with WebAssembly. The "GC" in `WasmGCLowering` points to Garbage Collection. The "lowering" suggests a transformation to a lower-level representation.

**3. Identifying Key Classes and Methods:**

* **`WasmGCLowering` Class:** This is the central class. Its constructor and `Reduce` method are crucial. The constructor initializes state, and the `Reduce` method clearly handles different operation types.
* **`Reduce` Method and `switch` Statement:**  The `Reduce` method and its `switch` statement based on `node->opcode()` are the core logic. This is where the different WebAssembly operations are handled. Each `case` corresponds to a specific WebAssembly instruction related to Garbage Collection.
* **Helper Methods:**  Methods like `Null`, `IsNull`, and the various `Reduce...` methods (e.g., `ReduceWasmTypeCheck`, `ReduceWasmStructGet`) handle specific aspects of the lowering process.
* **`gasm_` (likely a `WasmGraphAssembler`):** This member variable is used extensively to generate lower-level machine code instructions. It provides methods like `LoadImmutable`, `TaggedEqual`, `TrapIf`, etc.

**4. Understanding the "Lowering" Concept:**

The term "lowering" in compiler terminology means transforming a higher-level representation of code into a lower-level one, closer to machine instructions. In this context, the code is taking WebAssembly GC instructions and converting them into a form that the V8 JavaScript engine can execute. This involves things like:

* Generating explicit null checks (or relying on trap handlers).
* Performing type checks and casts.
* Accessing and manipulating memory for structs and arrays.

**5. Focusing on Individual `Reduce` Cases:**

Now, the detailed analysis involves looking at the individual `case` statements in the `Reduce` method. For each case, try to understand:

* **What WebAssembly operation it corresponds to:**  The `IrOpcode::k...` names are generally quite descriptive (e.g., `kWasmTypeCheck`, `kWasmStructGet`).
* **What inputs it takes:** The `node->InputAt(...)` calls reveal the operands of the WebAssembly instruction.
* **What it does:** The code within each `case` performs the lowering logic, often using the `gasm_` object to generate lower-level operations.
* **What the output is:**  The `ReplaceWithValue` call indicates the result of the lowering process for that specific node.

**6. Identifying JavaScript Connections:**

The code directly deals with WebAssembly GC features, which are an extension to the core WebAssembly specification. The connection to JavaScript lies in how V8 executes WebAssembly. V8 needs to translate these WebAssembly GC operations into equivalent JavaScript runtime operations or lower-level machine code that manages JavaScript objects. The conversion between WebAssembly types (like `externref`) and JavaScript values (like `null` or JavaScript objects) is a key aspect of this connection.

**7. Inferring Code Logic and Examples:**

For the `ReduceWasmTypeCheck` and `ReduceWasmTypeCast` functions, the logic is about verifying and converting between different WebAssembly reference types. The assumptions and example provided in the initial good answer are excellent here: assuming an object and a target RTT (Runtime Type Information) and showing how the code would check compatibility.

**8. Identifying Potential Programming Errors:**

The code deals with null checks and type casts, which are common sources of errors in programming, especially in languages with manual memory management or complex type systems. The explicit checks and traps for null dereferences and illegal casts point to the types of errors the lowering process aims to handle.

**9. Synthesizing the Summary:**

Finally, combine the understanding gained from the individual parts into a concise summary. The summary should highlight the core purpose of the file: lowering WebAssembly GC operations for execution within V8. It should mention key aspects like type checking, casting, null handling, and memory access for structs and arrays.

**Self-Correction/Refinement during the Process:**

* **Initial Misinterpretations:**  Initially, one might not fully grasp the "lowering" concept. Reading more about compiler design or V8's architecture would help.
* **Overlooking Details:** It's easy to skim over important details like the `null_check_strategy_` or the specific conditions in the `if` statements. Careful reading and potentially looking up related V8 documentation are necessary.
* **Connecting to JavaScript:** The exact mechanisms of how WebAssembly GC interacts with JavaScript's object model might not be immediately obvious. Further research into V8's WebAssembly implementation would be needed for a deeper understanding.

By following these steps, including careful reading, keyword identification, and logical deduction, one can arrive at a comprehensive understanding of the `wasm-gc-lowering.cc` file's functionality.
好的，让我们来分析一下 `v8/src/compiler/wasm-gc-lowering.cc` 这个 V8 源代码文件的功能。

**1. 文件类型判断:**

首先，根据您的描述，如果文件以 `.tq` 结尾，它才是 V8 Torque 源代码。`wasm-gc-lowering.cc` 以 `.cc` 结尾，所以它是一个 **C++ 源代码文件**，而不是 Torque 文件。

**2. 主要功能归纳:**

从代码的结构和包含的头文件来看，`wasm-gc-lowering.cc` 的主要功能是 **降低 (Lowering) WebAssembly 垃圾回收 (GC) 相关的操作**。

更具体地说，这个文件实现了一个 `WasmGCLowering` 类，它是一个 `AdvancedReducer`，用于在 V8 的编译器中将 WebAssembly GC 的高级操作转换为更底层的、更易于 V8 执行的中间表示形式。

**3. 详细功能分解:**

* **类型检查和转换:**
    * `ReduceWasmTypeCheck`, `ReduceWasmTypeCheckAbstract`:  处理 WebAssembly 的类型检查操作，判断一个对象是否属于某个特定的类型。
    * `ReduceWasmTypeCast`, `ReduceWasmTypeCastAbstract`: 处理 WebAssembly 的类型转换操作，尝试将一个对象转换为另一个类型，如果转换失败会触发陷阱 (trap)。
    * `ReduceWasmAnyConvertExtern`, `ReduceWasmExternConvertAny`: 处理 WebAssembly 的 `anyref` 和 `externref` 之间的转换。
* **空值处理:**
    * `ReduceAssertNotNull`:  处理断言非空操作，如果对象为空则触发陷阱。
    * `ReduceNull`: 生成 WebAssembly 的 `null` 值。
    * `ReduceIsNull`, `ReduceIsNotNull`:  判断一个对象是否为空。
* **RTT (Runtime Type Information) 相关:**
    * `ReduceRttCanon`:  获取规范的 RTT 值。
    * `ReduceTypeGuard`:  类型保护，用于在类型已知的情况下优化代码。
* **结构体 (Struct) 操作:**
    * `ReduceWasmStructGet`:  获取 WebAssembly 结构体中的字段值。
    * `ReduceWasmStructSet`:  设置 WebAssembly 结构体中的字段值。
* **数组 (Array) 操作:**
    * `ReduceWasmArrayGet`:  获取 WebAssembly 数组中的元素值。
    * `ReduceWasmArraySet`:  设置 WebAssembly 数组中的元素值。
    * `ReduceWasmArrayLength`:  获取 WebAssembly 数组的长度。
    * `ReduceWasmArrayInitializeLength`: 初始化数组的长度 (可能在数组创建时使用)。
* **字符串 (String) 操作:**
    * `ReduceStringAsWtf16`: 将字符串转换为 WTF-16 编码。
    * `ReduceStringPrepareForGetCodeunit`:  为获取字符串的代码单元做准备。
* **其他辅助功能:**
    * `TaggedOffset`: 计算带标签的偏移量。
    * `Null`:  获取指定 WebAssembly 类型的空值。
    * `IsNull`: 检查一个值是否为指定 WebAssembly 类型的空值。

**4. 与 JavaScript 的关系 (需要 JavaScript 示例):**

WebAssembly 最终会在 JavaScript 引擎 (如 V8) 中执行。WebAssembly GC 的引入使得 WebAssembly 可以直接操作具有垃圾回收特性的对象，这更接近 JavaScript 的对象模型。

`wasm-gc-lowering.cc` 的工作是将 WebAssembly 的 GC 操作转换为 V8 能够理解和执行的底层操作。 例如：

* **WebAssembly 的引用类型 (`anyref`, `eqref`, `structref`, `arrayref`, `funcref`, `externref`) 与 JavaScript 值的映射：**  `anyref` 可以容纳所有引用类型的值，包括 JavaScript 对象 (通过 `externref`)。类型检查和转换操作确保了在 WebAssembly 和 JavaScript 之间传递引用时的类型安全。
* **WebAssembly 的结构体和数组与 JavaScript 对象的某种潜在关联 (尽管不一定是直接映射)：**  V8 必须能够有效地表示和操作 WebAssembly 的结构体和数组，这可能涉及到创建和管理 JavaScript 对象或者使用 V8 内部的表示形式。

**JavaScript 示例 (概念性):**

虽然无法直接用 JavaScript 代码来展示 `wasm-gc-lowering.cc` 的内部工作原理，但可以说明 WebAssembly GC 功能在 JavaScript 中的体现：

```javascript
// 假设有一个 WebAssembly 模块导出了一个接受 anyref 参数的函数
const instance = await WebAssembly.instantiateStreaming(fetch('my_module.wasm'));
const wasmFunc = instance.exports.myFunction;

// 传递一个 JavaScript 对象给 WebAssembly 函数
wasmFunc({});

// 在 WebAssembly 内部， myfunction 可能会对传入的 anyref 进行类型检查或转换
// 例如，判断它是否是一个结构体或者一个特定的 JavaScript 对象类型。
```

**5. 代码逻辑推理 (假设输入与输出):**

假设 `ReduceWasmStructGet` 函数接收以下输入：

* **输入节点 (node):**  代表 `wasm.struct.get` 指令的 IR 节点。
* **操作数:**
    * `object`:  一个指向 WebAssembly 结构体实例的节点。
    * `field_index`:  要获取的字段的索引。
    * `field_type`:  字段的类型。

**可能的处理流程和输出:**

1. **空值检查 (根据 `info.null_check`):**  如果需要进行空值检查，则生成代码检查 `object` 是否为空，如果为空则触发陷阱。
2. **计算字段偏移量:**  根据 `field_index` 和结构体的布局信息，计算出该字段在内存中的偏移量。
3. **加载字段值:**  生成机器码指令，从 `object` 指向的内存地址加上偏移量处加载字段的值。加载的类型由 `field_type` 决定。
4. **输出:**  一个新的 IR 节点，代表加载的字段值。

**假设输入与输出示例:**

* **假设输入:**
    * `object`: 一个指向地址 `0x12345678` 的节点的引用 (假设该地址存储了一个有效的 WebAssembly 结构体)。
    * `field_index`: `1` (表示要获取第二个字段)。
    * `field_type`: `i32` (表示第二个字段是 32 位整数)。
* **可能的输出:**
    * 一个新的 IR 节点，表示从地址 `0x12345678 + offset_of_field_1` 加载的 32 位整数值。

**6. 涉及用户常见的编程错误:**

`wasm-gc-lowering.cc` 处理的许多操作都与 WebAssembly GC 的安全性和正确性密切相关，因此它间接涉及了用户在编写 WebAssembly 代码时可能犯的错误：

* **空指针解引用:**  `ReduceAssertNotNull`, `ReduceWasmStructGet`, `ReduceWasmArrayGet` 等函数中的空值检查机制可以防止 WebAssembly 代码尝试访问空引用，这在手动内存管理的语言中是一个常见的错误。
* **类型错误:**  `ReduceWasmTypeCheck`, `ReduceWasmTypeCast` 等函数确保了类型安全，防止将一个类型的对象错误地当作另一个类型的对象使用，这类似于 JavaScript 中的类型错误，但在 WebAssembly 中需要更严格的检查。
* **数组越界访问:**  虽然这段代码没有直接处理数组越界，但与数组相关的操作为后续的边界检查奠定了基础。
* **非法类型转换:**  `ReduceWasmTypeCast` 能够在类型转换失败时触发陷阱，防止程序在类型不匹配的情况下继续执行。

**示例 (WebAssembly 层面的错误):**

```wasm
;; 假设定义了一个结构体 Point { x: i32, y: i32 }

(module
  (type $Point_t (struct (field i32) (field i32)))
  (global $null_point (ref null $Point_t) null)

  (func $access_point_x (param $p (ref $Point_t)) (result i32)
    (local.get $p)
    (struct.get $Point_t 0) ;; 获取 x 字段
  )

  (func $main
    ;; 错误示例：尝试访问空结构体的字段
    (call $access_point_x (global.get $null_point))
  )
)
```

在上面的 WebAssembly 代码中，`$main` 函数尝试访问一个空结构体的 `x` 字段，这会导致一个运行时错误。`ReduceWasmStructGet` 这样的函数在 lowering 阶段会插入必要的空值检查，从而在 V8 执行这段代码时触发陷阱，防止程序崩溃或产生未定义的行为。

**7. 功能归纳 (总结第 1 部分):**

`v8/src/compiler/wasm-gc-lowering.cc` 的主要功能是 **在 V8 编译 WebAssembly 代码的过程中，将 WebAssembly 垃圾回收 (GC) 相关的指令转换成更底层的、更接近机器码的中间表示形式**。它涵盖了类型检查、类型转换、空值处理、结构体和数组的访问和修改等操作，旨在确保 WebAssembly GC 功能在 V8 中的正确、安全和高效执行。 这个过程是连接 WebAssembly 的高级 GC 特性和 V8 底层执行机制的关键步骤。

请提供第 2 部分的内容，以便我进行更全面的分析。

Prompt: 
```
这是目录为v8/src/compiler/wasm-gc-lowering.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/wasm-gc-lowering.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/wasm-gc-lowering.h"

#include "src/base/logging.h"
#include "src/common/globals.h"
#include "src/compiler/access-builder.h"
#include "src/compiler/common-operator.h"
#include "src/compiler/compiler-source-position-table.h"
#include "src/compiler/node-properties.h"
#include "src/compiler/opcodes.h"
#include "src/compiler/operator.h"
#include "src/compiler/wasm-graph-assembler.h"
#include "src/objects/heap-number.h"
#include "src/objects/string.h"
#include "src/wasm/object-access.h"
#include "src/wasm/wasm-engine.h"
#include "src/wasm/wasm-linkage.h"
#include "src/wasm/wasm-objects.h"
#include "src/wasm/wasm-subtyping.h"

namespace v8 {
namespace internal {
namespace compiler {

namespace {
int TaggedOffset(FieldAccess access) {
  DCHECK(access.base_is_tagged);
  return wasm::ObjectAccess::ToTagged(access.offset);
}
}  // namespace

WasmGCLowering::WasmGCLowering(Editor* editor, MachineGraph* mcgraph,
                               const wasm::WasmModule* module,
                               bool disable_trap_handler,
                               SourcePositionTable* source_position_table)
    : AdvancedReducer(editor),
      null_check_strategy_(trap_handler::IsTrapHandlerEnabled() &&
                                   V8_STATIC_ROOTS_BOOL && !disable_trap_handler
                               ? NullCheckStrategy::kTrapHandler
                               : NullCheckStrategy::kExplicit),
      gasm_(mcgraph, mcgraph->zone()),
      module_(module),
      dead_(mcgraph->Dead()),
      mcgraph_(mcgraph),
      source_position_table_(source_position_table) {}

Reduction WasmGCLowering::Reduce(Node* node) {
  switch (node->opcode()) {
    case IrOpcode::kWasmTypeCheck:
      return ReduceWasmTypeCheck(node);
    case IrOpcode::kWasmTypeCheckAbstract:
      return ReduceWasmTypeCheckAbstract(node);
    case IrOpcode::kWasmTypeCast:
      return ReduceWasmTypeCast(node);
    case IrOpcode::kWasmTypeCastAbstract:
      return ReduceWasmTypeCastAbstract(node);
    case IrOpcode::kAssertNotNull:
      return ReduceAssertNotNull(node);
    case IrOpcode::kNull:
      return ReduceNull(node);
    case IrOpcode::kIsNull:
      return ReduceIsNull(node);
    case IrOpcode::kIsNotNull:
      return ReduceIsNotNull(node);
    case IrOpcode::kRttCanon:
      return ReduceRttCanon(node);
    case IrOpcode::kTypeGuard:
      return ReduceTypeGuard(node);
    case IrOpcode::kWasmAnyConvertExtern:
      return ReduceWasmAnyConvertExtern(node);
    case IrOpcode::kWasmExternConvertAny:
      return ReduceWasmExternConvertAny(node);
    case IrOpcode::kWasmStructGet:
      return ReduceWasmStructGet(node);
    case IrOpcode::kWasmStructSet:
      return ReduceWasmStructSet(node);
    case IrOpcode::kWasmArrayGet:
      return ReduceWasmArrayGet(node);
    case IrOpcode::kWasmArraySet:
      return ReduceWasmArraySet(node);
    case IrOpcode::kWasmArrayLength:
      return ReduceWasmArrayLength(node);
    case IrOpcode::kWasmArrayInitializeLength:
      return ReduceWasmArrayInitializeLength(node);
    case IrOpcode::kStringAsWtf16:
      return ReduceStringAsWtf16(node);
    case IrOpcode::kStringPrepareForGetCodeunit:
      return ReduceStringPrepareForGetCodeunit(node);
    default:
      return NoChange();
  }
}

Node* WasmGCLowering::Null(wasm::ValueType type) {
  RootIndex index =
      type.use_wasm_null() ? RootIndex::kWasmNull : RootIndex::kNullValue;
  return gasm_.LoadImmutable(MachineType::Pointer(), gasm_.LoadRootRegister(),
                             IsolateData::root_slot_offset(index));
}

Node* WasmGCLowering::IsNull(Node* object, wasm::ValueType type) {
#if V8_STATIC_ROOTS_BOOL
  Node* null_value = gasm_.UintPtrConstant(
      type.use_wasm_null() ? StaticReadOnlyRoot::kWasmNull
                           : StaticReadOnlyRoot::kNullValue);
#else
  Node* null_value = Null(type);
#endif
  return gasm_.TaggedEqual(object, null_value);
}

// TODO(manoskouk): Use the Callbacks infrastructure from wasm-compiler.h to
// unify all check/cast implementations.
// TODO(manoskouk): Find a way to optimize branches on typechecks.
Reduction WasmGCLowering::ReduceWasmTypeCheck(Node* node) {
  DCHECK_EQ(node->opcode(), IrOpcode::kWasmTypeCheck);

  Node* object = node->InputAt(0);
  Node* rtt = node->InputAt(1);
  Node* effect_input = NodeProperties::GetEffectInput(node);
  Node* control_input = NodeProperties::GetControlInput(node);
  auto config = OpParameter<WasmTypeCheckConfig>(node->op());
  int rtt_depth = wasm::GetSubtypingDepth(module_, config.to.ref_index());
  bool object_can_be_null = config.from.is_nullable();
  bool object_can_be_i31 =
      wasm::IsSubtypeOf(wasm::kWasmI31Ref.AsNonNull(), config.from, module_);

  gasm_.InitializeEffectControl(effect_input, control_input);

  auto end_label = gasm_.MakeLabel(MachineRepresentation::kWord32);
  bool is_cast_from_any = config.from.is_reference_to(wasm::HeapType::kAny);

  // If we are casting from any and null results in check failure, then the
  // {IsDataRefMap} check below subsumes the null check. Otherwise, perform
  // an explicit null check now.
  if (object_can_be_null && (!is_cast_from_any || config.to.is_nullable())) {
    const int kResult = config.to.is_nullable() ? 1 : 0;
    gasm_.GotoIf(IsNull(object, wasm::kWasmAnyRef), &end_label,
                 BranchHint::kFalse, gasm_.Int32Constant(kResult));
  }

  if (object_can_be_i31) {
    gasm_.GotoIf(gasm_.IsSmi(object), &end_label, gasm_.Int32Constant(0));
  }

  Node* map = gasm_.LoadMap(object);

  if (module_->type(config.to.ref_index()).is_final) {
    gasm_.Goto(&end_label, gasm_.TaggedEqual(map, rtt));
  } else {
    // First, check if types happen to be equal. This has been shown to give
    // large speedups.
    gasm_.GotoIf(gasm_.TaggedEqual(map, rtt), &end_label, BranchHint::kTrue,
                 gasm_.Int32Constant(1));

    // Check if map instance type identifies a wasm object.
    if (is_cast_from_any) {
      Node* is_wasm_obj = gasm_.IsDataRefMap(map);
      gasm_.GotoIfNot(is_wasm_obj, &end_label, BranchHint::kTrue,
                      gasm_.Int32Constant(0));
    }

    Node* type_info = gasm_.LoadWasmTypeInfo(map);
    DCHECK_GE(rtt_depth, 0);
    // If the depth of the rtt is known to be less that the minimum supertype
    // array length, we can access the supertype without bounds-checking the
    // supertype array.
    if (static_cast<uint32_t>(rtt_depth) >= wasm::kMinimumSupertypeArraySize) {
      Node* supertypes_length =
          gasm_.BuildChangeSmiToIntPtr(gasm_.LoadImmutableFromObject(
              MachineType::TaggedSigned(), type_info,
              wasm::ObjectAccess::ToTagged(
                  WasmTypeInfo::kSupertypesLengthOffset)));
      gasm_.GotoIfNot(gasm_.UintLessThan(gasm_.IntPtrConstant(rtt_depth),
                                         supertypes_length),
                      &end_label, BranchHint::kTrue, gasm_.Int32Constant(0));
    }

    Node* maybe_match = gasm_.LoadImmutableFromObject(
        MachineType::TaggedPointer(), type_info,
        wasm::ObjectAccess::ToTagged(WasmTypeInfo::kSupertypesOffset +
                                     kTaggedSize * rtt_depth));

    gasm_.Goto(&end_label, gasm_.TaggedEqual(maybe_match, rtt));
  }

  gasm_.Bind(&end_label);

  ReplaceWithValue(node, end_label.PhiAt(0), gasm_.effect(), gasm_.control());
  node->Kill();
  return Replace(end_label.PhiAt(0));  // Meaningless argument.
}

Reduction WasmGCLowering::ReduceWasmTypeCheckAbstract(Node* node) {
  DCHECK_EQ(node->opcode(), IrOpcode::kWasmTypeCheckAbstract);

  Node* object = node->InputAt(0);
  Node* effect_input = NodeProperties::GetEffectInput(node);
  Node* control_input = NodeProperties::GetControlInput(node);
  WasmTypeCheckConfig config = OpParameter<WasmTypeCheckConfig>(node->op());
  const bool object_can_be_null = config.from.is_nullable();
  const bool null_succeeds = config.to.is_nullable();
  const bool object_can_be_i31 =
      wasm::IsSubtypeOf(wasm::kWasmI31Ref.AsNonNull(), config.from, module_) ||
      config.from.heap_representation() == wasm::HeapType::kExtern;

  gasm_.InitializeEffectControl(effect_input, control_input);

  Node* result = nullptr;
  auto end_label = gasm_.MakeLabel(MachineRepresentation::kWord32);

  wasm::HeapType::Representation to_rep = config.to.heap_representation();
  do {
    // The none-types only perform a null check. They need no control flow.
    if (to_rep == wasm::HeapType::kNone ||
        to_rep == wasm::HeapType::kNoExtern ||
        to_rep == wasm::HeapType::kNoFunc || to_rep == wasm::HeapType::kNoExn) {
      result = IsNull(object, config.from);
      break;
    }
    // Null checks performed by any other type check need control flow. We can
    // skip the null check if null fails, because it's covered by the Smi check
    // or instance type check we'll do later.
    if (object_can_be_null && null_succeeds) {
      const int kResult = null_succeeds ? 1 : 0;
      gasm_.GotoIf(IsNull(object, wasm::kWasmAnyRef), &end_label,
                   BranchHint::kFalse, gasm_.Int32Constant(kResult));
    }
    // i31 is special in that the Smi check is the last thing to do.
    if (to_rep == wasm::HeapType::kI31) {
      // If earlier optimization passes reached the limit of possible graph
      // transformations, we could DCHECK(object_can_be_i31) here.
      result = object_can_be_i31 ? gasm_.IsSmi(object) : gasm_.Int32Constant(0);
      break;
    }
    if (to_rep == wasm::HeapType::kEq) {
      if (object_can_be_i31) {
        gasm_.GotoIf(gasm_.IsSmi(object), &end_label, BranchHint::kFalse,
                     gasm_.Int32Constant(1));
      }
      result = gasm_.IsDataRefMap(gasm_.LoadMap(object));
      break;
    }
    // array, struct, string: i31 fails.
    if (object_can_be_i31) {
      gasm_.GotoIf(gasm_.IsSmi(object), &end_label, BranchHint::kFalse,
                   gasm_.Int32Constant(0));
    }
    if (to_rep == wasm::HeapType::kArray) {
      result = gasm_.HasInstanceType(object, WASM_ARRAY_TYPE);
      break;
    }
    if (to_rep == wasm::HeapType::kStruct) {
      result = gasm_.HasInstanceType(object, WASM_STRUCT_TYPE);
      break;
    }
    if (to_rep == wasm::HeapType::kString ||
        to_rep == wasm::HeapType::kExternString) {
      Node* instance_type = gasm_.LoadInstanceType(gasm_.LoadMap(object));
      result = gasm_.Uint32LessThan(instance_type,
                                    gasm_.Uint32Constant(FIRST_NONSTRING_TYPE));
      break;
    }
    UNREACHABLE();
  } while (false);

  DCHECK_NOT_NULL(result);
  if (end_label.IsUsed()) {
    gasm_.Goto(&end_label, result);
    gasm_.Bind(&end_label);
    result = end_label.PhiAt(0);
  }

  ReplaceWithValue(node, result, gasm_.effect(), gasm_.control());
  node->Kill();
  return Replace(result);  // Meaningless argument.
}

Reduction WasmGCLowering::ReduceWasmTypeCast(Node* node) {
  DCHECK_EQ(node->opcode(), IrOpcode::kWasmTypeCast);

  Node* object = node->InputAt(0);
  Node* rtt = node->InputAt(1);
  Node* effect_input = NodeProperties::GetEffectInput(node);
  Node* control_input = NodeProperties::GetControlInput(node);
  auto config = OpParameter<WasmTypeCheckConfig>(node->op());
  int rtt_depth = wasm::GetSubtypingDepth(module_, config.to.ref_index());
  bool object_can_be_null = config.from.is_nullable();
  bool object_can_be_i31 =
      wasm::IsSubtypeOf(wasm::kWasmI31Ref.AsNonNull(), config.from, module_);

  gasm_.InitializeEffectControl(effect_input, control_input);

  auto end_label = gasm_.MakeLabel();
  bool is_cast_from_any = config.from.is_reference_to(wasm::HeapType::kAny);

  // If we are casting from any and null results in check failure, then the
  // {IsDataRefMap} check below subsumes the null check. Otherwise, perform
  // an explicit null check now.
  if (object_can_be_null && (!is_cast_from_any || config.to.is_nullable())) {
    Node* is_null = IsNull(object, wasm::kWasmAnyRef);
    if (config.to.is_nullable()) {
      gasm_.GotoIf(is_null, &end_label, BranchHint::kFalse);
    } else if (!v8_flags.experimental_wasm_skip_null_checks) {
      gasm_.TrapIf(is_null, TrapId::kTrapIllegalCast);
      UpdateSourcePosition(gasm_.effect(), node);
    }
  }

  if (object_can_be_i31) {
    gasm_.TrapIf(gasm_.IsSmi(object), TrapId::kTrapIllegalCast);
    UpdateSourcePosition(gasm_.effect(), node);
  }

  Node* map = gasm_.LoadMap(object);

  if (module_->type(config.to.ref_index()).is_final) {
    gasm_.TrapUnless(gasm_.TaggedEqual(map, rtt), TrapId::kTrapIllegalCast);
    UpdateSourcePosition(gasm_.effect(), node);
    gasm_.Goto(&end_label);
  } else {
    // First, check if types happen to be equal. This has been shown to give
    // large speedups.
    gasm_.GotoIf(gasm_.TaggedEqual(map, rtt), &end_label, BranchHint::kTrue);

    // Check if map instance type identifies a wasm object.
    if (is_cast_from_any) {
      Node* is_wasm_obj = gasm_.IsDataRefMap(map);
      gasm_.TrapUnless(is_wasm_obj, TrapId::kTrapIllegalCast);
      UpdateSourcePosition(gasm_.effect(), node);
    }

    Node* type_info = gasm_.LoadWasmTypeInfo(map);
    DCHECK_GE(rtt_depth, 0);
    // If the depth of the rtt is known to be less that the minimum supertype
    // array length, we can access the supertype without bounds-checking the
    // supertype array.
    if (static_cast<uint32_t>(rtt_depth) >= wasm::kMinimumSupertypeArraySize) {
      Node* supertypes_length =
          gasm_.BuildChangeSmiToIntPtr(gasm_.LoadImmutableFromObject(
              MachineType::TaggedSigned(), type_info,
              wasm::ObjectAccess::ToTagged(
                  WasmTypeInfo::kSupertypesLengthOffset)));
      gasm_.TrapUnless(gasm_.UintLessThan(gasm_.IntPtrConstant(rtt_depth),
                                          supertypes_length),
                       TrapId::kTrapIllegalCast);
      UpdateSourcePosition(gasm_.effect(), node);
    }

    Node* maybe_match = gasm_.LoadImmutableFromObject(
        MachineType::TaggedPointer(), type_info,
        wasm::ObjectAccess::ToTagged(WasmTypeInfo::kSupertypesOffset +
                                     kTaggedSize * rtt_depth));

    gasm_.TrapUnless(gasm_.TaggedEqual(maybe_match, rtt),
                     TrapId::kTrapIllegalCast);
    UpdateSourcePosition(gasm_.effect(), node);
    gasm_.Goto(&end_label);
  }

  gasm_.Bind(&end_label);

  ReplaceWithValue(node, object, gasm_.effect(), gasm_.control());
  node->Kill();
  return Replace(object);
}

Reduction WasmGCLowering::ReduceWasmTypeCastAbstract(Node* node) {
  DCHECK_EQ(node->opcode(), IrOpcode::kWasmTypeCastAbstract);

  Node* object = node->InputAt(0);
  Node* effect_input = NodeProperties::GetEffectInput(node);
  Node* control_input = NodeProperties::GetControlInput(node);
  WasmTypeCheckConfig config = OpParameter<WasmTypeCheckConfig>(node->op());
  const bool object_can_be_null = config.from.is_nullable();
  const bool null_succeeds = config.to.is_nullable();
  const bool object_can_be_i31 =
      wasm::IsSubtypeOf(wasm::kWasmI31Ref.AsNonNull(), config.from, module_) ||
      config.from.heap_representation() == wasm::HeapType::kExtern;

  gasm_.InitializeEffectControl(effect_input, control_input);

  auto end_label = gasm_.MakeLabel();

  wasm::HeapType::Representation to_rep = config.to.heap_representation();

  do {
    // The none-types only perform a null check.
    if (to_rep == wasm::HeapType::kNone ||
        to_rep == wasm::HeapType::kNoExtern ||
        to_rep == wasm::HeapType::kNoFunc || to_rep == wasm::HeapType::kNoExn) {
      gasm_.TrapUnless(IsNull(object, config.from), TrapId::kTrapIllegalCast);
      UpdateSourcePosition(gasm_.effect(), node);
      break;
    }
    // Null checks performed by any other type cast can be skipped if null
    // fails, because it's covered by the Smi check
    // or instance type check we'll do later.
    if (object_can_be_null && null_succeeds &&
        !v8_flags.experimental_wasm_skip_null_checks) {
      gasm_.GotoIf(IsNull(object, config.from), &end_label, BranchHint::kFalse);
    }
    if (to_rep == wasm::HeapType::kI31) {
      // If earlier optimization passes reached the limit of possible graph
      // transformations, we could DCHECK(object_can_be_i31) here.
      Node* success =
          object_can_be_i31 ? gasm_.IsSmi(object) : gasm_.Int32Constant(0);
      gasm_.TrapUnless(success, TrapId::kTrapIllegalCast);
      UpdateSourcePosition(gasm_.effect(), node);
      break;
    }
    if (to_rep == wasm::HeapType::kEq) {
      if (object_can_be_i31) {
        gasm_.GotoIf(gasm_.IsSmi(object), &end_label, BranchHint::kFalse);
      }
      gasm_.TrapUnless(gasm_.IsDataRefMap(gasm_.LoadMap(object)),
                       TrapId::kTrapIllegalCast);
      UpdateSourcePosition(gasm_.effect(), node);
      break;
    }
    // array, struct, string: i31 fails.
    if (object_can_be_i31) {
      gasm_.TrapIf(gasm_.IsSmi(object), TrapId::kTrapIllegalCast);
      UpdateSourcePosition(gasm_.effect(), node);
    }
    if (to_rep == wasm::HeapType::kArray) {
      gasm_.TrapUnless(gasm_.HasInstanceType(object, WASM_ARRAY_TYPE),
                       TrapId::kTrapIllegalCast);
      UpdateSourcePosition(gasm_.effect(), node);
      break;
    }
    if (to_rep == wasm::HeapType::kStruct) {
      gasm_.TrapUnless(gasm_.HasInstanceType(object, WASM_STRUCT_TYPE),
                       TrapId::kTrapIllegalCast);
      UpdateSourcePosition(gasm_.effect(), node);
      break;
    }
    if (to_rep == wasm::HeapType::kString ||
        to_rep == wasm::HeapType::kExternString) {
      Node* instance_type = gasm_.LoadInstanceType(gasm_.LoadMap(object));
      gasm_.TrapUnless(
          gasm_.Uint32LessThan(instance_type,
                               gasm_.Uint32Constant(FIRST_NONSTRING_TYPE)),
          TrapId::kTrapIllegalCast);
      UpdateSourcePosition(gasm_.effect(), node);
      break;
    }
    UNREACHABLE();
  } while (false);

  if (end_label.IsUsed()) {
    gasm_.Goto(&end_label);
    gasm_.Bind(&end_label);
  }

  ReplaceWithValue(node, object, gasm_.effect(), gasm_.control());
  node->Kill();
  return Replace(object);
}

Reduction WasmGCLowering::ReduceAssertNotNull(Node* node) {
  DCHECK_EQ(node->opcode(), IrOpcode::kAssertNotNull);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);
  Node* object = NodeProperties::GetValueInput(node, 0);
  gasm_.InitializeEffectControl(effect, control);
  auto op_parameter = OpParameter<AssertNotNullParameters>(node->op());
  // When able, implement a non-null assertion by loading from the object just
  // after the map word. This will trap for null and be handled by the trap
  // handler.
  if (op_parameter.trap_id == TrapId::kTrapNullDereference) {
    if (!v8_flags.experimental_wasm_skip_null_checks) {
      // For supertypes of i31ref, we would need to check for i31ref anyway
      // before loading from the object, so we might as well just check directly
      // for null.
      // For subtypes of externref, we use JS null, so we have to check
      // explicitly.
      if (null_check_strategy_ == NullCheckStrategy::kExplicit ||
          wasm::IsSubtypeOf(wasm::kWasmI31Ref.AsNonNull(), op_parameter.type,
                            module_) ||
          !op_parameter.type.use_wasm_null()) {
        gasm_.TrapIf(IsNull(object, op_parameter.type), op_parameter.trap_id);
        UpdateSourcePosition(gasm_.effect(), node);
      } else {
        static_assert(WasmStruct::kHeaderSize > kTaggedSize);
        static_assert(WasmArray::kHeaderSize > kTaggedSize);
        static_assert(WasmInternalFunction::kHeaderSize > kTaggedSize);
        Node* trap_null = gasm_.LoadTrapOnNull(
            MachineType::Int32(), object,
            gasm_.IntPtrConstant(wasm::ObjectAccess::ToTagged(kTaggedSize)));
        UpdateSourcePosition(trap_null, node);
      }
    }
  } else {
    gasm_.TrapIf(IsNull(object, op_parameter.type), op_parameter.trap_id);
    UpdateSourcePosition(gasm_.effect(), node);
  }

  ReplaceWithValue(node, object, gasm_.effect(), gasm_.control());
  node->Kill();
  return Replace(object);
}

Reduction WasmGCLowering::ReduceNull(Node* node) {
  DCHECK_EQ(node->opcode(), IrOpcode::kNull);
  auto type = OpParameter<wasm::ValueType>(node->op());
  return Replace(Null(type));
}

Reduction WasmGCLowering::ReduceIsNull(Node* node) {
  DCHECK_EQ(node->opcode(), IrOpcode::kIsNull);
  Node* object = NodeProperties::GetValueInput(node, 0);
  auto type = OpParameter<wasm::ValueType>(node->op());
  return Replace(IsNull(object, type));
}

Reduction WasmGCLowering::ReduceIsNotNull(Node* node) {
  DCHECK_EQ(node->opcode(), IrOpcode::kIsNotNull);
  Node* object = NodeProperties::GetValueInput(node, 0);
  auto type = OpParameter<wasm::ValueType>(node->op());
  return Replace(
      gasm_.Word32Equal(IsNull(object, type), gasm_.Int32Constant(0)));
}

Reduction WasmGCLowering::ReduceRttCanon(Node* node) {
  DCHECK_EQ(node->opcode(), IrOpcode::kRttCanon);
  int type_index = OpParameter<int>(node->op());
  Node* instance_node = node->InputAt(0);
  Node* maps_list = gasm_.LoadImmutable(
      MachineType::TaggedPointer(), instance_node,
      WasmTrustedInstanceData::kManagedObjectMapsOffset - kHeapObjectTag);
  return Replace(gasm_.LoadImmutable(
      MachineType::TaggedPointer(), maps_list,
      wasm::ObjectAccess::ElementOffsetInTaggedFixedArray(type_index)));
}

Reduction WasmGCLowering::ReduceTypeGuard(Node* node) {
  DCHECK_EQ(node->opcode(), IrOpcode::kTypeGuard);
  Node* alias = NodeProperties::GetValueInput(node, 0);
  ReplaceWithValue(node, alias);
  node->Kill();
  return Replace(alias);
}

namespace {
constexpr int32_t kInt31MaxValue = 0x3fffffff;
constexpr int32_t kInt31MinValue = -kInt31MaxValue - 1;
}  // namespace

Reduction WasmGCLowering::ReduceWasmAnyConvertExtern(Node* node) {
  DCHECK_EQ(node->opcode(), IrOpcode::kWasmAnyConvertExtern);
  Node* input = NodeProperties::GetValueInput(node, 0);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);
  gasm_.InitializeEffectControl(effect, control);

  auto end_label = gasm_.MakeLabel(MachineRepresentation::kTagged);
  auto null_label = gasm_.MakeLabel();
  auto smi_label = gasm_.MakeLabel();
  auto int_to_smi_label = gasm_.MakeLabel();
  auto heap_number_label = gasm_.MakeLabel();

  gasm_.GotoIf(IsNull(input, wasm::kWasmExternRef), &null_label);
  gasm_.GotoIf(gasm_.IsSmi(input), &smi_label);
  Node* is_heap_number = gasm_.HasInstanceType(input, HEAP_NUMBER_TYPE);
  gasm_.GotoIf(is_heap_number, &heap_number_label);
  // For anything else, just pass through the value.
  gasm_.Goto(&end_label, input);

  gasm_.Bind(&null_label);
  gasm_.Goto(&end_label, Null(wasm::kWasmNullRef));

  // Canonicalize SMI.
  gasm_.Bind(&smi_label);
  if constexpr (SmiValuesAre31Bits()) {
    gasm_.Goto(&end_label, input);
  } else {
    auto to_heap_number_label = gasm_.MakeLabel();
    Node* int_value = gasm_.BuildChangeSmiToInt32(input);

    // Convert to heap number if the int32 does not fit into an i31ref.
    gasm_.GotoIf(
        gasm_.Int32LessThan(gasm_.Int32Constant(kInt31MaxValue), int_value),
        &to_heap_number_label);
    gasm_.GotoIf(
        gasm_.Int32LessThan(int_value, gasm_.Int32Constant(kInt31MinValue)),
        &to_heap_number_label);
    gasm_.Goto(&end_label, input);

    gasm_.Bind(&to_heap_number_label);
    Node* heap_number = gasm_.CallBuiltin(Builtin::kWasmInt32ToHeapNumber,
                                          Operator::kPure, int_value);
    gasm_.Goto(&end_label, heap_number);
  }

  // Convert HeapNumber to SMI if possible.
  gasm_.Bind(&heap_number_label);
  Node* float_value = gasm_.LoadFromObject(
      MachineType::Float64(), input,
      wasm::ObjectAccess::ToTagged(AccessBuilder::ForHeapNumberValue().offset));
  // Check range of float value.
  gasm_.GotoIf(
      gasm_.Float64LessThan(float_value, gasm_.Float64Constant(kInt31MinValue)),
      &end_label, input);
  gasm_.GotoIf(
      gasm_.Float64LessThan(gasm_.Float64Constant(kInt31MaxValue), float_value),
      &end_label, input);
  // Check if value is -0.
  Node* is_minus_zero = nullptr;
  if (mcgraph_->machine()->Is64()) {
    Node* minus_zero = gasm_.Int64Constant(base::bit_cast<int64_t>(-0.0));
    Node* float_bits = gasm_.BitcastFloat64ToInt64(float_value);
    is_minus_zero = gasm_.Word64Equal(float_bits, minus_zero);
  } else {
    constexpr int32_t kMinusZeroLoBits = static_cast<int32_t>(0);
    constexpr int32_t kMinusZeroHiBits = static_cast<int32_t>(1) << 31;
    auto done = gasm_.MakeLabel(MachineRepresentation::kBit);

    Node* value_lo = gasm_.Float64ExtractLowWord32(float_value);
    gasm_.GotoIfNot(
        gasm_.Word32Equal(value_lo, gasm_.Int32Constant(kMinusZeroLoBits)),
        &done, gasm_.Int32Constant(0));
    Node* value_hi = gasm_.Float64ExtractHighWord32(float_value);
    gasm_.Goto(&done, gasm_.Word32Equal(value_hi,
                                        gasm_.Int32Constant(kMinusZeroHiBits)));
    gasm_.Bind(&done);
    is_minus_zero = done.PhiAt(0);
  }
  gasm_.GotoIf(is_minus_zero, &end_label, input);
  // Check if value is integral.
  Node* int_value = gasm_.ChangeFloat64ToInt32(float_value);
  gasm_.GotoIf(
      gasm_.Float64Equal(float_value, gasm_.ChangeInt32ToFloat64(int_value)),
      &int_to_smi_label);
  gasm_.Goto(&end_label, input);

  gasm_.Bind(&int_to_smi_label);
  gasm_.Goto(&end_label, gasm_.BuildChangeInt32ToSmi(int_value));

  gasm_.Bind(&end_label);
  ReplaceWithValue(node, end_label.PhiAt(0), gasm_.effect(), gasm_.control());
  node->Kill();
  return Replace(end_label.PhiAt(0));
}

Reduction WasmGCLowering::ReduceWasmExternConvertAny(Node* node) {
  DCHECK_EQ(node->opcode(), IrOpcode::kWasmExternConvertAny);
  Node* object = node->InputAt(0);
  gasm_.InitializeEffectControl(NodeProperties::GetEffectInput(node),
                                NodeProperties::GetControlInput(node));
  auto label = gasm_.MakeLabel(MachineRepresentation::kTagged);
  gasm_.GotoIfNot(IsNull(object, wasm::kWasmAnyRef), &label, object);
  gasm_.Goto(&label, Null(wasm::kWasmExternRef));
  gasm_.Bind(&label);
  ReplaceWithValue(node, label.PhiAt(0), gasm_.effect(), gasm_.control());
  node->Kill();
  return Replace(label.PhiAt(0));
}

Reduction WasmGCLowering::ReduceWasmStructGet(Node* node) {
  DCHECK_EQ(node->opcode(), IrOpcode::kWasmStructGet);
  WasmFieldInfo info = OpParameter<WasmFieldInfo>(node->op());

  Node* object = NodeProperties::GetValueInput(node, 0);

  gasm_.InitializeEffectControl(NodeProperties::GetEffectInput(node),
                                NodeProperties::GetControlInput(node));

  MachineType type = MachineType::TypeForRepresentation(
      info.type->field(info.field_index).machine_representation(),
      info.is_signed);

  Node* offset = gasm_.FieldOffset(info.type, info.field_index);

  bool explicit_null_check =
      info.null_check == kWithNullCheck &&
      (null_check_strategy_ == NullCheckStrategy::kExplicit ||
       info.field_index > wasm::kMaxStructFieldIndexForImplicitNullCheck);
  bool implicit_null_check =
      info.null_check == kWithNullCheck && !explicit_null_check;

  if (explicit_null_check) {
    gasm_.TrapIf(IsNull(object, wasm::kWasmAnyRef),
                 TrapId::kTrapNullDereference);
    UpdateSourcePosition(gasm_.effect(), node);
  }

  Node* load = implicit_null_check ? gasm_.LoadTrapOnNull(type, object, offset)
               : info.type->mutability(info.field_index)
                   ? gasm_.LoadFromObject(type, object, offset)
                   : gasm_.LoadImmutableFromObject(type, object, offset);
  if (implicit_null_check) {
    UpdateSourcePosition(load, node);
  }

  ReplaceWithValue(node, load, gasm_.effect(), gasm_.control());
  node->Kill();
  return Replace(load);
}

Reduction WasmGCLowering::ReduceWasmStructSet(Node* node) {
  DCHECK_EQ(node->opcode(), IrOpcode::kWasmStructSet);
  WasmFieldInfo info = OpParameter<WasmFieldInfo>(node->op());

  gasm_.InitializeEffectControl(NodeProperties::GetEffectInput(node),
                                NodeProperties::GetControlInput(node));

  Node* object = NodeProperties::GetValueInput(node, 0);
  Node* value = NodeProperties::GetValueInput(node, 1);

  bool explicit_null_check =
      info.null_check == kWithNullCheck &&
      (null_check_strategy_ == NullCheckStrategy::kExplicit ||
       info.field_index > wasm::kMaxStructFieldIndexForImplicitNullCheck);
  bool implicit_null_check =
      info.null_check == kWithNullCheck && !explicit_null_check;

  if (explicit_null_check) {
    gasm_.TrapIf(IsNull(object, wasm::kWasmAnyRef),
                 TrapId::kTrapNullDereference);
    UpdateSourcePosition(gasm_.effect(), node);
  }

  wasm::ValueType field_type = info.type->field(info.field_index);
  Node* offset = gasm_.FieldOffset(info.type, info.field_index);

  Node* store =
      implicit_null_check
          ? gasm_.StoreTrapOnNull({field_type.machine_representation(),
                                   field_type.is_reference() ? kFullWriteBarrier
                                                             : kNoWriteBarrier},
                                  object, offset, value)
      : info.type->mutability(info.field_index)
          ? gasm_.StoreToObject(ObjectAccessForGCStores(field_type), object,
                                offset, value)
          : gasm_.InitializeImmutableInObject(
                ObjectAccessForGCStores(field_type), object, offset, value);
  if (implicit_null_check) {
    UpdateSourcePosition(store, node);
  }

  ReplaceWithValue(node, store, gasm_.effect(), gasm_.control());
  node->Kill();
  return Replace(store);
}

Reduction WasmGCLowering::ReduceWasmArrayGet(Node* node) {
  DCHECK_EQ(node->opcode(), IrOpcode::kWasmArrayGet);
  WasmElementInfo info = OpParameter<WasmElementInfo>(node->op());

  Node* object = NodeProperties::GetValueInput(node, 0);
  Node* index = NodeProperties::GetValueInput(node, 1);

  gasm_.InitializeEffectControl(NodeProperties::GetEffectInput(node),
                                NodeProperties::GetControlInput(node));

  Node* offset = gasm_.WasmArrayElementOffset(index, info.type->element_type());

  MachineType type = MachineType::TypeForRepresentation(
      info.type->element_type().machine_representation(), info.is_signed);

  Node* value = info.type->mutability()
                    ? gasm_.LoadFromObject(type, object, offset)
                    : gasm_.LoadImmutableFromObject(type, object, offset);

  return Replace(value);
}

Reduction WasmGCLowering::ReduceWasmArraySet(Node* node) {
  DCHECK_EQ(node->opcode(), IrOpcode::kWasmArraySet);
  const wasm::ArrayType* type = OpParameter<const wasm::ArrayType*>(node->op());

  Node* object = NodeProperties::GetValueInput(node, 0);
  Node* index = NodeProperties::GetValueInput(node, 1);
  Node* value = NodeProperties::GetValueInput(node, 2);

  gasm_.InitializeEffectControl(NodeProperties::GetEffectInput(node),
                                NodeProperties::GetControlInput(node));

  Node* offset = gasm_.WasmArrayElementOffset(index, type->element_type());

  ObjectAccess access = ObjectAccessForGCStores(type->element_type());

  Node* store =
      type->mutability()
          ? gasm_.StoreToObject(access, object, offset, value)
          : gasm_.InitializeImmutableInObject(access, object, offset, value);

  return Replace(store);
}

Reduction WasmGCLowering::ReduceWasmArrayLength(Node* node) {
  DCHECK_EQ(node->opcode(), IrOpcode::kWasmArrayLength);
  Node* object = NodeProperties::GetValueInput(node, 0);

  gasm_.InitializeEffectControl(NodeProperties::GetEffectInput(node),
                                NodeProperties::GetControlInput(node));

  bool null_check = OpParameter<bool>(node->op());

  if (null_check_strategy_ == NullCheckStrategy::kExplicit &&
      null_check == kWithNullCheck) {
    gasm_.TrapIf(IsNull(object, wasm::kWasmAnyRef),
                 TrapId::kTrapNullDereference);
    UpdateSourcePosition(gasm_.effect(), node);
  }

  bool use_null_trap =
      null_check_strategy_ == NullCheckStrategy::kTrapHandler &&
      null_check == kWithNullCheck;
  Node* length =
      use_null_trap
          ? gasm_.LoadTrapOnNull(
                MachineType::Uint32(), object,
                gasm_.IntPtrConstant(
                    wasm::ObjectAccess::ToTagged(WasmArray::kLengthOffset)))
          : gasm_.LoadImmutableFromObject(
                MachineType::Uint32(), object,
                wasm::ObjectAccess::ToTagged(WasmArray::kLengthOffset));
  if (us
"""


```