Response: The user wants to understand the functionality of the C++ code provided in `v8/src/compiler/wasm-gc-lowering.cc`. I need to:

1. **Summarize the code's purpose**: Focus on what the `WasmGCLowering` class does. The name suggests it's related to lowering WebAssembly Garbage Collection (GC) features to lower-level operations.
2. **Identify its connection to JavaScript**: Determine if and how this code interacts with JavaScript's execution within the V8 engine.
3. **Provide a JavaScript example**: If a connection exists, illustrate it with a simple JavaScript snippet that would trigger the functionality of this C++ code.

**Thinking Process:**

* **Analyze the class name and file path**: `WasmGCLowering` in the `compiler` directory strongly indicates a compilation phase that transforms WebAssembly GC constructs.
* **Examine included headers**: Headers like `src/wasm/wasm-gc-lowering.h`, `src/compiler/operator.h`, `src/wasm/wasm-objects.h` confirm this is part of the WebAssembly compilation pipeline dealing with GC.
* **Inspect the `Reduce` method**: This method is the core of the class. It handles various WebAssembly opcode cases related to GC, like `kWasmTypeCheck`, `kWasmTypeCast`, `kWasmStructGet`, `kWasmArrayGet`, etc. The actions within these cases involve generating lower-level machine code using `gasm_` (presumably a `GraphAssembler`).
* **Look for JavaScript integration points**:  Functions like `ReduceWasmAnyConvertExtern` and `ReduceWasmExternConvertAny` suggest the code handles conversions between WebAssembly's GC types and JavaScript's representation of external values. This is a key link.
* **Consider JavaScript's interaction with WebAssembly GC**: JavaScript can directly interact with WebAssembly GC features if the module imports or exports GC types. This provides the context for the C++ code's actions.

**Hypothesis:**

This C++ code is responsible for translating high-level WebAssembly GC instructions into lower-level machine code operations within the V8 JavaScript engine's compiler. It facilitates the interaction between JavaScript and WebAssembly's GC by handling type checks, casts, and conversions of GC objects.

**JavaScript Example Idea:**

A simple example would involve creating a WebAssembly module that uses GC features (like structs or arrays) and then interacting with those features from JavaScript. This interaction would implicitly trigger the lowering process handled by the C++ code.

**Refining the JavaScript Example:**

The example should demonstrate a scenario where the C++ code's actions are clearly relevant. Type checking or accessing fields of a GC object would be good candidates.

**Final Plan:**

1. Summarize that `v8/src/compiler/wasm-gc-lowering.cc` implements the `WasmGCLowering` class, which is a compiler pass in V8 responsible for lowering WebAssembly's Garbage Collection (GC) related operations into lower-level machine code.
2. Explain that this process is essential for the V8 engine to efficiently execute WebAssembly code that uses GC features.
3. Highlight the connection to JavaScript through the handling of conversions between WebAssembly GC types and JavaScript types (e.g., `anyref` and `externref`).
4. Provide a JavaScript example that demonstrates the interaction with WebAssembly GC features, implicitly showing where the C++ code plays a role. The example should involve creating a WebAssembly module with GC types and accessing its members from JavaScript.
这个C++源代码文件 `v8/src/compiler/wasm-gc-lowering.cc` 实现了 V8 引擎中用于降低 WebAssembly 垃圾回收 (GC) 相关操作的 `WasmGCLowering` 类。

**主要功能归纳:**

`WasmGCLowering` 类是一个编译器优化过程，它将 WebAssembly 代码中与垃圾回收相关的抽象操作 (例如类型检查、类型转换、空值断言、结构体和数组的访问等) 转换为更底层的、机器相关的操作。 它的主要目标是：

1. **实现 WebAssembly GC 的语义:**  确保 WebAssembly 的 GC 功能 (如类型安全、空值检查等) 在 V8 引擎中正确执行。
2. **进行底层代码生成:**  将高级的 WebAssembly GC 指令转化为 V8 引擎的中间表示 (MachineGraph) 中的节点，以便后续的代码生成阶段能够生成最终的机器码。
3. **处理类型检查和转换:**  实现 WebAssembly 中 `instanceof` 和类型转换 (cast) 等操作，确保类型安全。
4. **处理空值:**  实现对 WebAssembly 中 `null` 值的处理，包括空值检查和断言。
5. **处理结构体和数组:**  实现对 WebAssembly 结构体和数组的字段访问和元素访问。
6. **处理 `anyref` 和 `externref` 的转换:**  实现 WebAssembly 的 `anyref` 和 JavaScript 的 `externref` 之间的转换。
7. **支持静态根:**  利用 V8 的静态根机制来优化某些操作。
8. **处理字符串:**  实现 WebAssembly 字符串到 UTF-16 编码的转换以及准备获取字符串代码单元的操作。

**与 JavaScript 的关系及 JavaScript 示例:**

该文件直接参与了 V8 引擎编译和执行 WebAssembly 代码的过程，而 WebAssembly 可以在 JavaScript 环境中运行并与 JavaScript 代码互操作。 当 JavaScript 代码调用或接收使用了 WebAssembly GC 特性的 WebAssembly 函数时，这个 `WasmGCLowering` 类的工作就会发挥作用。

以下是一个 JavaScript 示例，它展示了如何创建一个使用了 GC 特性的 WebAssembly 模块，并从 JavaScript 中与之交互。这个交互的过程会间接地触发 `WasmGCLowering` 中定义的功能。

```javascript
// 假设你有一个名为 'wasm_gc_module.wasm' 的 WebAssembly 模块，
// 它定义了一个使用了 GC 特性的结构体类型和相关的函数。

async function loadAndRunWasm() {
  const response = await fetch('wasm_gc_module.wasm');
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.instantiate(buffer, {}); // 假设没有导入

  const instance = module.instance;

  // 假设 WebAssembly 模块导出了一个创建结构体的函数
  const createMyStruct = instance.exports.createMyStruct;

  // 假设 WebAssembly 模块导出了一个获取结构体字段的函数
  const getStructField = instance.exports.getStructField;

  // 假设 WebAssembly 模块导出了一个接收结构体参数的函数
  const processStruct = instance.exports.processStruct;

  // 创建一个 WebAssembly 结构体实例
  const myStructInstance = createMyStruct(10, "hello");

  // 获取结构体的字段值
  const fieldValue = getStructField(myStructInstance);
  console.log("结构体字段值:", fieldValue);

  // 将结构体实例传递给 WebAssembly 函数
  processStruct(myStructInstance);

  // 在上述过程中，V8 引擎在编译和执行 WebAssembly 代码时，
  // 如果遇到了与 GC 相关的操作（例如访问 myStructInstance 的字段），
  // 就会使用 WasmGCLowering 类来降低这些操作到更底层的指令。
  // 例如，当调用 getStructField(myStructInstance) 时，
  // WasmGCLowering 会负责将结构体字段访问操作转换为底层的内存加载操作，
  // 并可能包含空值检查等。

  // 假设 WebAssembly 模块导出了一个进行类型检查的函数
  const isMyStruct = instance.exports.isMyStruct;
  const isString = instance.exports.isString;

  console.log("myStructInstance 是 MyStruct 吗?", isMyStruct(myStructInstance));
  console.log("myStructInstance 是 string 吗?", isString(myStructInstance));

  // 上述 isMyStruct 和 isString 函数的实现可能对应于
  // WasmGCLowering 中的 ReduceWasmTypeCheck 或 ReduceWasmTypeCheckAbstract 函数，
  // 用于将 WebAssembly 的类型检查操作转化为底层的比较和跳转指令。
}

loadAndRunWasm();
```

**解释 JavaScript 示例与 C++ 代码的关系:**

在这个 JavaScript 示例中：

* 当 JavaScript 代码调用 `createMyStruct` 创建一个 WebAssembly 结构体实例时，`WasmGCLowering` 负责处理结构体的创建和内存布局。
* 当 JavaScript 代码调用 `getStructField` 访问结构体的字段时，`WasmGCLowering` 中的 `ReduceWasmStructGet` 函数会将这个操作转换为加载结构体相应偏移量处内存的指令，并可能包含空值检查。
* 当 JavaScript 代码调用 `processStruct` 并将结构体实例作为参数传递时，`WasmGCLowering` 确保参数的类型是正确的。
* 当 JavaScript 代码调用 `isMyStruct` 或 `isString` 进行类型检查时，`WasmGCLowering` 中的 `ReduceWasmTypeCheck` 或 `ReduceWasmTypeCheckAbstract` 函数会将 WebAssembly 的类型检查操作转换为底层的比较指令。

总而言之，`v8/src/compiler/wasm-gc-lowering.cc` 是 V8 引擎中至关重要的一个组成部分，它使得 JavaScript 能够无缝地与使用垃圾回收特性的 WebAssembly 模块进行交互，保证了类型安全和程序的正确执行。 它位于编译器优化的核心环节，负责将高级的 WebAssembly GC 概念转化为 V8 引擎能够理解和执行的底层操作。

### 提示词
```
这是目录为v8/src/compiler/wasm-gc-lowering.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
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
  if (use_null_trap) {
    UpdateSourcePosition(length, node);
  }

  ReplaceWithValue(node, length, gasm_.effect(), gasm_.control());
  node->Kill();
  return Replace(length);
}

Reduction WasmGCLowering::ReduceWasmArrayInitializeLength(Node* node) {
  DCHECK_EQ(node->opcode(), IrOpcode::kWasmArrayInitializeLength);
  Node* object = NodeProperties::GetValueInput(node, 0);
  Node* length = NodeProperties::GetValueInput(node, 1);

  gasm_.InitializeEffectControl(NodeProperties::GetEffectInput(node),
                                NodeProperties::GetControlInput(node));

  Node* set_length = gasm_.InitializeImmutableInObject(
      ObjectAccess{MachineType::Uint32(), kNoWriteBarrier}, object,
      wasm::ObjectAccess::ToTagged(WasmArray::kLengthOffset), length);

  return Replace(set_length);
}

Reduction WasmGCLowering::ReduceStringAsWtf16(Node* node) {
  DCHECK_EQ(node->opcode(), IrOpcode::kStringAsWtf16);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);
  Node* str = NodeProperties::GetValueInput(node, 0);

  gasm_.InitializeEffectControl(effect, control);

  auto done = gasm_.MakeLabel(MachineRepresentation::kTaggedPointer);
  Node* instance_type = gasm_.LoadInstanceType(gasm_.LoadMap(str));
  Node* string_representation = gasm_.Word32And(
      instance_type, gasm_.Int32Constant(kStringRepresentationMask));
  gasm_.GotoIf(gasm_.Word32Equal(string_representation,
                                 gasm_.Int32Constant(kSeqStringTag)),
               &done, str);
  gasm_.Goto(&done, gasm_.CallBuiltin(Builtin::kWasmStringAsWtf16,
                                      Operator::kEliminatable, str));
  gasm_.Bind(&done);
  ReplaceWithValue(node, done.PhiAt(0), gasm_.effect(), gasm_.control());
  node->Kill();
  return Replace(done.PhiAt(0));
}

Reduction WasmGCLowering::ReduceStringPrepareForGetCodeunit(Node* node) {
  DCHECK_EQ(node->opcode(), IrOpcode::kStringPrepareForGetCodeunit);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);
  Node* original_string = NodeProperties::GetValueInput(node, 0);

  gasm_.InitializeEffectControl(effect, control);

  auto dispatch =
      gasm_.MakeLoopLabel(MachineRepresentation::kTaggedPointer,  // String.
                          MachineRepresentation::kWord32,   // Instance type.
                          MachineRepresentation::kWord32);  // Offset.
  auto next = gasm_.MakeLabel(MachineRepresentation::kTaggedPointer,  // String.
                              MachineRepresentation::kWord32,  // Instance type.
                              MachineRepresentation::kWord32);  // Offset.
  auto direct_string =
      gasm_.MakeLabel(MachineRepresentation::kTaggedPointer,  // String.
                      MachineRepresentation::kWord32,         // Instance type.
                      MachineRepresentation::kWord32);        // Offset.

  // These values will be used to replace the original node's projections.
  // The first, "string", is either a SeqString or Tagged<Smi>(0) (in case of
  // external string). Notably this makes it GC-safe: if that string moves, this
  // pointer will be updated accordingly. The second, "offset", has full
  // register width so that it can be used to store external pointers: for
  // external strings, we add up the character backing store's base address and
  // any slice offset. The third, "character width", is a shift width, i.e. it
  // is 0 for one-byte strings, 1 for two-byte strings,
  // kCharWidthBailoutSentinel for uncached external strings (for which
  // "string"/"offset" are invalid and unusable).
  auto done =
      gasm_.MakeLabel(MachineRepresentation::kTagged,        // String.
                      MachineType::PointerRepresentation(),  // Offset.
                      MachineRepresentation::kWord32);       // Character width.

  Node* original_type = gasm_.LoadInstanceType(gasm_.LoadMap(original_string));
  gasm_.Goto(&dispatch, original_string, original_type, gasm_.Int32Constant(0));

  gasm_.Bind(&dispatch);
  {
    auto thin_string = gasm_.MakeLabel();
    auto cons_string = gasm_.MakeLabel();

    Node* string = dispatch.PhiAt(0);
    Node* instance_type = dispatch.PhiAt(1);
    Node* offset = dispatch.PhiAt(2);
    static_assert(kIsIndirectStringTag == 1);
    static constexpr int kIsDirectStringTag = 0;
    gasm_.GotoIf(gasm_.Word32Equal(
                     gasm_.Word32And(instance_type, gasm_.Int32Constant(
                                                        kIsIndirectStringMask)),
                     gasm_.Int32Constant(kIsDirectStringTag)),
                 &direct_string, string, instance_type, offset);

    // Handle indirect strings.
    Node* string_representation = gasm_.Word32And(
        instance_type, gasm_.Int32Constant(kStringRepresentationMask));
    gasm_.GotoIf(gasm_.Word32Equal(string_representation,
                                   gasm_.Int32Constant(kThinStringTag)),
                 &thin_string);
    gasm_.GotoIf(gasm_.Word32Equal(string_representation,
                                   gasm_.Int32Constant(kConsStringTag)),
                 &cons_string);

    // Sliced string.
    Node* new_offset = gasm_.Int32Add(
        offset, gasm_.BuildChangeSmiToInt32(gasm_.LoadImmutableFromObject(
                    MachineType::TaggedSigned(), string,
                    TaggedOffset(AccessBuilder::ForSlicedStringOffset()))));
    Node* parent = gasm_.LoadImmutableFromObject(
        MachineType::TaggedPointer(), string,
        TaggedOffset(AccessBuilder::ForSlicedStringParent()));
    Node* parent_type = gasm_.LoadInstanceType(gasm_.LoadMap(parent));
    gasm_.Goto(&next, parent, parent_type, new_offset);

    // Thin string.
    gasm_.Bind(&thin_string);
    Node* actual = gasm_.LoadImmutableFromObject(
        MachineType::TaggedPointer(), string,
        TaggedOffset(AccessBuilder::ForThinStringActual()));
    Node* actual_type = gasm_.LoadInstanceType(gasm_.LoadMap(actual));
    // ThinStrings always reference (internalized) direct strings.
    gasm_.Goto(&direct_string, actual, actual_type, offset);

    // Flat cons string. (Non-flat cons strings are ruled out by
    // string.as_wtf16.)
    gasm_.Bind(&cons_string);
    Node* first = gasm_.LoadImmutableFromObject(
        MachineType::TaggedPointer(), string,
        TaggedOffset(AccessBuilder::ForConsStringFirst()));
    Node* first_type = gasm_.LoadInstanceType(gasm_.LoadMap(first));
    gasm_.Goto(&next, first, first_type, offset);

    gasm_.Bind(&next);
    gasm_.Goto(&dispatch, next.PhiAt(0), next.PhiAt(1), next.PhiAt(2));
  }

  gasm_.Bind(&direct_string);
  {
    Node* string = direct_string.PhiAt(0);
    Node* instance_type = direct_string.PhiAt(1);
    Node* offset = direct_string.PhiAt(2);

    Node* is_onebyte = gasm_.Word32And(
        instance_type, gasm_.Int32Constant(kStringEncodingMask));
    // Char width shift is 1 - (is_onebyte).
    static_assert(kStringEncodingMask == 1 << 3);
    Node* charwidth_shift =
        gasm_.Int32Sub(gasm_.Int32Constant(1),
                       gasm_.Word32Shr(is_onebyte, gasm_.Int32Constant(3)));

    auto external = gasm_.MakeLabel();
    Node* string_representation = gasm_.Word32And(
        instance_type, gasm_.Int32Constant(kStringRepresentationMask));
    gasm_.GotoIf(gasm_.Word32Equal(string_representation,
                                   gasm_.Int32Constant(kExternalStringTag)),
                 &external);

    // Sequential string.
    DCHECK_EQ(AccessBuilder::ForSeqOneByteStringCharacter().header_size,
              AccessBuilder::ForSeqTwoByteStringCharacter().header_size);
    const int chars_start_offset =
        AccessBuilder::ForSeqOneByteStringCharacter().header_size;
    Node* final_offset = gasm_.Int32Add(
        gasm_.Int32Constant(wasm::ObjectAccess::ToTagged(chars_start_offset)),
        gasm_.Word32Shl(offset, charwidth_shift));
    gasm_.Goto(&done, string, gasm_.BuildChangeInt32ToIntPtr(final_offset),
               charwidth_shift);

    // External string.
    gasm_.Bind(&external);
    gasm_.GotoIf(
        gasm_.Word32And(instance_type,
                        gasm_.Int32Constant(kUncachedExternalStringMask)),
        &done, string, gasm_.IntPtrConstant(0),
        gasm_.Int32Constant(kCharWidthBailoutSentinel));
    Node* resource = gasm_.BuildLoadExternalPointerFromObject(
        string, AccessBuilder::ForExternalStringResourceData().offset,
        kExternalStringResourceDataTag, gasm_.LoadRootRegister());
    Node* shifted_offset = gasm_.Word32Shl(offset, charwidth_shift);
    final_offset = gasm_.IntPtrAdd(
        resource, gasm_.BuildChangeInt32ToIntPtr(shifted_offset));
    gasm_.Goto(&done, gasm_.SmiConstant(0), final_offset, charwidth_shift);
  }

  gasm_.Bind(&done);
  Node* base = done.PhiAt(0);
  Node* final_offset = done.PhiAt(1);
  Node* charwidth_shift = done.PhiAt(2);

  Node* base_proj = NodeProperties::FindProjection(node, 0);
  Node* offset_proj = NodeProperties::FindProjection(node, 1);
  Node* charwidth_proj = NodeProperties::FindProjection(node, 2);
  if (base_proj) {
    ReplaceWithValue(base_proj, base, gasm_.effect(), gasm_.control());
    base_proj->Kill();
  }
  if (offset_proj) {
    ReplaceWithValue(offset_proj, final_offset, gasm_.effect(),
                     gasm_.control());
    offset_proj->Kill();
  }
  if (charwidth_proj) {
    ReplaceWithValue(charwidth_proj, charwidth_shift, gasm_.effect(),
                     gasm_.control());
    charwidth_proj->Kill();
  }

  // Wire up the dangling end of the new effect chain.
  ReplaceWithValue(node, node, gasm_.effect(), gasm_.control());

  node->Kill();
  return Replace(base);
}

void WasmGCLowering::UpdateSourcePosition(Node* new_node, Node* old_node) {
  if (source_position_table_) {
    SourcePosition position =
        source_position_table_->GetSourcePosition(old_node);
    DCHECK(position.ScriptOffset() != kNoSourcePosition);
    source_position_table_->SetSourcePosition(new_node, position);
  }
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```