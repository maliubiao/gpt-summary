Response:
My thought process for analyzing the given C++ header file went something like this:

1. **Identify the Core Purpose:** The filename `wasm-gc-typed-optimization-reducer.h` and the leading comment immediately suggest this code is related to optimizing WebAssembly code that uses Garbage Collection (GC) and involves type information. The "reducer" part hints at a compiler pass that simplifies or transforms the code.

2. **High-Level Structure:** I scanned the file to understand its overall organization. I noticed:
    * Header guards (`#ifndef`, `#define`, `#endif`) which are standard C++ practice.
    * Conditional compilation (`#if !V8_ENABLE_WEBASSEMBLY`) indicating this code is only relevant when WebAssembly is enabled.
    * Inclusion of other V8 headers, suggesting dependencies on other compiler components (`assembler.h`, `operations.h`, etc.).
    * A namespace `v8::internal::compiler::turboshaft`, which helps organize V8's internal code.
    * Two main classes: `WasmGCTypeAnalyzer` and `WasmGCTypedOptimizationReducer`.

3. **Analyze `WasmGCTypeAnalyzer`:** I focused on the comments and member functions of this class.
    * The primary goal is to *infer* type information. The comment gives a clear example of how this works: tracking type refinement within `if` blocks.
    * Key methods like `Run()`, `GetInputTypeOrSentinelType()`, and various `Process...` methods (e.g., `ProcessTypeCast`, `ProcessIsNull`) reveal the steps involved in analyzing the control flow graph (CFG) and individual operations.
    * The presence of `TypeSnapshotTable` and `block_to_snapshot_` indicates that the analyzer maintains type information at different points in the code, likely at the end of basic blocks.
    * `RefineTypeKnowledge` suggests the analyzer updates its type information as it encounters new constraints.
    * The mention of "bottom" or "uninhabited" types signals the handling of code that will always trap.

4. **Analyze `WasmGCTypedOptimizationReducer`:** This class builds upon the analyzer.
    * The comment states its purpose: to *reduce* type checks and casts based on the information gathered by the analyzer.
    * The template structure `template <class Next> class WasmGCTypedOptimizationReducer : public Next` suggests this is part of a chain of compiler passes (the "reducer" pattern).
    * The `Analyze()` method calls the analyzer and then calls the base class's `Analyze()`, indicating the order of execution.
    * The `REDUCE_INPUT_GRAPH` macros (e.g., `REDUCE_INPUT_GRAPH(WasmTypeCast)`) are the core of the reducer. They handle specific operation types and attempt to simplify them using the type information from the analyzer.
    * The code within each `REDUCE_INPUT_GRAPH` method checks if optimizations are possible based on the `analyzer_.GetInputTypeOrSentinelType()` result. It then performs actions like removing redundant casts, simplifying casts to null checks, or refining type information in the operation itself.
    * The handling of `TrapIf` and `Unreachable` reinforces the idea of dealing with code that is known to be invalid.

5. **Connect to JavaScript/Wasm:** I considered how these optimizations might relate to the user-facing aspects of WebAssembly. Type casts, null checks, and struct/array accesses are common operations in Wasm. The optimizations here aim to make these operations more efficient when the compiler can statically prove certain conditions.

6. **Look for Code Logic and Examples:** I examined the logic within the `REDUCE_INPUT_GRAPH` methods. The `WasmTypeCast` and `WasmTypeCheck` reduction logic is quite detailed, demonstrating how subtype relationships and nullability are used for optimization. I started formulating potential input and output scenarios in my mind.

7. **Consider Common Programming Errors:** The focus on null checks and type safety naturally led to thinking about common errors like `NullPointerException` or incorrect type casts, which are frequent sources of bugs in programming.

8. **Address Specific Questions:** Finally, I systematically addressed each of the user's requests:
    * **Functionality:**  Summarize the roles of both classes.
    * **Torque:** Check the file extension.
    * **JavaScript Relation:**  Connect to the behavior of Wasm type casts and checks as exposed to JavaScript (through the Wasm API).
    * **Code Logic/Examples:** Devise simple Wasm snippets and trace how the reducer might transform them.
    * **Common Errors:** Relate the optimizations to preventing common runtime errors.

This iterative process of scanning, analyzing components, connecting to higher-level concepts, and then focusing on specifics allowed me to understand the purpose and functionality of the given V8 header file. The comments within the code were invaluable in this process.
好的，让我们来分析一下 `v8/src/compiler/turboshaft/wasm-gc-typed-optimization-reducer.h` 这个 V8 源代码文件。

**功能概述**

这个头文件定义了 `WasmGCTypedOptimizationReducer` 类，它是一个 Turboshaft 编译器管道中的一个组件，专门用于优化 WebAssembly 代码中与垃圾回收 (GC) 和类型相关的操作。 它的核心功能是：

1. **类型推断 (Type Inference):**  通过 `WasmGCTypeAnalyzer` 类，该 reducer 首先分析 WebAssembly 代码的控制流图 (CFG)，并尝试推断出程序中各种表达式和变量的更精确的类型信息。  例如，如果在一个 `if` 语句中进行了类型检查，那么在 `if` 分支内部，编译器可以知道被检查的变量具有更具体的类型。

2. **基于类型信息的优化 (Type-Based Optimization):**  基于推断出的类型信息，`WasmGCTypedOptimizationReducer` 尝试简化或移除冗余的类型检查和类型转换操作，从而提高代码执行效率。

**详细功能拆解**

* **`WasmGCTypeAnalyzer` 类:**
    * **分析输入图:** 遍历 WebAssembly 代码的图表示，跟踪类型信息在不同操作和控制流分支中的变化。
    * **维护类型快照:**  在代码的不同点（例如，基本块的末尾）记录当前的类型信息。
    * **处理各种 WASM GC 操作:** 针对 `ref.test`, `ref.cast`, `struct.get`, `array.get` 等 GC 相关的操作，分析其对类型信息的影响。
    * **类型精炼 (Type Refinement):**  根据类型检查或断言等操作，更新对变量类型的认知。例如，如果 `ref.test $MyType` 返回真，那么后续使用该变量时，可以认为它是 `$MyType` 的子类型。

* **`WasmGCTypedOptimizationReducer` 类:**
    * **使用类型分析器:**  首先运行 `WasmGCTypeAnalyzer` 来获取类型信息。
    * **简化 `wasm_type_cast` (类型转换):**
        * 如果分析器确定要转换的对象已经是目标类型的子类型，则可以移除类型转换操作。
        * 如果转换的目标类型是非空类型，但源类型可能为空，则可以将类型转换替换为非空断言。
        * 如果源类型和目标类型之间没有交集，则可以插入一个总是会触发的 trap 指令。
    * **简化 `wasm_type_check` (类型检查):**
        * 如果分析器确定要检查的对象总是目标类型的子类型，则可以将类型检查替换为返回 `true` 的常量。
        * 如果要检查的对象与目标类型不兼容，则可以替换为返回 `false` 的常量。
    * **简化 `assert_not_null` (非空断言):**
        * 如果分析器确定对象永远不会为空，则可以移除非空断言。
    * **简化 `is_null` (判空):**
        * 如果分析器确定对象永远不会为空，则可以将判空操作替换为返回 `false` 的常量。
        * 如果分析器确定对象总是为空，则可以将判空操作替换为返回 `true` 的常量。
    * **移除 `wasm_type_annotation` (类型注解):**  类型注解在优化阶段已经完成了它的作用，可以被移除。
    * **优化 `struct_get` 和 `struct_set` (结构体访问):**
        * 如果分析器确定结构体对象永远不会为空，则可以移除结构体访问前的空指针检查。
    * **优化 `array_length` (数组长度):**
        * 如果分析器确定数组对象永远不会为空，则可以移除获取数组长度前的空指针检查。
    * **优化 `AnyConvertExtern` (外部值转换):**  移除冗余的 `any.convert_extern(extern.convert_any(x))` 模式。

**关于文件扩展名和 Torque**

你提到的 `.tq` 扩展名是用于 V8 的 Torque 语言的。  `v8/src/compiler/turboshaft/wasm-gc-typed-optimization-reducer.h` 的扩展名是 `.h`，这意味着它是一个标准的 C++ 头文件，而不是 Torque 文件。因此，它不是用 Torque 编写的。

**与 JavaScript 的关系**

虽然这个文件本身是 C++ 代码，属于 V8 引擎的内部实现，但它直接影响了 WebAssembly 代码在 JavaScript 环境中的执行效率。  WebAssembly 提供了与 JavaScript 互操作的能力。当 JavaScript 调用 WebAssembly 函数，或者 WebAssembly 回调 JavaScript 函数时，涉及到类型转换和类型检查。

例如，考虑以下 JavaScript 和 WebAssembly 代码片段：

**JavaScript:**

```javascript
const wasmModule = new WebAssembly.Module(binary);
const wasmInstance = new WebAssembly.Instance(wasmModule, imports);
const wasmFunc = wasmInstance.exports.myWasmFunction;

let result = wasmFunc(someObject); // someObject 可能是一个 JavaScript 对象
```

**WebAssembly (假设的):**

```wasm
(module
  (type $my_functype (func (param anyref) (result i32)))
  (func $myWasmFunction (type $my_functype) (param $p anyref) (result i32)
    local.get $p
    ref.test (ref $MyWasmType)  ;; 类型检查
    if
      local.get $p
      ref.cast (ref $MyWasmType) ;; 类型转换
      struct.get $MyWasmType 0
      return
    end
    i32.const 0
  )
  (type $MyWasmType (struct (field i32)))
  (export "myWasmFunction" (func $myWasmFunction))
)
```

在这个例子中，`someObject` 从 JavaScript 传递到 WebAssembly 的 `myWasmFunction`。

* **类型推断:** `WasmGCTypeAnalyzer` 可能会分析 `ref.test` 指令，并在 `if` 分支内部推断出 `$p` 具有 `$MyWasmType` 或其子类型的特征。
* **类型优化:** `WasmGCTypedOptimizationReducer` 可能会观察到 `ref.cast` 的输入 `$p` 在 `if` 分支内部已经被确认为 `$MyWasmType` 的子类型，因此可以移除或简化这个类型转换操作，因为它总是会成功。

**代码逻辑推理示例**

**假设输入 (WebAssembly 中间表示的一部分):**

```
%1 = Parameter [0] : anyref
%2 = WasmTypeCheck %1, rtt($MyType) : i32
BranchIf %2, block #3, block #4

block #3:
  %5 = WasmTypeCast %1, rtt($MyType) : $MyType
  %6 = StructGet %5, field 0 : i32
  Return %6

block #4:
  %7 = Int32Constant 0
  Return %7
```

**分析器推断出的类型信息:**

在 `block #3` 的入口处，由于 `BranchIf` 指令依赖于 `%2` (`WasmTypeCheck`) 的结果为真，分析器可以推断出 `%1` 在 `block #3` 中至少是 `$MyType` 的子类型。

**优化器执行的简化:**

`WasmGCTypedOptimizationReducer` 会检查 `WasmTypeCast` 操作 `%5`。由于分析器已经推断出 `%1` 在此处是 `$MyType` 的子类型，因此类型转换 `%5` 是冗余的，可以被移除。

**优化后的输出:**

```
%1 = Parameter [0] : anyref
%2 = WasmTypeCheck %1, rtt($MyType) : i32
BranchIf %2, block #3, block #4

block #3:
  %5 = %1  // 类型转换被移除
  %6 = StructGet %5, field 0 : i32
  Return %6

block #4:
  %7 = Int32Constant 0
  Return %7
```

**用户常见的编程错误示例**

涉及 WebAssembly GC 类型时，常见的编程错误包括：

1. **错误的类型转换:** 尝试将一个对象转换为不兼容的类型，导致运行时错误 (trap)。

   **WebAssembly 示例:**

   ```wasm
   (module
     (type $A (struct (field i32)))
     (type $B (struct (field f64)))
     (func (param anyref) (result (ref $B))
       local.get 0
       ref.cast (ref $B)  ;; 如果传入的不是 $B 类型或其子类型，会 trap
     )
   )
   ```

   `WasmGCTypedOptimizationReducer` 可以通过类型分析来识别某些总是会失败的类型转换，并在编译时发出警告或插入 trap 指令。

2. **空指针解引用:**  在对象可能为空的情况下，直接访问其字段或方法，导致运行时错误。

   **WebAssembly 示例:**

   ```wasm
   (module
     (type $MyType (struct (field i32)))
     (func (param (ref null $MyType)) (result i32)
       local.get 0
       struct.get $MyType 0 ;; 如果传入的是 null，会 trap
     )
   )
   ```

   `WasmGCTypedOptimizationReducer` 可以尝试推断对象是否可能为空，并基于此优化掉一些不必要的空指针检查，或者在确定总是空指针解引用的情况下发出警告。

3. **错误的类型假设:**  在没有进行充分类型检查的情况下，假设某个变量具有特定的类型，导致后续操作失败。

   **WebAssembly 示例:**

   ```wasm
   (module
     (type $Base (struct (field i32)))
     (type $Derived (sub $Base (field f64)))
     (func (param (ref $Base)) (result f64)
       local.get 0
       ref.cast (ref $Derived) ;; 如果传入的是 $Base 但不是 $Derived，会 trap
       struct.get $Derived 1
     )
   )
   ```

   `WasmGCTypedOptimizationReducer` 的类型分析能力可以帮助编译器更好地理解代码中的类型关系，并进行更有效的优化。

总而言之，`v8/src/compiler/turboshaft/wasm-gc-typed-optimization-reducer.h` 定义了一个关键的编译器组件，它通过静态分析 WebAssembly 代码的类型信息来优化性能，减少冗余的类型检查和转换，并有助于及早发现潜在的类型错误。 它的工作使得 V8 能够更高效地执行 WebAssembly 代码，特别是那些使用了 GC 特性的代码。

### 提示词
```
这是目录为v8/src/compiler/turboshaft/wasm-gc-typed-optimization-reducer.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/wasm-gc-typed-optimization-reducer.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2023 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if !V8_ENABLE_WEBASSEMBLY
#error This header should only be included if WebAssembly is enabled.
#endif  // !V8_ENABLE_WEBASSEMBLY

#ifndef V8_COMPILER_TURBOSHAFT_WASM_GC_TYPED_OPTIMIZATION_REDUCER_H_
#define V8_COMPILER_TURBOSHAFT_WASM_GC_TYPED_OPTIMIZATION_REDUCER_H_

#include "src/compiler/turboshaft/assembler.h"
#include "src/compiler/turboshaft/operations.h"
#include "src/compiler/turboshaft/phase.h"
#include "src/compiler/turboshaft/snapshot-table-opindex.h"
#include "src/compiler/wasm-graph-assembler.h"
#include "src/wasm/wasm-subtyping.h"

namespace v8::internal::compiler::turboshaft {

// The WasmGCTypedOptimizationReducer infers type information based on the input
// graph and reduces type checks and casts based on that information.
//
// This is done in two steps:
// 1) The WasmGCTypeAnalyzer infers the types based on the input graph, e.g.:
//    func (param anyref) (result i32)
//      local.get 0
//      ref.test $MyType
//      if                     // local 0 is known to be (a subtype of) $MyType
//        local.get 0
//        ref.cast $MyType     // the input of this cast is a subtype of $MyType
//                             // it can be removed during reduction
//        struct.get $MyType 0
//        return
//      end                    // local 0 is still anyref
//        i32.const 0
//
// 2) The WasmGCTypedOptimizationReducer reduces the graph to a new graph
//    potentially removing, simplifying (e.g. replacing a cast with a null
//    check) or refining (setting the from type to a more specific type) type
//    operations.

class WasmGCTypeAnalyzer {
 public:
  WasmGCTypeAnalyzer(PipelineData* data, Graph& graph, Zone* zone)
      : data_(data), graph_(graph), phase_zone_(zone) {
    // If we ever want to run this analyzer for Wasm wrappers, we'll need
    // to make it handle their {CanonicalSig} signatures.
    DCHECK_NOT_NULL(signature_);
  }

  void Run();

  // Returns the input type for the operation or bottom if the operation shall
  // always trap.
  wasm::ValueType GetInputTypeOrSentinelType(OpIndex op) const {
    auto iter = input_type_map_.find(op);
    DCHECK_NE(iter, input_type_map_.end());
    return iter->second;
  }

 private:
  using TypeSnapshotTable = SparseOpIndexSnapshotTable<wasm::ValueType>;
  using Snapshot = TypeSnapshotTable::Snapshot;
  using MaybeSnapshot = TypeSnapshotTable::MaybeSnapshot;

  void StartNewSnapshotFor(const Block& block);
  void ProcessOperations(const Block& block);
  void ProcessBlock(const Block& block);
  void ProcessBranchOnTarget(const BranchOp& branch, const Block& target);

  void ProcessTypeCast(const WasmTypeCastOp& type_cast);
  void ProcessTypeCheck(const WasmTypeCheckOp& type_check);
  void ProcessAssertNotNull(const AssertNotNullOp& type_cast);
  void ProcessNull(const NullOp& null);
  void ProcessIsNull(const IsNullOp& is_null);
  void ProcessParameter(const ParameterOp& parameter);
  void ProcessStructGet(const StructGetOp& struct_get);
  void ProcessStructSet(const StructSetOp& struct_set);
  void ProcessArrayGet(const ArrayGetOp& array_get);
  void ProcessArrayLength(const ArrayLengthOp& array_length);
  void ProcessGlobalGet(const GlobalGetOp& global_get);
  void ProcessRefFunc(const WasmRefFuncOp& ref_func);
  void ProcessAllocateArray(const WasmAllocateArrayOp& allocate_array);
  void ProcessAllocateStruct(const WasmAllocateStructOp& allocate_struct);
  void ProcessPhi(const PhiOp& phi);
  void ProcessTypeAnnotation(const WasmTypeAnnotationOp& type_annotation);

  void CreateMergeSnapshot(const Block& block);
  bool CreateMergeSnapshot(base::Vector<const Snapshot> predecessors,
                           base::Vector<const bool> reachable);

  // Updates the knowledge in the side table about the type of {object},
  // returning the previous known type. Returns bottom if the refined type is
  // uninhabited. In this case the operation shall always trap.
  wasm::ValueType RefineTypeKnowledge(OpIndex object, wasm::ValueType new_type,
                                      const Operation& op);
  // Updates the knowledge in the side table to be a non-nullable type for
  // {object}, returning the previous known type. Returns bottom if the refined
  // type is uninhabited. In this case the operation shall always trap.
  wasm::ValueType RefineTypeKnowledgeNotNull(OpIndex object,
                                             const Operation& op);

  OpIndex ResolveAliases(OpIndex object) const;
  wasm::ValueType GetResolvedType(OpIndex object) const;

  // Returns the reachability status of a block. For any predecessor, this marks
  // whether the *end* of the block is reachable, for the current block it marks
  // whether the current instruction is reachable. (For successors the
  // reachability is unknown.)
  bool IsReachable(const Block& block) const;

  PipelineData* data_;
  Graph& graph_;
  Zone* phase_zone_;
  const wasm::WasmModule* module_ = data_->wasm_module();
  const wasm::FunctionSig* signature_ = data_->wasm_module_sig();
  // Contains the snapshots for all blocks in the CFG.
  TypeSnapshotTable types_table_{phase_zone_};
  // Maps the block id to a snapshot in the table defining the type knowledge
  // at the end of the block.
  FixedBlockSidetable<MaybeSnapshot> block_to_snapshot_{graph_.block_count(),
                                                        phase_zone_};

  // Tracks reachability of blocks throughout the analysis. Marking a block as
  // unreachable means that the block in question is unreachable from the
  // current "point of view" of the analysis, e.g. marking the current block as
  // "unreachable" means that from "now on" all succeeding statements can treat
  // it as unreachable, not that the beginning of the block was unreachable.
  BitVector block_is_unreachable_{static_cast<int>(graph_.block_count()),
                                  phase_zone_};

  const Block* current_block_ = nullptr;
  // For any operation that could potentially refined, this map stores an entry
  // to the inferred input type based on the analysis.
  ZoneUnorderedMap<OpIndex, wasm::ValueType> input_type_map_{phase_zone_};
  // Marker wheteher it is the first time visiting a loop header. In that case,
  // loop phis can only use type information based on the forward edge of the
  // loop. The value is false outside of loop headers.
  bool is_first_loop_header_evaluation_ = false;
};

#include "src/compiler/turboshaft/define-assembler-macros.inc"

template <class Next>
class WasmGCTypedOptimizationReducer : public Next {
 public:
  TURBOSHAFT_REDUCER_BOILERPLATE(WasmGCTypedOptimization)

  void Analyze() {
    analyzer_.Run();
    Next::Analyze();
  }

  V<Object> REDUCE_INPUT_GRAPH(WasmTypeCast)(V<Object> op_idx,
                                             const WasmTypeCastOp& cast_op) {
    LABEL_BLOCK(no_change) {
      return Next::ReduceInputGraphWasmTypeCast(op_idx, cast_op);
    }
    if (ShouldSkipOptimizationStep()) goto no_change;

    wasm::ValueType type = analyzer_.GetInputTypeOrSentinelType(op_idx);
    if (type.is_uninhabited()) {
      // We are either already in unreachable code (then this instruction isn't
      // even emitted) or the type analyzer inferred that this instruction will
      // always trap. In either case emitting an unconditional trap to increase
      // the chances of logic errors just leading to wrong behaviors but not
      // resulting in security issues.
      __ TrapIf(1, TrapId::kTrapIllegalCast);
      __ Unreachable();
      return OpIndex::Invalid();
    }
    if (type != wasm::ValueType()) {
      CHECK(!type.is_uninhabited());
      CHECK(wasm::IsSameTypeHierarchy(type.heap_type(),
                                      cast_op.config.to.heap_type(), module_));
      bool to_nullable = cast_op.config.to.is_nullable();
      if (wasm::IsHeapSubtypeOf(type.heap_type(), cast_op.config.to.heap_type(),
                                module_, module_)) {
        if (to_nullable || type.is_non_nullable()) {
          // The inferred type is already as specific as the cast target, the
          // cast is guaranteed to always succeed and can therefore be removed.
          return __ MapToNewGraph(cast_op.object());
        } else {
          // The inferred heap type is already as specific as the cast target,
          // but the source can be nullable and the target cannot be, so a null
          // check is still required.
          return __ AssertNotNull(__ MapToNewGraph(cast_op.object()), type,
                                  TrapId::kTrapIllegalCast);
        }
      }
      if (wasm::HeapTypesUnrelated(type.heap_type(),
                                   cast_op.config.to.heap_type(), module_,
                                   module_)) {
        // A cast between unrelated types can only succeed if the argument is
        // null. Otherwise, it always fails.
        V<Word32> non_trapping_condition =
            type.is_nullable() && to_nullable ? __ IsNull(__ MapToNewGraph(
                                                              cast_op.object()),
                                                          type)
                                              : __ Word32Constant(0);
        __ TrapIfNot(non_trapping_condition, TrapId::kTrapIllegalCast);
        if (!to_nullable) {
          __ Unreachable();
        }
        return __ MapToNewGraph(cast_op.object());
      }

      // If the cast resulted in an uninhabitable type, the analyzer should have
      // returned a sentinel (bottom) type as {type}.
      CHECK(!wasm::Intersection(type, cast_op.config.to, module_, module_)
                 .type.is_uninhabited());

      // The cast cannot be replaced. Still, we can refine the source type, so
      // that the lowering could potentially skip null or smi checks.
      wasm::ValueType from_type =
          wasm::Intersection(type, cast_op.config.from, module_, module_).type;
      DCHECK(!from_type.is_uninhabited());
      WasmTypeCheckConfig config{from_type, cast_op.config.to};
      return __ WasmTypeCast(__ MapToNewGraph(cast_op.object()),
                             __ MapToNewGraph(cast_op.rtt()), config);
    }
    goto no_change;
  }

  V<Word32> REDUCE_INPUT_GRAPH(WasmTypeCheck)(
      V<Word32> op_idx, const WasmTypeCheckOp& type_check) {
    LABEL_BLOCK(no_change) {
      return Next::ReduceInputGraphWasmTypeCheck(op_idx, type_check);
    }
    if (ShouldSkipOptimizationStep()) goto no_change;

    wasm::ValueType type = analyzer_.GetInputTypeOrSentinelType(op_idx);
    if (type.is_uninhabited()) {
      __ Unreachable();
      return OpIndex::Invalid();
    }
    if (type != wasm::ValueType()) {
      CHECK(!type.is_uninhabited());
      CHECK(wasm::IsSameTypeHierarchy(
          type.heap_type(), type_check.config.to.heap_type(), module_));
      bool to_nullable = type_check.config.to.is_nullable();
      if (wasm::IsHeapSubtypeOf(type.heap_type(),
                                type_check.config.to.heap_type(), module_,
                                module_)) {
        if (to_nullable || type.is_non_nullable()) {
          // The inferred type is guaranteed to be a subtype of the checked
          // type.
          return __ Word32Constant(1);
        } else {
          // The inferred type is guaranteed to be a subtype of the checked
          // type if it is not null.
          return __ Word32Equal(
              __ IsNull(__ MapToNewGraph(type_check.object()), type), 0);
        }
      }
      if (wasm::HeapTypesUnrelated(type.heap_type(),
                                   type_check.config.to.heap_type(), module_,
                                   module_)) {
        if (to_nullable && type.is_nullable()) {
          return __ IsNull(__ MapToNewGraph(type_check.object()), type);
        } else {
          return __ Word32Constant(0);
        }
      }

      // If there isn't a type that matches our known input type and the
      // type_check.config.to type, the type check always fails.
      wasm::ValueType true_type =
          wasm::Intersection(type, type_check.config.to, module_, module_).type;
      if (true_type.is_uninhabited()) {
        return __ Word32Constant(0);
      }

      // The check cannot be replaced. Still, we can refine the source type, so
      // that the lowering could potentially skip null or smi checks.
      wasm::ValueType from_type =
          wasm::Intersection(type, type_check.config.from, module_, module_)
              .type;
      DCHECK(!from_type.is_uninhabited());
      WasmTypeCheckConfig config{from_type, type_check.config.to};
      return __ WasmTypeCheck(__ MapToNewGraph(type_check.object()),
                              __ MapToNewGraph(type_check.rtt()), config);
    }
    goto no_change;
  }

  V<Object> REDUCE_INPUT_GRAPH(AssertNotNull)(
      V<Object> op_idx, const AssertNotNullOp& assert_not_null) {
    LABEL_BLOCK(no_change) {
      return Next::ReduceInputGraphAssertNotNull(op_idx, assert_not_null);
    }
    if (ShouldSkipOptimizationStep()) goto no_change;

    wasm::ValueType type = analyzer_.GetInputTypeOrSentinelType(op_idx);
    if (type.is_uninhabited()) {
      // We are either already in unreachable code (then this instruction isn't
      // even emitted) or the type analyzer inferred that this instruction will
      // always trap. In either case emitting an unconditional trap to increase
      // the chances of logic errors just leading to wrong behaviors but not
      // resulting in security issues.
      __ TrapIf(1, assert_not_null.trap_id);
      __ Unreachable();
      return OpIndex::Invalid();
    }
    if (type.is_non_nullable()) {
      return __ MapToNewGraph(assert_not_null.object());
    }
    goto no_change;
  }

  V<Word32> REDUCE_INPUT_GRAPH(IsNull)(V<Word32> op_idx,
                                       const IsNullOp& is_null) {
    LABEL_BLOCK(no_change) {
      return Next::ReduceInputGraphIsNull(op_idx, is_null);
    }
    if (ShouldSkipOptimizationStep()) goto no_change;

    const wasm::ValueType type = analyzer_.GetInputTypeOrSentinelType(op_idx);
    if (type.is_uninhabited()) {
      __ Unreachable();
      return OpIndex::Invalid();
    }
    if (type.is_non_nullable()) {
      return __ Word32Constant(0);
    }
    if (type != wasm::ValueType() &&
        wasm::ToNullSentinel({type, module_}) == type) {
      return __ Word32Constant(1);
    }
    goto no_change;
  }

  V<Object> REDUCE_INPUT_GRAPH(WasmTypeAnnotation)(
      V<Object> op_idx, const WasmTypeAnnotationOp& type_annotation) {
    // Remove type annotation operations as they are not needed any more.
    return __ MapToNewGraph(type_annotation.value());
  }

  V<Any> REDUCE_INPUT_GRAPH(StructGet)(V<Any> op_idx,
                                       const StructGetOp& struct_get) {
    LABEL_BLOCK(no_change) {
      return Next::ReduceInputGraphStructGet(op_idx, struct_get);
    }
    if (ShouldSkipOptimizationStep()) goto no_change;

    const wasm::ValueType type = analyzer_.GetInputTypeOrSentinelType(op_idx);
    if (type.is_uninhabited()) {
      // We are either already in unreachable code (then this instruction isn't
      // even emitted) or the type analyzer inferred that this instruction will
      // always trap. In either case emitting an unconditional trap to increase
      // the chances of logic errors just leading to wrong behaviors but not
      // resulting in security issues.
      __ TrapIf(1, TrapId::kTrapNullDereference);
      __ Unreachable();
      return OpIndex::Invalid();
    }
    // Remove the null check if it is known to be not null.
    if (struct_get.null_check == kWithNullCheck && type.is_non_nullable()) {
      return __ StructGet(__ MapToNewGraph(struct_get.object()),
                          struct_get.type, struct_get.type_index,
                          struct_get.field_index, struct_get.is_signed,
                          kWithoutNullCheck);
    }
    goto no_change;
  }

  V<None> REDUCE_INPUT_GRAPH(StructSet)(V<None> op_idx,
                                        const StructSetOp& struct_set) {
    LABEL_BLOCK(no_change) {
      return Next::ReduceInputGraphStructSet(op_idx, struct_set);
    }
    if (ShouldSkipOptimizationStep()) goto no_change;

    const wasm::ValueType type = analyzer_.GetInputTypeOrSentinelType(op_idx);
    if (type.is_uninhabited()) {
      // We are either already in unreachable code (then this instruction isn't
      // even emitted) or the type analyzer inferred that this instruction will
      // always trap. In either case emitting an unconditional trap to increase
      // the chances of logic errors just leading to wrong behaviors but not
      // resulting in security issues.
      __ TrapIf(1, TrapId::kTrapNullDereference);
      __ Unreachable();
      return OpIndex::Invalid();
    }
    // Remove the null check if it is known to be not null.
    if (struct_set.null_check == kWithNullCheck && type.is_non_nullable()) {
      __ StructSet(__ MapToNewGraph(struct_set.object()),
                   __ MapToNewGraph(struct_set.value()), struct_set.type,
                   struct_set.type_index, struct_set.field_index,
                   kWithoutNullCheck);
      return OpIndex::Invalid();
    }
    goto no_change;
  }

  V<Word32> REDUCE_INPUT_GRAPH(ArrayLength)(V<Word32> op_idx,
                                            const ArrayLengthOp& array_length) {
    LABEL_BLOCK(no_change) {
      return Next::ReduceInputGraphArrayLength(op_idx, array_length);
    }
    if (ShouldSkipOptimizationStep()) goto no_change;

    const wasm::ValueType type = analyzer_.GetInputTypeOrSentinelType(op_idx);
    // Remove the null check if it is known to be not null.
    if (array_length.null_check == kWithNullCheck && type.is_non_nullable()) {
      return __ ArrayLength(__ MapToNewGraph(array_length.array()),
                            kWithoutNullCheck);
    }
    goto no_change;
  }

  // TODO(14108): This isn't a type optimization and doesn't fit well into this
  // reducer.
  V<Object> REDUCE(AnyConvertExtern)(V<Object> object) {
    LABEL_BLOCK(no_change) { return Next::ReduceAnyConvertExtern(object); }
    if (ShouldSkipOptimizationStep()) goto no_change;

    if (object.valid()) {
      const ExternConvertAnyOp* externalize =
          __ output_graph().Get(object).template TryCast<ExternConvertAnyOp>();
      if (externalize != nullptr) {
        // Directly return the object as
        // any.convert_extern(extern.convert_any(x)) == x.
        return externalize->object();
      }
    }
    goto no_change;
  }

 private:
  Graph& graph_ = __ modifiable_input_graph();
  const wasm::WasmModule* module_ = __ data() -> wasm_module();
  WasmGCTypeAnalyzer analyzer_{__ data(), graph_, __ phase_zone()};
};

#include "src/compiler/turboshaft/undef-assembler-macros.inc"

}  // namespace v8::internal::compiler::turboshaft

#endif  // V8_COMPILER_TURBOSHAFT_WASM_GC_TYPED_OPTIMIZATION_REDUCER_H_
```