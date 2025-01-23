Response:
The user is asking for a breakdown of the functionality of the provided C++ header file. I need to analyze the code and identify its purpose and the optimizations it performs. Specifically, I need to address the following points:

1. **Core Functionality:** What does this code do?
2. **Torque Source:** Determine if the file is a Torque file (it's not, based on the `.h` extension).
3. **JavaScript Relation:**  Explain if and how this code relates to JavaScript execution, providing a JavaScript example if applicable.
4. **Logic Inference:** Describe any logical deductions or transformations performed by the code, including hypothetical inputs and outputs.
5. **Common Programming Errors:** Identify any common programming mistakes that this optimization aims to mitigate or is related to.

**Analysis of the Code:**

* **Header Guard:** Standard C++ header guard (`#ifndef`, `#define`, `#endif`).
* **Includes:** Includes various V8 internal headers related to compilation, code generation, and data structures. This confirms it's part of the Turboshaft compiler pipeline.
* **Namespace:**  The code is within the `v8::internal::compiler::turboshaft` namespace.
* **`CreateAllocateBuiltinDescriptor`:** A function to create a descriptor for allocation builtins.
* **`ValueNeedsWriteBarrier`:**  A function that determines if a write barrier is needed for a given value during garbage collection. It handles constant heap objects and Phi nodes.
* **`UnwrapAllocate`:**  A utility function to trace back through bitcasts and arithmetic operations to find the original `AllocateOp`.
* **`MemoryAnalyzer` Struct:** This is the core of the optimization. It tracks the most recent non-folded allocation and the reserved space for future allocations. It aims to:
    * **Allocation Folding:** Merge multiple small allocations into a single larger one.
    * **Write Barrier Elimination:**  Eliminate unnecessary write barriers when storing into newly allocated objects.
* **`MemoryOptimizationReducer` Class:**  A compiler phase that utilizes the `MemoryAnalyzer`. It overrides methods from a base class (`Next`). Key functionalities include:
    * **`Analyze()`:** Initializes and runs the `MemoryAnalyzer`.
    * **`REDUCE_INPUT_GRAPH(Store)`:**  Handles store operations and potentially removes write barriers based on the analyzer's findings.
    * **`REDUCE(Allocate)`:**  Handles allocation operations, implementing the allocation folding optimization.
    * **`REDUCE(DecodeExternalPointer)`:** Handles decoding external pointers (relevant for sandboxed environments).
* **Template Metaprogramming:** The use of templates (`MemoryOptimizationReducer`) suggests this is part of a larger compiler pipeline.
* **Wasm Support:** The code includes conditional compilation (`#if V8_ENABLE_WEBASSEMBLY`) to handle WebAssembly compilation.
* **Builtin Calls:** The code interacts with built-in functions for allocation.

**Planning the Response:**

1. **Summarize Core Functionality:** Start by stating that this file defines a compiler optimization pass that focuses on memory management within the Turboshaft compiler. Highlight allocation folding and write barrier elimination.
2. **Torque Status:** Explicitly state that the file is a C++ header file, not a Torque file.
3. **JavaScript Connection:** Explain the connection to JavaScript by describing how these optimizations improve the performance of JavaScript code execution by reducing allocation overhead and GC pressure. Provide a simple JavaScript example that demonstrates the kind of memory operations being optimized.
4. **Logic Inference Examples:** Give concrete examples of allocation folding and write barrier elimination. Provide a simplified hypothetical input (sequence of allocation and store operations) and the expected optimized output.
5. **Common Errors:** Discuss common JavaScript programming patterns that can benefit from these optimizations and potential pitfalls related to memory management that these optimizations help mitigate (although the optimizations are automatic and not directly controlled by the user).
这个文件 `v8/src/compiler/turboshaft/memory-optimization-reducer.h` 定义了一个 **Turboshaft 编译器的优化步骤**，专注于 **内存优化**。它的主要功能是：

1. **合并多个小的内存分配 (Allocation Folding):**  将多个连续的小对象分配合并成一个较大的分配。这可以减少分配的次数，从而降低运行时开销。
2. **消除不必要的写屏障 (Write Barrier Elimination):**  当存储一个值到一个新分配的对象时，通常需要一个写屏障来通知垃圾回收器对象间的引用关系。这个优化可以识别出某些情况下写屏障是不必要的，并将其移除，从而提高性能。

**它不是一个 Torque 源代码。** 因为文件名以 `.h` 结尾，这表示它是一个 C++ 头文件，而不是 Torque 源代码（Torque 源代码通常以 `.tq` 结尾）。

**它与 JavaScript 的功能有密切关系。**  JavaScript 引擎在运行时需要频繁地分配内存来创建对象。Turboshaft 是 V8 引擎的下一代编译器，其目标是生成更高效的机器码。 `MemoryOptimizationReducer` 通过优化内存分配和写屏障操作，直接提升 JavaScript 代码的执行效率。

**JavaScript 举例说明:**

假设有以下 JavaScript 代码：

```javascript
function createPoint(x, y) {
  const point = { x: x, y: y };
  return point;
}

const p1 = createPoint(1, 2);
const p2 = createPoint(3, 4);
```

在这个例子中，`createPoint` 函数会被调用两次，每次都会分配一个新的对象 `{ x: x, y: y }`。`MemoryOptimizationReducer` 可能会将这两次小的对象分配合并成一次较大的分配，从而减少内存分配的开销。

**代码逻辑推理 (假设输入与输出):**

**假设输入 (Turboshaft IR):**

```
// Block 0:
  %1: Allocate size=16, type=kYoung
  %2: Store %1[0] = constant 1
  %3: Store %1[8] = constant 2
  %4: Allocate size=16, type=kYoung
  %5: Store %4[0] = constant 3
  %6: Store %4[8] = constant 4
  Return %4
```

**优化后的输出 (Turboshaft IR):**

```
// Block 0:
  %1: Allocate size=32, type=kYoung  // 合并了两个分配
  %2: Store %1[0] = constant 1
  %3: Store %1[8] = constant 2
  // 第二个分配被折叠到第一个分配中
  %4: Bitcast %1 + 16  // 逻辑上的第二个对象起始地址
  %5: Store %4[0] = constant 3  // 实际存储在合并分配的偏移位置
  %6: Store %4[8] = constant 4
  Return %4
```

**解释:**

* 原始 IR 中有两个独立的 `Allocate` 操作。
* 优化后，第一个 `Allocate` 操作分配了更大的空间 (32 字节，足够容纳两个 16 字节的对象)。
* 第二个 `Allocate` 操作被移除，并用一个 `Bitcast` 操作代替，计算出逻辑上第二个对象在合并分配中的起始地址。
* 所有的 `Store` 操作仍然存在，但它们现在可能相对于合并后的分配进行偏移。

**关于写屏障消除的假设输入与输出:**

**假设输入 (Turboshaft IR):**

```
// Block 0:
  %1: Allocate size=16, type=kYoung
  %2: Store %1[0] = %other_object, write_barrier=kMayNeedWriteBarrier
  Return %1
```

**优化后的输出 (Turboshaft IR):**

```
// Block 0:
  %1: Allocate size=16, type=kYoung
  %2: Store %1[0] = %other_object, write_barrier=kNoWriteBarrier  // 消除了写屏障
  Return %1
```

**解释:** 如果 `%1` 是一个新分配的年轻代对象，并且 `%other_object` 也被认为是年轻代对象或者是不需要写屏障的对象，那么写屏障操作可以被安全地移除。

**涉及用户常见的编程错误 (间接相关):**

虽然这个优化器本身不直接修复用户的代码错误，但它旨在提高性能，而某些编程模式可能会增加内存分配的压力，从而使这个优化器更有价值。

* **过度创建小对象:**  在循环或频繁调用的函数中创建大量小的临时对象会增加垃圾回收的压力。例如：

```javascript
function processData(data) {
  const results = [];
  for (const item of data) {
    results.push({ processed: item * 2 }); // 每次循环都创建一个新对象
  }
  return results;
}
```

`MemoryOptimizationReducer` 可以通过合并这些小的对象分配来减轻这种压力。

* **频繁的属性添加:** 动态地向对象添加属性可能会导致 V8 引擎进行内部的对象结构调整，这涉及到内存分配。虽然优化器不能完全消除这种开销，但它可以优化相关的分配操作。

**需要注意的是：**  `MemoryOptimizationReducer` 是 V8 内部的优化，开发者通常不需要直接与它交互。它的存在是为了自动提升 JavaScript 代码的执行效率。用户编写高效的 JavaScript 代码仍然重要，但编译器优化器可以进一步提升性能。

### 提示词
```
这是目录为v8/src/compiler/turboshaft/memory-optimization-reducer.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/memory-optimization-reducer.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_COMPILER_TURBOSHAFT_MEMORY_OPTIMIZATION_REDUCER_H_
#define V8_COMPILER_TURBOSHAFT_MEMORY_OPTIMIZATION_REDUCER_H_

#include <optional>

#include "src/base/template-utils.h"
#include "src/builtins/builtins.h"
#include "src/codegen/external-reference.h"
#include "src/compiler/turboshaft/assembler.h"
#include "src/compiler/turboshaft/copying-phase.h"
#include "src/compiler/turboshaft/operations.h"
#include "src/compiler/turboshaft/opmasks.h"
#include "src/compiler/turboshaft/phase.h"
#include "src/compiler/turboshaft/utils.h"
#include "src/compiler/write-barrier-kind.h"
#include "src/zone/zone-containers.h"

namespace v8::internal::compiler::turboshaft {

#include "src/compiler/turboshaft/define-assembler-macros.inc"

const TSCallDescriptor* CreateAllocateBuiltinDescriptor(Zone* zone,
                                                        Isolate* isolate);

inline bool ValueNeedsWriteBarrier(const Graph* graph, const Operation& value,
                                   Isolate* isolate) {
  if (value.Is<Opmask::kBitcastWordPtrToSmi>()) {
    return false;
  } else if (const ConstantOp* constant = value.TryCast<ConstantOp>()) {
    if (constant->kind == ConstantOp::Kind::kHeapObject) {
      RootIndex root_index;
      if (isolate->roots_table().IsRootHandle(constant->handle(),
                                              &root_index) &&
          RootsTable::IsImmortalImmovable(root_index)) {
        return false;
      }
    }
  } else if (const PhiOp* phi = value.TryCast<PhiOp>()) {
    if (phi->rep == RegisterRepresentation::Tagged()) {
      return base::any_of(phi->inputs(), [graph, isolate](OpIndex input) {
        const Operation& input_op = graph->Get(input);
        // If we have a Phi as the Phi's input, we give up to avoid infinite
        // recursion.
        if (input_op.Is<PhiOp>()) return true;
        return ValueNeedsWriteBarrier(graph, input_op, isolate);
      });
    }
  }
  return true;
}

inline const AllocateOp* UnwrapAllocate(const Graph* graph,
                                        const Operation* op) {
  while (true) {
    if (const AllocateOp* allocate = op->TryCast<AllocateOp>()) {
      return allocate;
    } else if (const TaggedBitcastOp* bitcast =
                   op->TryCast<TaggedBitcastOp>()) {
      op = &graph->Get(bitcast->input());
    } else if (const WordBinopOp* binop = op->TryCast<WordBinopOp>();
               binop && binop->kind == any_of(WordBinopOp::Kind::kAdd,
                                              WordBinopOp::Kind::kSub)) {
      op = &graph->Get(binop->left());
    } else {
      return nullptr;
    }
  }
}

// The main purpose of memory optimization is folding multiple allocations
// into one. For this, the first allocation reserves additional space, that is
// consumed by subsequent allocations, which only move the allocation top
// pointer and are therefore guaranteed to succeed. Another nice side-effect
// of allocation folding is that more stores are performed on the most recent
// allocation, which allows us to eliminate the write barrier for the store.
//
// This analysis works by keeping track of the most recent non-folded
// allocation, as well as the number of bytes this allocation needs to reserve
// to satisfy all subsequent allocations.
// We can do write barrier elimination across loops if the loop does not
// contain any potentially allocating operations.
struct MemoryAnalyzer {
  enum class AllocationFolding { kDoAllocationFolding, kDontAllocationFolding };

  PipelineData* data;
  Zone* phase_zone;
  const Graph& input_graph;
  Isolate* isolate_ = data->isolate();
  AllocationFolding allocation_folding;
  bool is_wasm;
  MemoryAnalyzer(PipelineData* data, Zone* phase_zone, const Graph& input_graph,
                 AllocationFolding allocation_folding, bool is_wasm)
      : data(data),
        phase_zone(phase_zone),
        input_graph(input_graph),
        allocation_folding(allocation_folding),
        is_wasm(is_wasm) {}

  struct BlockState {
    const AllocateOp* last_allocation = nullptr;
    std::optional<uint32_t> reserved_size = std::nullopt;

    bool operator!=(const BlockState& other) {
      return last_allocation != other.last_allocation ||
             reserved_size != other.reserved_size;
    }
  };
  FixedBlockSidetable<std::optional<BlockState>> block_states{
      input_graph.block_count(), phase_zone};
  ZoneAbslFlatHashMap<const AllocateOp*, const AllocateOp*> folded_into{
      phase_zone};
  ZoneAbslFlatHashSet<V<None>> skipped_write_barriers{phase_zone};
  ZoneAbslFlatHashMap<const AllocateOp*, uint32_t> reserved_size{phase_zone};
  BlockIndex current_block = BlockIndex(0);
  BlockState state;
  TurboshaftPipelineKind pipeline_kind = data->pipeline_kind();

  bool IsPartOfLastAllocation(const Operation* op) {
    const AllocateOp* allocation = UnwrapAllocate(&input_graph, op);
    if (allocation == nullptr) return false;
    if (state.last_allocation == nullptr) return false;
    if (state.last_allocation->type != AllocationType::kYoung) return false;
    if (state.last_allocation == allocation) return true;
    auto it = folded_into.find(allocation);
    if (it == folded_into.end()) return false;
    return it->second == state.last_allocation;
  }

  bool SkipWriteBarrier(const StoreOp& store) {
    const Operation& object = input_graph.Get(store.base());
    const Operation& value = input_graph.Get(store.value());

    WriteBarrierKind write_barrier_kind = store.write_barrier;
    if (write_barrier_kind != WriteBarrierKind::kAssertNoWriteBarrier) {
      // If we have {kAssertNoWriteBarrier}, we cannot skip elimination
      // checks.
      if (ShouldSkipOptimizationStep()) return false;
    }
    if (IsPartOfLastAllocation(&object)) return true;
    if (!ValueNeedsWriteBarrier(&input_graph, value, isolate_)) return true;
    if (v8_flags.disable_write_barriers) return true;
    if (write_barrier_kind == WriteBarrierKind::kAssertNoWriteBarrier) {
      std::stringstream str;
      str << "MemoryOptimizationReducer could not remove write barrier for "
             "operation\n  #"
          << input_graph.Index(store) << ": " << store.ToString() << "\n";
      FATAL("%s", str.str().c_str());
    }
    return false;
  }

  bool IsFoldedAllocation(V<AnyOrNone> op) {
    return folded_into.count(
        input_graph.Get(op).template TryCast<AllocateOp>());
  }

  std::optional<uint32_t> ReservedSize(V<AnyOrNone> alloc) {
    if (auto it = reserved_size.find(
            input_graph.Get(alloc).template TryCast<AllocateOp>());
        it != reserved_size.end()) {
      return it->second;
    }
    return std::nullopt;
  }

  void Run();

  void Process(const Operation& op);
  void ProcessBlockTerminator(const Operation& op);
  void ProcessAllocation(const AllocateOp& alloc);
  void ProcessStore(const StoreOp& store);
  void MergeCurrentStateIntoSuccessor(const Block* successor);
};

template <class Next>
class MemoryOptimizationReducer : public Next {
 public:
  TURBOSHAFT_REDUCER_BOILERPLATE(MemoryOptimization)
  // TODO(dmercadier): Add static_assert that this is ran as part of a
  // CopyingPhase.

  void Analyze() {
    auto* info = __ data() -> info();
#if V8_ENABLE_WEBASSEMBLY
    bool is_wasm = info->IsWasm() || info->IsWasmBuiltin();
#else
    bool is_wasm = false;
#endif
    analyzer_.emplace(
        __ data(), __ phase_zone(), __ input_graph(),
        info->allocation_folding()
            ? MemoryAnalyzer::AllocationFolding::kDoAllocationFolding
            : MemoryAnalyzer::AllocationFolding::kDontAllocationFolding,
        is_wasm);
    analyzer_->Run();
    Next::Analyze();
  }

  V<None> REDUCE_INPUT_GRAPH(Store)(V<None> ig_index, const StoreOp& store) {
    if (store.write_barrier != WriteBarrierKind::kAssertNoWriteBarrier) {
      // We cannot skip this optimization if we have to eliminate a
      // {kAssertNoWriteBarrier}.
      if (ShouldSkipOptimizationStep()) {
        return Next::ReduceInputGraphStore(ig_index, store);
      }
    }
    if (analyzer_->skipped_write_barriers.count(ig_index)) {
      __ Store(__ MapToNewGraph(store.base()), __ MapToNewGraph(store.index()),
               __ MapToNewGraph(store.value()), store.kind, store.stored_rep,
               WriteBarrierKind::kNoWriteBarrier, store.offset,
               store.element_size_log2,
               store.maybe_initializing_or_transitioning,
               store.indirect_pointer_tag());
      return V<None>::Invalid();
    }
    DCHECK_NE(store.write_barrier, WriteBarrierKind::kAssertNoWriteBarrier);
    return Next::ReduceInputGraphStore(ig_index, store);
  }

  V<HeapObject> REDUCE(Allocate)(V<WordPtr> size, AllocationType type) {
    DCHECK_EQ(type, any_of(AllocationType::kYoung, AllocationType::kOld));

    if (v8_flags.single_generation && type == AllocationType::kYoung) {
      type = AllocationType::kOld;
    }

    V<WordPtr> top_address;
    if (isolate_ != nullptr) {
      top_address = __ ExternalConstant(
          type == AllocationType::kYoung
              ? ExternalReference::new_space_allocation_top_address(isolate_)
              : ExternalReference::old_space_allocation_top_address(isolate_));
    } else {
      // Wasm mode: producing isolate-independent code, loading the isolate
      // address at runtime.
#if V8_ENABLE_WEBASSEMBLY
      V<WasmTrustedInstanceData> instance_data = __ WasmInstanceDataParameter();
      int top_address_offset =
          type == AllocationType::kYoung
              ? WasmTrustedInstanceData::kNewAllocationTopAddressOffset
              : WasmTrustedInstanceData::kOldAllocationTopAddressOffset;
      top_address =
          __ Load(instance_data, LoadOp::Kind::TaggedBase().Immutable(),
                  MemoryRepresentation::UintPtr(), top_address_offset);
#else
      UNREACHABLE();
#endif  // V8_ENABLE_WEBASSEMBLY
    }

    if (analyzer_->IsFoldedAllocation(__ current_operation_origin())) {
      DCHECK_NE(__ GetVariable(top(type)), V<WordPtr>::Invalid());
      V<WordPtr> obj_addr = __ GetVariable(top(type));
      __ SetVariable(top(type), __ WordPtrAdd(__ GetVariable(top(type)), size));
      __ StoreOffHeap(top_address, __ GetVariable(top(type)),
                      MemoryRepresentation::UintPtr());
      return __ BitcastWordPtrToHeapObject(
          __ WordPtrAdd(obj_addr, __ IntPtrConstant(kHeapObjectTag)));
    }

    __ SetVariable(top(type), __ LoadOffHeap(top_address,
                                             MemoryRepresentation::UintPtr()));

    V<CallTarget> allocate_builtin;
    if (!analyzer_->is_wasm) {
      if (type == AllocationType::kYoung) {
        allocate_builtin =
            __ BuiltinCode(Builtin::kAllocateInYoungGeneration, isolate_);
      } else {
        allocate_builtin =
            __ BuiltinCode(Builtin::kAllocateInOldGeneration, isolate_);
      }
    } else {
#if V8_ENABLE_WEBASSEMBLY
      // This lowering is used by Wasm, where we compile isolate-independent
      // code. Builtin calls simply encode the target builtin ID, which will
      // be patched to the builtin's address later.
      if (isolate_ == nullptr) {
        Builtin builtin;
        if (type == AllocationType::kYoung) {
          builtin = Builtin::kWasmAllocateInYoungGeneration;
        } else {
          builtin = Builtin::kWasmAllocateInOldGeneration;
        }
        static_assert(std::is_same<Smi, BuiltinPtr>(),
                      "BuiltinPtr must be Smi");
        allocate_builtin = __ NumberConstant(static_cast<int>(builtin));
      } else {
        if (type == AllocationType::kYoung) {
          allocate_builtin =
              __ BuiltinCode(Builtin::kWasmAllocateInYoungGeneration, isolate_);
        } else {
          allocate_builtin =
              __ BuiltinCode(Builtin::kWasmAllocateInOldGeneration, isolate_);
        }
      }
#else
      UNREACHABLE();
#endif
    }

    Block* call_runtime = __ NewBlock();
    Block* done = __ NewBlock();

    V<WordPtr> limit_address = GetLimitAddress(type);

    // If the allocation size is not statically known or is known to be larger
    // than kMaxRegularHeapObjectSize, do not update {top(type)} in case of a
    // runtime call. This is needed because we cannot allocation-fold large and
    // normal-sized objects.
    uint64_t constant_size{};
    if (!__ matcher().MatchIntegralWordConstant(
            size, WordRepresentation::WordPtr(), &constant_size) ||
        constant_size > kMaxRegularHeapObjectSize) {
      Variable result =
          __ NewLoopInvariantVariable(RegisterRepresentation::Tagged());
      if (!constant_size) {
        // Check if we can do bump pointer allocation here.
        V<WordPtr> top_value = __ GetVariable(top(type));
        __ SetVariable(result,
                       __ BitcastWordPtrToHeapObject(__ WordPtrAdd(
                           top_value, __ IntPtrConstant(kHeapObjectTag))));
        V<WordPtr> new_top = __ WordPtrAdd(top_value, size);
        V<WordPtr> limit =
            __ LoadOffHeap(limit_address, MemoryRepresentation::UintPtr());
        __ GotoIfNot(LIKELY(__ UintPtrLessThan(new_top, limit)), call_runtime);
        __ GotoIfNot(LIKELY(__ UintPtrLessThan(
                         size, __ IntPtrConstant(kMaxRegularHeapObjectSize))),
                     call_runtime);
        __ SetVariable(top(type), new_top);
        __ StoreOffHeap(top_address, new_top, MemoryRepresentation::UintPtr());
        __ Goto(done);
      }
      if (constant_size || __ Bind(call_runtime)) {
        __ SetVariable(
            result, __ template Call<HeapObject>(allocate_builtin, {size},
                                                 AllocateBuiltinDescriptor()));
        __ Goto(done);
      }

      __ BindReachable(done);
      return __ GetVariable(result);
    }

    V<WordPtr> reservation_size;
    if (auto c = analyzer_->ReservedSize(__ current_operation_origin())) {
      reservation_size = __ UintPtrConstant(*c);
    } else {
      reservation_size = size;
    }
    // Check if we can do bump pointer allocation here.
    bool reachable =
        __ GotoIfNot(__ UintPtrLessThan(
                         size, __ IntPtrConstant(kMaxRegularHeapObjectSize)),
                     call_runtime, BranchHint::kTrue) !=
        ConditionalGotoStatus::kGotoDestination;
    if (reachable) {
      V<WordPtr> limit =
          __ LoadOffHeap(limit_address, MemoryRepresentation::UintPtr());
      __ Branch(__ UintPtrLessThan(
                    __ WordPtrAdd(__ GetVariable(top(type)), reservation_size),
                    limit),
                done, call_runtime, BranchHint::kTrue);
    }

    // Call the runtime if bump pointer area exhausted.
    if (__ Bind(call_runtime)) {
      V<HeapObject> allocated = __ template Call<HeapObject>(
          allocate_builtin, {reservation_size}, AllocateBuiltinDescriptor());
      __ SetVariable(top(type),
                     __ WordPtrSub(__ BitcastHeapObjectToWordPtr(allocated),
                                   __ IntPtrConstant(kHeapObjectTag)));
      __ Goto(done);
    }

    __ BindReachable(done);
    // Compute the new top and write it back.
    V<WordPtr> obj_addr = __ GetVariable(top(type));
    __ SetVariable(top(type), __ WordPtrAdd(__ GetVariable(top(type)), size));
    __ StoreOffHeap(top_address, __ GetVariable(top(type)),
                    MemoryRepresentation::UintPtr());
    return __ BitcastWordPtrToHeapObject(
        __ WordPtrAdd(obj_addr, __ IntPtrConstant(kHeapObjectTag)));
  }

  OpIndex REDUCE(DecodeExternalPointer)(OpIndex handle,
                                        ExternalPointerTag tag) {
#ifdef V8_ENABLE_SANDBOX
    // Decode loaded external pointer.
    V<WordPtr> table;
    if (isolate_ != nullptr) {
      // Here we access the external pointer table through an ExternalReference.
      // Alternatively, we could also hardcode the address of the table since it
      // is never reallocated. However, in that case we must be able to
      // guarantee that the generated code is never executed under a different
      // Isolate, as that would allow access to external objects from different
      // Isolates. It also would break if the code is serialized/deserialized at
      // some point.
      V<WordPtr> table_address =
          IsSharedExternalPointerType(tag)
              ? __
                LoadOffHeap(
                    __ ExternalConstant(
                        ExternalReference::
                            shared_external_pointer_table_address_address(
                                isolate_)),
                    MemoryRepresentation::UintPtr())
              : __ ExternalConstant(
                    ExternalReference::external_pointer_table_address(
                        isolate_));
      table = __ LoadOffHeap(table_address,
                             Internals::kExternalPointerTableBasePointerOffset,
                             MemoryRepresentation::UintPtr());
    } else {
#if V8_ENABLE_WEBASSEMBLY
      V<WordPtr> isolate_root = __ LoadRootRegister();
      if (IsSharedExternalPointerType(tag)) {
        V<WordPtr> table_address =
            __ Load(isolate_root, LoadOp::Kind::RawAligned(),
                    MemoryRepresentation::UintPtr(),
                    IsolateData::shared_external_pointer_table_offset());
        table = __ Load(table_address, LoadOp::Kind::RawAligned(),
                        MemoryRepresentation::UintPtr(),
                        Internals::kExternalPointerTableBasePointerOffset);
      } else {
        table = __ Load(isolate_root, LoadOp::Kind::RawAligned(),
                        MemoryRepresentation::UintPtr(),
                        IsolateData::external_pointer_table_offset() +
                            Internals::kExternalPointerTableBasePointerOffset);
      }
#else
      UNREACHABLE();
#endif
    }

    V<Word32> index =
        __ Word32ShiftRightLogical(handle, kExternalPointerIndexShift);
    V<Word64> pointer = __ LoadOffHeap(table, __ ChangeUint32ToUint64(index), 0,
                                       MemoryRepresentation::Uint64());
    pointer = __ Word64BitwiseAnd(pointer, __ Word64Constant(~tag));
    return pointer;
#else   // V8_ENABLE_SANDBOX
    UNREACHABLE();
#endif  // V8_ENABLE_SANDBOX
  }

 private:
  std::optional<MemoryAnalyzer> analyzer_;
  Isolate* isolate_ = __ data() -> isolate();
  const TSCallDescriptor* allocate_builtin_descriptor_ = nullptr;
  std::optional<Variable> top_[2];

  static_assert(static_cast<int>(AllocationType::kYoung) == 0);
  static_assert(static_cast<int>(AllocationType::kOld) == 1);
  Variable top(AllocationType type) {
    DCHECK(type == AllocationType::kYoung || type == AllocationType::kOld);
    if (V8_UNLIKELY(!top_[static_cast<int>(type)].has_value())) {
      top_[static_cast<int>(type)].emplace(
          __ NewLoopInvariantVariable(RegisterRepresentation::WordPtr()));
    }
    return top_[static_cast<int>(type)].value();
  }

  const TSCallDescriptor* AllocateBuiltinDescriptor() {
    if (allocate_builtin_descriptor_ == nullptr) {
      allocate_builtin_descriptor_ =
          CreateAllocateBuiltinDescriptor(__ graph_zone(), isolate_);
    }
    return allocate_builtin_descriptor_;
  }

  V<WordPtr> GetLimitAddress(AllocationType type) {
    V<WordPtr> limit_address;
    if (isolate_ != nullptr) {
      limit_address = __ ExternalConstant(
          type == AllocationType::kYoung
              ? ExternalReference::new_space_allocation_limit_address(isolate_)
              : ExternalReference::old_space_allocation_limit_address(
                    isolate_));
    } else {
      // Wasm mode: producing isolate-independent code, loading the isolate
      // address at runtime.
#if V8_ENABLE_WEBASSEMBLY
      V<WasmTrustedInstanceData> instance_node = __ WasmInstanceDataParameter();
      int limit_address_offset =
          type == AllocationType::kYoung
              ? WasmTrustedInstanceData::kNewAllocationLimitAddressOffset
              : WasmTrustedInstanceData::kOldAllocationLimitAddressOffset;
      limit_address =
          __ Load(instance_node, LoadOp::Kind::TaggedBase(),
                  MemoryRepresentation::UintPtr(), limit_address_offset);
#else
      UNREACHABLE();
#endif  // V8_ENABLE_WEBASSEMBLY
    }
    return limit_address;
  }
};

#include "src/compiler/turboshaft/undef-assembler-macros.inc"

}  // namespace v8::internal::compiler::turboshaft

#endif  // V8_COMPILER_TURBOSHAFT_MEMORY_OPTIMIZATION_REDUCER_H_
```