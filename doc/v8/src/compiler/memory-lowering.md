Response: Let's break down the thought process for analyzing the `memory-lowering.cc` file.

1. **Understand the Context:** The first step is recognizing where this file lives within the V8 project. The path `v8/src/compiler/memory-lowering.cc` tells us it's part of the compiler and specifically deals with "memory lowering."  This immediately suggests its role is in transforming high-level memory operations into lower-level, machine-specific instructions.

2. **Identify Key Components:** Scan the file for major structural elements:
    * **Includes:** These point to dependencies and related functionalities. Notice headers like `src/compiler/js-graph.h`, `src/compiler/linkage.h`, `src/compiler/simplified-operator.h`, and `#if V8_ENABLE_WEBASSEMBLY`. This reinforces that this code is deeply intertwined with the compiler and handles both standard JavaScript and WebAssembly.
    * **Namespaces:**  `v8::internal::compiler` provides the scope and confirms the component.
    * **Class `MemoryLowering`:** This is the central class. Its constructor and methods will define the file's primary actions.
    * **Inner Class `AllocationGroup`:**  This suggests a mechanism for grouping allocations, likely for optimization.
    * **Methods of `MemoryLowering`:**  The `Reduce` method is a strong indicator of a compiler phase that transforms nodes in a graph. Methods like `ReduceAllocateRaw`, `ReduceLoadFromObject`, `ReduceStoreElement`, etc., clearly indicate the types of memory operations being handled.
    * **Helper Functions:** Functions like `AlignToAllocationAlignment`, `ComputeIndex`, and the anonymous namespace function `ValueNeedsWriteBarrier` suggest supporting logic.
    * **Conditional Compilation (`#if`):** The presence of `#if V8_ENABLE_WEBASSEMBLY` highlights that the file handles both JavaScript and WebAssembly.

3. **Analyze the `MemoryLowering` Class:** Focus on the core functionality:
    * **Constructor:**  It takes `JSGraph`, `Zone`, `JSGraphAssembler`, and flags as arguments. This confirms its role within the Turbofan pipeline.
    * **`Reduce(Node* node)`:** This is the heart of the lowering process. The `switch` statement handles different `IrOpcode`s (Intermediate Representation Opcodes), indicating the types of nodes being transformed. The opcodes relate to allocation, loading, and storing data.
    * **`ReduceAllocateRaw`:** This function seems crucial for handling memory allocation. The logic involves checking allocation types, potentially folding allocations for optimization, and interacting with the garbage collector. The differentiation between young and old generation is important for GC efficiency.
    * **`ReduceLoad*` and `ReduceStore*` methods:** These handle reading and writing data to different memory locations (objects, elements, fields). They also consider factors like unaligned access, map words, and write barriers.
    * **`ComputeIndex`:**  This helper calculates the correct memory offset for element access, taking into account element size and header information.
    * **`ComputeWriteBarrierKind`:** This function determines if a write barrier is needed, considering factors like allocation age and the type of the written value. Write barriers are crucial for garbage collection correctness.

4. **Analyze the `AllocationGroup` Class:** This class groups related allocations together. This is a key optimization technique (allocation folding) to improve performance by reducing the overhead of individual allocations.

5. **Identify the Connection to JavaScript:**
    * **Core Memory Operations:** The operations being lowered (allocation, load, store) are fundamental to how JavaScript manages data.
    * **Object Model:**  The terms "object," "element," and "field" directly map to JavaScript's object model.
    * **Garbage Collection:** The mention of "young generation" and "old generation" allocation, along with write barriers, directly relates to JavaScript's garbage collection mechanism.
    * **Example Construction:**  Think about simple JavaScript operations that involve these memory concepts:
        * Creating an object (`{}`).
        * Accessing a property (`obj.prop`).
        * Accessing an array element (`arr[i]`).
        * Modifying a property or array element (`obj.prop = value`, `arr[i] = value`).

6. **Formulate the Summary:** Combine the observations into a concise description:
    * **Purpose:**  Lower high-level memory operations to machine-specific instructions.
    * **Key Class:** `MemoryLowering`.
    * **Mechanism:** Transforming nodes in the compiler's intermediate representation graph.
    * **Core Operations:** Allocation, loading, and storing.
    * **Optimizations:** Allocation folding (through `AllocationGroup`).
    * **Garbage Collection:** Handling young and old generation allocations, write barriers.
    * **WebAssembly Support:**  Conditional compilation indicates handling of WebAssembly memory.
    * **JavaScript Connection:** The lowered operations directly implement JavaScript's memory model, including object creation, property access, and array manipulation.

7. **Construct the JavaScript Examples:** Create concrete examples that demonstrate the JavaScript-level operations that would be handled by the code in `memory-lowering.cc`. Focus on the concepts of object creation, property access (load and store), and array access. Use comments to explicitly link the JavaScript code to the concepts discussed in the C++ code.

8. **Review and Refine:** Read through the summary and examples to ensure clarity, accuracy, and completeness. Check for any technical terms that might need further explanation. For instance, briefly explaining "write barrier" enhances understanding.这个 C++ 代码文件 `memory-lowering.cc` 是 V8 JavaScript 引擎中 **Turbofan 优化编译器** 的一个关键组成部分。它的主要功能是执行 **内存底层化 (Memory Lowering)**，这是编译优化过程中的一个阶段。

**核心功能归纳:**

* **将高级内存操作转换为低级机器操作:**  Turbofan 编译器在早期阶段使用高级的、平台无关的内存操作（例如 `Allocate`, `LoadFromObject`, `StoreElement` 等）。`memory-lowering.cc` 的目标是将这些高级操作转换为更接近目标机器的底层操作，例如加载和存储机器字（machine words）。
* **处理内存分配:** 它负责将抽象的内存分配操作 (`AllocateRaw`) 转换为实际的内存分配过程，包括：
    * **选择分配空间:**  区分年轻代 (Young Generation) 和老年代 (Old Generation) 的分配，这与垃圾回收策略有关。
    * **Bump 指针分配:** 尝试使用快速的 bump 指针分配策略，即在预留的内存块中递增指针来分配对象。
    * **调用运行时分配函数:**  如果 bump 指针分配失败（例如，空间不足），则调用底层的运行时分配函数。
    * **Allocation Folding (可选):**  它实现了“分配折叠”优化，可以将多个小的连续分配合并成一个大的分配，减少分配的开销。
* **处理内存加载和存储操作:**  它将高级的加载和存储操作（例如从对象加载字段、存储到数组元素）转换为底层的机器加载和存储指令，包括：
    * **计算内存地址:**  根据对象的基地址、偏移量和索引等信息计算出实际的内存地址。
    * **处理对齐:**  确保内存访问满足目标平台的对齐要求。
    * **处理写屏障 (Write Barriers):**  在存储对象指针时，插入写屏障，这是垃圾回收器跟踪对象引用的关键机制。
    * **处理不同类型的数据:**  根据加载和存储的数据类型（例如，Tagged 对象指针、整数、浮点数）生成相应的机器指令。
* **WebAssembly 支持:** 文件中包含了对 WebAssembly 的支持，允许在 Turbofan 编译 WebAssembly 代码时进行内存底层化。
* **为后续的机器码生成做准备:**  内存底层化是生成最终机器码之前的必要步骤，它为指令选择和寄存器分配等后续阶段提供了更底层的操作。

**与 JavaScript 的关系及 JavaScript 示例:**

`memory-lowering.cc` 的工作是 JavaScript 引擎内部的实现细节，JavaScript 开发者通常不需要直接与之交互。但是，它直接影响了 JavaScript 代码的性能。  我们编写的 JavaScript 代码最终会被 V8 编译成机器码，而 `memory-lowering.cc` 就参与了这个编译过程中的关键环节。

以下是一些 JavaScript 示例，以及 `memory-lowering.cc` 可能如何处理它们背后的内存操作：

**1. 对象创建和属性访问:**

```javascript
const obj = { x: 10, y: "hello" };
const value = obj.x;
obj.y = "world";
```

* **`const obj = { x: 10, y: "hello" };`**:  这会触发内存分配。`memory-lowering.cc` 中的 `ReduceAllocateRaw` 函数会将这个高级的分配操作转换为底层的内存分配指令，可能会区分年轻代和老年代的分配。 `AllocationFolding` 可能会尝试将这个对象的分配与之前的分配合并。
* **`const value = obj.x;`**:  这会触发一个属性加载操作。`memory-lowering.cc` 中的 `ReduceLoadFromObject` 会根据对象的内存布局和 `x` 属性的偏移量，生成加载机器字的指令。
* **`obj.y = "world";`**:  这会触发一个属性存储操作。`memory-lowering.cc` 中的 `ReduceStoreToObject` 会生成存储指令，并且 **如果 `y` 属性存储的是一个对象指针，则会插入写屏障**，以通知垃圾回收器 `obj` 对象现在引用了新的字符串 "world"。

**2. 数组操作:**

```javascript
const arr = [1, 2, 3];
const element = arr[1];
arr[0] = 4;
```

* **`const arr = [1, 2, 3];`**:  这同样涉及内存分配，用于存储数组的元素。
* **`const element = arr[1];`**:  `memory-lowering.cc` 中的 `ReduceLoadElement` 会根据数组的起始地址和索引 1 计算出元素的内存地址，并生成加载指令。
* **`arr[0] = 4;`**:  `memory-lowering.cc` 中的 `ReduceStoreElement` 会生成存储指令来更新数组的第一个元素。 由于数字通常是直接存储的值，这里可能不需要写屏障。

**3. WebAssembly 内存访问 (如果启用了 WebAssembly):**

```javascript
const wasmInstance = new WebAssembly.Instance(module);
const linearMemory = wasmInstance.exports.memory;
const buffer = new Uint8Array(linearMemory.buffer);
const value = buffer[10];
buffer[20] = 42;
```

在 WebAssembly 的场景下，`memory-lowering.cc` 中 `#if V8_ENABLE_WEBASSEMBLY` 相关的代码会处理 WebAssembly 线性内存的加载和存储操作，确保对 WebAssembly 内存的访问是安全且高效的。

**总结:**

`memory-lowering.cc` 是 V8 编译器中一个低级别的组件，它将高级的内存操作转换为机器可以执行的指令。虽然 JavaScript 开发者不需要直接编写或理解这段 C++ 代码，但它的优化工作直接影响了 JavaScript 代码的执行效率。通过理解其基本功能，可以更好地理解 JavaScript 引擎是如何在底层管理内存的。

Prompt: 
```
这是目录为v8/src/compiler/memory-lowering.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2019 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/memory-lowering.h"

#include "src/codegen/interface-descriptors-inl.h"
#include "src/common/globals.h"
#include "src/compiler/js-graph.h"
#include "src/compiler/linkage.h"
#include "src/compiler/node-matchers.h"
#include "src/compiler/node-properties.h"
#include "src/compiler/node.h"
#include "src/compiler/simplified-operator.h"
#include "src/roots/roots-inl.h"
#include "src/sandbox/external-pointer-inl.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-linkage.h"
#include "src/wasm/wasm-objects.h"
#endif
namespace v8 {
namespace internal {
namespace compiler {

// An allocation group represents a set of allocations that have been folded
// together.
class MemoryLowering::AllocationGroup final : public ZoneObject {
 public:
  AllocationGroup(Node* node, AllocationType allocation, Zone* zone);
  AllocationGroup(Node* node, AllocationType allocation, Node* size,
                  Zone* zone);
  ~AllocationGroup() = default;

  void Add(Node* object);
  bool Contains(Node* object) const;
  bool IsYoungGenerationAllocation() const {
    return allocation() == AllocationType::kYoung;
  }

  AllocationType allocation() const { return allocation_; }
  Node* size() const { return size_; }

 private:
  ZoneSet<NodeId> node_ids_;
  AllocationType const allocation_;
  Node* const size_;

  static inline AllocationType CheckAllocationType(AllocationType allocation) {
    // For non-generational heap, all young allocations are redirected to old
    // space.
    if (v8_flags.single_generation && allocation == AllocationType::kYoung) {
      return AllocationType::kOld;
    }
    return allocation;
  }

  DISALLOW_IMPLICIT_CONSTRUCTORS(AllocationGroup);
};

MemoryLowering::MemoryLowering(JSGraph* jsgraph, Zone* zone,
                               JSGraphAssembler* graph_assembler, bool is_wasm,
                               AllocationFolding allocation_folding,
                               WriteBarrierAssertFailedCallback callback,
                               const char* function_debug_name)
    : isolate_(jsgraph->isolate()),
      zone_(zone),
      graph_(jsgraph->graph()),
      common_(jsgraph->common()),
      machine_(jsgraph->machine()),
      graph_assembler_(graph_assembler),
      is_wasm_(is_wasm),
      allocation_folding_(allocation_folding),
      write_barrier_assert_failed_(callback),
      function_debug_name_(function_debug_name) {}

Zone* MemoryLowering::graph_zone() const { return graph()->zone(); }

Reduction MemoryLowering::Reduce(Node* node) {
  switch (node->opcode()) {
    case IrOpcode::kAllocate:
      // Allocate nodes were purged from the graph in effect-control
      // linearization.
      UNREACHABLE();
    case IrOpcode::kAllocateRaw:
      return ReduceAllocateRaw(node);
    case IrOpcode::kLoadFromObject:
    case IrOpcode::kLoadImmutableFromObject:
      return ReduceLoadFromObject(node);
    case IrOpcode::kLoadElement:
      return ReduceLoadElement(node);
    case IrOpcode::kLoadField:
      return ReduceLoadField(node);
    case IrOpcode::kStoreToObject:
    case IrOpcode::kInitializeImmutableInObject:
      return ReduceStoreToObject(node);
    case IrOpcode::kStoreElement:
      return ReduceStoreElement(node);
    case IrOpcode::kStoreField:
      return ReduceStoreField(node);
    case IrOpcode::kStore:
      return ReduceStore(node);
    default:
      return NoChange();
  }
}

void MemoryLowering::EnsureAllocateOperator() {
  if (allocate_operator_.is_set()) return;

  auto descriptor = AllocateDescriptor{};
  StubCallMode mode = isolate_ != nullptr ? StubCallMode::kCallCodeObject
                                          : StubCallMode::kCallBuiltinPointer;
  auto call_descriptor = Linkage::GetStubCallDescriptor(
      graph_zone(), descriptor, descriptor.GetStackParameterCount(),
      CallDescriptor::kCanUseRoots, Operator::kNoThrow, mode);
  allocate_operator_.set(common()->Call(call_descriptor));
}

#if V8_ENABLE_WEBASSEMBLY
Node* MemoryLowering::GetWasmInstanceNode() {
  if (wasm_instance_node_.is_set()) return wasm_instance_node_.get();
  for (Node* use : graph()->start()->uses()) {
    if (use->opcode() == IrOpcode::kParameter &&
        ParameterIndexOf(use->op()) == wasm::kWasmInstanceDataParameterIndex) {
      wasm_instance_node_.set(use);
      return use;
    }
  }
  UNREACHABLE();  // The instance node must have been created before.
}
#endif  // V8_ENABLE_WEBASSEMBLY

#define __ gasm()->

Node* MemoryLowering::AlignToAllocationAlignment(Node* value) {
  if (!V8_COMPRESS_POINTERS_8GB_BOOL) return value;

  auto already_aligned = __ MakeLabel(MachineRepresentation::kWord64);
  Node* alignment_check = __ WordEqual(
      __ WordAnd(value, __ UintPtrConstant(kObjectAlignment8GbHeapMask)),
      __ UintPtrConstant(0));

  __ GotoIf(alignment_check, &already_aligned, value);
  {
    Node* aligned_value;
    if (kObjectAlignment8GbHeap == 2 * kTaggedSize) {
      aligned_value = __ IntPtrAdd(value, __ IntPtrConstant(kTaggedSize));
    } else {
      aligned_value = __ WordAnd(
          __ IntPtrAdd(value, __ IntPtrConstant(kObjectAlignment8GbHeapMask)),
          __ UintPtrConstant(~kObjectAlignment8GbHeapMask));
    }
    __ Goto(&already_aligned, aligned_value);
  }

  __ Bind(&already_aligned);

  return already_aligned.PhiAt(0);
}

Reduction MemoryLowering::ReduceAllocateRaw(Node* node,
                                            AllocationType allocation_type,
                                            AllocationState const** state_ptr) {
  DCHECK_EQ(IrOpcode::kAllocateRaw, node->opcode());
  DCHECK_IMPLIES(allocation_folding_ == AllocationFolding::kDoAllocationFolding,
                 state_ptr != nullptr);
  if (v8_flags.single_generation && allocation_type == AllocationType::kYoung) {
    allocation_type = AllocationType::kOld;
  }
  // InstructionStream objects may have a maximum size smaller than
  // kMaxHeapObjectSize due to guard pages. If we need to support allocating
  // code here we would need to call
  // MemoryChunkLayout::MaxRegularCodeObjectSize() at runtime.
  DCHECK_NE(allocation_type, AllocationType::kCode);
  Node* value;
  Node* size = node->InputAt(0);
  Node* effect = node->InputAt(1);
  Node* control = node->InputAt(2);

  gasm()->InitializeEffectControl(effect, control);

  Node* allocate_builtin;
  if (!is_wasm_) {
    if (allocation_type == AllocationType::kYoung) {
      allocate_builtin = __ AllocateInYoungGenerationStubConstant();
    } else {
      allocate_builtin = __ AllocateInOldGenerationStubConstant();
    }
  } else {
#if V8_ENABLE_WEBASSEMBLY
    // This lowering is used by Wasm, where we compile isolate-independent
    // code. Builtin calls simply encode the target builtin ID, which will
    // be patched to the builtin's address later.
    if (isolate_ == nullptr) {
      Builtin builtin;
      if (allocation_type == AllocationType::kYoung) {
        builtin = Builtin::kWasmAllocateInYoungGeneration;
      } else {
        builtin = Builtin::kWasmAllocateInOldGeneration;
      }
      static_assert(std::is_same<Smi, BuiltinPtr>(), "BuiltinPtr must be Smi");
      allocate_builtin =
          graph()->NewNode(common()->NumberConstant(static_cast<int>(builtin)));
    } else {
      if (allocation_type == AllocationType::kYoung) {
        allocate_builtin = __ WasmAllocateInYoungGenerationStubConstant();
      } else {
        allocate_builtin = __ WasmAllocateInOldGenerationStubConstant();
      }
    }
#else
    UNREACHABLE();
#endif
  }

  // Determine the top/limit addresses.
  Node* top_address;
  Node* limit_address;
  if (isolate_ != nullptr) {
    top_address = __ ExternalConstant(
        allocation_type == AllocationType::kYoung
            ? ExternalReference::new_space_allocation_top_address(isolate())
            : ExternalReference::old_space_allocation_top_address(isolate()));
    limit_address = __ ExternalConstant(
        allocation_type == AllocationType::kYoung
            ? ExternalReference::new_space_allocation_limit_address(isolate())
            : ExternalReference::old_space_allocation_limit_address(isolate()));
  } else {
    // Wasm mode: producing isolate-independent code, loading the isolate
    // address at runtime.
#if V8_ENABLE_WEBASSEMBLY
    Node* instance_node = GetWasmInstanceNode();
    int top_address_offset =
        allocation_type == AllocationType::kYoung
            ? WasmTrustedInstanceData::kNewAllocationTopAddressOffset
            : WasmTrustedInstanceData::kOldAllocationTopAddressOffset;
    int limit_address_offset =
        allocation_type == AllocationType::kYoung
            ? WasmTrustedInstanceData::kNewAllocationLimitAddressOffset
            : WasmTrustedInstanceData::kOldAllocationLimitAddressOffset;
    top_address =
        __ Load(MachineType::Pointer(), instance_node,
                __ IntPtrConstant(top_address_offset - kHeapObjectTag));
    limit_address =
        __ Load(MachineType::Pointer(), instance_node,
                __ IntPtrConstant(limit_address_offset - kHeapObjectTag));
#else
    UNREACHABLE();
#endif  // V8_ENABLE_WEBASSEMBLY
  }

  // Check if we can fold this allocation into a previous allocation represented
  // by the incoming {state}.
  IntPtrMatcher m(size);
  if (m.IsInRange(0, kMaxRegularHeapObjectSize) && v8_flags.inline_new &&
      allocation_folding_ == AllocationFolding::kDoAllocationFolding) {
    intptr_t const object_size =
        ALIGN_TO_ALLOCATION_ALIGNMENT(m.ResolvedValue());
    AllocationState const* state = *state_ptr;
    if (state->size() <= kMaxRegularHeapObjectSize - object_size &&
        state->group()->allocation() == allocation_type) {
      // We can fold this Allocate {node} into the allocation {group}
      // represented by the given {state}. Compute the upper bound for
      // the new {state}.
      intptr_t const state_size = state->size() + object_size;

      // Update the reservation check to the actual maximum upper bound.
      AllocationGroup* const group = state->group();
      if (machine()->Is64()) {
        if (OpParameter<int64_t>(group->size()->op()) < state_size) {
          NodeProperties::ChangeOp(group->size(),
                                   common()->Int64Constant(state_size));
        }
      } else {
        if (OpParameter<int32_t>(group->size()->op()) < state_size) {
          NodeProperties::ChangeOp(
              group->size(),
              common()->Int32Constant(static_cast<int32_t>(state_size)));
        }
      }

      // Update the allocation top with the new object allocation.
      // TODO(bmeurer): Defer writing back top as much as possible.
      DCHECK_IMPLIES(V8_COMPRESS_POINTERS_8GB_BOOL,
                     IsAligned(object_size, kObjectAlignment8GbHeap));
      Node* top = __ IntAdd(state->top(), __ IntPtrConstant(object_size));
      __ Store(StoreRepresentation(MachineType::PointerRepresentation(),
                                   kNoWriteBarrier),
               top_address, __ IntPtrConstant(0), top);

      // Compute the effective inner allocated address.
      value = __ BitcastWordToTagged(
          __ IntAdd(state->top(), __ IntPtrConstant(kHeapObjectTag)));
      effect = gasm()->effect();
      control = gasm()->control();

      // Extend the allocation {group}.
      group->Add(value);
      *state_ptr =
          AllocationState::Open(group, state_size, top, effect, zone());
    } else {
      auto call_runtime = __ MakeDeferredLabel();
      auto done = __ MakeLabel(MachineType::PointerRepresentation());

      // Setup a mutable reservation size node; will be patched as we fold
      // additional allocations into this new group.
      Node* reservation_size = __ UniqueIntPtrConstant(object_size);

      // Load allocation top and limit.
      Node* top =
          __ Load(MachineType::Pointer(), top_address, __ IntPtrConstant(0));
      Node* limit =
          __ Load(MachineType::Pointer(), limit_address, __ IntPtrConstant(0));

      // Check if we need to collect garbage before we can start bump pointer
      // allocation (always done for folded allocations).
      Node* check = __ UintLessThan(__ IntAdd(top, reservation_size), limit);

      __ GotoIfNot(check, &call_runtime);
      __ Goto(&done, top);

      __ Bind(&call_runtime);
      {
        EnsureAllocateOperator();
        Node* vfalse = __ BitcastTaggedToWord(__ Call(
            allocate_operator_.get(), allocate_builtin, reservation_size));
        vfalse = __ IntSub(vfalse, __ IntPtrConstant(kHeapObjectTag));
        __ Goto(&done, vfalse);
      }

      __ Bind(&done);

      // Compute the new top and write it back.
      top = __ IntAdd(done.PhiAt(0), __ IntPtrConstant(object_size));
      __ Store(StoreRepresentation(MachineType::PointerRepresentation(),
                                   kNoWriteBarrier),
               top_address, __ IntPtrConstant(0), top);

      // Compute the initial object address.
      value = __ BitcastWordToTagged(
          __ IntAdd(done.PhiAt(0), __ IntPtrConstant(kHeapObjectTag)));
      effect = gasm()->effect();
      control = gasm()->control();

      // Start a new allocation group.
      AllocationGroup* group = zone()->New<AllocationGroup>(
          value, allocation_type, reservation_size, zone());
      *state_ptr =
          AllocationState::Open(group, object_size, top, effect, zone());
    }
  } else {
    auto call_runtime = __ MakeDeferredLabel();
    auto done = __ MakeLabel(MachineRepresentation::kTaggedPointer);

    // Load allocation top and limit.
    Node* top =
        __ Load(MachineType::Pointer(), top_address, __ IntPtrConstant(0));
    Node* limit =
        __ Load(MachineType::Pointer(), limit_address, __ IntPtrConstant(0));

    // Compute the new top.
    Node* new_top = __ IntAdd(top, AlignToAllocationAlignment(size));

    // Check if we can do bump pointer allocation here.
    Node* check = __ UintLessThan(new_top, limit);
    __ GotoIfNot(check, &call_runtime);
    __ GotoIfNot(
        __ UintLessThan(size, __ IntPtrConstant(kMaxRegularHeapObjectSize)),
        &call_runtime);
    __ Store(StoreRepresentation(MachineType::PointerRepresentation(),
                                 kNoWriteBarrier),
             top_address, __ IntPtrConstant(0), new_top);
    __ Goto(&done, __ BitcastWordToTagged(
                       __ IntAdd(top, __ IntPtrConstant(kHeapObjectTag))));

    __ Bind(&call_runtime);
    EnsureAllocateOperator();
    __ Goto(&done, __ Call(allocate_operator_.get(), allocate_builtin, size));

    __ Bind(&done);
    value = done.PhiAt(0);
    effect = gasm()->effect();
    control = gasm()->control();

    if (state_ptr) {
      // Create an unfoldable allocation group.
      AllocationGroup* group =
          zone()->New<AllocationGroup>(value, allocation_type, zone());
      *state_ptr = AllocationState::Closed(group, effect, zone());
    }
  }

  return Replace(value);
}

Reduction MemoryLowering::ReduceLoadFromObject(Node* node) {
  DCHECK(node->opcode() == IrOpcode::kLoadFromObject ||
         node->opcode() == IrOpcode::kLoadImmutableFromObject);
  ObjectAccess const& access = ObjectAccessOf(node->op());

  MachineType machine_type = access.machine_type;

  if (machine_type.IsMapWord()) {
    CHECK_EQ(machine_type.semantic(), MachineSemantic::kAny);
    return ReduceLoadMap(node);
  }

  MachineRepresentation rep = machine_type.representation();
  const Operator* load_op =
      ElementSizeInBytes(rep) > kTaggedSize &&
              !machine()->UnalignedLoadSupported(machine_type.representation())
          ? machine()->UnalignedLoad(machine_type)
          : machine()->Load(machine_type);
  NodeProperties::ChangeOp(node, load_op);
  return Changed(node);
}

Reduction MemoryLowering::ReduceLoadElement(Node* node) {
  DCHECK_EQ(IrOpcode::kLoadElement, node->opcode());
  ElementAccess const& access = ElementAccessOf(node->op());
  Node* index = node->InputAt(1);
  node->ReplaceInput(1, ComputeIndex(access, index));
  MachineType type = access.machine_type;
  DCHECK(!type.IsMapWord());
  NodeProperties::ChangeOp(node, machine()->Load(type));
  return Changed(node);
}

Reduction MemoryLowering::ReduceLoadExternalPointerField(Node* node) {
  DCHECK_EQ(node->opcode(), IrOpcode::kLoadField);
  FieldAccess const& access = FieldAccessOf(node->op());

#ifdef V8_ENABLE_SANDBOX
  ExternalPointerTag tag = access.external_pointer_tag;
  DCHECK_NE(tag, kExternalPointerNullTag);
  // Fields for sandboxed external pointer contain a 32-bit handle, not a
  // 64-bit raw pointer.
  NodeProperties::ChangeOp(node, machine()->Load(MachineType::Uint32()));

  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);
  __ InitializeEffectControl(effect, control);

  // Clone the load node and put it here.
  // TODO(turbofan): consider adding GraphAssembler::Clone() suitable for
  // cloning nodes from arbitrary locations in effect/control chains.
  static_assert(kExternalPointerIndexShift > kSystemPointerSizeLog2);
  Node* handle = __ AddNode(graph()->CloneNode(node));
  Node* shift_amount =
      __ Int32Constant(kExternalPointerIndexShift - kSystemPointerSizeLog2);
  Node* offset = __ Word32Shr(handle, shift_amount);

  // Uncomment this to generate a breakpoint for debugging purposes.
  // __ DebugBreak();

  // Decode loaded external pointer.
  //
  // Here we access the external pointer table through an ExternalReference.
  // Alternatively, we could also hardcode the address of the table since it
  // is never reallocated. However, in that case we must be able to guarantee
  // that the generated code is never executed under a different Isolate, as
  // that would allow access to external objects from different Isolates. It
  // also would break if the code is serialized/deserialized at some point.
  Node* table_address =
      IsSharedExternalPointerType(tag)
          ? __
            Load(MachineType::Pointer(),
                 __ ExternalConstant(
                     ExternalReference::
                         shared_external_pointer_table_address_address(
                             isolate())),
                 __ IntPtrConstant(0))
          : __ ExternalConstant(
                ExternalReference::external_pointer_table_address(isolate()));
  Node* table = __ Load(MachineType::Pointer(), table_address,
                        Internals::kExternalPointerTableBasePointerOffset);
  Node* pointer =
      __ Load(MachineType::Pointer(), table, __ ChangeUint32ToUint64(offset));
  pointer = __ WordAnd(pointer, __ IntPtrConstant(~tag));
  return Replace(pointer);
#else
  NodeProperties::ChangeOp(node, machine()->Load(access.machine_type));
  return Changed(node);
#endif  // V8_ENABLE_SANDBOX
}

Reduction MemoryLowering::ReduceLoadBoundedSize(Node* node) {
#ifdef V8_ENABLE_SANDBOX
  const Operator* load_op =
      !machine()->UnalignedLoadSupported(MachineRepresentation::kWord64)
          ? machine()->UnalignedLoad(MachineType::Uint64())
          : machine()->Load(MachineType::Uint64());
  NodeProperties::ChangeOp(node, load_op);

  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);
  __ InitializeEffectControl(effect, control);

  Node* raw_value = __ AddNode(graph()->CloneNode(node));
  Node* shift_amount = __ IntPtrConstant(kBoundedSizeShift);
  Node* decoded_size = __ Word64Shr(raw_value, shift_amount);
  return Replace(decoded_size);
#else
  UNREACHABLE();
#endif
}

Reduction MemoryLowering::ReduceLoadMap(Node* node) {
#ifdef V8_MAP_PACKING
  NodeProperties::ChangeOp(node, machine()->Load(MachineType::AnyTagged()));

  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);
  __ InitializeEffectControl(effect, control);

  node = __ AddNode(graph()->CloneNode(node));
  return Replace(__ UnpackMapWord(node));
#else
  NodeProperties::ChangeOp(node, machine()->Load(MachineType::TaggedPointer()));
  return Changed(node);
#endif
}

Reduction MemoryLowering::ReduceLoadField(Node* node) {
  DCHECK_EQ(IrOpcode::kLoadField, node->opcode());
  FieldAccess const& access = FieldAccessOf(node->op());
  Node* offset = __ IntPtrConstant(access.offset - access.tag());
  node->InsertInput(graph_zone(), 1, offset);
  MachineType type = access.machine_type;

  if (type.IsMapWord()) {
    DCHECK(!access.type.Is(Type::ExternalPointer()));
    return ReduceLoadMap(node);
  }

  if (access.type.Is(Type::ExternalPointer())) {
    return ReduceLoadExternalPointerField(node);
  }

  if (access.is_bounded_size_access) {
    return ReduceLoadBoundedSize(node);
  }

  NodeProperties::ChangeOp(node, machine()->Load(type));

  return Changed(node);
}

Reduction MemoryLowering::ReduceStoreToObject(Node* node,
                                              AllocationState const* state) {
  DCHECK(node->opcode() == IrOpcode::kStoreToObject ||
         node->opcode() == IrOpcode::kInitializeImmutableInObject);
  ObjectAccess const& access = ObjectAccessOf(node->op());
  Node* object = node->InputAt(0);
  Node* value = node->InputAt(2);

  WriteBarrierKind write_barrier_kind = ComputeWriteBarrierKind(
      node, object, value, state, access.write_barrier_kind);
  DCHECK(!access.machine_type.IsMapWord());
  MachineRepresentation rep = access.machine_type.representation();
  StoreRepresentation store_rep(rep, write_barrier_kind);
  const Operator* store_op = ElementSizeInBytes(rep) > kTaggedSize &&
                                     !machine()->UnalignedStoreSupported(rep)
                                 ? machine()->UnalignedStore(rep)
                                 : machine()->Store(store_rep);
  NodeProperties::ChangeOp(node, store_op);
  return Changed(node);
}

Reduction MemoryLowering::ReduceStoreElement(Node* node,
                                             AllocationState const* state) {
  DCHECK_EQ(IrOpcode::kStoreElement, node->opcode());
  ElementAccess const& access = ElementAccessOf(node->op());
  Node* object = node->InputAt(0);
  Node* index = node->InputAt(1);
  Node* value = node->InputAt(2);
  node->ReplaceInput(1, ComputeIndex(access, index));
  WriteBarrierKind write_barrier_kind = ComputeWriteBarrierKind(
      node, object, value, state, access.write_barrier_kind);
  NodeProperties::ChangeOp(
      node, machine()->Store(StoreRepresentation(
                access.machine_type.representation(), write_barrier_kind)));
  return Changed(node);
}

Reduction MemoryLowering::ReduceStoreField(Node* node,
                                           AllocationState const* state) {
  DCHECK_EQ(IrOpcode::kStoreField, node->opcode());
  FieldAccess const& access = FieldAccessOf(node->op());
  // External pointer must never be stored by optimized code when sandbox is
  // turned on
  DCHECK(!access.type.Is(Type::ExternalPointer()) || !V8_ENABLE_SANDBOX_BOOL);
  // SandboxedPointers are not currently stored by optimized code.
  DCHECK(!access.type.Is(Type::SandboxedPointer()));
  // Bounded size fields are not currently stored by optimized code.
  DCHECK(!access.is_bounded_size_access);
  MachineType machine_type = access.machine_type;
  Node* object = node->InputAt(0);
  Node* value = node->InputAt(1);

  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);
  __ InitializeEffectControl(effect, control);

  WriteBarrierKind write_barrier_kind = ComputeWriteBarrierKind(
      node, object, value, state, access.write_barrier_kind);
  Node* offset = __ IntPtrConstant(access.offset - access.tag());
  node->InsertInput(graph_zone(), 1, offset);

  if (machine_type.IsMapWord()) {
    machine_type = MachineType::TaggedPointer();
#ifdef V8_MAP_PACKING
    Node* mapword = __ PackMapWord(TNode<Map>::UncheckedCast(value));
    node->ReplaceInput(2, mapword);
#endif
  }
  if (machine_type.representation() ==
      MachineRepresentation::kIndirectPointer) {
    // Indirect pointer stores require knowledge of the indirect pointer tag of
    // the field. This is technically only required for stores that need a
    // write barrier, but currently we track the tag for all such stores.
    DCHECK_NE(access.indirect_pointer_tag, kIndirectPointerNullTag);
    Node* tag = __ IntPtrConstant(access.indirect_pointer_tag);
    node->InsertInput(graph_zone(), 3, tag);
    NodeProperties::ChangeOp(
        node, machine()->StoreIndirectPointer(write_barrier_kind));
  } else {
    NodeProperties::ChangeOp(
        node, machine()->Store(StoreRepresentation(
                  machine_type.representation(), write_barrier_kind)));
  }
  return Changed(node);
}

Reduction MemoryLowering::ReduceStore(Node* node,
                                      AllocationState const* state) {
  DCHECK_EQ(IrOpcode::kStore, node->opcode());
  StoreRepresentation representation = StoreRepresentationOf(node->op());
  Node* object = node->InputAt(0);
  Node* value = node->InputAt(2);
  WriteBarrierKind write_barrier_kind = ComputeWriteBarrierKind(
      node, object, value, state, representation.write_barrier_kind());
  if (write_barrier_kind != representation.write_barrier_kind()) {
    NodeProperties::ChangeOp(
        node, machine()->Store(StoreRepresentation(
                  representation.representation(), write_barrier_kind)));
    return Changed(node);
  }
  return NoChange();
}

Node* MemoryLowering::ComputeIndex(ElementAccess const& access, Node* index) {
  int const element_size_shift =
      ElementSizeLog2Of(access.machine_type.representation());
  if (element_size_shift) {
    index = __ WordShl(index, __ IntPtrConstant(element_size_shift));
  }
  int const fixed_offset = access.header_size - access.tag();
  if (fixed_offset) {
    index = __ IntAdd(index, __ IntPtrConstant(fixed_offset));
  }
  return index;
}

#undef __

namespace {

bool ValueNeedsWriteBarrier(Node* value, Isolate* isolate) {
  switch (value->opcode()) {
    case IrOpcode::kBitcastWordToTaggedSigned:
      return false;
    case IrOpcode::kHeapConstant: {
      RootIndex root_index;
      if (isolate->roots_table().IsRootHandle(HeapConstantOf(value->op()),
                                              &root_index) &&
          RootsTable::IsImmortalImmovable(root_index)) {
        return false;
      }
      break;
    }
    default:
      break;
  }
  return true;
}

}  // namespace

Reduction MemoryLowering::ReduceAllocateRaw(Node* node) {
  DCHECK_EQ(IrOpcode::kAllocateRaw, node->opcode());
  const AllocateParameters& allocation = AllocateParametersOf(node->op());
  return ReduceAllocateRaw(node, allocation.allocation_type(), nullptr);
}

WriteBarrierKind MemoryLowering::ComputeWriteBarrierKind(
    Node* node, Node* object, Node* value, AllocationState const* state,
    WriteBarrierKind write_barrier_kind) {
  if (state && state->IsYoungGenerationAllocation() &&
      state->group()->Contains(object)) {
    write_barrier_kind = kNoWriteBarrier;
  }
  if (!ValueNeedsWriteBarrier(value, isolate())) {
    write_barrier_kind = kNoWriteBarrier;
  }
  if (v8_flags.disable_write_barriers) {
    write_barrier_kind = kNoWriteBarrier;
  }
  if (write_barrier_kind == WriteBarrierKind::kAssertNoWriteBarrier) {
    write_barrier_assert_failed_(node, object, function_debug_name_, zone());
  }
  return write_barrier_kind;
}

MemoryLowering::AllocationGroup::AllocationGroup(Node* node,
                                                 AllocationType allocation,
                                                 Zone* zone)
    : node_ids_(zone),
      allocation_(CheckAllocationType(allocation)),
      size_(nullptr) {
  node_ids_.insert(node->id());
}

MemoryLowering::AllocationGroup::AllocationGroup(Node* node,
                                                 AllocationType allocation,
                                                 Node* size, Zone* zone)
    : node_ids_(zone),
      allocation_(CheckAllocationType(allocation)),
      size_(size) {
  node_ids_.insert(node->id());
}

void MemoryLowering::AllocationGroup::Add(Node* node) {
  node_ids_.insert(node->id());
}

bool MemoryLowering::AllocationGroup::Contains(Node* node) const {
  // Additions should stay within the same allocated object, so it's safe to
  // ignore them.
  while (node_ids_.find(node->id()) == node_ids_.end()) {
    switch (node->opcode()) {
      case IrOpcode::kBitcastTaggedToWord:
      case IrOpcode::kBitcastWordToTagged:
      case IrOpcode::kInt32Add:
      case IrOpcode::kInt64Add:
        node = NodeProperties::GetValueInput(node, 0);
        break;
      default:
        return false;
    }
  }
  return true;
}

MemoryLowering::AllocationState::AllocationState()
    : group_(nullptr),
      size_(std::numeric_limits<int>::max()),
      top_(nullptr),
      effect_(nullptr) {}

MemoryLowering::AllocationState::AllocationState(AllocationGroup* group,
                                                 Node* effect)
    : group_(group),
      size_(std::numeric_limits<int>::max()),
      top_(nullptr),
      effect_(effect) {}

MemoryLowering::AllocationState::AllocationState(AllocationGroup* group,
                                                 intptr_t size, Node* top,
                                                 Node* effect)
    : group_(group), size_(size), top_(top), effect_(effect) {}

bool MemoryLowering::AllocationState::IsYoungGenerationAllocation() const {
  return group() && group()->IsYoungGenerationAllocation();
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8

"""

```