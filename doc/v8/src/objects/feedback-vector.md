Response: Let's break down the thought process for analyzing this C++ code and explaining its JavaScript relevance.

1. **Understand the Goal:** The primary goal is to understand the purpose of `feedback-vector.cc` within the V8 JavaScript engine and connect it to JavaScript concepts.

2. **Initial Scan and Keywords:** Quickly scan the code for recognizable terms. "Feedback," "Slot," "Metadata," "IC" (Inline Cache), "Optimized Code," "Megamorphic," "Monomorphic," "Polymorphic" stand out. These strongly suggest this file is related to performance optimization within V8.

3. **File Location - Context is Key:** The file path `v8/src/objects/feedback-vector.cc` is important. The `objects` directory indicates this code defines data structures and their related operations. `feedback-vector` suggests it manages information about how code is executing.

4. **Copyright and Includes:** Notice the copyright statement and `#include` directives. These tell us:
    * It's part of the V8 project.
    * It depends on other V8 components (`deoptimizer`, `heap`, `ic`, `objects`). This hints at its role within the larger engine.

5. **Core Data Structures: `FeedbackVectorSpec`, `FeedbackMetadata`, `FeedbackVector`:** Focus on the primary classes.
    * **`FeedbackVectorSpec`:**  Methods like `AddSlot` suggest it's a blueprint or specification for creating `FeedbackVector`s. It defines the *types* of feedback to be collected.
    * **`FeedbackMetadata`:**  Seems to hold *static* information about the feedback structure, like the kind of feedback stored in each slot. Methods like `GetKind` and `SetKind` confirm this.
    * **`FeedbackVector`:**  This appears to be the central data structure. It holds the *actual* feedback data collected during execution. Methods like `GetKind`, `Set`, and the presence of "OptimizedCode" related functions are crucial.

6. **Feedback Slots and Kinds:** Pay attention to `FeedbackSlot` and `FeedbackSlotKind`. The `enum` `FeedbackSlotKind` lists various types of operations (e.g., `Call`, `LoadProperty`, `BinaryOp`). This is a key insight: the feedback vector tracks performance-related data for different kinds of JavaScript operations.

7. **Inline Caches (ICs):** The presence of "IC" and terms like "Monomorphic," "Polymorphic," and "Megamorphic" strongly indicate a connection to inline caches. The code seems to be storing information about the types and shapes of objects involved in operations, which is the core of ICs.

8. **Optimization Connection:** The "OptimizedCode" related functions (`SetOptimizedCode`, `ClearOptimizedCode`) directly link the feedback vector to V8's optimization pipeline (Turbofan, Maglev). The feedback is used to guide optimization decisions.

9. **JavaScript Examples - The "Aha!" Moment:**  Now, connect the C++ concepts to concrete JavaScript. For each `FeedbackSlotKind` or optimization concept, think of a simple JavaScript snippet that would trigger that kind of feedback.

    * **`Call`:**  A function call is the obvious example.
    * **`LoadProperty`:** Accessing a property of an object.
    * **`BinaryOp`:** Performing arithmetic or logical operations.
    * **Monomorphic/Polymorphic/Megamorphic:** Consider how the shape of objects affects optimization. Accessing the same property on objects of the same shape is monomorphic; different shapes lead to polymorphism and eventually megamorphism.

10. **Structure of the Explanation:** Organize the findings logically:
    * Start with a concise summary of the file's purpose.
    * Explain the key data structures and their roles.
    * Detail how feedback slots and kinds work.
    * Explain the connection to inline caches and optimization.
    * Provide clear JavaScript examples that illustrate the concepts.
    * Conclude with the overall significance.

11. **Refinement and Clarity:**  Review the explanation for clarity and accuracy. Ensure the JavaScript examples are simple and directly demonstrate the related C++ functionality. Use clear and concise language.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "Maybe this is just about error handling?"  *Correction:* The prevalence of performance-related terms and the "IC" connection quickly refutes this.
* **Stuck on a specific function:** If a particular function is unclear (e.g., `NexusConfig`),  look at where it's used. In this case, it's used within `FeedbackNexus`, suggesting it's related to accessing and modifying feedback data, possibly with considerations for multi-threading.
* **JavaScript examples too complex:** Start with very basic examples and gradually add complexity if needed. The goal is to illustrate the concept clearly, not to write a full-fledged application.

By following this process of scanning, identifying key elements, connecting them to broader concepts, and then illustrating with concrete examples, we can effectively understand and explain the functionality of complex C++ code like `feedback-vector.cc` in the context of JavaScript.
这个C++源代码文件 `feedback-vector.cc` 属于 V8 JavaScript 引擎，它的主要功能是**管理 JavaScript 函数的性能反馈信息，用于优化代码执行**。

更具体地说，它定义了以下关键概念和功能：

1. **`FeedbackVector`**: 这是存储运行时反馈信息的核心数据结构。每个被执行的 JavaScript 函数都会关联一个 `FeedbackVector`。

2. **`FeedbackSlot`**: `FeedbackVector` 内部包含多个 `FeedbackSlot`，每个槽位用于存储特定类型的反馈信息。例如，可能有一个槽位记录函数被调用的次数，另一个槽位记录某个属性访问操作中遇到的对象类型。

3. **`FeedbackSlotKind`**: 这是一个枚举类型，定义了各种可以存储在 `FeedbackSlot` 中的反馈信息的类型。例如：
    * `kCall`: 用于记录函数调用的信息。
    * `kLoadProperty`: 用于记录属性加载操作的信息。
    * `kStoreProperty`: 用于记录属性存储操作的信息。
    * `kBinaryOp`: 用于记录二元运算的信息。
    * 等等。

4. **`FeedbackMetadata`**:  与 `FeedbackVector` 关联的元数据，描述了 `FeedbackVector` 的结构，包括每个槽位存储的 `FeedbackSlotKind`。

5. **内联缓存 (Inline Caches, ICs)**:  `FeedbackVector` 中存储的信息被 V8 的内联缓存机制利用。ICs 是一种优化技术，它会记住之前执行过的操作中遇到的对象类型和属性，以便在后续执行中更快地执行相同的操作。`FeedbackVector` 记录了这些观察到的类型和属性。

6. **代码优化**:  收集到的反馈信息会影响 V8 的代码优化决策。例如，如果某个属性访问操作总是访问相同类型的对象，V8 可以进行更积极的优化，生成更高效的机器码。如果观察到不同的对象类型，V8 可能会生成更通用的代码或者执行去优化。

**与 JavaScript 的关系及示例：**

`feedback-vector.cc` 直接影响 JavaScript 代码的执行性能。它通过收集运行时信息来指导 V8 的优化器，使得经常执行的代码能够更快地运行。

以下是一些 JavaScript 示例，说明了 `FeedbackVector` 如何记录和影响执行：

**示例 1: 函数调用**

```javascript
function add(a, b) {
  return a + b;
}

add(1, 2); // 第一次调用
add(3, 4); // 第二次调用
```

当 `add` 函数第一次被调用时，V8 会创建一个 `FeedbackVector` 并分配一个 `FeedbackSlot` 用于记录 `Call` 相关的反馈。 每次调用 `add`，`FeedbackVector` 可能会记录以下信息：

* 函数被调用的次数（递增）。
* 传递给函数的参数类型 (例如，都是数字)。

这些信息可以帮助 V8 的优化器判断 `add` 函数是否值得优化，以及可以进行哪些优化（例如，假设参数总是数字）。

**示例 2: 属性访问**

```javascript
const obj1 = { x: 1 };
const obj2 = { x: 2 };

function getX(obj) {
  return obj.x;
}

getX(obj1); // 第一次调用，访问 obj1.x
getX(obj2); // 第二次调用，访问 obj2.x
```

当 `getX` 函数执行时，涉及到属性访问 `obj.x`。 `FeedbackVector` 会分配一个 `FeedbackSlot` 用于 `LoadProperty` 操作。  V8 可能会记录：

* 第一次调用时，`obj` 的类型是 `obj1` 的类型。
* 第二次调用时，`obj` 的类型是 `obj2` 的类型。

如果多次调用 `getX` 都传入相同结构的对象（例如，都只包含一个名为 `x` 的属性），V8 可以将属性访问内联化，直接访问对象内存，而无需进行昂贵的查找操作。如果传入不同结构的对象，V8 可能会采取更保守的策略。

**示例 3: 二元运算**

```javascript
function multiply(a, b) {
  return a * b;
}

multiply(5, 10);   // 第一次调用
multiply("2", "3"); // 第二次调用
```

对于二元运算 `a * b`，`FeedbackVector` 会分配一个 `FeedbackSlot` 用于 `BinaryOp`。 V8 可能会记录：

* 第一次调用时，操作数 `a` 和 `b` 都是数字。
* 第二次调用时，操作数 `a` 和 `b` 都是字符串。

基于这些反馈，V8 的优化器可以为数字乘法生成快速路径，为字符串乘法（会涉及类型转换）生成不同的路径。如果操作数的类型不稳定，V8 可能会生成更通用的代码或者推迟优化。

**总结：**

`feedback-vector.cc` 中定义的机制是 V8 引擎实现高性能 JavaScript 执行的关键组成部分。它通过在运行时收集关于代码执行情况的反馈信息，为内联缓存和代码优化提供了重要的依据，使得 V8 能够根据实际运行情况动态地优化 JavaScript 代码。 JavaScript 开发者通常不需要直接与这些 C++ 结构交互，但他们编写的代码的性能会受到 `FeedbackVector` 及其相关优化的显著影响。

### 提示词
```
这是目录为v8/src/objects/feedback-vector.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/objects/feedback-vector.h"

#include <bit>
#include <optional>

#include "src/common/globals.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/diagnostics/code-tracer.h"
#include "src/heap/heap-inl.h"
#include "src/heap/local-factory-inl.h"
#include "src/ic/handler-configuration-inl.h"
#include "src/ic/ic-inl.h"
#include "src/objects/data-handler-inl.h"
#include "src/objects/feedback-vector-inl.h"
#include "src/objects/hash-table-inl.h"
#include "src/objects/map-inl.h"
#include "src/objects/objects.h"

namespace v8::internal {

FeedbackSlot FeedbackVectorSpec::AddSlot(FeedbackSlotKind kind) {
  int slot = slot_count();
  int entries_per_slot = FeedbackMetadata::GetSlotSize(kind);
  append(kind);
  for (int i = 1; i < entries_per_slot; i++) {
    append(FeedbackSlotKind::kInvalid);
  }
  return FeedbackSlot(slot);
}

static bool IsPropertyNameFeedback(Tagged<MaybeObject> feedback) {
  Tagged<HeapObject> heap_object;
  if (!feedback.GetHeapObjectIfStrong(&heap_object)) return false;
  if (IsString(heap_object)) {
    DCHECK(IsInternalizedString(heap_object));
    return true;
  }
  if (!IsSymbol(heap_object)) return false;
  Tagged<Symbol> symbol = Cast<Symbol>(heap_object);
  ReadOnlyRoots roots = symbol->GetReadOnlyRoots();
  return symbol != roots.uninitialized_symbol() &&
         symbol != roots.mega_dom_symbol() &&
         symbol != roots.megamorphic_symbol();
}

std::ostream& operator<<(std::ostream& os, FeedbackSlotKind kind) {
  return os << FeedbackMetadata::Kind2String(kind);
}

FeedbackSlotKind FeedbackMetadata::GetKind(FeedbackSlot slot) const {
  int index = VectorICComputer::index(0, slot.ToInt());
  int data = get(index);
  return VectorICComputer::decode(data, slot.ToInt());
}

void FeedbackMetadata::SetKind(FeedbackSlot slot, FeedbackSlotKind kind) {
  int index = VectorICComputer::index(0, slot.ToInt());
  int data = get(index);
  int new_data = VectorICComputer::encode(data, slot.ToInt(), kind);
  set(index, new_data);
}

uint16_t FeedbackMetadata::GetCreateClosureParameterCount(int index) const {
  DCHECK_LT(index, create_closure_slot_count());
  int offset = kHeaderSize + word_count() * kInt32Size + index * kUInt16Size;
  return ReadField<uint16_t>(offset);
}

void FeedbackMetadata::SetCreateClosureParameterCount(
    int index, uint16_t parameter_count) {
  DCHECK_LT(index, create_closure_slot_count());
  int offset = kHeaderSize + word_count() * kInt32Size + index * kUInt16Size;
  return WriteField<uint16_t>(offset, parameter_count);
}

// static
template <typename IsolateT>
Handle<FeedbackMetadata> FeedbackMetadata::New(IsolateT* isolate,
                                               const FeedbackVectorSpec* spec) {
  auto* factory = isolate->factory();

  const int slot_count = spec->slot_count();
  const int create_closure_slot_count = spec->create_closure_slot_count();
  if (slot_count == 0 && create_closure_slot_count == 0) {
    return factory->empty_feedback_metadata();
  }
#ifdef DEBUG
  for (int i = 0; i < slot_count;) {
    FeedbackSlotKind kind = spec->GetKind(FeedbackSlot(i));
    int entry_size = FeedbackMetadata::GetSlotSize(kind);
    for (int j = 1; j < entry_size; j++) {
      kind = spec->GetKind(FeedbackSlot(i + j));
      DCHECK_EQ(FeedbackSlotKind::kInvalid, kind);
    }
    i += entry_size;
  }
#endif

  Handle<FeedbackMetadata> metadata =
      factory->NewFeedbackMetadata(slot_count, create_closure_slot_count);

  // Initialize the slots. The raw data section has already been pre-zeroed in
  // NewFeedbackMetadata.
  for (int i = 0; i < slot_count; i++) {
    FeedbackSlot slot(i);
    FeedbackSlotKind kind = spec->GetKind(slot);
    metadata->SetKind(slot, kind);
  }

  for (int i = 0; i < create_closure_slot_count; i++) {
    uint16_t parameter_count = spec->GetCreateClosureParameterCount(i);
    metadata->SetCreateClosureParameterCount(i, parameter_count);
  }

  return metadata;
}

template Handle<FeedbackMetadata> FeedbackMetadata::New(
    Isolate* isolate, const FeedbackVectorSpec* spec);
template Handle<FeedbackMetadata> FeedbackMetadata::New(
    LocalIsolate* isolate, const FeedbackVectorSpec* spec);

bool FeedbackMetadata::SpecDiffersFrom(
    const FeedbackVectorSpec* other_spec) const {
  if (other_spec->slot_count() != slot_count()) {
    return true;
  }

  int slots = slot_count();
  for (int i = 0; i < slots;) {
    FeedbackSlot slot(i);
    FeedbackSlotKind kind = GetKind(slot);
    int entry_size = FeedbackMetadata::GetSlotSize(kind);

    if (kind != other_spec->GetKind(slot)) {
      return true;
    }
    i += entry_size;
  }
  return false;
}

const char* FeedbackMetadata::Kind2String(FeedbackSlotKind kind) {
  switch (kind) {
    case FeedbackSlotKind::kInvalid:
      return "Invalid";
    case FeedbackSlotKind::kCall:
      return "Call";
    case FeedbackSlotKind::kLoadProperty:
      return "LoadProperty";
    case FeedbackSlotKind::kLoadGlobalInsideTypeof:
      return "LoadGlobalInsideTypeof";
    case FeedbackSlotKind::kLoadGlobalNotInsideTypeof:
      return "LoadGlobalNotInsideTypeof";
    case FeedbackSlotKind::kLoadKeyed:
      return "LoadKeyed";
    case FeedbackSlotKind::kHasKeyed:
      return "HasKeyed";
    case FeedbackSlotKind::kSetNamedSloppy:
      return "SetNamedSloppy";
    case FeedbackSlotKind::kSetNamedStrict:
      return "SetNamedStrict";
    case FeedbackSlotKind::kDefineNamedOwn:
      return "DefineNamedOwn";
    case FeedbackSlotKind::kDefineKeyedOwn:
      return "DefineKeyedOwn";
    case FeedbackSlotKind::kStoreGlobalSloppy:
      return "StoreGlobalSloppy";
    case FeedbackSlotKind::kStoreGlobalStrict:
      return "StoreGlobalStrict";
    case FeedbackSlotKind::kSetKeyedSloppy:
      return "StoreKeyedSloppy";
    case FeedbackSlotKind::kSetKeyedStrict:
      return "StoreKeyedStrict";
    case FeedbackSlotKind::kStoreInArrayLiteral:
      return "StoreInArrayLiteral";
    case FeedbackSlotKind::kBinaryOp:
      return "BinaryOp";
    case FeedbackSlotKind::kCompareOp:
      return "CompareOp";
    case FeedbackSlotKind::kDefineKeyedOwnPropertyInLiteral:
      return "DefineKeyedOwnPropertyInLiteral";
    case FeedbackSlotKind::kLiteral:
      return "Literal";
    case FeedbackSlotKind::kForIn:
      return "ForIn";
    case FeedbackSlotKind::kInstanceOf:
      return "InstanceOf";
    case FeedbackSlotKind::kTypeOf:
      return "TypeOf";
    case FeedbackSlotKind::kCloneObject:
      return "CloneObject";
    case FeedbackSlotKind::kJumpLoop:
      return "JumpLoop";
  }
}

FeedbackSlotKind FeedbackVector::GetKind(FeedbackSlot slot) const {
  DCHECK(!is_empty());
  return metadata()->GetKind(slot);
}

FeedbackSlotKind FeedbackVector::GetKind(FeedbackSlot slot,
                                         AcquireLoadTag tag) const {
  DCHECK(!is_empty());
  return metadata(tag)->GetKind(slot);
}

// static
Handle<ClosureFeedbackCellArray> ClosureFeedbackCellArray::New(
    Isolate* isolate, DirectHandle<SharedFunctionInfo> shared,
    AllocationType allocation) {
  int length = shared->feedback_metadata()->create_closure_slot_count();
  if (length == 0) {
    return isolate->factory()->empty_closure_feedback_cell_array();
  }

  // Pre-allocate the cells s.t. we can initialize `result` without further
  // allocation.
  DirectHandleVector<FeedbackCell> cells(isolate);
  cells.reserve(length);
  for (int i = 0; i < length; i++) {
    Handle<FeedbackCell> cell = isolate->factory()->NewNoClosuresCell();
#ifdef V8_ENABLE_LEAPTIERING
    uint16_t parameter_count =
        shared->feedback_metadata()->GetCreateClosureParameterCount(i);
    Tagged<Code> initial_code = *BUILTIN_CODE(isolate, CompileLazy);
    cell->allocate_dispatch_handle(isolate, parameter_count, initial_code);
#endif
    cells.push_back(cell);
  }

  std::optional<DisallowGarbageCollection> no_gc;
  auto result = Allocate(isolate, length, &no_gc, allocation);
  for (int i = 0; i < length; i++) {
    result->set(i, *cells[i]);
  }

  return result;
}

// static
Handle<FeedbackVector> FeedbackVector::New(
    Isolate* isolate, DirectHandle<SharedFunctionInfo> shared,
    DirectHandle<ClosureFeedbackCellArray> closure_feedback_cell_array,
    DirectHandle<FeedbackCell> parent_feedback_cell,
    IsCompiledScope* is_compiled_scope) {
  DCHECK(is_compiled_scope->is_compiled());
  Factory* factory = isolate->factory();

  DirectHandle<FeedbackMetadata> feedback_metadata(shared->feedback_metadata(),
                                                   isolate);
  const int slot_count = feedback_metadata->slot_count();

  Handle<FeedbackVector> vector = factory->NewFeedbackVector(
      shared, closure_feedback_cell_array, parent_feedback_cell);

  DCHECK_EQ(vector->length(), slot_count);

  DCHECK_EQ(vector->shared_function_info(), *shared);
  DCHECK_EQ(vector->invocation_count(), 0);
#ifndef V8_ENABLE_LEAPTIERING
  DCHECK_EQ(vector->tiering_state(), TieringState::kNone);
  DCHECK(!vector->maybe_has_maglev_code());
  DCHECK(!vector->maybe_has_turbofan_code());
  DCHECK(vector->maybe_optimized_code().IsCleared());
#endif  // !V8_ENABLE_LEAPTIERING

  // Ensure we can skip the write barrier
  DirectHandle<Symbol> uninitialized_sentinel = UninitializedSentinel(isolate);
  DCHECK_EQ(ReadOnlyRoots(isolate).uninitialized_symbol(),
            *uninitialized_sentinel);
  for (int i = 0; i < slot_count;) {
    FeedbackSlot slot(i);
    FeedbackSlotKind kind = feedback_metadata->GetKind(slot);
    int entry_size = FeedbackMetadata::GetSlotSize(kind);

    Tagged<MaybeObject> extra_value = *uninitialized_sentinel;
    switch (kind) {
      case FeedbackSlotKind::kLoadGlobalInsideTypeof:
      case FeedbackSlotKind::kLoadGlobalNotInsideTypeof:
      case FeedbackSlotKind::kStoreGlobalSloppy:
      case FeedbackSlotKind::kStoreGlobalStrict:
      case FeedbackSlotKind::kJumpLoop:
        vector->Set(slot, ClearedValue(isolate), SKIP_WRITE_BARRIER);
        break;
      case FeedbackSlotKind::kForIn:
      case FeedbackSlotKind::kCompareOp:
      case FeedbackSlotKind::kBinaryOp:
      case FeedbackSlotKind::kTypeOf:
        vector->Set(slot, Smi::zero(), SKIP_WRITE_BARRIER);
        break;
      case FeedbackSlotKind::kLiteral:
        vector->Set(slot, Smi::zero(), SKIP_WRITE_BARRIER);
        break;
      case FeedbackSlotKind::kCall:
        vector->Set(slot, *uninitialized_sentinel, SKIP_WRITE_BARRIER);
        extra_value = Smi::zero();
        break;
      case FeedbackSlotKind::kCloneObject:
      case FeedbackSlotKind::kLoadProperty:
      case FeedbackSlotKind::kLoadKeyed:
      case FeedbackSlotKind::kHasKeyed:
      case FeedbackSlotKind::kSetNamedSloppy:
      case FeedbackSlotKind::kSetNamedStrict:
      case FeedbackSlotKind::kDefineNamedOwn:
      case FeedbackSlotKind::kDefineKeyedOwn:
      case FeedbackSlotKind::kSetKeyedSloppy:
      case FeedbackSlotKind::kSetKeyedStrict:
      case FeedbackSlotKind::kStoreInArrayLiteral:
      case FeedbackSlotKind::kDefineKeyedOwnPropertyInLiteral:
      case FeedbackSlotKind::kInstanceOf:
        vector->Set(slot, *uninitialized_sentinel, SKIP_WRITE_BARRIER);
        break;

      case FeedbackSlotKind::kInvalid:
        UNREACHABLE();
    }
    for (int j = 1; j < entry_size; j++) {
      vector->Set(slot.WithOffset(j), extra_value, SKIP_WRITE_BARRIER);
    }
    i += entry_size;
  }

  if (!isolate->is_best_effort_code_coverage()) {
    AddToVectorsForProfilingTools(isolate, vector);
  }
  parent_feedback_cell->set_value(*vector, kReleaseStore);
  return vector;
}

// static
Handle<FeedbackVector> FeedbackVector::NewForTesting(
    Isolate* isolate, const FeedbackVectorSpec* spec) {
  DirectHandle<FeedbackMetadata> metadata =
      FeedbackMetadata::New(isolate, spec);
  DirectHandle<SharedFunctionInfo> shared =
      isolate->factory()->NewSharedFunctionInfoForBuiltin(
          isolate->factory()->empty_string(), Builtin::kIllegal, 0, kDontAdapt);
  // Set the raw feedback metadata to circumvent checks that we are not
  // overwriting existing metadata.
  shared->set_raw_outer_scope_info_or_feedback_metadata(*metadata);
  DirectHandle<ClosureFeedbackCellArray> closure_feedback_cell_array =
      ClosureFeedbackCellArray::New(isolate, shared);
  DirectHandle<FeedbackCell> parent_cell =
      isolate->factory()->NewNoClosuresCell();

  IsCompiledScope is_compiled_scope(shared->is_compiled_scope(isolate));
  return FeedbackVector::New(isolate, shared, closure_feedback_cell_array,
                             parent_cell, &is_compiled_scope);
}

// static
Handle<FeedbackVector> FeedbackVector::NewWithOneBinarySlotForTesting(
    Zone* zone, Isolate* isolate) {
  FeedbackVectorSpec one_slot(zone);
  one_slot.AddBinaryOpICSlot();
  return NewForTesting(isolate, &one_slot);
}

// static
Handle<FeedbackVector> FeedbackVector::NewWithOneCompareSlotForTesting(
    Zone* zone, Isolate* isolate) {
  FeedbackVectorSpec one_slot(zone);
  one_slot.AddCompareICSlot();
  return NewForTesting(isolate, &one_slot);
}

// static
void FeedbackVector::AddToVectorsForProfilingTools(
    Isolate* isolate, DirectHandle<FeedbackVector> vector) {
  DCHECK(!isolate->is_best_effort_code_coverage());
  if (!vector->shared_function_info()->IsSubjectToDebugging()) return;
  Handle<ArrayList> list = Cast<ArrayList>(
      isolate->factory()->feedback_vectors_for_profiling_tools());
  list = ArrayList::Add(isolate, list, vector);
  isolate->SetFeedbackVectorsForProfilingTools(*list);
}

#ifdef V8_ENABLE_LEAPTIERING

void FeedbackVector::set_tiering_in_progress(bool in_progress) {
  set_flags(TieringInProgressBit::update(flags(), in_progress));
}

#else

void FeedbackVector::SetOptimizedCode(IsolateForSandbox isolate,
                                      Tagged<Code> code) {
  DCHECK(CodeKindIsOptimizedJSFunction(code->kind()));
  int32_t state = flags();
  // Skip setting optimized code if it would cause us to tier down.
  if (!has_optimized_code()) {
    state = MaybeHasTurbofanCodeBit::update(state, false);
  } else if (!CodeKindCanTierUp(optimized_code(isolate)->kind()) ||
             optimized_code(isolate)->kind() > code->kind()) {
    if (!v8_flags.stress_concurrent_inlining_attach_code &&
        !optimized_code(isolate)->marked_for_deoptimization()) {
      return;
    }
    // If we fall through, we may be tiering down. This is fine since we only do
    // that when the current code is marked for deoptimization, or because we're
    // stress testing.
    state = MaybeHasTurbofanCodeBit::update(state, false);
  }
  // TODO(mythria): We could see a CompileOptimized state here either from
  // tests that use %OptimizeFunctionOnNextCall, --always-turbofan or because we
  // re-mark the function for non-concurrent optimization after an OSR. We
  // should avoid these cases and also check that marker isn't
  // TieringState::kRequestTurbofan*.
  set_maybe_optimized_code(MakeWeak(code->wrapper()));
  // TODO(leszeks): Reconsider whether this could clear the tiering state vs.
  // the callers doing so.
  state = TieringStateBits::update(state, TieringState::kNone);
  if (code->is_maglevved()) {
    DCHECK(!MaybeHasTurbofanCodeBit::decode(state));
    state = MaybeHasMaglevCodeBit::update(state, true);
  } else {
    DCHECK(code->is_turbofanned());
    state = MaybeHasTurbofanCodeBit::update(state, true);
    state = MaybeHasMaglevCodeBit::update(state, false);
  }
  set_flags(state);
}

void FeedbackVector::ClearOptimizedCode() {
  DCHECK(has_optimized_code());
  DCHECK(maybe_has_maglev_code() || maybe_has_turbofan_code());
  set_maybe_optimized_code(ClearedValue(GetIsolate()));
  set_maybe_has_maglev_code(false);
  set_maybe_has_turbofan_code(false);
}

void FeedbackVector::EvictOptimizedCodeMarkedForDeoptimization(
    Isolate* isolate, Tagged<SharedFunctionInfo> shared, const char* reason) {
  Tagged<MaybeObject> slot = maybe_optimized_code();
  if (slot.IsCleared()) {
    set_maybe_has_maglev_code(false);
    set_maybe_has_turbofan_code(false);
    return;
  }

  Tagged<Code> code = Cast<CodeWrapper>(slot.GetHeapObject())->code(isolate);
  if (code->marked_for_deoptimization()) {
    Deoptimizer::TraceEvictFromOptimizedCodeCache(isolate, shared, reason);
    ClearOptimizedCode();
  }
}

void FeedbackVector::set_tiering_state(TieringState state) {
  int32_t new_flags = flags();
  new_flags = TieringStateBits::update(new_flags, state);
  set_flags(new_flags);
}

#endif  // V8_ENABLE_LEAPTIERING

void FeedbackVector::reset_flags() {
  set_flags(
#ifdef V8_ENABLE_LEAPTIERING
      TieringInProgressBit::encode(false) |
#else
      TieringStateBits::encode(TieringState::kNone) |
      LogNextExecutionBit::encode(false) |
      MaybeHasMaglevCodeBit::encode(false) |
      MaybeHasTurbofanCodeBit::encode(false) |
#endif  // V8_ENABLE_LEAPTIERING
      OsrTieringInProgressBit::encode(false) |
      MaybeHasMaglevOsrCodeBit::encode(false) |
      MaybeHasTurbofanOsrCodeBit::encode(false));
}

void FeedbackVector::SetOptimizedOsrCode(Isolate* isolate, FeedbackSlot slot,
                                         Tagged<Code> code) {
  DCHECK(CodeKindIsOptimizedJSFunction(code->kind()));
  DCHECK(!slot.IsInvalid());
  auto current = GetOptimizedOsrCode(isolate, slot);
  if (V8_UNLIKELY(current && current.value()->kind() > code->kind())) {
    return;
  }
  Set(slot, MakeWeak(code->wrapper()));
  set_maybe_has_optimized_osr_code(true, code->kind());
}

bool FeedbackVector::osr_tiering_in_progress() {
  return OsrTieringInProgressBit::decode(flags());
}

void FeedbackVector::set_osr_tiering_in_progress(bool osr_in_progress) {
  set_flags(OsrTieringInProgressBit::update(flags(), osr_in_progress));
}

bool FeedbackVector::ClearSlots(Isolate* isolate, ClearBehavior behavior) {
  if (!shared_function_info()->HasFeedbackMetadata()) return false;
  Tagged<MaybeObject> uninitialized_sentinel =
      FeedbackVector::RawUninitializedSentinel(isolate);

  bool feedback_updated = false;
  FeedbackMetadataIterator iter(metadata());
  while (iter.HasNext()) {
    FeedbackSlot slot = iter.Next();

    Tagged<MaybeObject> obj = Get(slot);
    if (obj != uninitialized_sentinel) {
      FeedbackNexus nexus(isolate, *this, slot);
      feedback_updated |= nexus.Clear(behavior);
    }
  }
  return feedback_updated;
}

#ifdef V8_TRACE_FEEDBACK_UPDATES

// static
void FeedbackVector::TraceFeedbackChange(Isolate* isolate,
                                         Tagged<FeedbackVector> vector,
                                         FeedbackSlot slot,
                                         const char* reason) {
  int slot_count = vector->metadata()->slot_count();
  StdoutStream os;
  if (slot.IsInvalid()) {
    os << "[Feedback slots in ";
  } else {
    FeedbackSlotKind kind = vector->metadata()->GetKind(slot);
    os << "[Feedback slot " << slot.ToInt() << "/" << slot_count << " ("
       << FeedbackMetadata::Kind2String(kind) << ")"
       << " in ";
  }
  ShortPrint(vector->shared_function_info(), os);
  if (slot.IsInvalid()) {
    os << " updated - ";
  } else {
    os << " updated to ";
    vector->FeedbackSlotPrint(os, slot);
    os << " - ";
  }
  os << reason << "]" << std::endl;
}

#endif

MaybeObjectHandle NexusConfig::NewHandle(Tagged<MaybeObject> object) const {
  if (mode() == Mode::MainThread) {
    return handle(object, isolate_);
  }
  DCHECK_EQ(mode(), Mode::BackgroundThread);
  return handle(object, local_heap_);
}

void NexusConfig::SetFeedbackPair(Tagged<FeedbackVector> vector,
                                  FeedbackSlot start_slot,
                                  Tagged<MaybeObject> feedback,
                                  WriteBarrierMode mode,
                                  Tagged<MaybeObject> feedback_extra,
                                  WriteBarrierMode mode_extra) const {
  CHECK(can_write());
  CHECK_GT(vector->length(), start_slot.WithOffset(1).ToInt());
  base::SharedMutexGuard<base::kExclusive> shared_mutex_guard(
      isolate()->feedback_vector_access());
  vector->Set(start_slot, feedback, mode);
  vector->Set(start_slot.WithOffset(1), feedback_extra, mode_extra);
}

std::pair<Tagged<MaybeObject>, Tagged<MaybeObject>>
NexusConfig::GetFeedbackPair(Tagged<FeedbackVector> vector,
                             FeedbackSlot slot) const {
  base::SharedMutexGuardIf<base::kShared> scope(
      isolate()->feedback_vector_access(), mode() == BackgroundThread);
  Tagged<MaybeObject> feedback = vector->Get(slot);
  Tagged<MaybeObject> feedback_extra = vector->Get(slot.WithOffset(1));
  return std::make_pair(feedback, feedback_extra);
}

FeedbackNexus::FeedbackNexus(Isolate* isolate, Handle<FeedbackVector> vector,
                             FeedbackSlot slot)
    : vector_handle_(vector),
      slot_(slot),
      config_(NexusConfig::FromMainThread(isolate)) {
  kind_ = vector.is_null() ? FeedbackSlotKind::kInvalid : vector->GetKind(slot);
}

FeedbackNexus::FeedbackNexus(Isolate* isolate, Tagged<FeedbackVector> vector,
                             FeedbackSlot slot)
    : vector_(vector),
      slot_(slot),
      config_(NexusConfig::FromMainThread(isolate)) {
  kind_ = vector.is_null() ? FeedbackSlotKind::kInvalid : vector->GetKind(slot);
}

FeedbackNexus::FeedbackNexus(Handle<FeedbackVector> vector, FeedbackSlot slot,
                             const NexusConfig& config)
    : vector_handle_(vector),
      slot_(slot),
      kind_(vector->GetKind(slot, kAcquireLoad)),
      config_(config) {}

Handle<WeakFixedArray> FeedbackNexus::CreateArrayOfSize(int length) {
  DCHECK(config()->can_write());
  Handle<WeakFixedArray> array =
      config()->isolate()->factory()->NewWeakFixedArray(length);
  return array;
}

void FeedbackNexus::ConfigureUninitialized() {
  Isolate* isolate = config()->isolate();
  switch (kind()) {
    case FeedbackSlotKind::kStoreGlobalSloppy:
    case FeedbackSlotKind::kStoreGlobalStrict:
    case FeedbackSlotKind::kLoadGlobalNotInsideTypeof:
    case FeedbackSlotKind::kLoadGlobalInsideTypeof:
      SetFeedback(ClearedValue(isolate), SKIP_WRITE_BARRIER,
                  UninitializedSentinel(), SKIP_WRITE_BARRIER);
      break;
    case FeedbackSlotKind::kCloneObject:
    case FeedbackSlotKind::kCall:
      SetFeedback(UninitializedSentinel(), SKIP_WRITE_BARRIER, Smi::zero(),
                  SKIP_WRITE_BARRIER);
      break;
    case FeedbackSlotKind::kInstanceOf:
      SetFeedback(UninitializedSentinel(), SKIP_WRITE_BARRIER);
      break;
    case FeedbackSlotKind::kSetNamedSloppy:
    case FeedbackSlotKind::kSetNamedStrict:
    case FeedbackSlotKind::kSetKeyedSloppy:
    case FeedbackSlotKind::kSetKeyedStrict:
    case FeedbackSlotKind::kStoreInArrayLiteral:
    case FeedbackSlotKind::kDefineNamedOwn:
    case FeedbackSlotKind::kDefineKeyedOwn:
    case FeedbackSlotKind::kLoadProperty:
    case FeedbackSlotKind::kLoadKeyed:
    case FeedbackSlotKind::kHasKeyed:
    case FeedbackSlotKind::kDefineKeyedOwnPropertyInLiteral:
      SetFeedback(UninitializedSentinel(), SKIP_WRITE_BARRIER,
                  UninitializedSentinel(), SKIP_WRITE_BARRIER);
      break;
    case FeedbackSlotKind::kJumpLoop:
      SetFeedback(ClearedValue(isolate), SKIP_WRITE_BARRIER);
      break;
    default:
      UNREACHABLE();
  }
}

bool FeedbackNexus::Clear(ClearBehavior behavior) {
  bool feedback_updated = false;

  switch (kind()) {
    case FeedbackSlotKind::kCompareOp:
    case FeedbackSlotKind::kForIn:
    case FeedbackSlotKind::kBinaryOp:
    case FeedbackSlotKind::kTypeOf:
      if (V8_LIKELY(behavior == ClearBehavior::kDefault)) {
        // We don't clear these, either.
      } else if (!IsCleared()) {
        DCHECK_EQ(behavior, ClearBehavior::kClearAll);
        SetFeedback(Smi::zero(), SKIP_WRITE_BARRIER);
        feedback_updated = true;
      }
      break;

    case FeedbackSlotKind::kLiteral:
      if (!IsCleared()) {
        SetFeedback(Smi::zero(), SKIP_WRITE_BARRIER);
        feedback_updated = true;
      }
      break;

    case FeedbackSlotKind::kSetNamedSloppy:
    case FeedbackSlotKind::kSetNamedStrict:
    case FeedbackSlotKind::kSetKeyedSloppy:
    case FeedbackSlotKind::kSetKeyedStrict:
    case FeedbackSlotKind::kStoreInArrayLiteral:
    case FeedbackSlotKind::kDefineNamedOwn:
    case FeedbackSlotKind::kDefineKeyedOwn:
    case FeedbackSlotKind::kLoadProperty:
    case FeedbackSlotKind::kLoadKeyed:
    case FeedbackSlotKind::kHasKeyed:
    case FeedbackSlotKind::kStoreGlobalSloppy:
    case FeedbackSlotKind::kStoreGlobalStrict:
    case FeedbackSlotKind::kLoadGlobalNotInsideTypeof:
    case FeedbackSlotKind::kLoadGlobalInsideTypeof:
    case FeedbackSlotKind::kCall:
    case FeedbackSlotKind::kInstanceOf:
    case FeedbackSlotKind::kDefineKeyedOwnPropertyInLiteral:
    case FeedbackSlotKind::kCloneObject:
    case FeedbackSlotKind::kJumpLoop:
      if (!IsCleared()) {
        ConfigureUninitialized();
        feedback_updated = true;
      }
      break;

    case FeedbackSlotKind::kInvalid:
      UNREACHABLE();
  }
  return feedback_updated;
}

bool FeedbackNexus::ConfigureMegamorphic() {
  DisallowGarbageCollection no_gc;
  Isolate* isolate = config()->isolate();
  Tagged<MaybeObject> sentinel = MegamorphicSentinel();
  if (GetFeedback() != sentinel) {
    SetFeedback(sentinel, SKIP_WRITE_BARRIER, ClearedValue(isolate));
    return true;
  }

  return false;
}

void FeedbackNexus::ConfigureMegaDOM(const MaybeObjectHandle& handler) {
  DisallowGarbageCollection no_gc;
  Tagged<MaybeObject> sentinel = MegaDOMSentinel();

  SetFeedback(sentinel, SKIP_WRITE_BARRIER, *handler, UPDATE_WRITE_BARRIER);
}

bool FeedbackNexus::ConfigureMegamorphic(IcCheckType property_type) {
  DisallowGarbageCollection no_gc;
  Tagged<MaybeObject> sentinel = MegamorphicSentinel();
  Tagged<MaybeObject> maybe_extra =
      Smi::FromInt(static_cast<int>(property_type));

  auto feedback = GetFeedbackPair();
  bool update_required =
      feedback.first != sentinel || feedback.second != maybe_extra;
  if (update_required) {
    SetFeedback(sentinel, SKIP_WRITE_BARRIER, maybe_extra, SKIP_WRITE_BARRIER);
  }
  return update_required;
}

Tagged<Map> FeedbackNexus::GetFirstMap() const {
  FeedbackIterator it(this);
  if (!it.done()) {
    return it.map();
  }

  return Map();
}

InlineCacheState FeedbackNexus::ic_state() const {
  Tagged<MaybeObject> feedback, extra;
  std::tie(feedback, extra) = GetFeedbackPair();

  switch (kind()) {
    case FeedbackSlotKind::kLiteral:
      if (IsSmi(feedback)) return InlineCacheState::UNINITIALIZED;
      return InlineCacheState::MONOMORPHIC;

    case FeedbackSlotKind::kStoreGlobalSloppy:
    case FeedbackSlotKind::kStoreGlobalStrict:
    case FeedbackSlotKind::kLoadGlobalNotInsideTypeof:
    case FeedbackSlotKind::kLoadGlobalInsideTypeof:
    case FeedbackSlotKind::kJumpLoop: {
      if (IsSmi(feedback)) return InlineCacheState::MONOMORPHIC;

      DCHECK(feedback.IsWeakOrCleared());
      if (!feedback.IsCleared() || extra != UninitializedSentinel()) {
        return InlineCacheState::MONOMORPHIC;
      }
      return InlineCacheState::UNINITIALIZED;
    }

    case FeedbackSlotKind::kSetNamedSloppy:
    case FeedbackSlotKind::kSetNamedStrict:
    case FeedbackSlotKind::kSetKeyedSloppy:
    case FeedbackSlotKind::kSetKeyedStrict:
    case FeedbackSlotKind::kStoreInArrayLiteral:
    case FeedbackSlotKind::kDefineNamedOwn:
    case FeedbackSlotKind::kDefineKeyedOwn:
    case FeedbackSlotKind::kLoadProperty:
    case FeedbackSlotKind::kLoadKeyed:
    case FeedbackSlotKind::kHasKeyed: {
      if (feedback == UninitializedSentinel()) {
        return InlineCacheState::UNINITIALIZED;
      }
      if (feedback == MegamorphicSentinel()) {
        return InlineCacheState::MEGAMORPHIC;
      }
      if (feedback == MegaDOMSentinel()) {
        DCHECK(IsLoadICKind(kind()));
        return InlineCacheState::MEGADOM;
      }
      if (feedback.IsWeakOrCleared()) {
        // Don't check if the map is cleared.
        return InlineCacheState::MONOMORPHIC;
      }
      Tagged<HeapObject> heap_object;
      if (feedback.GetHeapObjectIfStrong(&heap_object)) {
        if (IsWeakFixedArray(heap_object)) {
          // Determine state purely by our structure, don't check if the maps
          // are cleared.
          return InlineCacheState::POLYMORPHIC;
        }
        if (IsName(heap_object)) {
          DCHECK(IsKeyedLoadICKind(kind()) || IsKeyedStoreICKind(kind()) ||
                 IsKeyedHasICKind(kind()) || IsDefineKeyedOwnICKind(kind()));
          Tagged<Object> extra_object = extra.GetHeapObjectAssumeStrong();
          Tagged<WeakFixedArray> extra_array =
              Cast<WeakFixedArray>(extra_object);
          return extra_array->length() > 2 ? InlineCacheState::POLYMORPHIC
                                           : InlineCacheState::MONOMORPHIC;
        }
      }
      // TODO(1393773): Remove once the issue is solved.
      Address vector_ptr = vector().ptr();
      config_.isolate()->PushParamsAndDie(
          reinterpret_cast<void*>(feedback.ptr()),
          reinterpret_cast<void*>(extra.ptr()),
          reinterpret_cast<void*>(vector_ptr),
          reinterpret_cast<void*>(static_cast<intptr_t>(slot_.ToInt())),
          reinterpret_cast<void*>(static_cast<intptr_t>(kind())),
          // Include part of the feedback vector containing the slot.
          reinterpret_cast<void*>(
              vector_ptr + FeedbackVector::OffsetOfElementAt(slot_.ToInt())));
      UNREACHABLE();
    }
    case FeedbackSlotKind::kCall: {
      Tagged<HeapObject> heap_object;
      if (feedback == MegamorphicSentinel()) {
        return InlineCacheState::GENERIC;
      } else if (feedback.IsWeakOrCleared()) {
        if (feedback.GetHeapObjectIfWeak(&heap_object)) {
          if (IsFeedbackCell(heap_object)) {
            return InlineCacheState::POLYMORPHIC;
          }
          CHECK(IsJSFunction(heap_object) || IsJSBoundFunction(heap_object));
        }
        return InlineCacheState::MONOMORPHIC;
      } else if (feedback.GetHeapObjectIfStrong(&heap_object) &&
                 IsAllocationSite(heap_object)) {
        return InlineCacheState::MONOMORPHIC;
      }

      CHECK_EQ(feedback, UninitializedSentinel());
      return InlineCacheState::UNINITIALIZED;
    }
    case FeedbackSlotKind::kBinaryOp: {
      BinaryOperationHint hint = GetBinaryOperationFeedback();
      if (hint == BinaryOperationHint::kNone) {
        return InlineCacheState::UNINITIALIZED;
      } else if (hint == BinaryOperationHint::kAny) {
        return InlineCacheState::GENERIC;
      }

      return InlineCacheState::MONOMORPHIC;
    }
    case FeedbackSlotKind::kCompareOp: {
      CompareOperationHint hint = GetCompareOperationFeedback();
      if (hint == CompareOperationHint::kNone) {
        return InlineCacheState::UNINITIALIZED;
      } else if (hint == CompareOperationHint::kAny) {
        return InlineCacheState::GENERIC;
      }

      return InlineCacheState::MONOMORPHIC;
    }
    case FeedbackSlotKind::kForIn: {
      ForInHint hint = GetForInFeedback();
      if (hint == ForInHint::kNone) {
        return InlineCacheState::UNINITIALIZED;
      } else if (hint == ForInHint::kAny) {
        return InlineCacheState::GENERIC;
      }
      return InlineCacheState::MONOMORPHIC;
    }
    case FeedbackSlotKind::kTypeOf: {
      if (feedback == Smi::zero()) {
        return InlineCacheState::UNINITIALIZED;
      } else if (feedback == Smi::FromInt(TypeOfFeedback::kAny)) {
        return InlineCacheState::MEGAMORPHIC;
      } else if (base::bits::CountPopulation(
                     static_cast<uint32_t>(feedback.ToSmi().value())) == 1) {
        return InlineCacheState::MONOMORPHIC;
      } else {
        return InlineCacheState::POLYMORPHIC;
      }
    }
    case FeedbackSlotKind::kInstanceOf: {
      if (feedback == UninitializedSentinel()) {
        return InlineCacheState::UNINITIALIZED;
      } else if (feedback == MegamorphicSentinel()) {
        return InlineCacheState::MEGAMORPHIC;
      }
      return InlineCacheState::MONOMORPHIC;
    }
    case FeedbackSlotKind::kDefineKeyedOwnPropertyInLiteral: {
      if (feedback == UninitializedSentinel()) {
        return InlineCacheState::UNINITIALIZED;
      } else if (feedback.IsWeakOrCleared()) {
        // Don't check if the map is cleared.
        return InlineCacheState::MONOMORPHIC;
      }

      return InlineCacheState::MEGAMORPHIC;
    }

    case FeedbackSlotKind::kCloneObject: {
      if (feedback == UninitializedSentinel()) {
        return InlineCacheState::UNINITIALIZED;
      }
      if (feedback == MegamorphicSentinel()) {
        return InlineCacheState::MEGAMORPHIC;
      }
      if (feedback.IsWeakOrCleared()) {
        return InlineCacheState::MONOMORPHIC;
      }

      DCHECK(IsWeakFixedArray(feedback.GetHeapObjectAssumeStrong()));
      return InlineCacheState::POLYMORPHIC;
    }

    case FeedbackSlotKind::kInvalid:
      UNREACHABLE();
  }
  return InlineCacheState::UNINITIALIZED;
}

void FeedbackNexus::ConfigurePropertyCellMode(DirectHandle<PropertyCell> cell) {
  DCHECK(IsGlobalICKind(kind()));
  SetFeedback(MakeWeak(*cell), UPDATE_WRITE_BARRIER, UninitializedSentinel(),
              SKIP_WRITE_BARRIER);
}

#if DEBUG
namespace {
bool shouldStressLexicalIC(int script_context_index, int context_slot_index) {
  return (script_context_index + context_slot_index) % 100 == 0;
}
}  // namespace
#endif

bool FeedbackNexus::ConfigureLexicalVarMode(int script_context_index,
                                            int context_slot_index,
                                            bool immutable) {
  DCHECK(IsGlobalICKind(kind()));
  DCHECK_LE(0, script_context_index);
  DCHECK_LE(0, context_slot_index);
#if DEBUG
  if (v8_flags.stress_ic &&
      shouldStressLexicalIC(script_context_index, context_slot_index)) {
    return false;
  }
#endif
  if (!ContextIndexBits::is_valid(script_context_index) ||
      !SlotIndexBits::is_valid(context_slot_index) ||
      !ImmutabilityBit::is_valid(immutable)) {
    return false;
  }
  int config = ContextIndexBits::encode(script_context_index) |
               SlotIndexBits::encode(context_slot_index) |
               ImmutabilityBit::encode(immutable);

  SetFeedback(Smi::From31BitPattern(config), SKIP_WRITE_BARRIER,
              UninitializedSentinel(), SKIP_WRITE_BARRIER);
  return true;
}

void FeedbackNexus::ConfigureHandlerMode(const MaybeObjectHandle& handler) {
  DCHECK(IsGlobalICKind(kind()));
  DCHECK(IC::IsHandler(*handler));
  SetFeedback(ClearedValue(config()->isolate()), UPDATE_WRITE_BARRIER, *handler,
              UPDATE_WRITE_BARRIER);
}

void FeedbackNexus::ConfigureCloneObject(
    Handle<Map> source_map, const MaybeObjectHandle& handler_handle) {
  // TODO(olivf): Introduce a CloneHandler to deal with all the logic of this
  // state machine which is now spread between Runtime_CloneObjectIC_Miss and
  // this method.
  auto GetHandler = [=]() {
    if (IsSmi(*handler_handle)) {
      return *handler_handle;
    }
    return MakeWeak(*handler_handle);
  };
  DCHECK(config()->can_write());
  Isolate* isolate = config()->isolate();
  Handle<HeapObject> feedback;
  {
    Tagged<MaybeObject> maybe_feedback = GetFeedback();
    if (maybe_feedback.IsStrongOrWeak()) {
      feedback = handle(maybe_feedback.GetHeapObject(), isolate);
    } else {
      DCHECK(maybe_feedback.IsCleared());
    }
  }
  switch (ic_state()) {
    case InlineCacheState::UNINITIALIZED:
      // Cache the first map seen which meets the fast case requirements.
      SetFeedback(MakeWeak(*source_map), UPDATE_WRITE_BARRIER, GetHandler());
      break;
    case InlineCacheState::MONOMORPHIC:
      if (feedback.is_null() || feedback.is_identical_to(source_map) ||
          Cast<Map>(*feedback)->is_deprecated()) {
        SetFeedback(MakeWeak(*source_map), UPDATE_WRITE_BARRIER, GetHandler());
      } else {
        // Transition to POLYMORPHIC.
        DirectHandle<WeakFixedArray> array =
            CreateArrayOfSize(2 * kCloneObjectPolymorphicEntrySize);
        DisallowGarbageCollection no_gc;
        Tagged<WeakFixedArray> raw_array = *array;
        raw_array->set(0, MakeWeak(*feedback));
        raw_array->set(1, GetFeedbackExtra());
        raw_array->set(2, MakeWeak(*source_map));
        raw_array->set(3, GetHandler());
        SetFeedback(raw_array, UPDATE_WRITE_BARRIER, ClearedValue(isolate));
      }
      break;
    case InlineCacheState::POLYMORPHIC: {
      const int kMaxElements = v8_flags.max_valid_polymorphic_map_count *
                               kCloneObjectPolymorphicEntrySize;
      DirectHandle<WeakFixedArray> array = Cast<WeakFixedArray>(feedback);
      int i = 0;
      for (; i < array->length(); i += kCloneObjectPolymorphicEntrySize) {
        Tagged<MaybeObject> feedback_map = array->get(i);
        if (feedback_map.IsCleared()) break;
        Handle<Map> cached_map(Cast<Map>(feedback_map.GetHeapObject()),
                               isolate);
        if (cached_map.is_identical_to(source_map) ||
            cached_map->is_deprecated())
          break;
      }

      if (i >= array->length()) {
        if (i == kMaxElements) {
          // Transition to MEGAMORPHIC.
          Tagged<MaybeObject> sentinel = MegamorphicSentinel();
          SetFeedback(sentinel, SKIP_WRITE_BARRIER, ClearedValue(isolate));
          break;
        }

        // Grow polymorphic feedback array.
        DirectHandle<WeakFixedArray> new_array = CreateArrayOfSize(
            array->length() + kCloneObjectPolymorphicEntrySize);
        for (int j = 0; j < array->length(); ++j) {
          new_array->set(j, array->get(j));
        }
        SetFeedback(*new_array);
        array = new_array;
      }

      array->set(i, MakeWeak(*source_map));
      array->set(i + 1, GetHandler());
      break;
    }

    default:
      UNREACHABLE();
  }
}

int FeedbackNexus::GetCallCount() {
  DCHECK(IsCallICKind(kind()));

  Tagged<Object> call_count = Cast<Object>(GetFeedbackExtra());
  CHECK(IsSmi(call_count));
  uint32_t value = static_cast<uint32_t>(Smi::ToInt(call_count));
  return CallCountField::decode(value);
}

void FeedbackNexus::SetSpeculationMode(SpeculationMode mode) {
  DCHECK(IsCallICKind(kind()));

  Tagged<Object> call_count = Cast<Object>(GetFeedbackExtra());
  CHECK(IsSmi(call_count));
  uint32_t count = static_cast<uint32_t>(Smi::ToInt(call_count));
  count = SpeculationModeField::update(count, mode);
  Tagged<MaybeObject> feedback = GetFeedback();
  // We could've skipped WB here (since we set the slot to the same value again)
  // but we don't to make WB verification happy.
  SetFeedback(feedback, UPDATE_WRITE_BARRIER, Smi::FromInt(count),
              SKIP_WRITE_BARRIER);
}

SpeculationMode FeedbackNexus::GetSpeculationMode() {
  DCHECK(IsCallICKind(kind()));

  Tagged<Object> call_count = Cast<Object>(GetFeedbackExtra());
  CHECK(IsSmi(call_count));
  uint32_t value = static_cast<uint32_t>(Smi::ToInt(call_count));
  return SpeculationModeField::decode(value);
}

CallFeedbackContent FeedbackNexus::GetCallFeedbackContent() {
  DCHECK(IsCallICKind(kind()));

  Tagged<Object> call_count = Cast<Object>(GetFeedbackExtra());
  CHECK(IsSmi(call_count));
  uint32_t value = static_cast<uint32_t>(Smi::ToInt(call_count));
  return CallFeedbackContentField::decode(value);
}

float FeedbackNexus::ComputeCallFrequency() {
  DCHECK(IsCallICKind(kind()));

  double const invocation_count = vector()->invocation_count(kRelaxedLoad);
  double const call_count = GetCallCount();
  if (invocation_count == 0.0) {  // Prevent division by 0.
    return 0.0f;
  }
  return static_cast<float>(call_count / invocation_count);
}

void FeedbackNexus::ConfigureMonomorphic(Handle<Name> name,
                                         DirectHandle<Map> receiver_map,
                                         const MaybeObjectHandle& handler) {
  DCHECK(handler.is_null() || IC::IsHandler(*handler));
  if (kind() == FeedbackSlotKind::kDefineKeyedOwnPropertyInLiteral) {
    SetFeedback(MakeWeak(*receiver_map), UPDATE_WRITE_BARRIER, *name);
  } else {
    if (name.is_null()) {
      SetFeedback(MakeWeak(*receiver_map), UPDATE_WRITE_BARRIER, *handler);
    } else {
      DirectHandle<WeakFixedArray> array = CreateArrayOfSize(2);
      array->set(0, MakeWeak(*receiver_map));
      array->set(1, *handler);
      SetFeedback(*name, UPDATE_WRITE_BARRIER, *array);
    }
  }
}

void FeedbackNexus::ConfigurePolymorphic(
    Handle<Name> name, std::vector<MapAndHandler> const& maps_and_handlers) {
  int receiver_count = static_cast<int>(maps_and_handlers.size());
  DCHECK_GT(receiver_count, 1);
  DirectHandle<WeakFixedArray> array = CreateArrayOfSize(receiver_count * 2);

  for (int current = 0; current < receiver_count; ++current) {
    DirectHandle<Map> map = maps_and_handlers[current].first;
    array->set(current * 2, MakeWeak(*map));
    MaybeObjectHandle handler = maps_and_handlers[current].second;
    DCHECK(IC::IsHandler(*handler));
    array->set(current * 2 + 1, *handler);
  }

  if (name.is_null()) {
    SetFeedback(*array, UPDATE_WRITE_BARRIER, UninitializedSentinel(),
                SKIP_WRITE_BARRIER);
  } else {
    SetFeedback(*name, UPDATE_WRITE_BARRIER, *array);
  }
}

int FeedbackNexus::ExtractMaps(MapHandles* maps) const {
  DisallowGarbageCollection no_gc;
  int found = 0;
  for (FeedbackIterator it(this); !it.done(); it.Advance()) {
    maps->push_back(config()->NewHandle(it.map()));
    found++;
  }

  return found;
}

MaybeObjectHandle FeedbackNexus::ExtractMegaDOMHandler() {
  DCHECK(ic_state() == InlineCacheState::MEGADOM);
  DisallowGarbageCollection no_gc;

  auto pair = GetFeedbackPair();
  Tagged<MaybeObject> maybe_handler = pair.second;
  if (!maybe_handler.IsCleared()) {
    MaybeObjectHandle handler = config()->NewHandle(maybe_handler);
    return handler;
  }

  return MaybeObjectHandle();
}

int FeedbackNexus::ExtractMapsAndHandlers(
    std::vector<MapAndHandler>* maps_and_handlers,
    TryUpdateHandler map_handler) const {
  DCHECK(!IsDefineKeyedOwnPropertyInLiteralKind(kind()));
  DisallowGarbageCollection no_gc;
  int found = 0;

  for (FeedbackIterator it(this); !it.done(); it.Advance()) {
    Handle<Map> map = config()->NewHandle(it.map());
    Tagged<MaybeObject> maybe_handler = it.handler();
    if (!maybe_handler.IsCleared()) {
      DCHECK(IC::IsHandler(maybe_handler));
      MaybeObjectHandle handler = config()->NewHandle(maybe_handler);
      if (map_handler && !(map_handler(map).ToHandle(&map))) {
        continue;
      }
      maps_and_handlers->push_back(MapAndHandler(map, handler));
      found++;
    }
  }

  return found;
}

MaybeObjectHandle FeedbackNexus::FindHandlerForMap(
    DirectHandle<Map> map) const {
  DCHECK(!IsStoreInArrayLiteralICKind(kind()));

  for (FeedbackIterator it(this); !it.done(); it.Advance()) {
    if (it.map() == *map && !it.handler().IsCleared()) {
      return config()->NewHandle(it.handler());
    }
  }
  return MaybeObjectHandle();
}

Tagged<Name> FeedbackNexus::GetName() const {
  if (IsKeyedStoreICKind(kind()) || IsKeyedLoadICKind(kind()) ||
      IsKeyedHasICKind(kind()) || IsDefineKeyedOwnICKind(kind())) {
    Tagged<MaybeObject> feedback = GetFeedback();
    if (IsPropertyNameFeedback(feedback)) {
      return Cast<Name>(feedback.GetHeapObjectAssumeStrong());
    }
  }
  if (IsDefineKeyedOwnPropertyInLiteralKind(kind())) {
    Tagged<MaybeObject> extra = GetFeedbackExtra();
    if (IsPropertyNameFeedback(extra)) {
      return Cast<Name>(extra.GetHeapObjectAssumeStrong());
    }
  }
  return {};
}

KeyedAccessLoadMode FeedbackNexus::GetKeyedAccessLoadMode() const {
  DCHECK(IsKeyedLoadICKind(kind()) || IsKeyedHasICKind(kind()));
  // TODO(victorgomes): The KeyedAccessLoadMode::kInBounds is doing double duty
  // here. It shouldn't be used for property loads.
  if (GetKeyType() == IcCheckType::kProperty) {
    return KeyedAccessLoadMode::kInBounds;
  }
  std::vector<MapAndHandler> maps_and_handlers;
  ExtractMapsAndHandlers(&maps_and_handlers);
  KeyedAccessLoadMode mode = KeyedAccessLoadMode::kInBounds;
  for (MapAndHandler map_and_handler : maps_and_handlers) {
    mode = GeneralizeKeyedAccessLoadMode(
        mode, LoadHandler::GetKeyedAccessLoadMode(*map_and_handler.second));
  }
  return mode;
}

namespace {

bool BuiltinHasKeyedAccessStoreMode(Builtin builtin) {
  DCHECK(Builtins::IsBuiltinId(builtin));
  switch (builtin) {
    case Builtin::kKeyedStoreIC_SloppyArguments_InBounds:
    case Builtin::kKeyedStoreIC_SloppyArguments_NoTransitionGrowAndHandleCOW:
    case Builtin::kKeyedStoreIC_SloppyArguments_NoTransitionIgnoreTypedArrayOOB:
    case Builtin::kKeyedStoreIC_SloppyArguments_NoTransitionHandleCOW:
    case Builtin::kStoreFastElementIC_InBounds:
    case Builtin::kStoreFastElementIC_NoTransitionGrowAndHandleCOW:
    case Builtin::kStoreFastElementIC_NoTransitionIgnoreTypedArrayOOB:
    case Builtin::kStoreFastElementIC_NoTransitionHandleCOW:
    case Builtin::kElementsTransitionAndStore_InBounds:
    case Builtin::kElementsTransitionAndStore_NoTransitionGrowAndHandleCOW:
    case Builtin::kElementsTransitionAndStore_NoTransitionIgnoreTypedArrayOOB:
    case Builtin::kElementsTransitionAndStore_NoTransitionHandleCOW:
      return true;
    default:
      return false;
  }
  UNREACHABLE();
}

KeyedAccessStoreMode KeyedAccessStoreModeForBuiltin(Builtin builtin) {
  DCHECK(BuiltinHasKeyedAccessStoreMode(builtin));
  switch (builtin) {
    case Builtin::kKeyedStoreIC_SloppyArguments_InBounds:
    case Builtin::kStoreFastElementIC_InBounds:
    case Builtin::kElementsTransitionAndStore_InBounds:
      return KeyedAccessStoreMode::kInBounds;
    case Builtin::kKeyedStoreIC_SloppyArguments_NoTransitionGrowAndHandleCOW:
    case Builtin::kStoreFastElementIC_NoTransitionGrowAndHandleCOW:
    case Builtin::kElementsTransitionAndStore_NoTransitionGrowAndHandleCOW:
      return KeyedAccessStoreMode::kGrowAndHandleCOW;
    case Builtin::kKeyedStoreIC_SloppyArguments_NoTransitionIgnoreTypedArrayOOB:
    case Builtin::kStoreFastElementIC_NoTransitionIgnoreTypedArrayOOB:
    case Builtin::kElementsTransitionAndStore_NoTransitionIgnoreTypedArrayOOB:
      return KeyedAccessStoreMode::kIgnoreTypedArrayOOB;
    case Builtin::kKeyedStoreIC_SloppyArguments_NoTransitionHandleCOW:
    case Builtin::kStoreFastElementIC_NoTransitionHandleCOW:
    case Builtin::kElementsTransitionAndStore_NoTransitionHandleCOW:
      return KeyedAccessStoreMode::kHandleCOW;
    default:
      UNREACHABLE();
  }
}

}  // namespace

KeyedAccessStoreMode FeedbackNexus::GetKeyedAccessStoreMode() const {
  DCHECK(IsKeyedStoreICKind(kind()) || IsStoreInArrayLiteralICKind(kind()) ||
         IsDefineKeyedOwnPropertyInLiteralKind(kind()) ||
         IsDefineKeyedOwnICKind(kind()));
  KeyedAccessStoreMode mode = KeyedAccessStoreMode::kInBounds;

  if (GetKeyType() == IcCheckType::kProperty) return mode;

  std::vector<MapAndHandler> maps_and_handlers;
  ExtractMapsAndHandlers(&maps_and_handlers);
  for (const MapAndHandler& map_and_handler : maps_and_handlers) {
    const MaybeObjectHandle maybe_code_handler = map_and_handler.second;
    // The first handler that isn't the slow handler will have the bits we need.
    Builtin builtin_handler = Builtin::kNoBuiltinId;
    if (IsStoreHandler(*maybe_code_handler.object())) {
      auto data_handler = Cast<StoreHandler>(maybe_code_handler.object());

      if (IsSmi(data_handler->smi_handler())) {
        // Decode the KeyedAccessStoreMode information from the Handler.
        mode =
            StoreHandler::GetKeyedAccessStoreMode(data_handler->smi_handler());
        if (!StoreModeIsInBounds(mode)) return mode;
        continue;
      } else {
        Tagged<Code> code = Cast<Code>(data_handler->smi_handler());
        builtin_handler = code->builtin_id();
      }

    } else if (IsSmi(*maybe_code_handler.object())) {
      // Skip for Proxy Handlers.
      if (*maybe_code_handler.object() == StoreHandler::StoreProxy()) {
        continue;
      }
      // Decode the KeyedAccessStoreMode information from the Handler.
      mode = StoreHandler::GetKeyedAccessStoreMode(*maybe_code_handler);
      if (!StoreModeIsInBounds(mode)) return mode;
      continue;
    } else if (IsDefineKeyedOwnICKind(kind())) {
      mode = StoreHandler::GetKeyedAccessStoreMode(*maybe_code_handler);
      if (!StoreModeIsInBounds(mode)) return mode;
      continue;
    } else {
      // Element store without prototype chain check.
      Tagged<Code> code = Cast<Code>(*maybe_code_handler.object());
      builtin_handler = code->builtin_id();
    }

    if (Builtins::IsBuiltinId(builtin_handler)) {
      if (!BuiltinHasKeyedAccessStoreMode(builtin_handler)) continue;

      mode = KeyedAccessStoreModeForBuiltin(builtin_handler);
      break;
    }
  }

  return mode;
}

IcCheckType FeedbackNexus::GetKeyType() const {
  DCHECK(IsKeyedStoreICKind(kind()) || IsKeyedLoadICKind(kind()) ||
         IsStoreInArrayLiteralICKind(kind()) || IsKeyedHasICKind(kind()) ||
         IsDefineKeyedOwnPropertyInLiteralKind(kind()) ||
         IsDefineKeyedOwnICKind(kind()));
  auto pair = GetFeedbackPair();
  Tagged<MaybeObject> feedback = pair.first;
  if (feedback == MegamorphicSentinel()) {
    return static_cast<IcCheckType>(Smi::ToInt(Cast<Smi>(pair.second)));
  }
  Tagged<MaybeObject> maybe_name =
      IsDefineKeyedOwnPropertyInLiteralKind(kind()) ||
              IsDefineKeyedOwnICKind(kind())
          ? pair.second
          : feedback;
  return IsPropertyNameFeedback(maybe_name) ? IcCheckType::kProperty
                                            : IcCheckType::kElement;
}

BinaryOperationHint FeedbackNexus::GetBinaryOperationFeedback() const {
  DCHECK_EQ(kind(), FeedbackSlotKind::kBinaryOp);
  int feedback = GetFeedback().ToSmi().value();
  return BinaryOperationHintFromFeedback(feedback);
}

CompareOperationHint FeedbackNexus::GetCompareOperationFeedback() const {
  DCHECK_EQ(kind(), FeedbackSlotKind::kCompareOp);
  int feedback = GetFeedback().ToSmi().value();
  return CompareOperationHintFromFeedback(feedback);
}

TypeOfFeedback::Result FeedbackNexus::GetTypeOfFeedback() const {
  DCHECK_EQ(kind(), FeedbackSlotKind::kTypeOf);
  return static_cast<TypeOfFeedback::Result>(GetFeedback().ToSmi().value());
}

ForInHint FeedbackNexus::GetForInFeedback() const {
  DCHECK_EQ(kind(), FeedbackSlotKind::kForIn);
  int feedback = GetFeedback().ToSmi().value();
  return ForInHintFromFeedback(static_cast<ForInFeedback>(feedback));
}

MaybeHandle<JSObject> FeedbackNexus::GetConstructorFeedback() const {
  DCHECK_EQ(kind(), FeedbackSlotKind::kInstanceOf);
  Tagged<MaybeObject> feedback = GetFeedback();
  Tagged<HeapObject> heap_object;
  if (feedback.GetHeapObjectIfWeak(&heap_object)) {
    return config()->NewHandle(Cast<JSObject>(heap_object));
  }
  return MaybeHandle<JSObject>();
}

FeedbackIterator::FeedbackIterator(const FeedbackNexus* nexus)
    : done_(false), index_(-1), state_(kOther) {
  DCHECK(
      IsLoadICKind(nexus->kind()) || IsSetNamedICKind(nexus->kind()) ||
      IsKeyedLoadICKind(nexus->kind()) || IsKeyedStoreICKind(nexus->kind()) ||
      IsDefineNamedOwnICKind(nexus->kind()) ||
      IsDefineKeyedOwnPropertyInLiteralKind(nexus->kind()) ||
      IsStoreInArrayLiteralICKind(nexus->kind()) ||
      IsKeyedHasICKind(nexus->kind()) || IsDefineKeyedOwnICKind(nexus->kind()));

  DisallowGarbageCollection no_gc;
  auto pair = nexus->GetFeedbackPair();
  Tagged<MaybeObject> feedback = pair.first;
  bool is_named_feedback = IsPropertyNameFeedback(feedback);
  Tagged<HeapObject> heap_object;

  if ((feedback.GetHeapObjectIfStrong(&heap_object) &&
       IsWeakFixedArray(heap_object)) ||
      is_named_feedback) {
    index_ = 0;
    state_ = kPolymorphic;
    heap_object = feedback.GetHeapObjectAssumeStrong();
    if (is_named_feedback) {
      polymorphic_feedback_ = nexus->config()->NewHandle(
          Cast<WeakFixedArray>(pair.second.GetHeapObjectAssumeStrong()));
    } else {
      polymorphic_feedback_ =
          nexus->config()->NewHandle(Cast<WeakFixedArray>(heap_object));
    }
    AdvancePolymorphic();
  } else if (feedback.GetHeapObjectIfWeak(&heap_object)) {
    state_ = kMonomorphic;
    Tagged<MaybeObject> handler = pair.second;
    map_ = Cast<Map>(heap_object);
    handler_ = handler;
  } else {
    done_ = true;
  }
}

void FeedbackIterator::Advance() {
  CHECK(!done_);

  if (state_ == kMonomorphic) {
    done_ = true;
    return;
  }

  CHECK_EQ(state_, kPolymorphic);
  AdvancePolymorphic();
}

void FeedbackIterator::AdvancePolymorphic() {
  CHECK(!done_);
  CHECK_EQ(state_, kPolymorphic);
  int length = polymorphic_feedback_->length();
  Tagged<HeapObject> heap_object;

  while (index_ < length) {
    if (polymorphic_feedback_->get(index_).GetHeapObjectIfWeak(&heap_object)) {
      Tagged<MaybeObject> handler =
          polymorphic_feedback_->get(index_ + kHandlerOffset);
      map_ = Cast<Map>(heap_object);
      handler_ = handler;
      index_ += kEntrySize;
      return;
    }
    index_ += kEntrySize;
  }

  CHECK_EQ(index_, length);
  done_ = true;
}
}  // namespace v8::internal
```