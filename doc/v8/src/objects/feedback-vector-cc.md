Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/objects/feedback-vector.cc`.

Here's a breakdown of how to approach this:

1. **Identify the Core Purpose:** The file name `feedback-vector.cc` strongly suggests that this code is related to collecting and managing feedback during the execution of JavaScript code. This feedback is likely used for optimization purposes.

2. **Analyze Key Classes and Structures:**
    * `FeedbackVectorSpec`: Seems like a specification for creating `FeedbackVector`s. It defines the types and number of feedback slots.
    * `FeedbackMetadata`: Likely stores metadata about the feedback slots within a `FeedbackVector`, such as the type of feedback each slot holds.
    * `FeedbackVector`: The main class for storing feedback. It contains slots that hold information gathered during execution.
    * `FeedbackSlot`: Represents a single entry within a `FeedbackVector`.
    * `FeedbackSlotKind`: An enumeration defining the different types of feedback that can be stored in a slot (e.g., `kCall`, `kLoadProperty`).
    * `ClosureFeedbackCellArray`:  Related to feedback for closures.
    * `FeedbackCell`:  Individual cells within the `ClosureFeedbackCellArray`.
    * `FeedbackNexus`:  Provides a way to access and manipulate the feedback information within a `FeedbackVector` for a specific slot.

3. **Examine Key Functions and Methods:**
    * `FeedbackVectorSpec::AddSlot()`:  Adds a new slot to the specification.
    * `FeedbackMetadata::New()`: Creates a new `FeedbackMetadata` object based on a `FeedbackVectorSpec`.
    * `FeedbackMetadata::GetKind()`/`SetKind()`: Get or set the type of feedback for a given slot.
    * `FeedbackVector::New()`: Creates a new `FeedbackVector`.
    * `FeedbackVector::GetKind()`: Retrieves the type of feedback for a slot.
    * `FeedbackVector::SetOptimizedCode()`/`ClearOptimizedCode()`: Manage optimized code associated with the feedback vector.
    * `FeedbackNexus` methods (e.g., `ConfigureMegamorphic`, `Clear`, `ic_state`): Functions for interacting with and modifying feedback information for a specific slot.

4. **Infer Relationships and Interactions:**
    * A `FeedbackVectorSpec` is used to create a `FeedbackMetadata` object.
    * A `FeedbackVector` holds a reference to its `FeedbackMetadata`.
    * `FeedbackSlotKind` determines the structure and interpretation of the data within a `FeedbackSlot`.
    * `FeedbackNexus` acts as an intermediary to access and modify the feedback within a `FeedbackVector`.

5. **Consider Potential JavaScript Relevance:**  The feedback types (like `kCall`, `kLoadProperty`) directly correspond to common JavaScript operations. This suggests that the feedback mechanism is used to track how JavaScript code is executed.

6. **Identify Potential Programming Errors:** The code deals with optimizing code execution based on feedback. A potential programming error related to this could involve unexpected changes in object structure or function behavior that invalidate the collected feedback, leading to performance issues or deoptimization.

7. **Address the `.tq` Check:** The prompt explicitly asks about `.tq` files, which are related to Torque. Since the file ends in `.cc`, it's not a Torque file.

8. **Synthesize a Summary:** Combine the observations into a concise description of the file's purpose and key components.

**Self-Correction/Refinement:**

* Initially, I might focus too much on the low-level details of memory management. However, the request is for a functional summary, so focusing on the *purpose* of the classes and methods is more important.
*  The prompt asks for specific examples if there's a relationship with JavaScript. I need to think of concrete JavaScript scenarios that would trigger the different feedback types.
* The "code logic inference" aspect requires some thought. The `FeedbackMetadata::GetKind` and `SetKind` methods involving `VectorICComputer` look like they encode information, and I should try to describe that process at a high level.
* I should make sure to address all points in the prompt, including the `.tq` check and common programming errors.

By following these steps, I can arrive at a comprehensive summary of the `feedback-vector.cc` file.
好的，根据你提供的V8源代码 `v8/src/objects/feedback-vector.cc` 的内容，我们可以归纳一下它的功能：

**主要功能：**

`v8/src/objects/feedback-vector.cc` 实现了 V8 引擎中用于收集和管理 JavaScript 代码执行反馈信息的关键组件——`FeedbackVector` 及其相关的元数据结构。 这些反馈信息对于 V8 的优化编译（例如，TurboFan 和 Maglev）至关重要，它可以帮助编译器做出更智能的决策，从而提高代码的执行效率。

**详细功能点：**

1. **`FeedbackVectorSpec`**:  用于定义 `FeedbackVector` 的结构，包括需要收集的反馈信息的种类和数量。它允许程序指定需要跟踪哪些类型的操作（例如，函数调用、属性加载等）。

2. **`FeedbackMetadata`**:  存储关于 `FeedbackVector` 中每个 "槽" (slot) 的元数据，例如该槽用于记录哪种类型的反馈 (`FeedbackSlotKind`)。它还管理与闭包相关的反馈槽的参数计数。

3. **`FeedbackVector`**:  实际存储反馈信息的容器。
    * 它包含一系列的 "反馈槽" (`FeedbackSlot`)，每个槽可以存储关于特定代码位置的运行时信息。
    * 这些信息可以是类型信息、调用目标、属性访问模式等等。
    * `FeedbackVector` 与 `SharedFunctionInfo` 关联，这意味着它存储了特定函数的反馈信息。
    * 它还维护了函数的调用计数和优化状态等信息。
    * 提供了方法来创建新的 `FeedbackVector`，并初始化其槽位的值。
    * 提供了设置和清除优化代码（包括 Maglev 和 TurboFan 生成的代码）的方法。

4. **`FeedbackSlotKind`**:  一个枚举类型，定义了可以被收集的不同类型的反馈信息，例如：
    * `kCall`: 函数调用
    * `kLoadProperty`: 属性加载
    * `kStoreGlobalSloppy`/`kStoreGlobalStrict`: 全局变量存储（区分严格模式）
    * `kBinaryOp`/`kCompareOp`: 二元运算和比较运算
    * 等等。 每种 `FeedbackSlotKind` 可能需要占用一个或多个连续的槽位。

5. **`ClosureFeedbackCellArray` 和 `FeedbackCell`**:  用于存储与闭包相关的反馈信息。 `ClosureFeedbackCellArray` 是一个数组，包含多个 `FeedbackCell`，每个 `FeedbackCell` 可以存储关于闭包变量的信息。

6. **`FeedbackNexus`**:  提供了一种结构化的方式来访问和操作 `FeedbackVector` 中的特定反馈槽。它封装了对反馈信息的读取和写入操作，并考虑了线程安全问题。

**关于 .tq 结尾：**

你提到如果文件以 `.tq` 结尾，那么它是 V8 Torque 源代码。  由于 `v8/src/objects/feedback-vector.cc` 以 `.cc` 结尾，因此它是一个 **C++ 源代码文件**，而不是 Torque 源代码。

**与 JavaScript 的关系：**

`FeedbackVector` 的功能直接关系到 JavaScript 的运行时性能。 当 JavaScript 代码执行时，V8 引擎会利用 `FeedbackVector` 来收集关于代码行为的动态信息。 例如：

```javascript
function add(a, b) {
  return a + b;
}

add(1, 2); // 第一次调用
add(3, 4); // 第二次调用
add("hello", "world"); // 第三次调用，参数类型改变
```

在这个例子中，`FeedbackVector` 可能会记录以下信息：

* **`kCall`**:  `add` 函数被调用了。
* **`kBinaryOp` (在 `return a + b;` 行)**:
    * 前两次调用中，`+` 运算符的操作数都是数字 (`Smi`)。
    * 第三次调用中，操作数是字符串。

V8 的优化编译器（如 TurboFan）会读取 `FeedbackVector` 中的这些信息，并根据收集到的类型信息、调用目标等进行优化。例如，如果 `+` 运算符经常作用于数字，编译器可能会生成针对数字加法的优化代码。当参数类型改变时，这种优化可能需要调整甚至回退（去优化）。

**代码逻辑推理（假设输入与输出）：**

假设我们有一个 `FeedbackVectorSpec`，指定了一个 `kLoadProperty` 类型的反馈槽：

**假设输入：**

* `FeedbackVectorSpec` 实例，包含一个 `kLoadProperty` 类型的槽。
* 调用 `FeedbackMetadata::New(isolate, spec)` 创建 `FeedbackMetadata`。
* 调用 `FeedbackVector::New(isolate, shared_function_info, ...)` 创建 `FeedbackVector`。

**输出：**

* 创建的 `FeedbackMetadata` 对象，其内部数据结构会记录第一个槽的类型为 `kLoadProperty`。
* 创建的 `FeedbackVector` 对象，其第一个槽的初始值会被设置为一个表示未初始化的值（例如 `UninitializedSentinel`）。

**涉及用户常见的编程错误：**

虽然 `feedback-vector.cc` 是 V8 引擎的内部实现，但用户的一些编程错误可能会直接影响到反馈信息的收集和优化效果，从而影响性能。

**示例：类型不一致导致去优化**

```javascript
function multiply(a, b) {
  return a * b;
}

multiply(2, 3); // V8 可能会优化为整数乘法
multiply(2.5, 3.5); // 现在是浮点数乘法
multiply("2", 3); // 现在是字符串和数字的乘法，可能导致去优化
```

在这个例子中，如果 `multiply` 函数最初使用整数调用，V8 可能会进行优化。但如果后续调用使用了不同类型的参数（例如，浮点数或字符串），这会导致之前收集的反馈信息失效，V8 可能会放弃之前的优化，甚至进行去优化，从而降低性能。

**总结一下 `v8/src/objects/feedback-vector.cc` 的功能：**

该文件定义并实现了 V8 引擎中用于收集 JavaScript 代码运行时反馈信息的关键数据结构和方法。 这些反馈信息存储在 `FeedbackVector` 中，并通过 `FeedbackMetadata` 进行描述。  这些信息对于 V8 的优化编译至关重要，帮助引擎根据实际的运行时行为来优化代码，从而提高 JavaScript 的执行效率。 `FeedbackNexus` 提供了一种安全且结构化的方式来访问和修改这些反馈信息。 用户编写的 JavaScript 代码的行为直接影响着 `FeedbackVector` 中收集的信息，不一致的类型使用等编程模式可能导致优化失效。

Prompt: 
```
这是目录为v8/src/objects/feedback-vector.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/feedback-vector.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
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
  
"""


```