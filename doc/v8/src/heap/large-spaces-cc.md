Response:
Let's break down the thought process for analyzing this C++ code and fulfilling the request.

1. **Understanding the Core Request:** The fundamental goal is to understand the functionality of `v8/src/heap/large-spaces.cc`. The request also asks about its nature (Torque, relationship to JavaScript), provides examples if applicable, and addresses potential programming errors and logic.

2. **Initial Scan and Keyword Recognition:** Quickly read through the code, looking for recognizable keywords and structures. Things that jump out include:
    * `#include`: Indicating this is C++ code.
    * `namespace v8::internal`: Confirming it's V8 internal code.
    * Class names like `LargeObjectSpace`, `OldLargeObjectSpace`, `NewLargeObjectSpace`, `CodeLargeObjectSpace`, etc. These are key entities.
    * Methods like `AllocateRaw`, `FreeDeadObjects`, `Contains`, `AddPage`, `RemovePage`, `Verify`. These suggest the core actions.
    * Mentions of `Heap`, `MemoryChunk`, `LargePageMetadata`, `AllocationObserver`, `IncrementalMarking`, `ConcurrentMarking`, `GC`. These point to V8's memory management system.
    * `DCHECK` and `SLOW_DCHECK`: Assertion macros for debugging.
    * Comments like `// Copyright`, `// -----------------------------------------------------------------------------`.

3. **Identifying the Primary Purpose:** Based on the class names and methods, it becomes clear that this file deals with managing memory for *large objects* within the V8 heap. The different `*LargeObjectSpace` classes likely represent different categories or generations of large objects.

4. **Answering the ".tq" Question:** The request explicitly asks if the file *were* named `.tq`, what it would mean. Recognize that `.tq` signifies Torque code. Since this file is `.cc`, it's standard C++.

5. **JavaScript Relationship:** Consider how large objects in V8 relate to JavaScript. Large arrays, strings, and compiled code are prime candidates for being stored in large object spaces. Think about scenarios where these are created in JavaScript.

6. **Function-by-Function Analysis (Mental or Notes):**  Go through the important classes and their methods. For each:
    * **Purpose:** What does this class/method do?
    * **Key Data:** What data does it manage or operate on?
    * **Dependencies:** What other V8 components does it interact with?
    * **Important Logic:** Are there any key algorithms or decisions made within the function?

    For example, with `LargeObjectSpace::AllocateRaw`:
    * **Purpose:** Allocate memory for a large object.
    * **Key Data:** `object_size`, `executable` flag.
    * **Dependencies:** `Heap`, `MemoryAllocator`, `IncrementalMarking`.
    * **Important Logic:** Checks for expansion limits, starts incremental marking if needed, allocates a large page, updates metadata.

7. **Code Logic Inference and Examples:**  Choose a representative function and try to trace its execution with hypothetical inputs. `OldLargeObjectSpace::AllocateRaw` is a good choice because it involves several steps. Create a simple scenario (allocating a large string) to illustrate its flow.

8. **Common Programming Errors:** Think about what could go wrong when dealing with large objects in a garbage-collected environment. Memory leaks (though V8 handles this), performance issues with excessive large object allocation, and fragmentation (though large objects are less prone to this) come to mind.

9. **Structuring the Answer:** Organize the findings logically based on the request's structure:
    * **Functionality Summary:**  Provide a high-level overview.
    * **Torque Explanation:**  Address the `.tq` question.
    * **JavaScript Relationship:**  Explain the connection and provide examples.
    * **Code Logic Inference:** Present the chosen function, assumptions, and expected output.
    * **Common Programming Errors:** List and explain potential pitfalls.

10. **Refinement and Detail:**  Review the generated answer for clarity, accuracy, and completeness. Add more specific details where necessary (e.g., mentioning the different types of large object spaces). Ensure the language is precise and avoids jargon where possible, or explains it when used. For instance, clarifying what "executable" means in the context of memory allocation.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "Maybe this file just manages a list of large objects."  **Correction:** Realized it's deeper, involving allocation, deallocation, tracking, and interaction with the garbage collector.
* **Initial thought about JavaScript:**  "Just large arrays are stored here." **Correction:**  Considered other large objects like strings and compiled code.
* **Logic inference:** First attempt might be too simple. **Refinement:** Add more details about the steps involved in allocation, like the checks for space and the involvement of the memory allocator.
* **Error examples:**  Keep them focused and relevant to the code's functionality. Avoid overly generic programming errors.

By following this structured approach, combining code analysis with knowledge of V8's architecture, and iteratively refining the understanding, it's possible to generate a comprehensive and accurate answer like the example provided in the initial prompt.
好的，让我们来分析一下 `v8/src/heap/large-spaces.cc` 这个 V8 源代码文件的功能。

**文件功能概述**

`v8/src/heap/large-spaces.cc` 文件负责管理 V8 堆中的**大对象空间 (Large Object Space)**。与存放常规大小对象的空间不同，大对象空间用于存储尺寸较大的 JavaScript 对象，例如大型数组、长字符串、编译后的代码对象等。由于这些对象尺寸较大且生命周期可能较长，V8 会将它们分配到专门的大对象空间进行管理，以优化内存分配和垃圾回收的效率。

**主要功能点:**

1. **定义大对象空间的不同类型:**
   - `LargeObjectSpace`: 作为所有大对象空间的基类，定义了通用的大对象空间操作。
   - `OldLargeObjectSpace`: 用于存储老年代的大对象。这些对象通常经历了多次垃圾回收，被认为是存活时间较长的对象。
   - `NewLargeObjectSpace`: 用于存储新生代的大对象。这些对象是最近分配的，可能在后续的 Minor GC 中被回收或晋升到老年代。
   - `CodeLargeObjectSpace`:  专门用于存储编译后的代码对象。
   - `SharedLargeObjectSpace` 和 `SharedTrustedLargeObjectSpace`: 用于存储共享堆中的大对象。
   - `TrustedLargeObjectSpace`: 用于存储受信任上下文中的大对象。

2. **大对象的分配与管理:**
   - 提供 `AllocateRaw` 方法用于分配大对象的内存空间。该方法会考虑内存对齐、是否可执行等因素。
   - 使用 `LargePageMetadata` 结构来管理每个大对象所在的内存页信息。
   - 维护一个链表 (`memory_chunk_list_`) 来跟踪所有已分配的大对象内存页。
   - 提供了 `AddPage` 和 `RemovePage` 方法来添加和移除大对象的内存页。

3. **垃圾回收相关功能:**
   - `FreeDeadObjects`: 用于回收 `NewLargeObjectSpace` 中不再使用的对象。
   - `PromoteNewLargeObject`: 将新生代大对象提升到老年代大对象空间。
   - 与增量标记 (`incremental_marking`) 和并发标记 (`concurrent_marking`) 等垃圾回收机制集成，例如在分配时进行标记。
   - 实现了 `GetObjectIterator` 用于遍历大对象空间中的所有对象，这在垃圾回收和堆校验中非常有用。

4. **内存统计和观察者模式:**
   - 跟踪大对象空间的已用大小 (`size_`)、对象大小 (`objects_size_`) 和页数 (`page_count_`)。
   - 使用 `AllocationObserver` 支持观察者模式，允许在分配大对象时执行自定义的操作。

5. **堆校验 (`VERIFY_HEAP` 宏):**
   - 提供了 `Verify` 方法用于在调试模式下验证大对象空间的一致性和正确性。

**如果 `v8/src/heap/large-spaces.cc` 以 `.tq` 结尾**

如果 `v8/src/heap/large-spaces.cc` 以 `.tq` 结尾，那么它将是 V8 的 **Torque** 源代码文件。Torque 是 V8 使用的一种类型安全的 DSL (Domain Specific Language)，用于生成 C++ 代码。Torque 代码通常用于定义 V8 的内置函数、对象布局和类型系统等。

在这种情况下，`.tq` 文件会包含用 Torque 语法编写的关于大对象空间管理的逻辑描述，然后 V8 的构建系统会将这些 `.tq` 文件编译成相应的 C++ 代码 (很可能生成类似当前 `.cc` 文件的内容)。

**与 JavaScript 的功能关系**

`v8/src/heap/large-spaces.cc` 直接关系到 JavaScript 中大对象的内存管理。当 JavaScript 代码创建以下类型的对象时，V8 可能会将其分配到大对象空间：

- **大型数组:** 当创建一个非常大的数组时，例如 `const arr = new Array(1000000);`
- **长字符串:** 当创建一个非常长的字符串时，例如 `const str = "a".repeat(1000000);`
- **编译后的代码:** V8 的 JIT 编译器 TurboFan 生成的编译后的代码对象会存储在大代码对象空间 (`CodeLargeObjectSpace`) 中。
- **某些类型的 Typed Arrays:** 非常大的 Typed Arrays 也可能被分配到大对象空间。
- **Wasm 模块的实例:** WebAssembly 模块的实例可能包含大量的数据，也可能分配到大对象空间。

**JavaScript 示例:**

```javascript
// 创建一个大型数组，很可能分配到大对象空间
const largeArray = new Array(1000000);
largeArray[999999] = 123;

// 创建一个长字符串，很可能分配到大对象空间
const longString = "This is a very long string...".repeat(10000);

// (内部操作，用户不可直接控制) 当 V8 编译一个包含复杂逻辑的函数时，
// 生成的编译后代码会存储在 CodeLargeObjectSpace 中。
function complexFunction() {
  let sum = 0;
  for (let i = 0; i < 10000; i++) {
    sum += i * i;
  }
  return sum;
}
```

**代码逻辑推理 (假设输入与输出)**

假设我们调用 `OldLargeObjectSpace::AllocateRaw` 来分配一个大小为 1MB 的大对象：

**假设输入:**

- `local_heap`: 当前线程的局部堆对象。
- `object_size`: 1048576 (1MB)。
- `executable`: `NOT_EXECUTABLE` (假设不是代码对象)。

**代码逻辑推理:**

1. **对齐大小:** `object_size` 会被对齐到分配粒度。
2. **检查是否允许扩展:**  `heap()->ShouldExpandOldGenerationOnSlowAllocation()` 和 `heap()->CanExpandOldGeneration(object_size)` 会检查堆是否允许扩展来容纳这个对象。如果空间不足或策略不允许扩展，则返回 `AllocationResult::Failure()`。
3. **触发增量标记 (如果需要):** 如果达到分配限制，可能会调用 `heap()->StartIncrementalMarkingIfAllocationLimitIsReached()` 启动增量标记。
4. **分配 LargePage:** 调用 `AllocateLargePage(object_size, executable)` 在操作系统层面分配一块足够大的内存页。
5. **创建 HeapObject:** 如果分配成功，`LargePageMetadata` 会关联到一个 `HeapObject`。
6. **更新元数据:**  更新大对象空间的 `size_`、`objects_size_`、`page_count_`，并将新的内存页添加到 `memory_chunk_list_`。
7. **标记 (如果启用):** 如果启用了粘性标记位或正在进行黑色分配，则尝试标记新分配的对象。
8. **通知扩展:** 调用 `heap()->NotifyOldGenerationExpansion()` 通知堆老年代已扩展。
9. **触发观察者 (如果激活):** 如果有注册的 `AllocationObserver`，则会调用它们。

**预期输出 (如果分配成功):**

- 返回一个 `AllocationResult` 对象，其中包含指向新分配的 `HeapObject` 的指针。
- 大对象空间的内部状态 (例如 `size_`, `objects_size_`, `page_count_`) 会相应增加。
- 系统中会增加一块新的内存页用于存储该大对象。

**如果分配失败:**

- 返回 `AllocationResult::Failure()`。

**涉及用户常见的编程错误**

虽然用户通常不直接操作 `v8/src/heap/large-spaces.cc` 中的代码，但用户在编写 JavaScript 代码时可能会遇到与大对象相关的性能问题，这些问题与大对象空间的管理方式有关：

1. **创建过多的临时大对象:**  如果在循环或频繁调用的函数中创建大量的临时大对象（例如，在每次迭代中都生成一个很大的字符串），会导致频繁的大对象分配和回收，增加垃圾回收的压力，影响性能。

   ```javascript
   // 错误示例：在循环中创建大量临时长字符串
   function processData(data) {
     const results = [];
     for (const item of data) {
       const largeString = JSON.stringify(item).repeat(100); // 每次循环都创建大字符串
       results.push(largeString);
     }
     return results;
   }
   ```

   **改进建议:** 尽量重用大对象或避免在性能关键路径上创建不必要的大对象。

2. **意外地创建大对象:** 有时候，一些看似无害的操作可能会导致意外地创建大对象，例如：

   - **读取大型文件到字符串:**  使用 `fs.readFileSync` 读取一个很大的文件内容到字符串会创建一个大的字符串对象。
   - **操作大型数组时进行非原地修改:** 某些数组操作如果不是原地修改，可能会创建新的大型数组副本。

   **排查方法:** 使用 V8 的内存分析工具 (例如 Chrome DevTools 的 Memory 面板) 来检查堆中是否存在意外的大对象。

3. **持有对大对象的长期引用:** 如果程序中存在长期持有的对大对象的引用，会导致这些大对象无法被垃圾回收，占用内存。

   ```javascript
   // 错误示例：全局变量持有对大数组的引用
   let globalLargeArray;

   function initialize() {
     globalLargeArray = new Array(1000000);
   }

   // ... 即使不再需要 globalLargeArray，它仍然占用内存，因为全局作用域的生命周期很长。
   ```

   **改进建议:**  确保不再需要的大对象能够被垃圾回收，例如通过解除引用或使用 WeakRef 等机制。

理解 `v8/src/heap/large-spaces.cc` 的功能有助于我们更好地理解 V8 的内存管理机制，并编写出更高效的 JavaScript 代码，避免与大对象相关的性能问题。

Prompt: 
```
这是目录为v8/src/heap/large-spaces.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/heap/large-spaces.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/large-spaces.h"

#include "src/base/logging.h"
#include "src/base/platform/mutex.h"
#include "src/base/sanitizer/msan.h"
#include "src/common/globals.h"
#include "src/execution/isolate.h"
#include "src/heap/combined-heap.h"
#include "src/heap/concurrent-marking.h"
#include "src/heap/heap-verifier.h"
#include "src/heap/incremental-marking.h"
#include "src/heap/large-page-metadata.h"
#include "src/heap/list.h"
#include "src/heap/marking-state-inl.h"
#include "src/heap/marking.h"
#include "src/heap/memory-allocator.h"
#include "src/heap/memory-chunk-layout.h"
#include "src/heap/mutable-page-metadata-inl.h"
#include "src/heap/remembered-set.h"
#include "src/heap/slot-set.h"
#include "src/heap/spaces-inl.h"
#include "src/logging/log.h"
#include "src/objects/objects-inl.h"
#include "src/utils/ostreams.h"

namespace v8 {
namespace internal {

// -----------------------------------------------------------------------------
// LargeObjectSpaceObjectIterator

LargeObjectSpaceObjectIterator::LargeObjectSpaceObjectIterator(
    LargeObjectSpace* space) {
  current_ = space->first_page();
}

Tagged<HeapObject> LargeObjectSpaceObjectIterator::Next() {
  while (current_ != nullptr) {
    Tagged<HeapObject> object = current_->GetObject();
    current_ = current_->next_page();
    if (!IsFreeSpaceOrFiller(object)) return object;
  }
  return Tagged<HeapObject>();
}

// -----------------------------------------------------------------------------
// OldLargeObjectSpace

LargeObjectSpace::LargeObjectSpace(Heap* heap, AllocationSpace id)
    : Space(heap, id, nullptr),
      size_(0),
      page_count_(0),
      objects_size_(0),
      pending_object_(0) {}

size_t LargeObjectSpace::Available() const {
  // We return zero here since we cannot take advantage of already allocated
  // large object memory.
  return 0;
}

void LargeObjectSpace::TearDown() {
  while (!memory_chunk_list_.Empty()) {
    LargePageMetadata* page = first_page();
    LOG(heap()->isolate(),
        DeleteEvent("LargeObjectChunk",
                    reinterpret_cast<void*>(page->ChunkAddress())));
    memory_chunk_list_.Remove(page);
    heap()->memory_allocator()->Free(MemoryAllocator::FreeMode::kImmediately,
                                     page);
  }
}

void LargeObjectSpace::AdvanceAndInvokeAllocationObservers(Address soon_object,
                                                           size_t object_size) {
  if (!heap()->IsAllocationObserverActive()) return;

  if (object_size >= allocation_counter_.NextBytes()) {
    // Ensure that there is a valid object
    heap_->CreateFillerObjectAt(soon_object, static_cast<int>(object_size));

    allocation_counter_.InvokeAllocationObservers(soon_object, object_size,
                                                  object_size);
  }

  // Large objects can be accounted immediately since no LAB is involved.
  allocation_counter_.AdvanceAllocationObservers(object_size);
}

void LargeObjectSpace::AddAllocationObserver(AllocationObserver* observer) {
  allocation_counter_.AddAllocationObserver(observer);
}

void LargeObjectSpace::RemoveAllocationObserver(AllocationObserver* observer) {
  allocation_counter_.RemoveAllocationObserver(observer);
}

AllocationResult OldLargeObjectSpace::AllocateRaw(LocalHeap* local_heap,
                                                  int object_size) {
  return AllocateRaw(local_heap, object_size, NOT_EXECUTABLE);
}

AllocationResult OldLargeObjectSpace::AllocateRaw(LocalHeap* local_heap,
                                                  int object_size,
                                                  Executability executable) {
  object_size = ALIGN_TO_ALLOCATION_ALIGNMENT(object_size);
  DCHECK_IMPLIES(identity() == SHARED_LO_SPACE,
                 !allocation_counter_.HasAllocationObservers());
  DCHECK_IMPLIES(identity() == SHARED_LO_SPACE,
                 pending_object() == kNullAddress);

  // Check if we want to force a GC before growing the old space further.
  // If so, fail the allocation.
  if (!heap()->ShouldExpandOldGenerationOnSlowAllocation(
          local_heap, AllocationOrigin::kRuntime) ||
      !heap()->CanExpandOldGeneration(object_size)) {
    return AllocationResult::Failure();
  }

  heap()->StartIncrementalMarkingIfAllocationLimitIsReached(
      local_heap, heap()->GCFlagsForIncrementalMarking(),
      kGCCallbackScheduleIdleGarbageCollection);

  LargePageMetadata* page = AllocateLargePage(object_size, executable);
  if (page == nullptr) return AllocationResult::Failure();
  Tagged<HeapObject> object = page->GetObject();
  if (local_heap->is_main_thread() && identity() != SHARED_LO_SPACE) {
    UpdatePendingObject(object);
  }
  if (v8_flags.sticky_mark_bits ||
      heap()->incremental_marking()->black_allocation()) {
    heap()->marking_state()->TryMarkAndAccountLiveBytes(object, object_size);
  }
  DCHECK_IMPLIES(heap()->incremental_marking()->black_allocation(),
                 heap()->marking_state()->IsMarked(object));
  page->Chunk()->InitializationMemoryFence();
  heap()->NotifyOldGenerationExpansion(local_heap, identity(), page);

  if (local_heap->is_main_thread() && identity() != SHARED_LO_SPACE) {
    AdvanceAndInvokeAllocationObservers(object.address(),
                                        static_cast<size_t>(object_size));
  }
  return AllocationResult::FromObject(object);
}

LargePageMetadata* LargeObjectSpace::AllocateLargePage(
    int object_size, Executability executable) {
  base::MutexGuard expansion_guard(heap_->heap_expansion_mutex());

  if (identity() != NEW_LO_SPACE &&
      !heap()->IsOldGenerationExpansionAllowed(object_size, expansion_guard)) {
    return nullptr;
  }

  LargePageMetadata* page = heap()->memory_allocator()->AllocateLargePage(
      this, object_size, executable);
  if (page == nullptr) return nullptr;
  DCHECK_GE(page->area_size(), static_cast<size_t>(object_size));

  {
    base::RecursiveMutexGuard guard(&allocation_mutex_);
    AddPage(page, object_size);
  }

  return page;
}

size_t LargeObjectSpace::CommittedPhysicalMemory() const {
  // On a platform that provides lazy committing of memory, we over-account
  // the actually committed memory. There is no easy way right now to support
  // precise accounting of committed memory in large object space.
  return CommittedMemory();
}

void OldLargeObjectSpace::PromoteNewLargeObject(LargePageMetadata* page) {
  MemoryChunk* chunk = page->Chunk();
  DCHECK_EQ(page->owner_identity(), NEW_LO_SPACE);
  DCHECK(chunk->IsLargePage());
  DCHECK(chunk->IsFlagSet(MemoryChunk::FROM_PAGE));
  DCHECK(!chunk->IsFlagSet(MemoryChunk::TO_PAGE));
  PtrComprCageBase cage_base(heap()->isolate());
  static_cast<LargeObjectSpace*>(page->owner())->RemovePage(page);
  chunk->ClearFlagNonExecutable(MemoryChunk::FROM_PAGE);
  chunk->SetOldGenerationPageFlags(
      heap()->incremental_marking()->marking_mode(), LO_SPACE);
  AddPage(page, static_cast<size_t>(page->GetObject()->Size(cage_base)));
}

void LargeObjectSpace::AddPage(LargePageMetadata* page, size_t object_size) {
  size_ += static_cast<int>(page->size());
  AccountCommitted(page->size());
  objects_size_ += object_size;
  page_count_++;
  memory_chunk_list_.PushBack(page);
  page->set_owner(this);
  ForAll<ExternalBackingStoreType>(
      [this, page](ExternalBackingStoreType type, int index) {
        IncrementExternalBackingStoreBytes(
            type, page->ExternalBackingStoreBytes(type));
      });
}

void LargeObjectSpace::RemovePage(LargePageMetadata* page) {
  size_ -= static_cast<int>(page->size());
  AccountUncommitted(page->size());
  page_count_--;
  memory_chunk_list_.Remove(page);
  page->set_owner(nullptr);
  ForAll<ExternalBackingStoreType>(
      [this, page](ExternalBackingStoreType type, int index) {
        DecrementExternalBackingStoreBytes(
            type, page->ExternalBackingStoreBytes(type));
      });
}

void LargeObjectSpace::ShrinkPageToObjectSize(LargePageMetadata* page,
                                              Tagged<HeapObject> object,
                                              size_t object_size) {
  MemoryChunk* chunk = page->Chunk();
#ifdef DEBUG
  PtrComprCageBase cage_base(heap()->isolate());
  DCHECK_EQ(object, page->GetObject());
  DCHECK_EQ(object_size, page->GetObject()->Size(cage_base));
  DCHECK_EQ(chunk->executable(), NOT_EXECUTABLE);
#endif  // DEBUG

  const size_t used_committed_size =
      ::RoundUp(chunk->Offset(object.address()) + object_size,
                MemoryAllocator::GetCommitPageSize());

  // Object shrunk since last GC.
  if (object_size < page->area_size()) {
    page->ClearOutOfLiveRangeSlots(object.address() + object_size);
    const Address new_area_end = page->area_start() + object_size;

    // Object shrunk enough that we can even free some OS pages.
    if (used_committed_size < page->size()) {
      const size_t bytes_to_free = page->size() - used_committed_size;
      heap()->memory_allocator()->PartialFreeMemory(
          page, chunk->address() + used_committed_size, bytes_to_free,
          new_area_end);
      size_ -= bytes_to_free;
      AccountUncommitted(bytes_to_free);
    } else {
      // Can't free OS page but keep object area up-to-date.
      page->set_area_end(new_area_end);
    }
  }

  DCHECK_EQ(used_committed_size, page->size());
  DCHECK_EQ(object_size, page->area_size());
}

bool LargeObjectSpace::Contains(Tagged<HeapObject> object) const {
  MemoryChunkMetadata* chunk = MemoryChunkMetadata::FromHeapObject(object);

  bool owned = (chunk->owner() == this);

  SLOW_DCHECK(!owned || ContainsSlow(object.address()));

  return owned;
}

bool LargeObjectSpace::ContainsSlow(Address addr) const {
  MemoryChunk* chunk = MemoryChunk::FromAddress(addr);
  for (const LargePageMetadata* page : *this) {
    if (page->Chunk() == chunk) return true;
  }
  return false;
}

std::unique_ptr<ObjectIterator> LargeObjectSpace::GetObjectIterator(
    Heap* heap) {
  return std::unique_ptr<ObjectIterator>(
      new LargeObjectSpaceObjectIterator(this));
}

#ifdef VERIFY_HEAP
// We do not assume that the large object iterator works, because it depends
// on the invariants we are checking during verification.
void LargeObjectSpace::Verify(Isolate* isolate,
                              SpaceVerificationVisitor* visitor) const {
  size_t external_backing_store_bytes[static_cast<int>(
      ExternalBackingStoreType::kNumValues)] = {0};

  PtrComprCageBase cage_base(isolate);
  for (const LargePageMetadata* chunk = first_page(); chunk != nullptr;
       chunk = chunk->next_page()) {
    visitor->VerifyPage(chunk);

    // Each chunk contains an object that starts at the large object page's
    // object area start.
    Tagged<HeapObject> object = chunk->GetObject();
    PageMetadata* page = PageMetadata::FromHeapObject(object);
    CHECK(object.address() == page->area_start());

    // Only certain types may be in the large object space:
#define V(Name) Is##Name(object, cage_base) ||
    const bool is_valid_lo_space_object =
        DYNAMICALLY_SIZED_HEAP_OBJECT_LIST(V) false;
#undef V
    if (!is_valid_lo_space_object) {
      i::Print(object);
      FATAL("Found invalid Object (instance_type=%i) in large object space.",
            object->map(cage_base)->instance_type());
    }

    // Invoke visitor on each object.
    visitor->VerifyObject(object);

    ForAll<ExternalBackingStoreType>(
        [chunk, &external_backing_store_bytes](ExternalBackingStoreType type,
                                               int index) {
          external_backing_store_bytes[index] +=
              chunk->ExternalBackingStoreBytes(type);
        });

    visitor->VerifyPageDone(chunk);
  }
  ForAll<ExternalBackingStoreType>(
      [this, external_backing_store_bytes](ExternalBackingStoreType type,
                                           int index) {
        CHECK_EQ(external_backing_store_bytes[index],
                 ExternalBackingStoreBytes(type));
      });
}
#endif

#ifdef DEBUG
void LargeObjectSpace::Print() {
  StdoutStream os;
  LargeObjectSpaceObjectIterator it(this);
  for (Tagged<HeapObject> obj = it.Next(); !obj.is_null(); obj = it.Next()) {
    i::Print(obj, os);
  }
}
#endif  // DEBUG

void LargeObjectSpace::UpdatePendingObject(Tagged<HeapObject> object) {
  base::SharedMutexGuard<base::kExclusive> guard(&pending_allocation_mutex_);
  pending_object_.store(object.address(), std::memory_order_release);
}

OldLargeObjectSpace::OldLargeObjectSpace(Heap* heap)
    : LargeObjectSpace(heap, LO_SPACE) {}

OldLargeObjectSpace::OldLargeObjectSpace(Heap* heap, AllocationSpace id)
    : LargeObjectSpace(heap, id) {}

NewLargeObjectSpace::NewLargeObjectSpace(Heap* heap, size_t capacity)
    : LargeObjectSpace(heap, NEW_LO_SPACE), capacity_(capacity) {}

AllocationResult NewLargeObjectSpace::AllocateRaw(LocalHeap* local_heap,
                                                  int object_size) {
  object_size = ALIGN_TO_ALLOCATION_ALIGNMENT(object_size);
  DCHECK(local_heap->is_main_thread());
  // Do not allocate more objects if promoting the existing object would exceed
  // the old generation capacity.
  if (!heap()->CanExpandOldGeneration(SizeOfObjects())) {
    return AllocationResult::Failure();
  }

  // Allocation for the first object must succeed independent from the capacity.
  if (SizeOfObjects() > 0 && static_cast<size_t>(object_size) > Available()) {
    if (!v8_flags.separate_gc_phases ||
        !heap()->ShouldExpandYoungGenerationOnSlowAllocation(object_size)) {
      return AllocationResult::Failure();
    }
  }

  LargePageMetadata* page = AllocateLargePage(object_size, NOT_EXECUTABLE);
  if (page == nullptr) return AllocationResult::Failure();

  // The size of the first object may exceed the capacity.
  capacity_ = std::max(capacity_, SizeOfObjects());

  Tagged<HeapObject> result = page->GetObject();
  MemoryChunk* chunk = page->Chunk();
  chunk->SetFlagNonExecutable(MemoryChunk::TO_PAGE);
  UpdatePendingObject(result);
  if (v8_flags.minor_ms) {
    page->ClearLiveness();
  }
  chunk->InitializationMemoryFence();
  DCHECK(chunk->IsLargePage());
  DCHECK_EQ(page->owner_identity(), NEW_LO_SPACE);
  AdvanceAndInvokeAllocationObservers(result.address(),
                                      static_cast<size_t>(object_size));
  return AllocationResult::FromObject(result);
}

size_t NewLargeObjectSpace::Available() const {
  DCHECK_GE(capacity_, SizeOfObjects());
  return capacity_ - SizeOfObjects();
}

void NewLargeObjectSpace::Flip() {
  for (LargePageMetadata* page = first_page(); page != nullptr;
       page = page->next_page()) {
    MemoryChunk* chunk = page->Chunk();
    chunk->SetFlagNonExecutable(MemoryChunk::FROM_PAGE);
    chunk->ClearFlagNonExecutable(MemoryChunk::TO_PAGE);
  }
}

void NewLargeObjectSpace::FreeDeadObjects(
    const std::function<bool(Tagged<HeapObject>)>& is_dead) {
  bool is_marking = heap()->incremental_marking()->IsMarking();
  DCHECK_IMPLIES(v8_flags.minor_ms, !is_marking);
  DCHECK_IMPLIES(is_marking, heap()->incremental_marking()->IsMajorMarking());
  size_t surviving_object_size = 0;
  PtrComprCageBase cage_base(heap()->isolate());
  for (auto it = begin(); it != end();) {
    LargePageMetadata* page = *it;
    it++;
    Tagged<HeapObject> object = page->GetObject();
    if (is_dead(object)) {
      RemovePage(page);
      if (v8_flags.concurrent_marking && is_marking) {
        heap()->concurrent_marking()->ClearMemoryChunkData(page);
      }
      heap()->memory_allocator()->Free(MemoryAllocator::FreeMode::kImmediately,
                                       page);
    } else {
      surviving_object_size += static_cast<size_t>(object->Size(cage_base));
    }
  }
  // Right-trimming does not update the objects_size_ counter. We are lazily
  // updating it after every GC.
  objects_size_ = surviving_object_size;
}

void NewLargeObjectSpace::SetCapacity(size_t capacity) {
  capacity_ = std::max(capacity, SizeOfObjects());
}

CodeLargeObjectSpace::CodeLargeObjectSpace(Heap* heap)
    : OldLargeObjectSpace(heap, CODE_LO_SPACE) {}

AllocationResult CodeLargeObjectSpace::AllocateRaw(LocalHeap* local_heap,
                                                   int object_size) {
  return OldLargeObjectSpace::AllocateRaw(local_heap, object_size, EXECUTABLE);
}

void CodeLargeObjectSpace::AddPage(LargePageMetadata* page,
                                   size_t object_size) {
  OldLargeObjectSpace::AddPage(page, object_size);
}

void CodeLargeObjectSpace::RemovePage(LargePageMetadata* page) {
  heap()->isolate()->RemoveCodeMemoryChunk(page);
  OldLargeObjectSpace::RemovePage(page);
}

SharedLargeObjectSpace::SharedLargeObjectSpace(Heap* heap)
    : OldLargeObjectSpace(heap, SHARED_LO_SPACE) {}

SharedTrustedLargeObjectSpace::SharedTrustedLargeObjectSpace(Heap* heap)
    : OldLargeObjectSpace(heap, SHARED_TRUSTED_LO_SPACE) {}

TrustedLargeObjectSpace::TrustedLargeObjectSpace(Heap* heap)
    : OldLargeObjectSpace(heap, TRUSTED_LO_SPACE) {}

}  // namespace internal
}  // namespace v8

"""

```