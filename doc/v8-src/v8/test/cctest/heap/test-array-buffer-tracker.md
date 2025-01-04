Response: Let's break down the thought process to achieve the desired summary and JavaScript example.

1. **Understand the Goal:** The request is to summarize the functionality of the C++ code and illustrate its connection to JavaScript using a concrete example.

2. **Initial Scan and Keyword Spotting:**  Read through the C++ code, looking for recurring keywords and patterns. Key terms like `ArrayBuffer`, `tracking`, `GC`, `Scavenge`, `MC` (Mark-Compact), `promotion`, `sweep`, and `ExternalBackingStore` stand out. The presence of `TEST` macros strongly indicates this is a testing file.

3. **Identify the Core Functionality:** The tests revolve around the lifecycle of `ArrayBuffer` objects within V8's garbage collection system. The primary concern is how these buffers are tracked across different GC phases (minor, major, compaction) and how this tracking relates to memory management. The functions `IsTrackedYoung`, `IsTrackedOld`, and `IsTracked` are clearly central to this tracking mechanism.

4. **Deconstruct Individual Tests:**  Analyze each `TEST` function to understand its specific purpose.

    * `ArrayBuffer_OnlyMC`: Focuses on major GC (Mark-Compact) and verifies the `ArrayBuffer` stays tracked and is eventually untracked after garbage collection when no longer referenced.
    * `ArrayBuffer_OnlyScavenge`: Focuses on minor GC (scavenge) and its interaction with major GC. It checks tracking during minor GC and subsequent major GC.
    * `ArrayBuffer_ScavengeAndMC`: Combines minor and major GC to test the tracking state transitions.
    * `ArrayBuffer_Compaction`: Specifically tests tracking during a compaction GC.
    * `ArrayBuffer_UnregisterDuringSweep`: Addresses a potential race condition during concurrent sweeping when an `ArrayBuffer` is detached.
    * `ArrayBuffer_NonLivePromotion`:  Examines the tracking of `ArrayBuffer`s that are *not* considered live during incremental marking and promotion to old generation.
    * `ArrayBuffer_LivePromotion`: Checks the tracking of `ArrayBuffer`s that *are* considered live during incremental marking and promotion.
    * `ArrayBuffer_SemiSpaceCopyThenPagePromotion`: Tests tracking during semispace copying (minor GC) and subsequent page promotion to old generation.
    * `ArrayBuffer_PagePromotion`: Specifically focuses on tracking when an entire page containing an `ArrayBuffer` is promoted to old generation.
    * `ArrayBuffer_SemiSpaceCopyMultipleTasks`:  Seems to test concurrent semispace copying with multiple `ArrayBuffer`s on different pages, likely for thread safety.
    * `ArrayBuffer_ExternalBackingStoreSizeIncreases`: Checks if the tracked size of external memory associated with `ArrayBuffer`s increases upon creation.
    * `ArrayBuffer_ExternalBackingStoreSizeDecreases`: Verifies that the tracked size of external memory decreases after an `ArrayBuffer` is garbage collected.
    * `ArrayBuffer_ExternalBackingStoreSizeIncreasesMarkCompact`: Similar to the "Increases" test but specifically during a Mark-Compact GC.

5. **Synthesize a High-Level Summary:** Based on the deconstruction, formulate a concise description of the file's purpose. Emphasize the core concept of `ArrayBuffer` tracking through GC cycles and its goal of ensuring correct memory management.

6. **Identify JavaScript Relevance:**  Recognize that `ArrayBuffer` is a fundamental JavaScript type. The C++ code directly manages the underlying implementation of these JavaScript objects within the V8 engine.

7. **Construct a JavaScript Example:**  Create a simple JavaScript code snippet that demonstrates the creation and potential garbage collection of an `ArrayBuffer`. The example should highlight the actions that the C++ code is testing (creation, potential collection). Using `WeakRef` is a good way to observe when an object becomes eligible for garbage collection (though not a guarantee of immediate collection). Explicitly triggering garbage collection with `global.gc()` (when available) helps in demonstrating the point.

8. **Connect the C++ and JavaScript:** Explain how the C++ code's tracking mechanisms are relevant to the JavaScript example. Point out that the C++ code ensures that when the JavaScript `ArrayBuffer` is no longer reachable, its underlying memory is correctly reclaimed by the garbage collector, a process the C++ tests are verifying.

9. **Refine and Organize:**  Review the summary and JavaScript example for clarity, accuracy, and conciseness. Organize the information logically with clear headings and explanations. Ensure the example is easy to understand and directly relates to the C++ functionality.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Perhaps the code is about efficient allocation of `ArrayBuffer`s.
* **Correction:** The focus is more on the *lifecycle* and *tracking* through GC, not just allocation. The tests explicitly simulate GC scenarios.
* **Initial thought (for JS example):**  Just create and discard an `ArrayBuffer`.
* **Refinement:** Using `WeakRef` makes the connection to garbage collection more explicit and observable (though not deterministic). Mentioning `global.gc()` clarifies how to *attempt* to trigger the collection that the C++ code is testing.
* **Clarity improvement:** Ensure the language clearly explains the "why" behind the C++ tests and how they relate to the developer's experience with `ArrayBuffer` in JavaScript (correct memory management).
这个C++源代码文件 `test-array-buffer-tracker.cc` 的主要功能是**测试 V8 引擎中 ArrayBuffer 的追踪机制**。

更具体地说，它测试了在 V8 的垃圾回收（GC）过程中，`JSArrayBuffer` 对象及其相关的外部内存（backing store）如何被追踪和管理。 这些测试覆盖了以下几个方面：

**核心功能归纳:**

1. **追踪 `ArrayBuffer` 的生命周期:**  测试 `JSArrayBuffer` 在不同的 GC 阶段（新生代回收 Minor GC, 老生代回收 Major GC,  压缩 Compaction）中是否被正确地追踪。这包括对象在不同内存空间（新生代 Young Generation, 老生代 Old Generation）之间的移动和晋升 (promotion)。

2. **验证追踪状态:**  通过 `IsTrackedYoung`, `IsTrackedOld`, 和 `IsTracked` 等辅助函数，断言 `JSArrayBuffer` 在 GC 前后是否处于预期的追踪状态。

3. **测试不同的 GC 场景:**  模拟各种 GC 场景，例如只进行 Major GC，只进行 Minor GC，先进行 Minor GC 再进行 Major GC，以及进行内存压缩的 GC。

4. **处理并发扫描:**  测试在并发 ArrayBuffer 清扫 (sweeping) 过程中，如果 `ArrayBuffer` 被显式地解除关联 (detached)，引擎是否能够正确处理，避免数据竞争。

5. **检查增量标记的影响:**  在启用增量标记 (incremental marking) 的情况下，测试 `ArrayBuffer` 的标记状态在晋升到老生代时是否被正确保留。区分了应该被标记为存活 (live) 和不应该被标记为存活的 `ArrayBuffer` 的处理。

6. **测试外部内存管理:**  验证与 `ArrayBuffer` 关联的外部内存 (external backing store) 的大小在创建和垃圾回收后是否被正确地增加和减少。

**与 JavaScript 的功能关系及示例:**

这个 C++ 文件测试的底层机制直接关系到 JavaScript 中 `ArrayBuffer` 对象的内存管理。 当你在 JavaScript 中创建和使用 `ArrayBuffer` 时，V8 引擎会负责分配和回收其内存。 `test-array-buffer-tracker.cc` 中的测试确保了这个过程的正确性和效率。

**JavaScript 示例:**

```javascript
// 创建一个 ArrayBuffer
let buffer = new ArrayBuffer(1024);
console.log("ArrayBuffer 创建:", buffer.byteLength);

// 创建一个视图来操作 ArrayBuffer
let view = new Uint8Array(buffer);
view[0] = 42;

// 当 ArrayBuffer 不再被引用时，V8 的垃圾回收器会回收其占用的内存。
buffer = null;
view = null;

// 手动触发垃圾回收 (在某些环境下可用，不推荐在生产环境使用)
if (global.gc) {
  global.gc();
}

// 在垃圾回收发生后，ArrayBuffer 占用的内存应该被释放。
// test-array-buffer-tracker.cc 中的测试确保了这个过程的正确性。
```

**解释:**

1. **`let buffer = new ArrayBuffer(1024);`**: 这行 JavaScript 代码创建了一个 1024 字节的 `ArrayBuffer`。 在 V8 引擎内部，会分配相应的内存，并且 `test-array-buffer-tracker.cc` 中的测试会验证这个 `ArrayBuffer` 被正确地追踪。

2. **`buffer = null; view = null;`**:  当我们将 `buffer` 和 `view` 设置为 `null` 时，我们移除了对 `ArrayBuffer` 对象的引用。 如果没有其他对象引用它，这个 `ArrayBuffer` 就变成了垃圾回收的候选对象。

3. **`if (global.gc) { global.gc(); }`**:  这行代码尝试手动触发垃圾回收。 虽然在某些环境下 (例如 Node.js 启动时使用 `--expose-gc` 标志) 可以使用 `global.gc()`，但在一般的 Web 浏览器环境中不可用，也不推荐在生产代码中使用。 它的目的是为了演示 `ArrayBuffer` 的回收过程。

**`test-array-buffer-tracker.cc` 的作用:**

`test-array-buffer-tracker.cc` 中的 C++ 测试会模拟各种 GC 场景，验证当 JavaScript 代码执行类似上述操作时，V8 引擎能否正确地追踪 `buffer` 变量指向的 `ArrayBuffer` 对象。 它可以确保：

* 当 `ArrayBuffer` 仍然被引用时，它不会被意外回收。
* 当 `ArrayBuffer` 不再被引用时，它的内存最终会被垃圾回收器回收，避免内存泄漏。
* 在 GC 的各个阶段，`ArrayBuffer` 的状态（例如，位于新生代还是老生代）被正确记录和更新。

总而言之，`test-array-buffer-tracker.cc` 是 V8 引擎内部的一个重要测试文件，它确保了 JavaScript 中 `ArrayBuffer` 这种重要数据类型的内存管理机制的正确性和健壮性。 这直接影响到 JavaScript 程序的性能和稳定性。

Prompt: 
```
这是目录为v8/test/cctest/heap/test-array-buffer-tracker.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/api/api-inl.h"
#include "src/common/globals.h"
#include "src/execution/isolate.h"
#include "src/flags/flags.h"
#include "src/heap/array-buffer-sweeper.h"
#include "src/heap/heap-inl.h"
#include "src/heap/spaces.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/objects/objects-inl.h"
#include "test/cctest/cctest.h"
#include "test/cctest/heap/heap-utils.h"

namespace {

bool IsTrackedYoung(i::Heap* heap, i::ArrayBufferExtension* extension) {
  bool in_young = heap->array_buffer_sweeper()->young().ContainsSlow(extension);
  bool in_old = heap->array_buffer_sweeper()->old().ContainsSlow(extension);
  CHECK(!(in_young && in_old));
  return in_young;
}

bool IsTrackedOld(i::Heap* heap, i::ArrayBufferExtension* extension) {
  bool in_young = heap->array_buffer_sweeper()->young().ContainsSlow(extension);
  bool in_old = heap->array_buffer_sweeper()->old().ContainsSlow(extension);
  CHECK(!(in_young && in_old));
  return in_old;
}

bool IsTracked(i::Heap* heap, i::ArrayBufferExtension* extension) {
  bool in_young = heap->array_buffer_sweeper()->young().ContainsSlow(extension);
  bool in_old = heap->array_buffer_sweeper()->old().ContainsSlow(extension);
  CHECK(!(in_young && in_old));
  return in_young || in_old;
}

bool IsTracked(i::Heap* heap, i::Tagged<i::JSArrayBuffer> buffer) {
  return IsTracked(heap, buffer->extension());
}

}  // namespace

namespace v8 {
namespace internal {
namespace heap {

// The following tests make sure that JSArrayBuffer tracking works expected when
// moving the objects through various spaces during GC phases.

TEST(ArrayBuffer_OnlyMC) {
  v8_flags.concurrent_array_buffer_sweeping = false;

  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  Heap* heap = reinterpret_cast<Isolate*>(isolate)->heap();
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      CcTest::heap());

  ArrayBufferExtension* extension;
  {
    v8::HandleScope handle_scope(isolate);
    Local<v8::ArrayBuffer> ab = v8::ArrayBuffer::New(isolate, 100);
    DirectHandle<JSArrayBuffer> buf = v8::Utils::OpenDirectHandle(*ab);
    extension = buf->extension();
    CHECK(v8_flags.single_generation ? IsTrackedOld(heap, extension)
                                     : IsTrackedYoung(heap, extension));
    heap::InvokeAtomicMajorGC(heap);
    CHECK(IsTrackedOld(heap, extension));
    heap::InvokeAtomicMajorGC(heap);
    CHECK(IsTrackedOld(heap, extension));
  }
  heap::InvokeAtomicMajorGC(heap);
  CHECK(!IsTracked(heap, extension));
}

TEST(ArrayBuffer_OnlyScavenge) {
  if (v8_flags.single_generation) return;
  v8_flags.concurrent_array_buffer_sweeping = false;

  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  Heap* heap = reinterpret_cast<Isolate*>(isolate)->heap();
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      CcTest::heap());

  ArrayBufferExtension* extension;
  {
    v8::HandleScope handle_scope(isolate);
    Local<v8::ArrayBuffer> ab = v8::ArrayBuffer::New(isolate, 100);
    DirectHandle<JSArrayBuffer> buf = v8::Utils::OpenDirectHandle(*ab);
    extension = buf->extension();
    CHECK(IsTrackedYoung(heap, extension));
    heap::InvokeAtomicMinorGC(heap);
    CHECK(IsTrackedYoung(heap, extension));
    heap::InvokeAtomicMajorGC(heap);
    CHECK(IsTrackedOld(heap, extension));
  }
  heap::InvokeAtomicMajorGC(heap);
  CHECK(!IsTracked(heap, extension));
}

TEST(ArrayBuffer_ScavengeAndMC) {
  if (v8_flags.single_generation) return;
  v8_flags.concurrent_array_buffer_sweeping = false;

  ManualGCScope manual_gc_scope;
  CcTest::InitializeVM();
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  Heap* heap = reinterpret_cast<Isolate*>(isolate)->heap();
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      CcTest::heap());

  ArrayBufferExtension* extension;
  {
    v8::HandleScope handle_scope(isolate);
    Local<v8::ArrayBuffer> ab = v8::ArrayBuffer::New(isolate, 100);
    DirectHandle<JSArrayBuffer> buf = v8::Utils::OpenDirectHandle(*ab);
    extension = buf->extension();
    CHECK(IsTrackedYoung(heap, extension));
    heap::InvokeAtomicMinorGC(heap);
    CHECK(IsTrackedYoung(heap, extension));
    heap::InvokeAtomicMajorGC(heap);
    CHECK(IsTrackedOld(heap, extension));
    heap::InvokeAtomicMinorGC(heap);
    CHECK(IsTrackedOld(heap, extension));
  }
  heap::InvokeAtomicMinorGC(heap);
  CHECK(IsTrackedOld(heap, extension));
  heap::InvokeAtomicMajorGC(heap);
  CHECK(!IsTracked(heap, extension));
}

TEST(ArrayBuffer_Compaction) {
  if (!v8_flags.compact) return;
  ManualGCScope manual_gc_scope;
  heap::ManualEvacuationCandidatesSelectionScope
      manual_evacuation_candidate_selection_scope(manual_gc_scope);
  v8_flags.concurrent_array_buffer_sweeping = false;
  CcTest::InitializeVM();
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  Heap* heap = reinterpret_cast<Isolate*>(isolate)->heap();
  heap::AbandonCurrentlyFreeMemory(heap->old_space());

  v8::HandleScope handle_scope(isolate);
  Local<v8::ArrayBuffer> ab1 = v8::ArrayBuffer::New(isolate, 100);
  IndirectHandle<JSArrayBuffer> buf1 = v8::Utils::OpenIndirectHandle(*ab1);
  CHECK(IsTracked(heap, *buf1));
  heap::InvokeAtomicMajorGC(heap);

  PageMetadata* page_before_gc = PageMetadata::FromHeapObject(*buf1);
  heap::ForceEvacuationCandidate(page_before_gc);
  CHECK(IsTracked(heap, *buf1));

  {
    // We need to invoke GC without stack, otherwise no compaction is
    // performed.
    DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
    heap::InvokeMajorGC(heap);
  }

  PageMetadata* page_after_gc = PageMetadata::FromHeapObject(*buf1);
  CHECK(IsTracked(heap, *buf1));

  CHECK_NE(page_before_gc, page_after_gc);
}

TEST(ArrayBuffer_UnregisterDuringSweep) {
// Regular pages in old space (without compaction) are processed concurrently
// in the sweeper. If we happen to unregister a buffer (either explicitly, or
// implicitly through e.g. |Detach|) we need to sync with the sweeper
// task.
//
// Note: This test will will only fail on TSAN configurations.

// Disable verify-heap since it forces sweeping to be completed in the
// epilogue of the GC.
#ifdef VERIFY_HEAP
  i::v8_flags.verify_heap = false;
#endif  // VERIFY_HEAP
  ManualGCScope manual_gc_scope;
  i::v8_flags.concurrent_array_buffer_sweeping = false;

  CcTest::InitializeVM();
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  Heap* heap = reinterpret_cast<Isolate*>(isolate)->heap();
  {
    v8::HandleScope handle_scope(isolate);
    Local<v8::ArrayBuffer> ab = v8::ArrayBuffer::New(isolate, 100);
    DirectHandle<JSArrayBuffer> buf = v8::Utils::OpenDirectHandle(*ab);

    {
      v8::HandleScope new_handle_scope(isolate);
      // Allocate another buffer on the same page to force processing a
      // non-empty set of buffers in the last GC.
      Local<v8::ArrayBuffer> ab2 = v8::ArrayBuffer::New(isolate, 100);
      DirectHandle<JSArrayBuffer> buf2 = v8::Utils::OpenDirectHandle(*ab2);
      CHECK(IsTracked(heap, *buf));
      heap::InvokeAtomicMinorGC(heap);
      CHECK(IsTracked(heap, *buf));
      heap::InvokeAtomicMinorGC(heap);
      CHECK(IsTracked(heap, *buf));
      CHECK(IsTracked(heap, *buf2));
    }

    heap::InvokeMajorGC(heap);
    // |Detach| will cause the buffer to be |Unregister|ed. Without
    // barriers and proper synchronization this will trigger a data race on
    // TSAN.
    ab->Detach(v8::Local<v8::Value>()).Check();
  }
}

TEST(ArrayBuffer_NonLivePromotion) {
  if (!v8_flags.incremental_marking || v8_flags.separate_gc_phases) return;
  v8_flags.concurrent_array_buffer_sweeping = false;
  ManualGCScope manual_gc_scope;
  // The test verifies that the marking state is preserved when promoting
  // a buffer to old space.
  CcTest::InitializeVM();
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  Heap* heap = reinterpret_cast<Isolate*>(isolate)->heap();
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      CcTest::heap());

  {
    v8::HandleScope handle_scope(isolate);
    DirectHandle<FixedArray> root =
        heap->isolate()->factory()->NewFixedArray(1, AllocationType::kOld);
    {
      v8::HandleScope new_handle_scope(isolate);
      Local<v8::ArrayBuffer> ab = v8::ArrayBuffer::New(isolate, 100);
      DirectHandle<JSArrayBuffer> buf = v8::Utils::OpenDirectHandle(*ab);
      root->set(0, *buf);  // Buffer that should not be promoted as live.
    }
    heap::SimulateIncrementalMarking(heap, false);
    CHECK(IsTracked(heap, Cast<JSArrayBuffer>(root->get(0))));
    heap::InvokeAtomicMinorGC(heap);
    CHECK(IsTracked(heap, Cast<JSArrayBuffer>(root->get(0))));
    heap::InvokeAtomicMinorGC(heap);
    CHECK(IsTracked(heap, Cast<JSArrayBuffer>(root->get(0))));
    ArrayBufferExtension* extension =
        Cast<JSArrayBuffer>(root->get(0))->extension();
    root->set(0, ReadOnlyRoots(heap).undefined_value());
    heap::SimulateIncrementalMarking(heap, true);
    heap::InvokeAtomicMajorGC(heap);
    CHECK(!IsTracked(heap, extension));
  }
}

TEST(ArrayBuffer_LivePromotion) {
  if (!v8_flags.incremental_marking || v8_flags.separate_gc_phases) return;
  v8_flags.concurrent_array_buffer_sweeping = false;
  ManualGCScope manual_gc_scope;
  // The test verifies that the marking state is preserved when promoting
  // a buffer to old space.
  CcTest::InitializeVM();
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  Heap* heap = reinterpret_cast<Isolate*>(isolate)->heap();

  Tagged<JSArrayBuffer> raw_ab;
  {
    v8::HandleScope handle_scope(isolate);
    Handle<FixedArray> root =
        heap->isolate()->factory()->NewFixedArray(1, AllocationType::kOld);
    {
      v8::HandleScope new_handle_scope(isolate);
      Local<v8::ArrayBuffer> ab = v8::ArrayBuffer::New(isolate, 100);
      DirectHandle<JSArrayBuffer> buf = v8::Utils::OpenDirectHandle(*ab);
      root->set(0, *buf);  // Buffer that should be promoted as live.
    }
    // Store array in Global such that it is part of the root set when
    // starting incremental marking.
    v8::Global<Value> global_root(CcTest::isolate(),
                                  Utils::ToLocal(Cast<Object>(root)));
    heap::SimulateIncrementalMarking(heap, true);
    CHECK(IsTracked(heap, Cast<JSArrayBuffer>(root->get(0))));
    heap::InvokeMinorGC(heap);
    CHECK(IsTracked(heap, Cast<JSArrayBuffer>(root->get(0))));
    heap::InvokeMinorGC(heap);
    CHECK(IsTracked(heap, Cast<JSArrayBuffer>(root->get(0))));
    raw_ab = Cast<JSArrayBuffer>(root->get(0));
    root->set(0, ReadOnlyRoots(heap).undefined_value());
    // Prohibit page from being released.
    MemoryChunk::FromHeapObject(raw_ab)->MarkNeverEvacuate();
    heap::InvokeMajorGC(heap);
    CHECK(!heap->array_buffer_sweeper()->sweeping_in_progress());
    CHECK(IsTracked(heap, raw_ab));
  }
}

TEST(ArrayBuffer_SemiSpaceCopyThenPagePromotion) {
  if (!i::v8_flags.incremental_marking) return;
  if (v8_flags.minor_ms) return;
  v8_flags.concurrent_array_buffer_sweeping = false;
  ManualGCScope manual_gc_scope;
  // The test verifies that the marking state is preserved across semispace
  // copy.
  CcTest::InitializeVM();
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  Heap* heap = reinterpret_cast<Isolate*>(isolate)->heap();

  heap::SealCurrentObjects(heap);
  {
    v8::HandleScope handle_scope(isolate);
    DirectHandle<FixedArray> root =
        heap->isolate()->factory()->NewFixedArray(1, AllocationType::kOld);
    {
      v8::HandleScope new_handle_scope(isolate);
      Local<v8::ArrayBuffer> ab = v8::ArrayBuffer::New(isolate, 100);
      DirectHandle<JSArrayBuffer> buf = v8::Utils::OpenDirectHandle(*ab);
      root->set(0, *buf);  // Buffer that should be promoted as live.
      MemoryChunk::FromHeapObject(*buf)->MarkNeverEvacuate();
    }
    DirectHandleVector<FixedArray> handles(isolate);
    // Make the whole page transition from new->old, getting the buffers
    // processed in the sweeper (relying on marking information) instead of
    // processing during newspace evacuation.
    heap::FillCurrentPage(heap->new_space(), &handles);
    CHECK(IsTracked(heap, Cast<JSArrayBuffer>(root->get(0))));
    heap::InvokeAtomicMinorGC(heap);
    heap::SimulateIncrementalMarking(heap, true);
    heap::InvokeAtomicMajorGC(heap);
    CHECK(IsTracked(heap, Cast<JSArrayBuffer>(root->get(0))));
  }
}

TEST(ArrayBuffer_PagePromotion) {
  if (!i::v8_flags.incremental_marking || i::v8_flags.single_generation) return;
  i::v8_flags.concurrent_array_buffer_sweeping = false;

  ManualGCScope manual_gc_scope;
  // The test verifies that the marking state is preserved across semispace
  // copy.
  CcTest::InitializeVM();
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  Heap* heap = reinterpret_cast<Isolate*>(isolate)->heap();

  heap::SealCurrentObjects(heap);
  {
    v8::HandleScope handle_scope(isolate);
    DirectHandle<FixedArray> root =
        heap->isolate()->factory()->NewFixedArray(1, AllocationType::kOld);
    ArrayBufferExtension* extension;
    {
      v8::HandleScope new_handle_scope(isolate);
      Local<v8::ArrayBuffer> ab = v8::ArrayBuffer::New(isolate, 100);
      DirectHandle<JSArrayBuffer> buf = v8::Utils::OpenDirectHandle(*ab);
      extension = buf->extension();
      root->set(0, *buf);  // Buffer that should be promoted as live.
    }
    DirectHandleVector<FixedArray> handles(isolate);
    // Create live objects on page such that the whole page gets promoted
    heap::FillCurrentPage(heap->new_space(), &handles);
    CHECK(IsTrackedYoung(heap, extension));
    heap::SimulateIncrementalMarking(heap, true);
    heap::InvokeAtomicMajorGC(heap);
    CHECK(IsTrackedOld(heap, extension));
  }
}

UNINITIALIZED_TEST(ArrayBuffer_SemiSpaceCopyMultipleTasks) {
  if (v8_flags.optimize_for_size || v8_flags.single_generation) return;
  ManualGCScope manual_gc_scope;
  // Test allocates JSArrayBuffer on different pages before triggering a
  // full GC that performs the semispace copy. If parallelized, this test
  // ensures proper synchronization in TSAN configurations.
  v8_flags.min_semi_space_size = std::max(2 * PageMetadata::kPageSize / MB, 1);
  v8::Isolate::CreateParams create_params;
  create_params.array_buffer_allocator = CcTest::array_buffer_allocator();
  v8::Isolate* isolate = v8::Isolate::New(create_params);
  i::Isolate* i_isolate = reinterpret_cast<i::Isolate*>(isolate);
  {
    v8::Isolate::Scope isolate_scope(isolate);
    v8::HandleScope handle_scope(isolate);
    v8::Context::New(isolate)->Enter();
    Heap* heap = i_isolate->heap();

    // Ensure heap is in a clean state.
    heap::InvokeMajorGC(heap);
    heap::InvokeMajorGC(heap);

    Local<v8::ArrayBuffer> ab1 = v8::ArrayBuffer::New(isolate, 100);
    DirectHandle<JSArrayBuffer> buf1 = v8::Utils::OpenDirectHandle(*ab1);
    heap::FillCurrentPage(heap->new_space());
    Local<v8::ArrayBuffer> ab2 = v8::ArrayBuffer::New(isolate, 100);
    DirectHandle<JSArrayBuffer> buf2 = v8::Utils::OpenDirectHandle(*ab2);
    CHECK_NE(PageMetadata::FromHeapObject(*buf1),
             PageMetadata::FromHeapObject(*buf2));
    heap::InvokeAtomicMajorGC(heap);
  }
  isolate->Dispose();
}

TEST(ArrayBuffer_ExternalBackingStoreSizeIncreases) {
  if (v8_flags.single_generation) return;
  CcTest::InitializeVM();
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  Heap* heap = reinterpret_cast<Isolate*>(isolate)->heap();
  ExternalBackingStoreType type = ExternalBackingStoreType::kArrayBuffer;

  const Space* space = v8_flags.incremental_marking
                           ? static_cast<Space*>(heap->new_space())
                           : static_cast<Space*>(heap->old_space());
  const size_t backing_store_before = space->ExternalBackingStoreBytes(type);
  {
    const size_t kArraybufferSize = 117;
    v8::HandleScope handle_scope(isolate);
    Local<v8::ArrayBuffer> ab = v8::ArrayBuffer::New(isolate, kArraybufferSize);
    USE(ab);
    const size_t backing_store_after = space->ExternalBackingStoreBytes(type);
    CHECK_EQ(kArraybufferSize, backing_store_after - backing_store_before);
  }
}

TEST(ArrayBuffer_ExternalBackingStoreSizeDecreases) {
  if (v8_flags.single_generation) return;
  v8_flags.concurrent_array_buffer_sweeping = false;
  CcTest::InitializeVM();
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  Heap* heap = reinterpret_cast<Isolate*>(isolate)->heap();
  ExternalBackingStoreType type = ExternalBackingStoreType::kArrayBuffer;

  const size_t backing_store_before =
      heap->new_space()->ExternalBackingStoreBytes(type);
  {
    const size_t kArraybufferSize = 117;
    v8::HandleScope handle_scope(isolate);
    Local<v8::ArrayBuffer> ab = v8::ArrayBuffer::New(isolate, kArraybufferSize);
    USE(ab);
  }
  heap::InvokeAtomicMajorGC(heap);
  const size_t backing_store_after =
      heap->new_space()->ExternalBackingStoreBytes(type);
  CHECK_EQ(0, backing_store_after - backing_store_before);
}

TEST(ArrayBuffer_ExternalBackingStoreSizeIncreasesMarkCompact) {
  if (!v8_flags.compact) return;
  ManualGCScope manual_gc_scope;
  heap::ManualEvacuationCandidatesSelectionScope
      manual_evacuation_candidate_selection_scope(manual_gc_scope);
  v8_flags.concurrent_array_buffer_sweeping = false;
  CcTest::InitializeVM();
  LocalContext env;
  v8::Isolate* isolate = env->GetIsolate();
  Heap* heap = reinterpret_cast<Isolate*>(isolate)->heap();
  heap::AbandonCurrentlyFreeMemory(heap->old_space());
  ExternalBackingStoreType type = ExternalBackingStoreType::kArrayBuffer;

  // We need to invoke GC without stack, otherwise some objects may survive.
  DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);

  const size_t backing_store_before =
      heap->old_space()->ExternalBackingStoreBytes(type);

  const size_t kArraybufferSize = 117;
  {
    v8::HandleScope handle_scope(isolate);
    Local<v8::ArrayBuffer> ab1 =
        v8::ArrayBuffer::New(isolate, kArraybufferSize);
    IndirectHandle<JSArrayBuffer> buf1 = v8::Utils::OpenIndirectHandle(*ab1);
    CHECK(IsTracked(heap, *buf1));
    heap::InvokeAtomicMajorGC(heap);

    PageMetadata* page_before_gc = PageMetadata::FromHeapObject(*buf1);
    heap::ForceEvacuationCandidate(page_before_gc);
    CHECK(IsTracked(heap, *buf1));

    heap::InvokeMajorGC(heap);

    const size_t backing_store_after =
        heap->old_space()->ExternalBackingStoreBytes(type);
    CHECK_EQ(kArraybufferSize, backing_store_after - backing_store_before);
  }

  heap::InvokeAtomicMajorGC(heap);
  const size_t backing_store_after =
      heap->old_space()->ExternalBackingStoreBytes(type);
  CHECK_EQ(0, backing_store_after - backing_store_before);
}

}  // namespace heap
}  // namespace internal
}  // namespace v8

"""

```