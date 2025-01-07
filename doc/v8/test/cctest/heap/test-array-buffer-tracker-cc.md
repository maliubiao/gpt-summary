Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Initial Scan and Purpose Identification:**

   - The file name `test-array-buffer-tracker.cc` immediately suggests that it's testing something related to how V8 tracks `ArrayBuffer` objects.
   - The presence of `#include "src/heap/array-buffer-sweeper.h"` and related heap headers reinforces this idea.
   - The comment "// The following tests make sure that JSArrayBuffer tracking works expected when moving the objects through various spaces during GC phases." clearly states the primary goal.

2. **Understanding the Test Structure:**

   - The code uses the `TEST()` macro, which is a common pattern in C++ testing frameworks (like gtest, which V8 uses). This means each `TEST()` block is an independent test case.
   - The tests are grouped within namespaces `v8::internal::heap`. This indicates the code under test is part of V8's internal heap management.
   - The inclusion of `CcTest::InitializeVM()`, `LocalContext env`, and `v8::Isolate* isolate` suggests the tests are setting up a minimal V8 environment to run.

3. **Analyzing Helper Functions:**

   - The anonymous namespace at the beginning defines helper functions like `IsTrackedYoung`, `IsTrackedOld`, and `IsTracked`.
   - These functions interact with `heap->array_buffer_sweeper()`, indicating they are checking if an `ArrayBufferExtension` (which is associated with a `JSArrayBuffer`) is being tracked by the sweeper in the young or old generation heap spaces.
   - The `CHECK(!(in_young && in_old))` assertion confirms that an array buffer should not be tracked in both young and old generations simultaneously.

4. **Deconstructing Individual Test Cases:**

   - **`ArrayBuffer_OnlyMC`:**  The name suggests it focuses on Major GC (Mark-Compact). The test allocates an `ArrayBuffer`, performs multiple Major GCs, and checks if the buffer is tracked and then untracked after it's no longer reachable.
   - **`ArrayBuffer_OnlyScavenge`:**  This likely focuses on Minor GC (Scavenge). Similar allocation and GC sequence, but with Minor GCs involved. The `if (v8_flags.single_generation) return;` indicates this test is specific to generational garbage collection.
   - **`ArrayBuffer_ScavengeAndMC`:**  Combines both Minor and Major GCs to test the tracking behavior across different GC types.
   - **`ArrayBuffer_Compaction`:**  The name suggests it tests array buffer tracking during heap compaction. It forces evacuation of a page and verifies the buffer remains tracked even after the page moves.
   - **`ArrayBuffer_UnregisterDuringSweep`:**  This test deals with a more complex scenario involving concurrent sweeping. It detaches an array buffer during a GC, potentially causing it to be unregistered while the sweeper is running. The comment highlights the potential for data races in concurrent scenarios.
   - **`ArrayBuffer_NonLivePromotion`:**  Focuses on incremental marking. It allocates an array buffer and then makes it unreachable *before* a Major GC. The test verifies that the buffer is *not* promoted to the old generation as live.
   - **`ArrayBuffer_LivePromotion`:** Similar to the previous test, but the array buffer remains reachable during the initial marking phase, verifying its live promotion to old generation.
   - **`ArrayBuffer_SemiSpaceCopyThenPagePromotion`:** Tests tracking during semi-space copying (part of Minor GC) and subsequent page promotion to old space.
   - **`ArrayBuffer_PagePromotion`:**  Focuses on the scenario where an entire page containing an array buffer is promoted from new to old space.
   - **`ArrayBuffer_SemiSpaceCopyMultipleTasks`:**  Likely tests the concurrency aspects of semi-space copying when multiple array buffers are involved across different pages.
   - **`ArrayBuffer_ExternalBackingStoreSizeIncreases`:**  Verifies that the tracked size of external backing stores (where `ArrayBuffer` data is stored) increases when a new `ArrayBuffer` is created.
   - **`ArrayBuffer_ExternalBackingStoreSizeDecreases`:**  Checks that the tracked size decreases after an `ArrayBuffer` is garbage collected.
   - **`ArrayBuffer_ExternalBackingStoreSizeIncreasesMarkCompact`:** Similar to the "increases" test, but specifically for Mark-Compact GC.

5. **Identifying Connections to JavaScript:**

   - The code directly uses `v8::ArrayBuffer` and `v8::Local<v8::ArrayBuffer>`, which are the C++ API counterparts of JavaScript's `ArrayBuffer`.
   - The tests manipulate these C++ objects in ways that mirror how JavaScript code would create and use `ArrayBuffer`s, triggering garbage collection.

6. **Considering Potential User Errors:**

   - The `ArrayBuffer_UnregisterDuringSweep` test hints at potential issues with manually detaching array buffers, especially in concurrent environments. If a user relies on the backing store of a detached buffer, it might be prematurely reclaimed by the sweeper.
   - Generally, incorrect assumptions about when garbage collection will occur or how long an `ArrayBuffer` will persist can lead to errors. Forgetting to maintain references to `ArrayBuffer`s can cause them to be collected unexpectedly.

7. **Formulating the Explanation:**

   - Start with a high-level summary of the file's purpose.
   - List the functionalities of the test suite, briefly explaining each test case.
   - Explain the connection to JavaScript, providing a simple example.
   - For logic and reasoning, pick a representative test case and trace its execution with hypothetical inputs.
   - Illustrate potential user errors with concrete JavaScript examples.
   - Address the Torque question (which is straightforward in this case, as the file ends in `.cc`).

By following these steps, we can systematically analyze the C++ code and generate a comprehensive explanation covering its purpose, functionalities, JavaScript relevance, logic, and potential user errors.
这个C++源代码文件 `v8/test/cctest/heap/test-array-buffer-tracker.cc` 的主要功能是**测试 V8 引擎中用于跟踪 `ArrayBuffer` 对象的机制是否正常工作**。更具体地说，它验证了在垃圾回收 (GC) 的不同阶段，`ArrayBuffer` 的跟踪状态是否符合预期。

**功能列表:**

该测试文件包含多个独立的测试用例，每个用例都针对 `ArrayBuffer` 跟踪的不同方面：

1. **`ArrayBuffer_OnlyMC`**: 测试仅进行 Major GC (Mark-Compact) 时，`ArrayBuffer` 的跟踪行为。它验证了 `ArrayBuffer` 在 Major GC 后会被移动到旧生代并继续被跟踪，直到不再被引用。
2. **`ArrayBuffer_OnlyScavenge`**: 测试仅进行 Minor GC (Scavenge) 时，`ArrayBuffer` 的跟踪行为。它验证了年轻代的 `ArrayBuffer` 在 Minor GC 后仍然被跟踪，并在晋升到老年代后继续被跟踪。
3. **`ArrayBuffer_ScavengeAndMC`**: 测试交替进行 Minor GC 和 Major GC 时，`ArrayBuffer` 的跟踪行为。它验证了 `ArrayBuffer` 在两种 GC 场景下的跟踪状态转换。
4. **`ArrayBuffer_Compaction`**: 测试在进行堆压缩时，`ArrayBuffer` 的跟踪状态是否保持不变。它验证了即使 `ArrayBuffer` 在内存中移动，跟踪机制仍然能正确工作。
5. **`ArrayBuffer_UnregisterDuringSweep`**: 测试在并发垃圾回收的 Sweeping 阶段，如果 `ArrayBuffer` 被取消注册（例如通过 `Detach` 方法），是否会正确处理，避免数据竞争等问题。这个测试特别关注线程安全。
6. **`ArrayBuffer_NonLivePromotion`**:  测试在增量标记期间，如果一个年轻代的 `ArrayBuffer` 在 Minor GC 后不再被引用，是否不会被错误地晋升到老年代。
7. **`ArrayBuffer_LivePromotion`**: 测试在增量标记期间，如果一个年轻代的 `ArrayBuffer` 在 Minor GC 后仍然被引用，是否会被正确地晋升到老年代并继续被跟踪。
8. **`ArrayBuffer_SemiSpaceCopyThenPagePromotion`**: 测试在 Minor GC 的半空间复制过程中，`ArrayBuffer` 的标记状态是否被正确保留，以及后续页面晋升到老年代时的跟踪状态。
9. **`ArrayBuffer_PagePromotion`**: 测试当包含 `ArrayBuffer` 的整个内存页从新生代晋升到老年代时，`ArrayBuffer` 的跟踪状态是否正确。
10. **`ArrayBuffer_SemiSpaceCopyMultipleTasks`**:  测试在进行半空间复制时，如果有多个 `ArrayBuffer` 分布在不同的内存页上，并发处理是否正确，特别是对于线程安全。
11. **`ArrayBuffer_ExternalBackingStoreSizeIncreases`**: 测试当创建一个新的 `ArrayBuffer` 时，V8 跟踪的外部 backing store 的大小是否正确增加。
12. **`ArrayBuffer_ExternalBackingStoreSizeDecreases`**: 测试当一个 `ArrayBuffer` 被垃圾回收后，V8 跟踪的外部 backing store 的大小是否正确减少。
13. **`ArrayBuffer_ExternalBackingStoreSizeIncreasesMarkCompact`**:  类似于第 11 个测试，但专门针对 Major GC (Mark-Compact) 场景。

**关于文件扩展名和 Torque:**

`v8/test/cctest/heap/test-array-buffer-tracker.cc` 的扩展名是 `.cc`，表示这是一个 **C++ 源代码文件**。如果它的扩展名是 `.tq`，那么它才是一个 V8 Torque 源代码文件。

**与 JavaScript 的功能关系及示例:**

`ArrayBuffer` 是 JavaScript 中用于表示原始二进制数据的内置对象。此 C++ 测试文件验证了 V8 引擎如何管理和跟踪这些 `ArrayBuffer` 对象在内存中的生命周期。

**JavaScript 示例:**

```javascript
// 创建一个 ArrayBuffer 对象
let buffer = new ArrayBuffer(1024);

// 创建一个指向 ArrayBuffer 的视图 (例如 Uint8Array)
let view = new Uint8Array(buffer);

// 向视图写入数据
view[0] = 0xFF;
view[1] = 0x00;

// ... 在后续的代码中可能不再使用 buffer 变量，
// 但如果 view 仍然被引用，buffer 仍然会被垃圾回收器跟踪。

// 如果 buffer 和 view 都不再被引用，
// V8 的垃圾回收器最终会回收 buffer 占用的内存。
```

`v8/test/cctest/heap/test-array-buffer-tracker.cc` 中的测试用例模拟了 JavaScript 中创建、使用和最终可能不再使用的 `ArrayBuffer` 对象的生命周期，并验证了 V8 的内部机制是否能正确地跟踪这些对象，以便进行正确的垃圾回收。

**代码逻辑推理 (以 `ArrayBuffer_OnlyMC` 为例):**

**假设输入:**

1. V8 引擎启动，配置为非并发 `ArrayBuffer` sweeping。
2. 创建一个大小为 100 字节的 `ArrayBuffer` 对象，并通过 `DirectHandle` 获取其内部表示 `JSArrayBuffer` 的扩展对象 `extension`。

**代码逻辑:**

1. `CHECK(v8_flags.single_generation ? IsTrackedOld(heap, extension) : IsTrackedYoung(heap, extension));`:  根据 V8 的配置（单代或分代垃圾回收），断言新创建的 `ArrayBuffer` 被正确地跟踪在年轻代或老年代。
2. `heap::InvokeAtomicMajorGC(heap);`:  执行一次 Major GC。
3. `CHECK(IsTrackedOld(heap, extension));`: 断言 `ArrayBuffer` 在 Major GC 后仍然被跟踪在老年代。
4. `heap::InvokeAtomicMajorGC(heap);`: 再次执行一次 Major GC。
5. `CHECK(IsTrackedOld(heap, extension));`:  再次断言 `ArrayBuffer` 仍然被跟踪在老年代。
6. 在代码块结束时，`ab` 和 `buf` 超出作用域，但 `extension` 变量仍然持有对 `ArrayBuffer` 内部状态的引用。
7. `heap::InvokeAtomicMajorGC(heap);`:  执行第三次 Major GC。由于 `extension` 变量没有被显式地传递到 GC 过程中，且假设外部没有其他强引用指向该 `ArrayBuffer`，这次 GC 应该会回收该 `ArrayBuffer`。
8. `CHECK(!IsTracked(heap, extension));`: 断言 `ArrayBuffer` 不再被跟踪。

**输出:**

如果所有 `CHECK` 断言都通过，则表明 `ArrayBuffer` 的跟踪机制在仅进行 Major GC 的场景下工作正常。

**涉及用户常见的编程错误:**

1. **内存泄漏:**  如果 JavaScript 代码中创建了 `ArrayBuffer` 对象，但忘记释放对其的引用，或者存在循环引用，会导致这些 `ArrayBuffer` 无法被垃圾回收，从而造成内存泄漏。测试用例尝试覆盖这种情况，确保 V8 能够正确地跟踪并最终回收不再使用的 `ArrayBuffer`。

   **JavaScript 示例 (内存泄漏):**

   ```javascript
   let leakedBuffers = [];
   function createLeak() {
       let buffer = new ArrayBuffer(1024 * 1024); // 1MB
       leakedBuffers.push(buffer); // 将 buffer 添加到全局数组，阻止其被回收
       // ... 没有移除 leakedBuffers 中元素的操作
   }

   setInterval(createLeak, 1000); // 每秒创建一个新的 ArrayBuffer 并泄漏
   ```

2. **过早回收:**  在某些情况下，如果开发者错误地认为 `ArrayBuffer` 已经不再被需要，并过早地清除了对其的引用，可能会导致后续的代码尝试访问已经被回收的内存，从而引发错误。 然而，`ArrayBuffer` 通常通过 `TypedArray` 或 `DataView` 等视图来访问，只要这些视图还在被引用，底层的 `ArrayBuffer` 就会被保留。

   **JavaScript 示例 (可能导致意外行为):**

   ```javascript
   function processBuffer() {
       let buffer = new ArrayBuffer(100);
       let view = new Uint8Array(buffer);
       // ... 使用 view 操作 buffer

       // 错误地假设 buffer 可以被立即回收，即使 view 还在使用
       buffer = null;

       // 稍后尝试访问 view
       console.log(view[0]); // 这仍然有效，因为 view 保持了对 buffer 的引用
   }

   processBuffer();
   ```

总而言之，`v8/test/cctest/heap/test-array-buffer-tracker.cc` 是 V8 引擎中至关重要的测试文件，它确保了 `ArrayBuffer` 对象的内存管理和垃圾回收机制的正确性和稳定性，这直接影响着 JavaScript 程序的性能和可靠性。

Prompt: 
```
这是目录为v8/test/cctest/heap/test-array-buffer-tracker.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/heap/test-array-buffer-tracker.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

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