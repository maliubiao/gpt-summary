Response: The user wants a summary of the provided C++ code, specifically the `v8/test/unittests/heap/heap-unittest.cc` file. I need to identify the main functionalities tested in this file and their relevance to JavaScript.

**Plan:**

1. **Identify the core purpose:** The filename and the test structure (`TEST`, `TEST_F`) strongly suggest this is a unit test file for the V8 heap component.
2. **Analyze the test cases:**  Go through each `TEST` and `TEST_F` function, understanding what aspect of the heap is being tested. Keywords like `YoungGenerationSizeFromOldGenerationSize`, `GenerationSizesFromHeapSize`, `ASLR`, `ExternalLimit`, `HeapLayout`, `GrowAndShrinkNewSpace`, `RememberedSet`, etc., are good indicators of the functionality being tested.
3. **Group related tests:**  Organize the findings into logical categories based on the heap functionalities being tested.
4. **Determine the relation to JavaScript:**  For each category, consider how the underlying heap mechanism relates to JavaScript behavior. This often involves how memory is managed for JavaScript objects, garbage collection, and performance optimizations.
5. **Provide JavaScript examples:** Where a connection exists, create simple JavaScript code snippets that demonstrate the concept or feature being tested in the C++ code.
这个C++源代码文件 `v8/test/unittests/heap/heap-unittest.cc` 是 **V8 JavaScript 引擎** 中 **堆 (Heap)** 组件的 **单元测试** 文件。  它的主要功能是 **测试 V8 引擎中堆的各种行为和特性**，确保堆的实现符合预期，没有 bug。

具体来说，这个文件包含了一系列独立的测试用例（通过 `TEST` 和 `TEST_F` 宏定义），每个测试用例都针对堆的某个特定方面进行验证。

以下是该文件测试的一些主要功能归纳：

*   **堆大小计算和管理:**
    *   测试根据老生代大小计算新生代大小的逻辑 (`YoungGenerationSizeFromOldGenerationSize`)。
    *   测试根据总堆大小计算新生代和老生代大小的逻辑 (`GenerationSizesFromHeapSize`)。
    *   测试根据物理内存大小计算堆大小的逻辑 (`HeapSizeFromPhysicalMemory`)。
    *   测试新生代空间的增长和收缩 (`GrowAndShrinkNewSpace`, `CollectingAllAvailableGarbageShrinksNewSpace`)。
*   **地址空间布局随机化 (ASLR):**
    *   测试堆的内存分配地址是否具有一定的随机性 (`ASLR`)，提高安全性。
*   **外部内存限制:**
    *   测试外部（非 V8 管理）内存的软限制 (`ExternalLimitDefault`, `ExternalLimitStaysAboveDefaultForExplicitHandling`)。这与 JavaScript 中使用 `ArrayBuffer` 等外部资源有关。
*   **堆布局 (Heap Layout):**
    *   在指针压缩启用的情况下，测试堆内不同空间（老生代、代码空间等）的内存块是否位于预期的地址范围内 (`HeapLayout`)。
*   **对象分配:**
    *   测试经过优化的函数分配的对象是否总是在新生代 (`OptimizedAllocationAlwaysInNewSpace`)。
*   **记忆集 (Remembered Set):**
    *   测试在对象从新生代晋升到老生代时，老生代到新生代的引用是否正确地插入到记忆集中 (`RememberedSet_InsertOnPromotingObjectToOld`)，这对于垃圾回收器跟踪对象引用至关重要。
*   **垃圾回收相关:**
    *   测试特定的垃圾回收场景，例如在增量标记期间新生代空间是否会增长 (`SemiSpaceNewSpaceGrowsDuringFullGCIncrementalMarking`)。
    *   测试一些特定的垃圾回收相关的 bug 修复 (`Regress978156`, `Regress341769455`, `Regress364396306`)。
    *   测试黑分配页 (Black Allocated Pages) 的机制 (`BlackAllocatedPages`)，这是增量标记中的一种优化。
    *   测试分配超时机制 (`AllocationTimeout`)，用于模拟内存压力情况下的行为。
*   **堆空间包含判断:**
    *   测试判断一个地址是否属于特定堆空间的函数 (`ContainsSlow`)。

**与 JavaScript 的关系及示例:**

这个测试文件直接测试的是 V8 引擎的底层实现，但这些底层机制直接影响着 JavaScript 的运行和性能。以下是一些功能与 JavaScript 关系的示例：

1. **堆大小管理和垃圾回收:**  JavaScript 中创建的对象（包括普通对象、数组、函数等）都分配在堆上。堆的大小、新生代和老生代的划分、以及垃圾回收机制直接影响着 JavaScript 程序的内存使用和性能。频繁的垃圾回收可能会导致程序卡顿。

    ```javascript
    // JavaScript 中创建的对象会分配在堆上
    let obj = {};
    let arr = [1, 2, 3];
    function foo() {}
    ```

2. **外部内存限制:**  JavaScript 可以通过 `ArrayBuffer` 和 `SharedArrayBuffer` 等 API 使用外部内存。V8 的外部内存限制机制可以防止 JavaScript 代码过度使用外部内存，导致系统崩溃。

    ```javascript
    // 创建一个 1MB 的 ArrayBuffer，这部分内存由 JavaScript 管理，但可能在 V8 堆外部
    let buffer = new ArrayBuffer(1024 * 1024);
    ```

3. **对象分配和性能优化:**  V8 引擎会对 JavaScript 代码进行优化。测试中提到的 "经过优化的函数分配的对象是否总是在新生代" 就与这种优化有关。新生代垃圾回收更频繁、成本更低，将新创建的对象放在新生代可以提高垃圾回收效率。

    ```javascript
    function Point(x, y) {
      this.x = x;
      this.y = y;
    }

    // V8 可能会对 Point 的构造函数进行优化，并尝试将新创建的 Point 对象分配在新生代
    let p1 = new Point(1, 2);
    let p2 = new Point(3, 4);
    ```

4. **记忆集和增量标记:**  JavaScript 的垃圾回收是自动的。记忆集和增量标记是 V8 中用于优化垃圾回收的技术。记忆集用于记录老生代对象对新生代对象的引用，增量标记则允许垃圾回收过程分步进行，减少主线程的暂停时间，提升用户体验。

    ```javascript
    let parent = {};
    let child = {};
    parent.child = child; // 老生代对象 parent 引用了新生代对象 child
    ```

总而言之，`v8/test/unittests/heap/heap-unittest.cc` 这个文件通过大量的单元测试，确保 V8 引擎的堆组件能够正确、高效地管理 JavaScript 对象的内存，并为 JavaScript 的性能和稳定性提供保障。虽然开发者通常不需要直接接触这些底层细节，但理解这些机制有助于更好地理解 JavaScript 的运行原理和性能瓶颈。

Prompt: 
```
这是目录为v8/test/unittests/heap/heap-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/heap.h"

#include <cmath>
#include <iostream>
#include <limits>
#include <utility>

#include "include/v8-isolate.h"
#include "include/v8-object.h"
#include "src/common/globals.h"
#include "src/flags/flags.h"
#include "src/handles/handles-inl.h"
#include "src/heap/gc-tracer-inl.h"
#include "src/heap/gc-tracer.h"
#include "src/heap/heap-layout-inl.h"
#include "src/heap/heap-layout.h"
#include "src/heap/marking-state-inl.h"
#include "src/heap/minor-mark-sweep.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/heap/remembered-set.h"
#include "src/heap/safepoint.h"
#include "src/heap/spaces-inl.h"
#include "src/heap/trusted-range.h"
#include "src/objects/free-space-inl.h"
#include "src/objects/js-array-buffer-inl.h"
#include "src/sandbox/external-pointer-table.h"
#include "test/unittests/heap/heap-utils.h"
#include "test/unittests/test-utils.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace v8 {
namespace internal {

using HeapTest = TestWithHeapInternalsAndContext;

TEST(Heap, YoungGenerationSizeFromOldGenerationSize) {
  const size_t pm = i::Heap::kPointerMultiplier;
  const size_t hlm = i::Heap::kHeapLimitMultiplier;
  v8_flags.scavenger_max_new_space_capacity_mb = 64;

  // Low memory
  ASSERT_EQ((v8_flags.minor_ms ? 4 : 3) * 512u * pm * KB,
            i::Heap::YoungGenerationSizeFromOldGenerationSize(128u * hlm * MB));
  // High memory
  ASSERT_EQ(v8_flags.minor_ms ? 2 * i::Heap::DefaultMaxSemiSpaceSize()
                              : 3 * 16u / hlm * pm * MB,
            i::Heap::YoungGenerationSizeFromOldGenerationSize(256u * hlm * MB));
  ASSERT_EQ(v8_flags.minor_ms ? 2 * i::Heap::DefaultMaxSemiSpaceSize()
                              : 3 * 32u / hlm * pm * MB,
            i::Heap::YoungGenerationSizeFromOldGenerationSize(512u * hlm * MB));
  ASSERT_EQ(v8_flags.minor_ms ? 2 * i::Heap::DefaultMaxSemiSpaceSize()
                              : 3 * 64u / hlm * pm * MB,
            i::Heap::YoungGenerationSizeFromOldGenerationSize(1u * hlm * GB));
}

TEST(Heap, GenerationSizesFromHeapSize) {
  const size_t pm = i::Heap::kPointerMultiplier;
  const size_t hlm = i::Heap::kHeapLimitMultiplier;
  v8_flags.scavenger_max_new_space_capacity_mb = 64;

  size_t old, young;

  // Low memory
  i::Heap::GenerationSizesFromHeapSize(1 * KB, &young, &old);
  ASSERT_EQ(0u, old);
  ASSERT_EQ(0u, young);

  // On tiny heap max semi space capacity is set to the default capacity which
  // MinorMS does not double.
  i::Heap::GenerationSizesFromHeapSize(
      1 * KB + (v8_flags.minor_ms ? 2 : 3) * 512u * pm * KB, &young, &old);
  ASSERT_EQ(1u * KB, old);
  ASSERT_EQ((v8_flags.minor_ms ? 2 : 3) * 512u * pm * KB, young);

  i::Heap::GenerationSizesFromHeapSize(
      128 * hlm * MB + (v8_flags.minor_ms ? 4 : 3) * 512 * pm * KB, &young,
      &old);
  ASSERT_EQ(128u * hlm * MB, old);
  ASSERT_EQ((v8_flags.minor_ms ? 4 : 3) * 512u * pm * KB, young);

  // High memory
  i::Heap::GenerationSizesFromHeapSize(
      256u * hlm * MB + (v8_flags.minor_ms
                             ? 2 * i::Heap::DefaultMaxSemiSpaceSize()
                             : 3 * 16 / hlm * pm * MB),
      &young, &old);
  ASSERT_EQ(256u * hlm * MB, old);
  ASSERT_EQ(v8_flags.minor_ms ? 2 * i::Heap::DefaultMaxSemiSpaceSize()
                              : 3 * 16 / hlm * pm * MB,
            young);

  i::Heap::GenerationSizesFromHeapSize(
      512u * hlm * MB + (v8_flags.minor_ms
                             ? 2 * i::Heap::DefaultMaxSemiSpaceSize()
                             : 3 * 32 / hlm * pm * MB),
      &young, &old);
  ASSERT_EQ(512u * hlm * MB, old);
  ASSERT_EQ(v8_flags.minor_ms ? 2 * i::Heap::DefaultMaxSemiSpaceSize()
                              : 3 * 32U / hlm * pm * MB,
            young);

  i::Heap::GenerationSizesFromHeapSize(
      1u * hlm * GB + (v8_flags.minor_ms
                           ? 2 * i::Heap::DefaultMaxSemiSpaceSize()
                           : 3 * 64 / hlm * pm * MB),
      &young, &old);
  ASSERT_EQ(1u * hlm * GB, old);
  ASSERT_EQ(v8_flags.minor_ms ? 2 * i::Heap::DefaultMaxSemiSpaceSize()
                              : 3 * 64U / hlm * pm * MB,
            young);
}

TEST(Heap, HeapSizeFromPhysicalMemory) {
  const size_t pm = i::Heap::kPointerMultiplier;
  const size_t hlm = i::Heap::kHeapLimitMultiplier;
  v8_flags.scavenger_max_new_space_capacity_mb = 64;

  // The expected value is old_generation_size + semi_space_multiplier *
  // semi_space_size.

  // Low memory
  ASSERT_EQ(128 * hlm * MB + (v8_flags.minor_ms ? 4 : 3) * 512 * pm * KB,
            i::Heap::HeapSizeFromPhysicalMemory(0u));
  ASSERT_EQ(128 * hlm * MB + (v8_flags.minor_ms ? 4 : 3) * 512 * pm * KB,
            i::Heap::HeapSizeFromPhysicalMemory(512u * MB));
  // High memory
  ASSERT_EQ(256 * hlm * MB + (v8_flags.minor_ms
                                  ? 2 * i::Heap::DefaultMaxSemiSpaceSize()
                                  : 3 * 16 / hlm * pm * MB),
            i::Heap::HeapSizeFromPhysicalMemory(1u * GB));
  ASSERT_EQ(512 * hlm * MB + (v8_flags.minor_ms
                                  ? 2 * i::Heap::DefaultMaxSemiSpaceSize()
                                  : 3 * 32 / hlm * pm * MB),
            i::Heap::HeapSizeFromPhysicalMemory(2u * GB));
  ASSERT_EQ(
      1 * hlm * GB + (v8_flags.minor_ms ? 2 * i::Heap::DefaultMaxSemiSpaceSize()
                                        : 3 * 64 / hlm * pm * MB),
      i::Heap::HeapSizeFromPhysicalMemory(static_cast<uint64_t>(4u) * GB));
  ASSERT_EQ(
      1 * hlm * GB + (v8_flags.minor_ms ? 2 * i::Heap::DefaultMaxSemiSpaceSize()
                                        : 3 * 64 / hlm * pm * MB),
      i::Heap::HeapSizeFromPhysicalMemory(static_cast<uint64_t>(8u) * GB));
}

TEST_F(HeapTest, ASLR) {
#if V8_TARGET_ARCH_X64
#if V8_OS_DARWIN
  Heap* heap = i_isolate()->heap();
  std::set<void*> hints;
  for (int i = 0; i < 1000; i++) {
    hints.insert(heap->GetRandomMmapAddr());
  }
  if (hints.size() == 1) {
    EXPECT_TRUE((*hints.begin()) == nullptr);
    EXPECT_TRUE(i::GetRandomMmapAddr() == nullptr);
  } else {
    // It is unlikely that 1000 random samples will collide to less then 500
    // values.
    EXPECT_GT(hints.size(), 500u);
    const uintptr_t kRegionMask = 0xFFFFFFFFu;
    void* first = *hints.begin();
    for (void* hint : hints) {
      uintptr_t diff = reinterpret_cast<uintptr_t>(first) ^
                       reinterpret_cast<uintptr_t>(hint);
      EXPECT_LE(diff, kRegionMask);
    }
  }
#endif  // V8_OS_DARWIN
#endif  // V8_TARGET_ARCH_X64
}

TEST_F(HeapTest, ExternalLimitDefault) {
  Heap* heap = i_isolate()->heap();
  EXPECT_EQ(kExternalAllocationSoftLimit, heap->external_memory_soft_limit());
}

TEST_F(HeapTest, ExternalLimitStaysAboveDefaultForExplicitHandling) {
  v8_isolate()->AdjustAmountOfExternalAllocatedMemory(+10 * MB);
  v8_isolate()->AdjustAmountOfExternalAllocatedMemory(-10 * MB);
  Heap* heap = i_isolate()->heap();
  EXPECT_GE(heap->external_memory_soft_limit(), kExternalAllocationSoftLimit);
}

#ifdef V8_COMPRESS_POINTERS
TEST_F(HeapTest, HeapLayout) {
  // Produce some garbage.
  RunJS(
      "let ar = [];"
      "for (let i = 0; i < 100; i++) {"
      "  ar.push(Array(i));"
      "}"
      "ar.push(Array(32 * 1024 * 1024));");

  Address cage_base = i_isolate()->cage_base();
  EXPECT_TRUE(IsAligned(cage_base, size_t{4} * GB));

  Address code_cage_base = i_isolate()->code_cage_base();
  if (V8_EXTERNAL_CODE_SPACE_BOOL) {
    EXPECT_TRUE(IsAligned(code_cage_base, kMinExpectedOSPageSize));
  } else {
    EXPECT_TRUE(IsAligned(code_cage_base, size_t{4} * GB));
  }

#if V8_ENABLE_SANDBOX
  Address trusted_space_base =
      TrustedRange::GetProcessWideTrustedRange()->base();
  EXPECT_TRUE(IsAligned(trusted_space_base, size_t{4} * GB));
  base::AddressRegion trusted_reservation(trusted_space_base, size_t{4} * GB);
#endif

  // Check that all memory chunks belong this region.
  base::AddressRegion heap_reservation(cage_base, size_t{4} * GB);
  base::AddressRegion code_reservation(code_cage_base, size_t{4} * GB);

  IsolateSafepointScope scope(i_isolate()->heap());
  OldGenerationMemoryChunkIterator iter(i_isolate()->heap());
  while (MutablePageMetadata* chunk = iter.next()) {
    Address address = chunk->ChunkAddress();
    size_t size = chunk->area_end() - address;
    AllocationSpace owner_id = chunk->owner_identity();
    if (V8_EXTERNAL_CODE_SPACE_BOOL && IsAnyCodeSpace(owner_id)) {
      EXPECT_TRUE(code_reservation.contains(address, size));
#if V8_ENABLE_SANDBOX
    } else if (IsAnyTrustedSpace(owner_id)) {
      EXPECT_TRUE(trusted_reservation.contains(address, size));
#endif
    } else {
      EXPECT_TRUE(heap_reservation.contains(address, size));
    }
  }
}
#endif  // V8_COMPRESS_POINTERS

namespace {
void ShrinkNewSpace(NewSpace* new_space) {
  if (!v8_flags.minor_ms) {
    SemiSpaceNewSpace::From(new_space)->Shrink();
    return;
  }
  // MinorMS shrinks the space as part of sweeping. Here we fake a GC cycle, in
  // which we just shrink without marking or sweeping.
  PagedNewSpace* paged_new_space = PagedNewSpace::From(new_space);
  Heap* heap = paged_new_space->heap();
  heap->EnsureSweepingCompleted(Heap::SweepingForcedFinalizationMode::kV8Only);
  GCTracer* tracer = heap->tracer();
  tracer->StartObservablePause(base::TimeTicks::Now());
  tracer->StartCycle(GarbageCollector::MARK_COMPACTOR,
                     GarbageCollectionReason::kTesting, "heap unittest",
                     GCTracer::MarkingType::kAtomic);
  tracer->StartAtomicPause();
  paged_new_space->StartShrinking();
  for (auto it = paged_new_space->begin();
       it != paged_new_space->end() &&
       (paged_new_space->ShouldReleaseEmptyPage());) {
    PageMetadata* page = *it++;
    if (page->allocated_bytes() == 0) {
      paged_new_space->ReleasePage(page);
    } else {
      // The number of live bytes should be zero, because at this point we're
      // after a GC.
      DCHECK_EQ(0, page->live_bytes());
      // We set it to the number of allocated bytes, because FinishShrinking
      // below expects that all pages have been swept and those that remain
      // contain live bytes.
      page->SetLiveBytes(page->allocated_bytes());
    }
  }
  paged_new_space->FinishShrinking();
  for (PageMetadata* page : *paged_new_space) {
    // We reset the number of live bytes to zero, as is expected after a GC.
    page->SetLiveBytes(0);
  }
  tracer->StopAtomicPause();
  tracer->StopObservablePause(GarbageCollector::MARK_COMPACTOR,
                              base::TimeTicks::Now());
  tracer->NotifyFullSweepingCompleted();
}
}  // namespace

TEST_F(HeapTest, GrowAndShrinkNewSpace) {
  if (v8_flags.single_generation) return;
  {
    ManualGCScope manual_gc_scope(i_isolate());
    // Avoid shrinking new space in GC epilogue. This can happen if allocation
    // throughput samples have been taken while executing the benchmark.
    v8_flags.predictable = true;
    v8_flags.stress_concurrent_allocation = false;  // For SimulateFullSpace.
  }
  NewSpace* new_space = heap()->new_space();

  if (heap()->MaxSemiSpaceSize() == heap()->InitialSemiSpaceSize()) {
    return;
  }

  // Make sure we're in a consistent state to start out.
  InvokeMajorGC();
  InvokeMajorGC();
  ShrinkNewSpace(new_space);

  // Explicitly growing should double the space capacity.
  size_t old_capacity, new_capacity;
  old_capacity = new_space->TotalCapacity();
  GrowNewSpace();
  new_capacity = new_space->TotalCapacity();
  CHECK_EQ(2 * old_capacity, new_capacity);

  old_capacity = new_space->TotalCapacity();
  {
    v8::HandleScope temporary_scope(reinterpret_cast<v8::Isolate*>(isolate()));
    SimulateFullSpace(new_space);
  }
  new_capacity = new_space->TotalCapacity();
  CHECK_EQ(old_capacity, new_capacity);

  // Explicitly shrinking should not affect space capacity.
  old_capacity = new_space->TotalCapacity();
  ShrinkNewSpace(new_space);
  new_capacity = new_space->TotalCapacity();
  CHECK_EQ(old_capacity, new_capacity);

  // Let the scavenger empty the new space.
  EmptyNewSpaceUsingGC();
  CHECK_LE(new_space->Size(), old_capacity);

  // Explicitly shrinking should halve the space capacity.
  old_capacity = new_space->TotalCapacity();
  ShrinkNewSpace(new_space);
  new_capacity = new_space->TotalCapacity();
  if (v8_flags.minor_ms) {
    // Shrinking may not be able to remove any pages if all contain live
    // objects.
    CHECK_GE(old_capacity, new_capacity);
  } else {
    CHECK_EQ(old_capacity, 2 * new_capacity);
  }

  // Consecutive shrinking should not affect space capacity.
  old_capacity = new_space->TotalCapacity();
  ShrinkNewSpace(new_space);
  ShrinkNewSpace(new_space);
  ShrinkNewSpace(new_space);
  new_capacity = new_space->TotalCapacity();
  CHECK_EQ(old_capacity, new_capacity);
}

TEST_F(HeapTest, CollectingAllAvailableGarbageShrinksNewSpace) {
  if (v8_flags.single_generation) return;
  v8_flags.stress_concurrent_allocation = false;  // For SimulateFullSpace.
  if (heap()->MaxSemiSpaceSize() == heap()->InitialSemiSpaceSize()) {
    return;
  }

  v8::Isolate* iso = reinterpret_cast<v8::Isolate*>(isolate());
  v8::HandleScope scope(iso);
  NewSpace* new_space = heap()->new_space();
  size_t old_capacity, new_capacity;
  old_capacity = new_space->TotalCapacity();
  GrowNewSpace();
  new_capacity = new_space->TotalCapacity();
  CHECK_EQ(2 * old_capacity, new_capacity);
  {
    v8::HandleScope temporary_scope(iso);
    SimulateFullSpace(new_space);
  }
  InvokeMemoryReducingMajorGCs();
  new_capacity = new_space->TotalCapacity();
  CHECK_EQ(old_capacity, new_capacity);
}

// Test that HAllocateObject will always return an object in new-space.
TEST_F(HeapTest, OptimizedAllocationAlwaysInNewSpace) {
  if (v8_flags.single_generation) return;
  v8_flags.allow_natives_syntax = true;
  v8_flags.stress_concurrent_allocation = false;  // For SimulateFullSpace.
  if (!isolate()->use_optimizer() || v8_flags.always_turbofan) return;
  if (v8_flags.gc_global || v8_flags.stress_compaction ||
      v8_flags.stress_incremental_marking)
    return;
  v8::Isolate* iso = reinterpret_cast<v8::Isolate*>(isolate());
  ManualGCScope manual_gc_scope(isolate());
  v8::HandleScope scope(iso);
  v8::Local<v8::Context> ctx = iso->GetCurrentContext();
  SimulateFullSpace(heap()->new_space());
  AlwaysAllocateScopeForTesting always_allocate(heap());
  v8::Local<v8::Value> res = WithIsolateScopeMixin::RunJS(
      "function c(x) {"
      "  this.x = x;"
      "  for (var i = 0; i < 32; i++) {"
      "    this['x' + i] = x;"
      "  }"
      "}"
      "function f(x) { return new c(x); };"
      "%PrepareFunctionForOptimization(f);"
      "f(1); f(2); f(3);"
      "%OptimizeFunctionOnNextCall(f);"
      "f(4);");

  CHECK_EQ(4, res.As<v8::Object>()
                  ->GetRealNamedProperty(ctx, NewString("x"))
                  .ToLocalChecked()
                  ->Int32Value(ctx)
                  .FromJust());

  i::DirectHandle<JSReceiver> o =
      v8::Utils::OpenDirectHandle(*v8::Local<v8::Object>::Cast(res));

  CHECK(HeapLayout::InYoungGeneration(*o));
}

namespace {
template <RememberedSetType direction>
static size_t GetRememberedSetSize(Tagged<HeapObject> obj) {
  size_t count = 0;
  auto chunk = MutablePageMetadata::FromHeapObject(obj);
  RememberedSet<direction>::Iterate(
      chunk,
      [&count](MaybeObjectSlot slot) {
        count++;
        return KEEP_SLOT;
      },
      SlotSet::KEEP_EMPTY_BUCKETS);
  return count;
}
}  // namespace

TEST_F(HeapTest, RememberedSet_InsertOnPromotingObjectToOld) {
  if (v8_flags.single_generation || v8_flags.stress_incremental_marking) return;
  v8_flags.stress_concurrent_allocation = false;  // For SealCurrentObjects.
  ManualGCScope manual_gc_scope(isolate());
  Factory* factory = isolate()->factory();
  Heap* heap = isolate()->heap();
  SealCurrentObjects();
  HandleScope scope(isolate());

  // Create a young object and age it one generation inside the new space.
  DirectHandle<FixedArray> arr = factory->NewFixedArray(1);
  std::vector<Handle<FixedArray>> handles;
  if (v8_flags.minor_ms) {
    NewSpace* new_space = heap->new_space();
    CHECK_NE(new_space->TotalCapacity(), new_space->MaximumCapacity());
    // Fill current pages to force MinorMS to promote them.
    SimulateFullSpace(new_space, &handles);
    IsolateSafepointScope scope(heap);
    // New empty pages should remain in new space.
    new_space->Grow();
    CHECK(new_space->EnsureCurrentCapacity());
  }
  InvokeMinorGC();
  CHECK(HeapLayout::InYoungGeneration(*arr));

  // Add into 'arr' a reference to an object one generation younger.
  {
    HandleScope scope_inner(isolate());
    DirectHandle<Object> number = factory->NewHeapNumber(42);
    arr->set(0, *number);
  }

  // Promote 'arr' into old, its element is still in new, the old to new
  // refs are inserted into the remembered sets during GC.
  InvokeMinorGC();
  heap->EnsureSweepingCompleted(Heap::SweepingForcedFinalizationMode::kV8Only);

  CHECK(heap->InOldSpace(*arr));
  CHECK(HeapLayout::InYoungGeneration(arr->get(0)));
  if (v8_flags.minor_ms) {
    CHECK_EQ(1, GetRememberedSetSize<OLD_TO_NEW_BACKGROUND>(*arr));
  } else {
    CHECK_EQ(1, GetRememberedSetSize<OLD_TO_NEW>(*arr));
  }
}

TEST_F(HeapTest, Regress978156) {
  if (!v8_flags.incremental_marking) return;
  if (v8_flags.single_generation) return;
  ManualGCScope manual_gc_scope(isolate());

  HandleScope handle_scope(isolate());
  Heap* heap = isolate()->heap();

  // 1. Ensure that the new space is empty.
  EmptyNewSpaceUsingGC();
  // 2. Fill the new space with FixedArrays.
  std::vector<Handle<FixedArray>> arrays;
  SimulateFullSpace(heap->new_space(), &arrays);
  // 3. Trim the last array by one word thus creating a one-word filler.
  DirectHandle<FixedArray> last = arrays.back();
  CHECK_GT(last->length(), 0);
  heap->RightTrimArray(*last, last->length() - 1, last->length());
  // 4. Get the last filler on the page.
  Tagged<HeapObject> filler = HeapObject::FromAddress(
      MutablePageMetadata::FromHeapObject(*last)->area_end() - kTaggedSize);
  HeapObject::FromAddress(last->address() + last->Size());
  CHECK(IsFiller(filler));
  // 5. Start incremental marking.
  i::IncrementalMarking* marking = heap->incremental_marking();
  if (marking->IsStopped()) {
    IsolateSafepointScope scope(heap);
    heap->tracer()->StartCycle(
        GarbageCollector::MARK_COMPACTOR, GarbageCollectionReason::kTesting,
        "collector cctest", GCTracer::MarkingType::kIncremental);
    marking->Start(GarbageCollector::MARK_COMPACTOR,
                   i::GarbageCollectionReason::kTesting);
  }
  // 6. Mark the filler black to access its two markbits. This triggers
  // an out-of-bounds access of the marking bitmap in a bad case.
  heap->marking_state()->TryMarkAndAccountLiveBytes(filler);
}

TEST_F(HeapTest, SemiSpaceNewSpaceGrowsDuringFullGCIncrementalMarking) {
  if (!v8_flags.incremental_marking) return;
  if (v8_flags.single_generation) return;
  if (v8_flags.minor_ms) return;
  v8_flags.separate_gc_phases = true;
  ManualGCScope manual_gc_scope(isolate());

  HandleScope handle_scope(isolate());
  Heap* heap = isolate()->heap();

  // 1. Record gc_count and last scavenger epoch.
  auto gc_count = heap->gc_count();
  auto last_scavenger_epoch =
      heap->tracer()->CurrentEpoch(GCTracer::Scope::ScopeId::SCAVENGER);
  // 2. Fill the new space with FixedArrays.
  std::vector<Handle<FixedArray>> arrays;
  SimulateFullSpace(heap->new_space(), &arrays);
  CHECK_EQ(0, heap->new_space()->Available());
  AllocationResult failed_allocation = heap->allocator()->AllocateRaw(
      2 * kTaggedSize, AllocationType::kYoung, AllocationOrigin::kRuntime);
  EXPECT_TRUE(failed_allocation.IsFailure());
  // 3. Start incremental marking.
  i::IncrementalMarking* marking = heap->incremental_marking();
  CHECK(marking->IsStopped());
  {
    IsolateSafepointScope scope(heap);
    heap->tracer()->StartCycle(GarbageCollector::MARK_COMPACTOR,
                               GarbageCollectionReason::kTesting, "tesing",
                               GCTracer::MarkingType::kIncremental);
    marking->Start(GarbageCollector::MARK_COMPACTOR,
                   i::GarbageCollectionReason::kTesting);
  }
  // 4. Allocate in new space.
  AllocationResult allocation = heap->allocator()->AllocateRaw(
      2 * kTaggedSize, AllocationType::kYoung, AllocationOrigin::kRuntime);
  EXPECT_FALSE(allocation.IsFailure());
  // 5. Allocation should succeed without triggering a GC.
  EXPECT_EQ(gc_count, heap->gc_count());
  EXPECT_EQ(last_scavenger_epoch,
            heap->tracer()->CurrentEpoch(GCTracer::Scope::ScopeId::SCAVENGER));
}

#ifdef V8_ENABLE_ALLOCATION_TIMEOUT
namespace {
struct RandomGCIntervalTestSetter {
  RandomGCIntervalTestSetter() {
    static constexpr int kInterval = 87;
    v8_flags.random_gc_interval = kInterval;
  }
  ~RandomGCIntervalTestSetter() { v8_flags.random_gc_interval = 0; }
};

struct HeapTestWithRandomGCInterval : RandomGCIntervalTestSetter, HeapTest {};
}  // namespace

TEST_F(HeapTestWithRandomGCInterval, AllocationTimeout) {
  if (v8_flags.stress_incremental_marking) return;
  if (v8_flags.stress_concurrent_allocation) return;

  auto* allocator = heap()->allocator();

  // Invoke major GC to cause the timeout to be updated.
  InvokeMajorGC();
  const int initial_allocation_timeout =
      allocator->get_allocation_timeout_for_testing().value_or(0);
  ASSERT_GT(initial_allocation_timeout, 0);

  for (int i = 0; i < initial_allocation_timeout - 1; ++i) {
    AllocationResult allocation = allocator->AllocateRaw(
        2 * kTaggedSize, AllocationType::kYoung, AllocationOrigin::kRuntime);
    EXPECT_FALSE(allocation.IsFailure());
  }

  // The last allocation must fail.
  AllocationResult allocation = allocator->AllocateRaw(
      2 * kTaggedSize, AllocationType::kYoung, AllocationOrigin::kRuntime);
  EXPECT_TRUE(allocation.IsFailure());
}
#endif  // V8_ENABLE_ALLOCATION_TIMEOUT

TEST_F(HeapTest, Regress341769455) {
#ifdef V8_COMPRESS_POINTERS
  if (!v8_flags.incremental_marking) return;
  if (!v8_flags.minor_ms) return;
  Isolate* iso = isolate();
  bool original_concurrent_minor_ms_marking_value =
      v8_flags.concurrent_minor_ms_marking;
  ManualGCScope manual_gc_scope(iso);
  v8_flags.concurrent_minor_ms_marking =
      original_concurrent_minor_ms_marking_value;
  Heap* heap = iso->heap();
  HandleScope outer(iso);
  DirectHandle<JSArrayBuffer> ab;
  {
    // Make sure new space is empty
    InvokeAtomicMajorGC();
    ab = iso->factory()
             ->NewJSArrayBufferAndBackingStore(
                 1, InitializedFlag::kZeroInitialized, AllocationType::kYoung)
             .ToHandleChecked();
    // Reset the EPT handle to null.
    ab->init_extension();
    // MinorMS promotes pages that haven't been allocated on since the last GC.
    // Force a minor GC to reset the counter of bytes allocated on the page.
    InvokeAtomicMinorGC();
    // Set up a global to make sure the JSArrayBuffer is visited before the
    // atomic pause.
    Global<JSArrayBuffer> global(
        v8_isolate(), Utils::Convert<JSArrayBuffer, JSArrayBuffer>(ab));
    CHECK_EQ(Heap::HeapState::NOT_IN_GC, heap->gc_state());
    CHECK(heap->incremental_marking()->IsStopped());
    // Start incremental marking such that setting an extension (via
    // `EnsureExtension`) triggers a write barrier.
    v8_flags.incremental_marking = true;
    heap->StartIncrementalMarking(GCFlag::kNoFlags,
                                  GarbageCollectionReason::kTesting,
                                  GCCallbackFlags::kNoGCCallbackFlags,
                                  GarbageCollector::MINOR_MARK_SWEEPER);
    CHECK(heap->incremental_marking()->IsMinorMarking());
    heap->minor_mark_sweep_collector()->DrainMarkingWorklistForTesting();
    ab->EnsureExtension();
    heap->AppendArrayBufferExtension(*ab, ab->extension());
  }
  // Trigger a 2nd minor GC to promote the JSArrayBuffer to old space.
  CHECK(HeapLayout::InYoungGeneration(*ab));
  InvokeAtomicMinorGC();
  CHECK(!HeapLayout::InYoungGeneration(*ab));
  // If the EPT entry for the JSArrayBuffer wasn't promoted to the old table, a
  // 3rd minor GC will observe it as unmarked (since the owning object is old)
  // and free it. The major GC after it will then crash when trying to access
  // the extension of the JSArrayBuffer although the entry has been freed.
  InvokeAtomicMinorGC();
  InvokeAtomicMajorGC();
#endif  // V8_COMPRESS_POINTERS
}

namespace {
struct CompactionDisabler {
  CompactionDisabler() : was_enabled_(v8_flags.compact) {
    v8_flags.compact = false;
  }
  ~CompactionDisabler() {
    if (was_enabled_) {
      v8_flags.compact = true;
    }
  }
  const bool was_enabled_;
};
}  // namespace

TEST_F(HeapTest, BlackAllocatedPages) {
  if (!v8_flags.black_allocated_pages) return;
  if (!v8_flags.incremental_marking) return;

  // Disable compaction to test that the FreeListCategories of black allocated
  // pages are not reset.
  CompactionDisabler disable_compaction;

  Isolate* iso = isolate();
  ManualGCScope manual_gc_scope(iso);

  auto in_free_list = [](PageMetadata* page, Address address) {
    bool found = false;
    page->ForAllFreeListCategories(
        [address, &found](FreeListCategory* category) {
          category->IterateNodesForTesting(
              [address, &found](Tagged<FreeSpace> node) {
                if (!found) found = node.address() == address;
              });
        });
    return found;
  };

  Heap* heap = iso->heap();
  SimulateFullSpace(heap->old_space());

  // Allocate an object on a new page.
  HandleScope scope(iso);
  DirectHandle<FixedArray> arr =
      iso->factory()->NewFixedArray(1, AllocationType::kOld);
  Address next = arr->address() + arr->Size();

  // Assert that the next address is in the lab.
  const Address lab_top = heap->allocator()->old_space_allocator()->top();
  ASSERT_EQ(lab_top, next);

  auto* page = PageMetadata::FromAddress(next);
  const size_t wasted_before_incremental_marking_start = page->wasted_memory();

  heap->StartIncrementalMarking(
      GCFlag::kNoFlags, GarbageCollectionReason::kTesting,
      GCCallbackFlags::kNoGCCallbackFlags, GarbageCollector::MARK_COMPACTOR);

  // Expect the free-space object is created.
  auto freed = HeapObject::FromAddress(next);
  EXPECT_TRUE(IsFreeSpaceOrFiller(freed));

  // The free-space object must be accounted as wasted.
  EXPECT_EQ(wasted_before_incremental_marking_start + freed->Size(),
            page->wasted_memory());

  // Check that the free-space object is not in freelist.
  EXPECT_FALSE(in_free_list(page, next));

  // The page allocated before incremental marking is not black.
  EXPECT_FALSE(page->Chunk()->IsFlagSet(MemoryChunk::BLACK_ALLOCATED));

  // Allocate a new object on a BLACK_ALLOCATED page.
  arr = iso->factory()->NewFixedArray(1, AllocationType::kOld);
  next = arr->address() + arr->Size();

  // Expect the page to be black.
  page = PageMetadata::FromHeapObject(*arr);
  EXPECT_TRUE(page->Chunk()->IsFlagSet(MemoryChunk::BLACK_ALLOCATED));

  // Invoke GC.
  InvokeMajorGC();

  // The page is not black now.
  EXPECT_FALSE(page->Chunk()->IsFlagSet(MemoryChunk::BLACK_ALLOCATED));
  // After the GC the next free-space object must be in freelist.
  EXPECT_TRUE(in_free_list(page, next));
}

TEST_F(HeapTest, ContainsSlow) {
  Isolate* iso = isolate();
  ManualGCScope manual_gc_scope(iso);

  Heap* heap = iso->heap();
  SimulateFullSpace(heap->old_space());

  // Allocate an object on a new page.
  HandleScope scope(iso);
  DirectHandle<FixedArray> arr =
      iso->factory()->NewFixedArray(1, AllocationType::kOld);
  CHECK(heap->old_space()->ContainsSlow(arr->address()));
  CHECK(heap->old_space()->ContainsSlow(
      MemoryChunk::FromAddress(arr->address())->address()));
  CHECK(!heap->old_space()->ContainsSlow(0));

  DirectHandle<FixedArray> large_arr = iso->factory()->NewFixedArray(
      kMaxRegularHeapObjectSize + 1, AllocationType::kOld);
  CHECK(heap->lo_space()->ContainsSlow(large_arr->address()));
  CHECK(heap->lo_space()->ContainsSlow(
      MemoryChunk::FromAddress(large_arr->address())->address()));
  CHECK(!heap->lo_space()->ContainsSlow(0));
}

#if defined(V8_COMPRESS_POINTERS) && defined(V8_ENABLE_SANDBOX)
TEST_F(HeapTest, Regress364396306) {
  if (v8_flags.single_generation) return;
  if (v8_flags.separate_gc_phases) return;
  if (v8_flags.minor_ms) return;

  auto* iso = i_isolate();
  auto* heap = iso->heap();
  auto* space = heap->young_external_pointer_space();
  ManualGCScope manual_gc_scope(iso);

  int* external_int = new int;

  {
    {
      // Almost fill a segment with unreachable entries. Leave behind one unused
      // entry.
      v8::HandleScope scope(reinterpret_cast<v8::Isolate*>(iso));
      do {
        iso->factory()->NewExternal(external_int);
      } while (space->freelist_length() > 1);
    }
    {
      v8::HandleScope scope(reinterpret_cast<v8::Isolate*>(iso));
      // Allocate one reachable entry on the same segment to prevent discarding
      // the segment.
      iso->factory()->NewExternal(external_int);
      CHECK_EQ(1, space->NumSegmentsForTesting());
      // Allocate an entry on a new segment that will later be evacuated.
      Handle<JSObject> to_be_evacuated =
          iso->factory()->NewExternal(external_int);
      CHECK_EQ(2, space->NumSegmentsForTesting());
      CHECK(HeapLayout::InYoungGeneration(*to_be_evacuated));
      // Unmark to-be-evacuated entry and populate the freelist.
      InvokeMinorGC();
      CHECK(HeapLayout::InYoungGeneration(*to_be_evacuated));
      // Set up a global to make sure `to_be_evacuated` is visited before the
      // atomic pause.
      Global<JSObject> global_to_be_evacuated(
          v8_isolate(), Utils::Convert<JSObject, JSObject>(to_be_evacuated));
      // Make sure compaction is enabled for the space so that an evacuation
      // entry is created for `to_be_evacuated`.
      bool old_stress_compaction_flag =
          std::exchange(v8_flags.stress_compaction, true);
      heap->StartIncrementalMarking(GCFlag::kNoFlags,
                                    GarbageCollectionReason::kTesting);
      // Finish all available marking work to make sure the to-be-evacuated
      // entry is already marked.
      heap->incremental_marking()->AdvanceForTesting(
          v8::base::TimeDelta::Max());
      // Reset the `stress_compaction` flag. If it remains enabled, the minor
      // GCs below will be overriden with full GCs.
      v8_flags.stress_compaction = old_stress_compaction_flag;
    }

    // The to-be-evacuated entry is no longer reachable. Scavenger will override
    // the evacuation entry with a null address.
    InvokeMinorGC();
    // Iterating over segments again should not crash because of the null
    // address set by the previous Scavenger.
    InvokeMinorGC();
  }

  // Finalize the incremental GC so there are no references to `external_int`
  // before we free it.
  InvokeMajorGC();

  delete external_int;
}
#endif  // defined(V8_COMPRESS_POINTERS) && defined(V8_ENABLE_SANDBOX)

}  // namespace internal
}  // namespace v8

"""

```