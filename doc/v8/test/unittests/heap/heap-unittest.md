Response:
Let's break down the thought process for analyzing the provided C++ unittest file.

**1. Initial Scan and High-Level Understanding:**

The first step is to quickly scan the file for keywords and patterns. Immediately noticeable are:

* `#include`: Indicates this is C++ code.
* `TEST(Heap, ...)` and `TEST_F(HeapTest, ...)`: These clearly signal Google Test framework being used for unit testing the `Heap` component.
*  Names like `YoungGenerationSizeFromOldGenerationSize`, `GenerationSizesFromHeapSize`, `HeapSizeFromPhysicalMemory`, `GrowAndShrinkNewSpace`, `RememberedSet`, etc.: These strongly suggest the file focuses on testing the memory management aspects of V8's heap.
* `namespace v8 { namespace internal {`:  This confirms it's internal V8 code.

From this initial scan, we can confidently say: "This is a C++ unit test file for V8's heap management."

**2. Deeper Dive into Test Cases:**

Next, we go through each `TEST` or `TEST_F` block to understand what specific functionality is being tested. We look at the names of the tests and the assertions within them.

* **Size Calculations (`YoungGenerationSizeFromOldGenerationSize`, `GenerationSizesFromHeapSize`, `HeapSizeFromPhysicalMemory`):** These tests clearly focus on validating the formulas or logic used to determine the sizes of different heap generations (young, old) based on various input parameters like old generation size or physical memory. The `ASSERT_EQ` calls check if the calculated values match expected values.

* **ASLR (`ASLR`):** This tests Address Space Layout Randomization, a security feature. The test checks if allocated memory addresses are sufficiently randomized.

* **External Memory Limits (`ExternalLimitDefault`, `ExternalLimitStaysAboveDefaultForExplicitHandling`):** These test the mechanisms for managing and limiting external (off-heap) memory allocations.

* **Heap Layout (`HeapLayout`):** This test verifies the expected organization of different memory spaces (heap, code, trusted) within the process's address space. It iterates through memory chunks and checks if they fall within the expected regions.

* **New Space Management (`GrowAndShrinkNewSpace`, `CollectingAllAvailableGarbageShrinksNewSpace`):**  These tests focus on the dynamic resizing of the "new space" (where recently created objects reside). They check if growing doubles the capacity and shrinking halves it, and how garbage collection influences the size.

* **Optimized Allocation (`OptimizedAllocationAlwaysInNewSpace`):** This verifies that objects allocated by optimized (TurboFan) JavaScript functions are placed in the young generation.

* **Remembered Sets (`RememberedSet_InsertOnPromotingObjectToOld`):** This test examines how "remembered sets" are updated when an object in the young generation is promoted to the old generation while holding a reference to another young generation object. Remembered sets track cross-generational references for efficient garbage collection.

* **Bug Fixes (`Regress978156`, `Regress341769455`, `Regress364396306`):** Tests with "Regress" in their name usually target specific bug fixes. By looking at the operations performed (filling new space, triggering GCs, manipulating objects), we can infer the potential issues these tests are guarding against (e.g., out-of-bounds access, incorrect handling of external pointers).

* **Incremental Marking (`SemiSpaceNewSpaceGrowsDuringFullGCIncrementalMarking`):** This test checks the interaction between incremental garbage collection and new space growth.

* **Allocation Timeout (`AllocationTimeout`):** This test (conditional on `V8_ENABLE_ALLOCATION_TIMEOUT`) verifies a mechanism to trigger garbage collection if allocation requests exceed a certain threshold.

* **Black Allocation (`BlackAllocatedPages`):** This tests a specific optimization where pages allocated during incremental marking are marked as "black," influencing how free space is managed on those pages.

* **Contains (`ContainsSlow`):** This tests methods to check if a given memory address belongs to a specific memory space (old space, large object space).

**3. Answering Specific Questions:**

Now, with a good understanding of the file's purpose, we can address the specific prompts:

* **Functionality:**  Summarize the findings from the test case analysis.
* **Torque:** Check the file extension. It's `.cc`, not `.tq`.
* **JavaScript Relation:** Look for tests that involve running JavaScript code (`RunJS`). Identify the concepts being tested that are relevant to JavaScript memory management (e.g., object allocation, garbage collection). Provide a simple JavaScript example demonstrating a related concept.
* **Code Logic Inference:** Choose a test case (like the size calculation ones) and try to infer the logic being tested. Formulate hypothetical inputs and expected outputs based on the assertions.
* **Common Programming Errors:**  Think about what kind of errors the tested functionalities prevent. For example, incorrect size calculations could lead to memory exhaustion or crashes. The ASLR test relates to security vulnerabilities. The remembered set test relates to ensuring correct garbage collection and preventing dangling pointers.

**4. Refinement and Organization:**

Finally, organize the findings in a clear and structured way, using headings and bullet points as in the example answer. Ensure the language is concise and easy to understand. For the JavaScript example, keep it simple and directly relevant to the tested C++ functionality.

This structured approach, starting with a high-level overview and gradually digging deeper into specific test cases, allows for a comprehensive understanding of the C++ unit test file and enables accurate responses to the given prompts.
这个文件 `v8/test/unittests/heap/heap-unittest.cc` 是 V8 JavaScript 引擎的源代码，它包含了对 V8 堆 (heap) 组件进行单元测试的用例。 它的主要功能是 **验证 V8 堆的各种特性和功能是否按预期工作**。

以下是该文件更详细的功能列表：

* **测试堆的初始化和配置:**  测试堆的初始大小、最大大小、以及各种影响堆大小的配置选项 (例如 young generation 的大小)。
* **测试不同代 (generation) 大小的计算:**  验证计算 young generation 和 old generation 大小的逻辑，包括基于总堆大小、物理内存大小等的计算。
* **测试地址空间布局随机化 (ASLR):** 验证堆的地址空间是否被随机化，以提高安全性。
* **测试外部内存限制:**  验证对外部（非 V8 管理的）内存分配的限制和管理机制。
* **测试堆的布局:**  验证堆的各个部分（例如 old space, new space, code space）在内存中的布局是否符合预期。
* **测试 New Space 的增长和收缩:**  验证 New Space (用于存放新创建的临时对象) 能否根据需要增长和收缩，以及 GC 对其大小的影响。
* **测试对象的分配:**  验证对象能否成功在堆上分配，特别是对于优化后的代码，对象是否总是分配在 New Space 中。
* **测试 Remembered Set 的功能:**  验证 Remembered Set (用于记录 old generation 对象指向 new generation 对象的指针) 的插入操作，特别是在对象晋升到 old generation 时。
* **回归测试 (Regression Tests):**  包含一些用于复现和修复过的 bug 的测试用例，例如 `Regress978156`, `Regress341769455`, `Regress364396306`。这些测试确保之前修复的 bug 不会再次出现。
* **测试增量标记 (Incremental Marking) 相关的特性:** 验证增量垃圾回收机制的正确性，例如在增量标记过程中 New Space 的增长。
* **测试分配超时 (Allocation Timeout) 机制:**  验证当分配请求过于频繁时，会触发 GC 的机制 (如果 `V8_ENABLE_ALLOCATION_TIMEOUT` 宏被定义)。
* **测试 Black Allocated Pages 特性:**  验证在增量标记期间分配的对象所在的页面的管理方式。
* **测试 Contains 方法:**  验证判断给定地址是否属于堆的特定空间的方法。
* **测试 Young External Pointer Space:** 验证对 young external pointer space 的管理 (用于存放指向外部 C++ 对象的指针)。

**如果 `v8/test/unittests/heap/heap-unittest.cc` 以 `.tq` 结尾，那它是个 v8 torque 源代码。**  但根据提供的文件名，它是 `.cc` 文件，因此是 C++ 源代码。 Torque 是一种用于编写 V8 内部代码的领域特定语言，通常用于实现内置函数和运行时功能。

**与 JavaScript 的功能关系和示例:**

`v8/test/unittests/heap/heap-unittest.cc` 中测试的功能直接影响 JavaScript 的内存管理和性能。 堆是 JavaScript 对象存储的地方，垃圾回收器负责回收不再使用的内存。

例如，测试 New Space 的增长和收缩直接关系到 JavaScript 中短期对象的分配效率。如果 New Space 太小，会导致频繁的 Minor GC，影响性能。

以下 JavaScript 示例展示了与堆相关的概念：

```javascript
// 创建一些对象，这些对象会被分配到堆上
let obj1 = { a: 1 };
let obj2 = [1, 2, 3];
let obj3 = new Map();

// 随着更多对象的创建，堆的大小可能会增长
for (let i = 0; i < 10000; i++) {
  new Object();
}

// 当对象不再被引用时，垃圾回收器会回收它们的内存
obj1 = null;
obj2 = null;
obj3 = null;

// 触发垃圾回收（通常不需要手动调用，这里仅作演示）
// if (global.gc) {
//   global.gc();
// }
```

在这个例子中，`obj1`, `obj2`, `obj3` 以及循环中创建的匿名对象都会被分配到 V8 的堆上。 `heap-unittest.cc` 中的测试确保 V8 的堆能够正确地分配和管理这些对象的内存，并且垃圾回收器能够正确地回收不再使用的内存。

**代码逻辑推理、假设输入与输出:**

以 `TEST(Heap, YoungGenerationSizeFromOldGenerationSize)` 这个测试为例：

**假设输入:**

* `v8_flags.scavenger_max_new_space_capacity_mb` 被设置为 64。
* `minor_ms` flag (指示是否启用 Minor Mark-Sweep) 可能为 true 或 false。
* Old Generation 的大小，例如 `128u * hlm * MB` (低内存情况) 或 `256u * hlm * MB` (高内存情况)。

**代码逻辑:**

`YoungGenerationSizeFromOldGenerationSize` 函数根据 Old Generation 的大小和一些配置参数来计算 Young Generation 的大小。 计算公式会根据 `minor_ms` flag 的值而有所不同。

**预期输出:**

* 对于低内存情况 (`128u * hlm * MB`)，如果 `minor_ms` 为 false，则 Young Generation 的大小应该等于 `3 * 512u * pm * KB`。如果 `minor_ms` 为 true，则应该等于 `4 * 512u * pm * KB`。
* 对于高内存情况 (`256u * hlm * MB`)，如果 `minor_ms` 为 false，则 Young Generation 的大小应该等于 `3 * 16u / hlm * pm * MB`。如果 `minor_ms` 为 true，则应该等于 `2 * i::Heap::DefaultMaxSemiSpaceSize()`。

测试用例中的 `ASSERT_EQ` 断言会验证实际计算出的 Young Generation 大小是否与预期输出一致。

**用户常见的编程错误示例:**

虽然这个文件是测试 V8 内部代码的，但它测试的功能与用户在使用 JavaScript 时可能遇到的问题有关。 一些可能由堆管理问题引发的用户常见编程错误包括：

* **内存泄漏:**  用户创建了对象，但没有正确地释放它们的引用，导致这些对象一直占用堆内存，最终可能导致程序内存耗尽崩溃。 V8 的垃圾回收器会自动回收大部分不再使用的内存，但某些情况下（例如闭包中的引用），可能需要开发者注意避免内存泄漏。

  ```javascript
  // 潜在的内存泄漏示例
  function createLeakyClosure() {
    let largeArray = new Array(1000000);
    return function() {
      // largeArray 仍然被闭包引用，即使外部不再需要它
      console.log("执行了闭包");
    };
  }

  let leakyFunction = createLeakyClosure();
  // leakyFunction 仍然持有对 largeArray 的引用
  ```

* **性能问题:**  频繁创建大量临时对象可能导致频繁的垃圾回收，从而影响 JavaScript 程序的性能。  `heap-unittest.cc` 中测试的 New Space 管理功能旨在优化这种情况。

  ```javascript
  // 可能导致频繁 GC 的代码
  function processData(data) {
    let results = [];
    for (let item of data) {
      // 每次循环都创建新的临时对象
      let processedItem = { value: item * 2 };
      results.push(processedItem);
    }
    return results;
  }
  ```

* **栈溢出 (Stack Overflow):**  虽然 `heap-unittest.cc` 主要关注堆内存，但与函数调用相关的栈内存溢出也可能与内存管理有关。  过深的递归调用会导致栈内存耗尽。

  ```javascript
  // 导致栈溢出的递归调用
  function recursiveFunction() {
    recursiveFunction(); // 无限递归
  }

  // recursiveFunction(); // 执行这段代码会导致栈溢出
  ```

总结来说，`v8/test/unittests/heap/heap-unittest.cc` 是 V8 引擎中至关重要的一个测试文件，它确保了 JavaScript 程序的内存管理机制的正确性和效率，间接地帮助开发者避免了与内存相关的常见编程错误。

### 提示词
```
这是目录为v8/test/unittests/heap/heap-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/heap/heap-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```
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
```