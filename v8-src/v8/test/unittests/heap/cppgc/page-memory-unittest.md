Response: Let's break down the thought process for summarizing the C++ unittest file.

1. **Understand the Goal:** The request is to summarize the functionality of the C++ file `page-memory-unittest.cc` and explain its relation to JavaScript with an example if applicable.

2. **Initial Scan for Keywords:** Quickly scan the file for important terms and patterns. Keywords like `TEST`, `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_DEATH_IF_SUPPORTED`, class names (`MemoryRegionTest`, `PageMemoryTest`, `PageBackendTest`), and namespaces (`cppgc`, `internal`) jump out. This immediately tells me it's a testing file for the `cppgc` (C++ garbage collection) component of V8.

3. **Identify Core Classes Under Test:** The test names directly indicate the classes being tested:
    * `MemoryRegion`:  This seems to represent a contiguous block of memory.
    * `PageMemory`:  Likely a higher-level abstraction representing a page of memory, possibly with metadata.
    * `PageBackend`:  This suggests the underlying implementation for managing memory pages, including allocation and deallocation.

4. **Analyze Individual Test Cases:** Go through each `TEST` block and understand what it's testing for each class:

    * **`MemoryRegionTest`:**  Focuses on the basic properties and operations of `MemoryRegion`:
        * `Construct`: Verifies that a `MemoryRegion` object can be created with a base address and size, and that the `base()`, `size()`, and `end()` methods return the correct values.
        * `ContainsAddress`: Checks if a given address falls within the bounds of the `MemoryRegion`.
        * `ContainsMemoryRegion`: Checks if one `MemoryRegion` is entirely contained within another.

    * **`PageMemoryTest`:** Tests the `PageMemory` class:
        * `Construct`: Verifies the creation of a `PageMemory` object with overall and writable regions.
        * `ConstructNonContainedRegions` (in `DEBUG` mode): Ensures that the program crashes (as expected) if an attempt is made to create a `PageMemory` where the writable region is not contained within the overall region.

    * **`PageMemoryRegionTest`:**  Focuses on platform-specific behavior:
        * `PlatformUsesGuardPages`: Checks if the underlying memory allocator utilizes guard pages (protected memory regions at the boundaries of allocated pages) to detect out-of-bounds access. This is OS and architecture dependent.

    * **`PageBackendDeathTest`:** These tests specifically verify that accessing memory in certain scenarios leads to program termination (as expected in case of memory errors):
        * `ReservationIsFreed`: Checks if memory allocated by `PageBackend` is properly freed when the `PageBackend` object goes out of scope.
        * `FrontGuardPageAccessCrashes`: Confirms that accessing memory before the start of an allocated page (in the front guard page) causes a crash.
        * `BackGuardPageAccessCrashes`: Confirms that accessing memory after the end of the writable area but within the allocated page (in the back guard page) causes a crash.
        * `DestructingBackendDestroysPageMemory`: Ensures that memory managed by `PageBackend` is invalidated upon the backend's destruction.

    * **`PageBackendTreeTest`:** Tests the internal data structure (a tree) used by `PageBackend` to keep track of allocated memory regions:
        * `AddNormalLookupRemove`: Tests adding, finding, and removing a normal-sized page.
        * `AddLargeLookupRemove`: Tests the same operations for a large page.
        * `AddLookupRemoveMultiple`: Tests managing multiple normal and large pages.

    * **`PageBackendPoolTest`:** Tests the page pool mechanism used for recycling freed pages:
        * `ConstructorEmpty`: Checks that the pool is initially empty.
        * `AddTake`: Verifies adding a freed page to the pool and then taking it back for reuse.
        * `AddTakeWithDiscardInBetween`: Tests discarding pooled pages.
        * `AddTakeWithDiscardInBetweenWithDecommit`: Tests discarding with decommitment.
        * `PoolMemoryAccounting`: Checks the accounting of pooled memory.

    * **`PageBackendTest`:**  Tests the core allocation and lookup functionalities of `PageBackend`:
        * `AllocateNormalUsesPool`: Confirms that allocating a normal page reuses a page from the pool if available.
        * `AllocateLarge`: Tests allocating large pages.
        * `LookupNormal`: Verifies that the `Lookup` method correctly finds normal pages based on an address.
        * `LookupLarge`: Verifies the same for large pages.

5. **Synthesize the Functionality:** Based on the individual test cases, summarize the overall purpose of the file: It's a comprehensive suite of unit tests for the memory management components (`MemoryRegion`, `PageMemory`, `PageBackend`) of the `cppgc` library in V8. It verifies correct construction, containment checks, allocation, deallocation, guard page protection, page pooling, and internal data structure management.

6. **Relate to JavaScript (if applicable):**  Recognize that `cppgc` is the C++ garbage collector for V8, which is the JavaScript engine. The memory management tested here directly supports JavaScript execution. When JavaScript objects are created, `cppgc` allocates memory for them using the mechanisms tested in this file. When objects are no longer reachable, `cppgc` reclaims that memory.

7. **Provide a JavaScript Example:**  To illustrate the connection, provide a simple JavaScript example that demonstrates memory allocation. The creation of objects and the eventual garbage collection of those objects relies on the underlying `cppgc` and the correct functioning of the code being tested in this file.

8. **Refine and Organize:**  Structure the summary logically with clear headings. Use concise language and avoid unnecessary jargon. Ensure the JavaScript example clearly illustrates the link. Add a concluding sentence to reinforce the purpose of the file.

Self-Correction/Refinement during the process:

* **Initial thought:**  Focus too much on individual test details.
* **Correction:** Shift focus to the higher-level purpose of each test *in relation to the class being tested*.
* **Initial thought:** Miss the connection to JavaScript.
* **Correction:**  Recognize `cppgc` and its role in V8, and then think about how JavaScript code triggers these underlying memory management operations.
* **Initial thought:**  Provide a very complex JavaScript example.
* **Correction:** Use a simple and direct example to make the connection clear.
* **Initial thought:**  Not explicitly state the "unit test" nature of the file.
* **Correction:**  Clearly mention that it's a *unit test* file.
这个C++源代码文件 `page-memory-unittest.cc` 是 **V8 JavaScript 引擎** 中 **cppgc (C++ garbage collector)** 组件的单元测试文件。  它的主要功能是测试与 **内存页管理** 相关的核心 C++ 类的功能，包括：

* **`MemoryRegion`**: 表示一块连续的内存区域，测试其构造、包含地址和包含其他内存区域的功能。
* **`PageMemory`**: 表示一个内存页，包含整体的内存区域和可写入的内存区域，测试其构造和区域包含关系。
* **`PageBackend`**:  负责实际的内存页分配、释放和管理。测试其分配普通页、大页，释放内存，以及利用页池进行内存复用的功能。还测试了 guard page 机制，用于检测越界访问。
* **内部数据结构**: 测试 `PageBackend` 内部用于跟踪已分配内存页的树形数据结构 (`page_memory_region_tree_for_testing_`) 的添加、查找和删除功能。
* **页池 (`page_pool`)**: 测试 `PageBackend` 用于回收和复用已释放内存页的页池机制。

**它与 JavaScript 的功能有密切关系。** V8 引擎使用 cppgc 来管理 JavaScript 对象的内存。  当 JavaScript 代码创建对象时，cppgc 会分配内存来存储这些对象。 `page-memory-unittest.cc` 中测试的这些类和机制是 cppgc 进行内存管理的基础。

**JavaScript 举例说明:**

考虑以下简单的 JavaScript 代码：

```javascript
let obj1 = { name: "Alice", age: 30 };
let obj2 = { city: "New York" };

// ... 一段时间后，obj1 不再被使用

// 执行垃圾回收 (实际发生时间不确定，由引擎决定)
```

在这个例子中：

1. **对象创建:** 当 JavaScript 引擎执行 `let obj1 = ...` 和 `let obj2 = ...` 时，V8 的内存分配器（由 cppgc 管理）会分配内存来存储这两个对象。  `PageBackend` 可能会参与分配一个或多个内存页来容纳这些对象。 `MemoryRegion` 和 `PageMemory` 可能会用于表示这些分配的内存区域。

2. **垃圾回收:** 当 `obj1` 不再被引用时，cppgc 会识别到这一点，并将其标记为可回收。  在垃圾回收的某个阶段，cppgc 会释放 `obj1` 占用的内存。 `PageBackend` 的释放机制会被调用。 如果启用了页池，被释放的内存页可能会被添加到页池中以供后续分配复用。

3. **Guard Page:**  如果 `PageBackend` 配置了 guard page，那么在分配的内存页的边界会有不可访问的区域。 如果 JavaScript 代码（或者 V8 引擎自身的 C++ 代码中存在 bug）尝试访问这些 guard page 区域，将会触发错误，这正是 `PageBackendDeathTest` 中测试的内容。

**更具体地，`page-memory-unittest.cc` 中测试的功能与 JavaScript 的以下方面相关：**

* **内存分配效率:** 页池的测试确保了内存可以被高效地回收和复用，避免频繁的向操作系统请求新的内存页，从而提高 JavaScript 程序的性能。
* **内存安全性:** guard page 的测试确保了 V8 引擎能够有效地检测和防止内存越界访问，这对于保证 JavaScript 程序的稳定性和安全性至关重要。
* **垃圾回收机制:** 虽然这个文件没有直接测试垃圾回收算法，但它测试了垃圾回收器赖以工作的底层内存管理机制。  `PageBackend` 的分配和释放是垃圾回收器回收不再使用的 JavaScript 对象内存的基础。

**总结来说，`page-memory-unittest.cc`  是确保 V8 引擎的 C++ 垃圾回收器能够正确且安全地管理内存页的关键组成部分。  它的正常工作直接影响到 JavaScript 程序的性能、稳定性和安全性。**

Prompt: 
```
这是目录为v8/test/unittests/heap/cppgc/page-memory-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/cppgc/page-memory.h"

#include <algorithm>

#include "src/base/page-allocator.h"
#include "src/heap/cppgc/platform.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace cppgc {
namespace internal {

TEST(MemoryRegionTest, Construct) {
  constexpr size_t kSize = 17;
  uint8_t dummy[kSize];
  const MemoryRegion region(dummy, kSize);
  EXPECT_EQ(dummy, region.base());
  EXPECT_EQ(kSize, region.size());
  EXPECT_EQ(dummy + kSize, region.end());
}

namespace {

Address AtOffset(uint8_t* base, intptr_t offset) {
  return reinterpret_cast<Address>(reinterpret_cast<intptr_t>(base) + offset);
}

}  // namespace

TEST(MemoryRegionTest, ContainsAddress) {
  constexpr size_t kSize = 7;
  uint8_t dummy[kSize];
  const MemoryRegion region(dummy, kSize);
  EXPECT_FALSE(region.Contains(AtOffset(dummy, -1)));
  EXPECT_TRUE(region.Contains(dummy));
  EXPECT_TRUE(region.Contains(dummy + kSize - 1));
  EXPECT_FALSE(region.Contains(AtOffset(dummy, kSize)));
}

TEST(MemoryRegionTest, ContainsMemoryRegion) {
  constexpr size_t kSize = 7;
  uint8_t dummy[kSize];
  const MemoryRegion region(dummy, kSize);
  const MemoryRegion contained_region1(dummy, kSize - 1);
  EXPECT_TRUE(region.Contains(contained_region1));
  const MemoryRegion contained_region2(dummy + 1, kSize - 1);
  EXPECT_TRUE(region.Contains(contained_region2));
  const MemoryRegion not_contained_region1(AtOffset(dummy, -1), kSize);
  EXPECT_FALSE(region.Contains(not_contained_region1));
  const MemoryRegion not_contained_region2(AtOffset(dummy, kSize), 1);
  EXPECT_FALSE(region.Contains(not_contained_region2));
}

TEST(PageMemoryTest, Construct) {
  constexpr size_t kOverallSize = 17;
  uint8_t dummy[kOverallSize];
  const MemoryRegion overall_region(dummy, kOverallSize);
  const MemoryRegion writeable_region(dummy + 1, kOverallSize - 2);
  const PageMemory page_memory(overall_region, writeable_region);
  EXPECT_EQ(dummy, page_memory.overall_region().base());
  EXPECT_EQ(dummy + kOverallSize, page_memory.overall_region().end());
  EXPECT_EQ(dummy + 1, page_memory.writeable_region().base());
  EXPECT_EQ(dummy + kOverallSize - 1, page_memory.writeable_region().end());
}

#if DEBUG

TEST(PageMemoryDeathTest, ConstructNonContainedRegions) {
  constexpr size_t kOverallSize = 17;
  uint8_t dummy[kOverallSize];
  const MemoryRegion overall_region(dummy, kOverallSize);
  const MemoryRegion writeable_region(dummy + 1, kOverallSize);
  EXPECT_DEATH_IF_SUPPORTED(PageMemory(overall_region, writeable_region), "");
}

#endif  // DEBUG

// See the comment in globals.h when setting |kGuardPageSize| for details.
#if !(defined(V8_TARGET_ARCH_ARM64) && defined(V8_OS_MACOS))
TEST(PageMemoryRegionTest, PlatformUsesGuardPages) {
  // This tests that the testing allocator actually uses protected guard
  // regions.
  v8::base::PageAllocator allocator;
#if defined(V8_HOST_ARCH_PPC64) && !defined(_AIX)
  EXPECT_FALSE(SupportsCommittingGuardPages(allocator));
#elif defined(V8_HOST_ARCH_ARM64) || defined(V8_HOST_ARCH_LOONG64)
  if (allocator.CommitPageSize() == 4096) {
    EXPECT_TRUE(SupportsCommittingGuardPages(allocator));
  } else {
    // Arm64 supports both 16k and 64k OS pages.
    EXPECT_FALSE(SupportsCommittingGuardPages(allocator));
  }
#else  // Regular case.
  EXPECT_TRUE(SupportsCommittingGuardPages(allocator));
#endif
}
#endif  // !(defined(V8_TARGET_ARCH_ARM64) && defined(V8_OS_MACOS))

namespace {

V8_NOINLINE uint8_t access(volatile const uint8_t& u) { return u; }

}  // namespace

TEST(PageBackendDeathTest, ReservationIsFreed) {
  // Full sequence as part of the death test macro as otherwise, the macro
  // may expand to statements that re-purpose the previously freed memory
  // and thus not crash.
  EXPECT_DEATH_IF_SUPPORTED(
      v8::base::PageAllocator allocator; Address base; {
        PageBackend backend(allocator, allocator);
        base = backend.TryAllocateLargePageMemory(1024);
      } access(*base);
      , "");
}

TEST(PageBackendDeathTest, FrontGuardPageAccessCrashes) {
  v8::base::PageAllocator allocator;
  PageBackend backend(allocator, allocator);
  auto* base = backend.TryAllocateNormalPageMemory();
  if (SupportsCommittingGuardPages(allocator)) {
    EXPECT_DEATH_IF_SUPPORTED(access(base[-kGuardPageSize]), "");
  }
}

TEST(PageBackendDeathTest, BackGuardPageAccessCrashes) {
  v8::base::PageAllocator allocator;
  PageBackend backend(allocator, allocator);
  auto* base = backend.TryAllocateNormalPageMemory();
  if (SupportsCommittingGuardPages(allocator)) {
    EXPECT_DEATH_IF_SUPPORTED(access(base[kPageSize - 2 * kGuardPageSize]), "");
  }
}

TEST(PageBackendTreeTest, AddNormalLookupRemove) {
  v8::base::PageAllocator allocator;
  PageBackend backend(allocator, allocator);
  auto* writable_base = backend.TryAllocateNormalPageMemory();
  auto* reserved_base = writable_base - kGuardPageSize;
  auto& tree = backend.get_page_memory_region_tree_for_testing();
  ASSERT_EQ(
      reserved_base,
      tree.Lookup(reserved_base)->GetPageMemory().overall_region().base());
  ASSERT_EQ(reserved_base, tree.Lookup(reserved_base + kPageSize - 1)
                               ->GetPageMemory()
                               .overall_region()
                               .base());
  ASSERT_EQ(nullptr, tree.Lookup(reserved_base - 1));
  ASSERT_EQ(nullptr, tree.Lookup(reserved_base + kPageSize));
  backend.FreeNormalPageMemory(writable_base,
                               FreeMemoryHandling::kDoNotDiscard);
  ASSERT_EQ(nullptr, tree.Lookup(reserved_base));
  ASSERT_EQ(nullptr, tree.Lookup(reserved_base + kPageSize - 1));
}

TEST(PageBackendTreeTest, AddLargeLookupRemove) {
  v8::base::PageAllocator allocator;
  constexpr size_t kLargeSize = 5012;
  const size_t allocated_page_size =
      RoundUp(kLargeSize + 2 * kGuardPageSize, allocator.AllocatePageSize());
  PageBackend backend(allocator, allocator);
  auto* writable_base = backend.TryAllocateLargePageMemory(kLargeSize);
  auto* reserved_base = writable_base - kGuardPageSize;
  auto& tree = backend.get_page_memory_region_tree_for_testing();
  ASSERT_EQ(
      reserved_base,
      tree.Lookup(reserved_base)->GetPageMemory().overall_region().base());
  ASSERT_EQ(reserved_base, tree.Lookup(reserved_base + allocated_page_size - 1)
                               ->GetPageMemory()
                               .overall_region()
                               .base());
  ASSERT_EQ(nullptr, tree.Lookup(reserved_base - 1));
  ASSERT_EQ(nullptr, tree.Lookup(reserved_base + allocated_page_size));
  backend.FreeLargePageMemory(writable_base);
  ASSERT_EQ(nullptr, tree.Lookup(reserved_base));
  ASSERT_EQ(nullptr, tree.Lookup(reserved_base + allocated_page_size - 1));
}

TEST(PageBackendTreeTest, AddLookupRemoveMultiple) {
  v8::base::PageAllocator allocator;
  constexpr size_t kLargeSize = 3127;
  const size_t allocated_page_size =
      RoundUp(kLargeSize + 2 * kGuardPageSize, allocator.AllocatePageSize());

  PageBackend backend(allocator, allocator);
  auto& tree = backend.get_page_memory_region_tree_for_testing();

  auto* writable_normal_base = backend.TryAllocateNormalPageMemory();
  auto* reserved_normal_base = writable_normal_base - kGuardPageSize;
  auto* writable_large_base = backend.TryAllocateLargePageMemory(kLargeSize);
  auto* reserved_large_base = writable_large_base - kGuardPageSize;

  ASSERT_EQ(reserved_normal_base, tree.Lookup(reserved_normal_base)
                                      ->GetPageMemory()
                                      .overall_region()
                                      .base());
  ASSERT_EQ(reserved_normal_base,
            tree.Lookup(reserved_normal_base + kPageSize - 1)
                ->GetPageMemory()
                .overall_region()
                .base());
  ASSERT_EQ(reserved_large_base, tree.Lookup(reserved_large_base)
                                     ->GetPageMemory()
                                     .overall_region()
                                     .base());
  ASSERT_EQ(reserved_large_base,
            tree.Lookup(reserved_large_base + allocated_page_size - 1)
                ->GetPageMemory()
                .overall_region()
                .base());

  backend.FreeNormalPageMemory(writable_normal_base,
                               FreeMemoryHandling::kDoNotDiscard);

  ASSERT_EQ(reserved_large_base, tree.Lookup(reserved_large_base)
                                     ->GetPageMemory()
                                     .overall_region()
                                     .base());
  ASSERT_EQ(reserved_large_base,
            tree.Lookup(reserved_large_base + allocated_page_size - 1)
                ->GetPageMemory()
                .overall_region()
                .base());

  backend.FreeLargePageMemory(writable_large_base);

  ASSERT_EQ(nullptr, tree.Lookup(reserved_large_base));
  ASSERT_EQ(nullptr,
            tree.Lookup(reserved_large_base + allocated_page_size - 1));
}

TEST(PageBackendPoolTest, ConstructorEmpty) {
  v8::base::PageAllocator allocator;
  PageBackend backend(allocator, allocator);
  auto& pool = backend.page_pool();
  EXPECT_EQ(nullptr, pool.Take());
}

TEST(PageBackendPoolTest, AddTake) {
  v8::base::PageAllocator allocator;
  PageBackend backend(allocator, allocator);
  auto& pool = backend.page_pool();
  auto& raw_pool = pool.get_raw_pool_for_testing();

  EXPECT_TRUE(raw_pool.empty());
  auto* writable_base1 = backend.TryAllocateNormalPageMemory();
  EXPECT_TRUE(raw_pool.empty());

  backend.FreeNormalPageMemory(writable_base1,
                               FreeMemoryHandling::kDoNotDiscard);
  EXPECT_FALSE(raw_pool.empty());
  EXPECT_TRUE(raw_pool[0].region);
  EXPECT_EQ(raw_pool[0].region->GetPageMemory().writeable_region().base(),
            writable_base1);

  auto* writable_base2 = backend.TryAllocateNormalPageMemory();
  EXPECT_TRUE(raw_pool.empty());
  EXPECT_EQ(writable_base1, writable_base2);
}

namespace {
void AddTakeWithDiscardInBetween(bool decommit_pooled_pages) {
  v8::base::PageAllocator allocator;
  PageBackend backend(allocator, allocator);
  auto& pool = backend.page_pool();
  pool.SetDecommitPooledPages(decommit_pooled_pages);
  auto& raw_pool = pool.get_raw_pool_for_testing();

  EXPECT_TRUE(raw_pool.empty());
  auto* writable_base1 = backend.TryAllocateNormalPageMemory();
  EXPECT_TRUE(raw_pool.empty());
  EXPECT_EQ(0u, pool.PooledMemory());

  backend.FreeNormalPageMemory(writable_base1,
                               FreeMemoryHandling::kDoNotDiscard);
  EXPECT_FALSE(raw_pool.empty());
  EXPECT_TRUE(raw_pool[0].region);
  EXPECT_EQ(raw_pool[0].region->GetPageMemory().writeable_region().base(),
            writable_base1);
  size_t size = raw_pool[0].region->GetPageMemory().writeable_region().size();
  EXPECT_EQ(size, pool.PooledMemory());

  backend.DiscardPooledPages();
  // Not couting discarded memory.
  EXPECT_EQ(0u, pool.PooledMemory());

  auto* writable_base2 = backend.TryAllocateNormalPageMemory();
  EXPECT_TRUE(raw_pool.empty());
  EXPECT_EQ(0u, pool.PooledMemory());
  EXPECT_EQ(writable_base1, writable_base2);
  // Should not die: memory is writable.
  memset(writable_base2, 12, size);
}
}  // namespace

TEST(PageBackendPoolTest, AddTakeWithDiscardInBetween) {
  AddTakeWithDiscardInBetween(false);
}

TEST(PageBackendPoolTest, AddTakeWithDiscardInBetweenWithDecommit) {
  AddTakeWithDiscardInBetween(true);
}

TEST(PageBackendPoolTest, PoolMemoryAccounting) {
  v8::base::PageAllocator allocator;
  PageBackend backend(allocator, allocator);
  auto& pool = backend.page_pool();

  auto* writable_base1 = backend.TryAllocateNormalPageMemory();
  auto* writable_base2 = backend.TryAllocateNormalPageMemory();
  backend.FreeNormalPageMemory(writable_base1,
                               FreeMemoryHandling::kDoNotDiscard);
  backend.FreeNormalPageMemory(writable_base2,
                               FreeMemoryHandling::kDoNotDiscard);
  size_t normal_page_size = pool.get_raw_pool_for_testing()[0]
                                .region->GetPageMemory()
                                .writeable_region()
                                .size();

  EXPECT_EQ(2 * normal_page_size, pool.PooledMemory());
  backend.DiscardPooledPages();
  EXPECT_EQ(0u, pool.PooledMemory());

  auto* writable_base3 = backend.TryAllocateNormalPageMemory();
  backend.FreeNormalPageMemory(writable_base3,
                               FreeMemoryHandling::kDoNotDiscard);
  // One discarded, one not discarded.
  EXPECT_EQ(normal_page_size, pool.PooledMemory());
  backend.DiscardPooledPages();
  EXPECT_EQ(0u, pool.PooledMemory());
}

TEST(PageBackendTest, AllocateNormalUsesPool) {
  v8::base::PageAllocator allocator;
  PageBackend backend(allocator, allocator);
  Address writeable_base1 = backend.TryAllocateNormalPageMemory();
  EXPECT_NE(nullptr, writeable_base1);
  backend.FreeNormalPageMemory(writeable_base1,
                               FreeMemoryHandling::kDoNotDiscard);
  Address writeable_base2 = backend.TryAllocateNormalPageMemory();
  EXPECT_NE(nullptr, writeable_base2);
  EXPECT_EQ(writeable_base1, writeable_base2);
}

TEST(PageBackendTest, AllocateLarge) {
  v8::base::PageAllocator allocator;
  PageBackend backend(allocator, allocator);
  Address writeable_base1 = backend.TryAllocateLargePageMemory(13731);
  EXPECT_NE(nullptr, writeable_base1);
  Address writeable_base2 = backend.TryAllocateLargePageMemory(9478);
  EXPECT_NE(nullptr, writeable_base2);
  EXPECT_NE(writeable_base1, writeable_base2);
  backend.FreeLargePageMemory(writeable_base1);
  backend.FreeLargePageMemory(writeable_base2);
}

TEST(PageBackendTest, LookupNormal) {
  v8::base::PageAllocator allocator;
  PageBackend backend(allocator, allocator);
  Address writeable_base = backend.TryAllocateNormalPageMemory();
  if (kGuardPageSize) {
    EXPECT_EQ(nullptr, backend.Lookup(writeable_base - kGuardPageSize));
  }
  EXPECT_EQ(nullptr, backend.Lookup(writeable_base - 1));
  EXPECT_EQ(writeable_base, backend.Lookup(writeable_base));
  EXPECT_EQ(writeable_base, backend.Lookup(writeable_base + kPageSize -
                                           2 * kGuardPageSize - 1));
  EXPECT_EQ(nullptr,
            backend.Lookup(writeable_base + kPageSize - 2 * kGuardPageSize));
  if (kGuardPageSize) {
    EXPECT_EQ(nullptr,
              backend.Lookup(writeable_base - kGuardPageSize + kPageSize - 1));
  }
}

TEST(PageBackendTest, LookupLarge) {
  v8::base::PageAllocator allocator;
  PageBackend backend(allocator, allocator);
  constexpr size_t kSize = 7934;
  Address writeable_base = backend.TryAllocateLargePageMemory(kSize);
  if (kGuardPageSize) {
    EXPECT_EQ(nullptr, backend.Lookup(writeable_base - kGuardPageSize));
  }
  EXPECT_EQ(nullptr, backend.Lookup(writeable_base - 1));
  EXPECT_EQ(writeable_base, backend.Lookup(writeable_base));
  EXPECT_EQ(writeable_base, backend.Lookup(writeable_base + kSize - 1));
}

TEST(PageBackendDeathTest, DestructingBackendDestroysPageMemory) {
  v8::base::PageAllocator allocator;
  Address base;
  {
    PageBackend backend(allocator, allocator);
    base = backend.TryAllocateNormalPageMemory();
  }
  EXPECT_DEATH_IF_SUPPORTED(access(base[0]), "");
}

}  // namespace internal
}  // namespace cppgc

"""

```