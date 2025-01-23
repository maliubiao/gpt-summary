Response:
Let's break down the thought process for analyzing the C++ code and fulfilling the request.

1. **Understanding the Goal:** The request asks for a functional summary of the C++ code, including:
    * General purpose
    * Relation to JavaScript (if any)
    * Code logic with examples
    * Common programming errors it helps prevent/detect

2. **Initial Code Scan (Keywords and Structure):**  I'll quickly scan the code for key terms and structural elements:
    * `#include`: Includes standard and V8-specific headers (like `page-allocator.h`, `platform.h`). This immediately suggests low-level memory management.
    * `namespace cppgc::internal`:  Indicates this is internal V8 code, likely related to garbage collection.
    * `TEST(...)`:  Heavy use of Google Test framework, meaning this is a unit test file. The tests are named descriptively (e.g., `MemoryRegionTest`, `PageMemoryTest`, `PageBackendTest`).
    * `MemoryRegion`, `PageMemory`, `PageBackend`: These seem to be the core classes being tested.
    * `TryAllocateNormalPageMemory`, `TryAllocateLargePageMemory`, `FreeNormalPageMemory`, `FreeLargePageMemory`: Functions related to memory allocation and deallocation.
    * `kGuardPageSize`, `kPageSize`: Constants likely related to memory page sizes and guard pages.
    * `Contains`, `Lookup`: Methods suggesting operations on memory regions.
    * `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_DEATH_IF_SUPPORTED`: Google Test assertion macros, used for verifying expected behavior.

3. **Analyzing Core Classes (Inferring Functionality from Tests):**  The test names provide significant clues:
    * `MemoryRegionTest`:  Tests for constructing `MemoryRegion` objects and checking if they contain addresses or other memory regions. This class likely represents a contiguous block of memory.
    * `PageMemoryTest`: Tests for constructing `PageMemory` objects, which seem to consist of an "overall" region and a "writable" region. This suggests a distinction between the total allocated memory and the portion that's currently usable for writing.
    * `PageBackendTest`:  The most comprehensive set of tests. It covers:
        * Allocation and freeing of "normal" and "large" pages.
        * The use of a "pool" for reusing freed normal pages.
        * "Guard pages" and the expected crashes when accessing them. This strongly implies memory protection mechanisms.
        * A "tree" data structure for tracking allocated memory regions.

4. **Connecting to V8's Garbage Collection (CppGC):** The namespace `cppgc` and the context of page management strongly suggest this code is part of V8's C++ garbage collector. The concepts of pages, regions, and guard pages are common in memory management and particularly relevant to garbage collectors.

5. **Considering JavaScript Connection:**  Garbage collection is essential for JavaScript. While this C++ code isn't directly *written* in JavaScript, it's a foundational component that enables JavaScript's automatic memory management. JavaScript developers don't directly interact with these low-level details, but the functionality provided here is crucial for the JavaScript engine's operation.

6. **Generating Examples and Explanations:**

    * **Functionality:**  Summarize the roles of `MemoryRegion`, `PageMemory`, and `PageBackend` based on the test names and the operations performed.
    * **JavaScript Relation:** Explain the indirect relationship through garbage collection. A simple JavaScript example of object creation demonstrates the need for the underlying memory management provided by this C++ code.
    * **Code Logic:**  Choose a few representative tests (e.g., `MemoryRegionTest::ContainsAddress`, `PageBackendTreeTest::AddNormalLookupRemove`) and explain the setup, the assertion being made, and the underlying logic. Provide hypothetical inputs and outputs based on the test assertions.
    * **Common Errors:**  Focus on errors related to manual memory management (like accessing freed memory, buffer overflows) that this code helps prevent or detect. The guard page tests are a clear example of this.

7. **Addressing `.tq` Extension:**  The request specifically asks about `.tq`. Recall that `.tq` files are associated with V8's Torque language. Since the file ends in `.cc`, it's C++, so clarify the distinction.

8. **Review and Refine:**  Read through the generated explanation to ensure clarity, accuracy, and completeness. Check if all aspects of the request have been addressed. For instance, initially, I might not have explicitly mentioned the role of `v8::base::PageAllocator`. A review would prompt me to add this important detail. Also, ensure the language is accessible and avoids overly technical jargon where possible.

This structured approach allows for a systematic understanding of the code, even without deep prior knowledge of the specific V8 internals. By focusing on the tests and their names, we can infer the functionality of the underlying classes and their role in the larger context of a JavaScript engine.
`v8/test/unittests/heap/cppgc/page-memory-unittest.cc` 是一个 V8 项目的 C++ 单元测试文件，专门用于测试与 CppGC（C++ Garbage Collector）中页面内存管理相关的代码。

**主要功能:**

这个文件的主要目的是验证 `src/heap/cppgc/page-memory.h` 中定义的 `MemoryRegion` 和 `PageMemory` 类以及 `PageBackend` 类的正确性。它通过一系列的单元测试用例来检查这些类在各种场景下的行为是否符合预期。

**具体测试的功能点包括:**

1. **`MemoryRegion` 类的功能测试:**
   - **构造函数:** 验证 `MemoryRegion` 对象能否正确地使用给定的基地址和大小进行构造。
   - **`Contains(Address)`:** 验证 `MemoryRegion` 对象能否正确判断给定的地址是否包含在其管理的内存区域内。
   - **`Contains(MemoryRegion)`:** 验证 `MemoryRegion` 对象能否正确判断给定的另一个 `MemoryRegion` 是否完全包含在其管理的内存区域内。

2. **`PageMemory` 类的功能测试:**
   - **构造函数:** 验证 `PageMemory` 对象能否正确地使用整体内存区域和可写内存区域进行构造，并确保可写区域包含在整体区域内。
   - **断言测试 (DEBUG 模式):**  在 DEBUG 模式下，测试构造 `PageMemory` 对象时，如果可写区域不包含在整体区域内，会触发断言失败。

3. **平台 Guard Pages 的测试:**
   - **`SupportsCommittingGuardPages`:**  测试底层平台是否支持提交保护页（Guard Pages）。Guard Pages 用于检测内存访问越界错误。这个测试会根据不同的平台和配置进行不同的断言。

4. **`PageBackend` 类的功能测试:**
   - **内存分配和释放:** 测试 `PageBackend` 能否正确分配和释放普通大小的内存页 (`TryAllocateNormalPageMemory`, `FreeNormalPageMemory`) 和大内存页 (`TryAllocateLargePageMemory`, `FreeLargePageMemory`)。
   - **Guard Page 机制:** 测试访问分配的内存页的前后 Guard Pages 是否会导致程序崩溃，以验证 Guard Pages 的保护机制是否生效。
   - **内存区域树 (`PageMemoryRegionTree`):** 测试 `PageBackend` 内部用于跟踪已分配内存区域的树形数据结构的插入 (`Add`)、查找 (`Lookup`) 和删除 (`Remove`) 功能。这包括普通页和大页的测试。
   - **内存池 (`PagePool`):** 测试 `PageBackend` 内部用于缓存已释放的普通内存页的内存池的功能。包括：
     - 构造时为空。
     - 添加和取出内存页 (`AddTake`)。
     - 丢弃内存池中的页 (`DiscardPooledPages`)。
     - 内存池的内存统计 (`PooledMemory`)。
     - 分配普通内存页时会优先使用内存池中的页。
   - **查找已分配内存:** 测试 `PageBackend` 的 `Lookup` 方法能否根据给定的地址找到对应的已分配内存块，包括普通页和大页。
   - **析构函数:** 测试 `PageBackend` 对象析构时，会自动释放其管理的内存，并验证访问已释放的内存会导致程序崩溃。

**关于文件扩展名 `.tq` 和 JavaScript 的关系:**

- **`.tq` 结尾:** 如果文件名以 `.tq` 结尾，那么它通常是一个 **Torque** 源代码文件。Torque 是 V8 使用的一种领域特定语言，用于生成高效的 JavaScript 内置函数和运行时代码。
- **当前情况:**  `v8/test/unittests/heap/cppgc/page-memory-unittest.cc` 以 `.cc` 结尾，所以它是一个 **C++** 源代码文件，而不是 Torque 文件。
- **与 JavaScript 的关系:** 虽然这个文件是 C++ 代码，但它直接关系到 V8 的核心功能，即 JavaScript 引擎的内存管理。CppGC 负责 V8 中对象的垃圾回收，而页面内存管理是 CppGC 的基础。JavaScript 对象的分配和回收最终会涉及到这里测试的内存管理机制。

**JavaScript 示例 (间接关系):**

尽管这个 C++ 文件本身不包含 JavaScript 代码，但其测试的功能支撑着 JavaScript 的运行。例如，当你在 JavaScript 中创建很多对象时，V8 的 CppGC 会在后台进行内存管理，其中就包括对页面的分配和管理。

```javascript
// JavaScript 示例
let largeArray = [];
for (let i = 0; i < 1000000; i++) {
  largeArray.push({ index: i, data: "some data" });
}

// 当 largeArray 不再使用时，V8 的垃圾回收器 (CppGC) 会回收其占用的内存，
// 这个过程中就可能涉及到 PageMemory 和 PageBackend 中测试的内存管理操作。

largeArray = null; // 使 largeArray 成为垃圾回收的目标
```

**代码逻辑推理 (假设输入与输出):**

以 `TEST(MemoryRegionTest, ContainsAddress)` 为例：

**假设输入:**

- `dummy`: 指向一块大小为 7 字节的内存区域的起始地址。
- `region`: 一个 `MemoryRegion` 对象，其基地址为 `dummy`，大小为 7。
- `address1`: `dummy - 1` (在 `region` 之前)
- `address2`: `dummy` (在 `region` 的开始)
- `address3`: `dummy + 6` (在 `region` 的末尾)
- `address4`: `dummy + 7` (在 `region` 之后)

**预期输出:**

- `region.Contains(address1)` 返回 `false`
- `region.Contains(address2)` 返回 `true`
- `region.Contains(address3)` 返回 `true`
- `region.Contains(address4)` 返回 `false`

**涉及用户常见的编程错误 (举例说明):**

1. **内存访问越界 (Buffer Overflow):**

   ```c++
   // C++ 代码示例 (模拟可能导致错误的场景)
   constexpr size_t kSize = 7;
   uint8_t buffer[kSize];
   MemoryRegion region(buffer, kSize);

   // 用户错误：尝试访问超出 buffer 范围的内存
   buffer[10] = 0; // 错误！访问了 region 之外的内存

   // PageBackend 的 Guard Page 机制旨在检测此类错误。
   // 如果 Guard Page 被触碰，程序应该崩溃。
   ```

2. **使用已释放的内存 (Use-After-Free):**

   ```c++
   // C++ 代码示例 (模拟可能导致错误的场景)
   v8::base::PageAllocator allocator;
   PageBackend backend(allocator, allocator);
   Address writeable_base = backend.TryAllocateNormalPageMemory();

   // ... 使用 writeable_base ...

   backend.FreeNormalPageMemory(writeable_base, FreeMemoryHandling::kDoNotDiscard);

   // 用户错误：尝试访问已释放的内存
   // *writeable_base = 10; // 错误！访问了已经释放的内存

   // PageBackend 的析构函数测试和相关死亡测试旨在捕获此类错误。
   ```

3. **不正确的内存区域包含判断:**

   ```c++
   constexpr size_t kSize1 = 10;
   uint8_t buffer1[kSize1];
   MemoryRegion region1(buffer1, kSize1);

   constexpr size_t kSize2 = 5;
   uint8_t buffer2[kSize2];
   MemoryRegion region2(buffer2, kSize2);

   // 用户错误：可能误认为 region1 包含 region2，但实际情况并非如此
   // 除非 buffer2 的内存恰好完全位于 buffer1 内部。
   // MemoryRegion 的 Contains 方法的测试确保了这种判断的正确性。
   bool contains = region1.Contains(region2);
   ```

总而言之，`v8/test/unittests/heap/cppgc/page-memory-unittest.cc` 是 V8 引擎中至关重要的测试文件，它确保了 CppGC 核心的页面内存管理机制的正确性和健壮性，从而间接地保障了 JavaScript 程序的稳定运行。它通过各种单元测试覆盖了内存区域的创建、包含判断、内存页的分配和释放、Guard Page 机制以及内存池的管理等关键功能。

### 提示词
```
这是目录为v8/test/unittests/heap/cppgc/page-memory-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/heap/cppgc/page-memory-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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
```