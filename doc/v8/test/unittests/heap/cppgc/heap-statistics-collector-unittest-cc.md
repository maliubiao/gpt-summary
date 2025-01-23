Response:
Let's break down the thought process for analyzing the C++ code and fulfilling the request.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of `heap-statistics-collector-unittest.cc` within the v8/cppgc context. The prompt specifically asks for:

* **Functionality Summary:** What does this code *do*?
* **Torque Check:** Is it a Torque file?
* **JavaScript Relationship:**  Does it interact with JavaScript, and how?
* **Code Logic Reasoning:**  Provide input/output examples for the tests.
* **Common Programming Errors:**  Are there related pitfalls?

**2. Initial Code Scan and Keyword Spotting:**

I'd start by quickly scanning the code for recognizable patterns and keywords:

* `#include`:  This indicates C++ code and dependencies. The included headers (`heap-statistics-collector.h`, `cppgc/heap-statistics.h`, `testing/gtest/include/gtest/gtest.h`) are crucial. `gtest/gtest.h` immediately tells me this is a unit test file using Google Test.
* `namespace cppgc::internal`: This confirms we're dealing with the `cppgc` (C++ garbage collection) part of V8. The `internal` namespace suggests these are implementation details.
* `class HeapStatisticsCollectorTest : public testing::TestWithHeap`: This is the core of the unit test structure. It sets up a test fixture (`HeapStatisticsCollectorTest`) that inherits from `testing::TestWithHeap`, implying access to a test heap environment.
* `TEST_F`:  These are individual test cases within the fixture. The names are descriptive (e.g., `EmptyHeapBriefStatisitcs`, `NonEmptyNormalPage`).
* `Heap::From(GetHeap())->CollectStatistics(...)`: This is the central function being tested – collecting heap statistics. The different `DetailLevel` values (`kBrief`, `kDetailed`) are important.
* `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_NE`, `EXPECT_GT`: These are Google Test assertion macros, confirming the expected outcomes of the tests.
* `MakeGarbageCollected`: This function indicates the creation of objects managed by the garbage collector.
* `ConservativeMemoryDiscardingGC()`: This function suggests testing memory discarding behavior.
* `Persistent`: This indicates a persistent handle to a garbage-collected object, preventing it from being immediately collected.

**3. Deconstructing Test Cases (Detailed Analysis):**

I would then go through each `TEST_F` case and understand its specific purpose:

* **`EmptyHeapBriefStatisitcs` and `EmptyHeapDetailedStatisitcs`:** These tests verify the statistics reported for an empty heap. They check that sizes are zero and, in the detailed case, verify the number of memory spaces.
* **`NonEmptyNormalPage`:** This test allocates a small object, forcing the creation of a "normal" page, and then checks the detailed statistics to see if the sizes are correctly reported for the page and the object.
* **`NonEmptyLargePage`:**  Similar to the previous test, but it allocates a large object, ensuring it goes into a "large page."  The size calculations are different for large pages.
* **`BriefStatisticsWithDiscardingOnNormalPage`:** This test allocates an object, performs a garbage collection that *discards* memory, and checks that the resident size is less than the committed size (indicating memory was discarded).
* **`BriefStatisticsWithoutDiscardingOnNormalPage`:** This test allocates an object, performs a garbage collection that *doesn't discard* memory, and then checks for the presence of "pooled memory." It then performs a collection that *does* discard memory and checks that the pooled memory is gone.
* **`DetailedStatisticsWithDiscardingOnNormalPage`:** Similar to the brief statistics discarding test, but it verifies the detailed page statistics to confirm memory discarding at the page level.

**4. Answering the Specific Questions:**

Now, with a good understanding of the tests, I can address the prompt's questions:

* **Functionality:**  Synthesize the understanding of each test case into a concise summary of the file's purpose: testing the `HeapStatisticsCollector`.
* **Torque Check:** The filename ends in `.cc`, not `.tq`, so it's C++.
* **JavaScript Relationship:**  Connect the concept of garbage collection (and thus the need for statistics) to how JavaScript engines manage memory. Explain that these statistics are internal but reflect what's happening when JavaScript objects are created and destroyed. Provide a simple JavaScript example showing object creation.
* **Code Logic Reasoning:** Choose one or two of the simpler test cases (like `EmptyHeapBriefStatisitcs` or `NonEmptyNormalPage`) and walk through the assertions with example values.
* **Common Programming Errors:** Think about the *purpose* of these statistics. They help diagnose memory issues. Therefore, a common error is *not monitoring* memory usage or misunderstanding how garbage collection works, leading to unexpected memory growth or performance problems. Provide examples like memory leaks (in the context of C++ as the test is C++ related even if connected to JS).

**5. Refinement and Clarity:**

Finally, review the answers for clarity, accuracy, and conciseness. Ensure the language is easy to understand, especially the connection to JavaScript and common errors. Use bullet points and clear headings to structure the information.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe focus heavily on the C++ details.
* **Correction:** The prompt explicitly asks for a connection to JavaScript and common programming errors, so broaden the scope.
* **Initial thought:** Explain every single line of C++ code.
* **Correction:** Focus on the *purpose* of the tests and the overall functionality, not the minute details of the C++ implementation unless directly relevant to the prompt's questions.
* **Initial thought:** Only consider C++ memory leaks as common errors.
* **Correction:**  While C++ is the language of the test, consider the *impact* on JavaScript developers – issues like excessive memory usage in their applications due to the underlying engine's behavior.

By following this structured approach, combining code analysis with an understanding of the request, I can generate a comprehensive and helpful response.
好的，让我们来分析一下 `v8/test/unittests/heap/cppgc/heap-statistics-collector-unittest.cc` 这个 V8 C++ 源代码文件的功能。

**功能概述:**

`heap-statistics-collector-unittest.cc` 是一个单元测试文件，专门用于测试 `cppgc`（V8 的 C++ 垃圾回收器）中 `HeapStatisticsCollector` 类的功能。它的主要目的是验证 `HeapStatisticsCollector` 是否能够正确地收集和报告堆的各种统计信息。

**具体功能拆解:**

1. **测试不同详细程度的统计信息收集:**
   - `EmptyHeapBriefStatisitcs` 和 `EmptyHeapDetailedStatisitcs` 测试用例验证了在空堆的情况下，收集简要 (`kBrief`) 和详细 (`kDetailed`) 统计信息的正确性。
   - 它检查了如已用大小、池化内存大小等基本指标是否为 0。
   - 对于详细统计信息，它还检查了内存空间的数量和每个空间的统计信息（如已用大小、页统计信息、空闲列表统计信息）。

2. **测试非空堆的统计信息收集:**
   - `NonEmptyNormalPage` 测试用例创建了一个小对象（占用一个普通大小的页），并验证了详细统计信息是否正确地反映了堆的已用大小、提交大小、驻留大小以及页的统计信息。
   - `NonEmptyLargePage` 测试用例创建了一个大对象（占用一个大页），并验证了详细统计信息对于大页的统计是否正确。

3. **测试垃圾回收对统计信息的影响:**
   - `BriefStatisticsWithDiscardingOnNormalPage` 测试用例模拟了垃圾回收并丢弃内存的情况，然后检查简要统计信息是否反映了驻留大小小于提交大小（因为部分内存被丢弃）。
   - `BriefStatisticsWithoutDiscardingOnNormalPage` 测试用例模拟了垃圾回收但不丢弃内存的情况，然后检查简要统计信息中池化内存的大小。它还测试了在不丢弃内存和丢弃内存的情况下，池化内存的变化。
   - `DetailedStatisticsWithDiscardingOnNormalPage` 测试用例模拟了垃圾回收并丢弃内存的情况，并检查详细统计信息中页的驻留大小是否小于提交大小。

**关于文件类型:**

`v8/test/unittests/heap/cppgc/heap-statistics-collector-unittest.cc` 的文件扩展名是 `.cc`，这表明它是一个 **C++ 源代码文件**。因此，它不是一个 Torque 源代码文件。

**与 JavaScript 的关系:**

虽然这个文件本身是 C++ 代码，但它测试的是 V8 引擎的核心组件 `cppgc`，而 `cppgc` 负责管理 V8 中 C++ 对象的内存。JavaScript 对象最终也是由 V8 引擎管理的，在底层涉及到 `cppgc` 的内存分配和垃圾回收。

当 JavaScript 代码创建对象时，V8 引擎会在堆上分配内存。`HeapStatisticsCollector` 收集的统计信息就反映了这些内存分配和回收的情况。

**JavaScript 示例:**

虽然无法直接用 JavaScript 代码来展示这个 C++ 单元测试的功能，但我们可以用 JavaScript 来说明它所监控的内存行为：

```javascript
// 创建一些 JavaScript 对象
let obj1 = { name: "Object 1" };
let obj2 = { data: [1, 2, 3, 4, 5] };
let arr = new Array(10000);

// 执行一些操作，可能会触发垃圾回收
for (let i = 0; i < 1000; i++) {
  let temp = { value: i };
}

// obj1 和 obj2 仍然被引用，不会被立即回收
console.log(obj1.name);

// arr 也被引用
console.log(arr.length);

// 某些对象可能因为不再被引用而被垃圾回收

// HeapStatisticsCollector 负责收集类似以下信息（只是概念上的）：
// - 堆的总大小
// - 已用大小（obj1, obj2, arr 占用的内存）
// - 空闲大小
// - 不同类型的内存区域的使用情况
```

在这个 JavaScript 例子中，`HeapStatisticsCollector` 的工作就是监控 V8 引擎为了存储 `obj1`、`obj2` 和 `arr` 等 JavaScript 对象而进行的内存分配和回收操作。

**代码逻辑推理 (假设输入与输出):**

让我们以 `EmptyHeapBriefStatisitcs` 测试用例为例：

**假设输入:**
- 创建一个空的 `cppgc::Heap` 实例。

**代码逻辑:**
- 调用 `Heap::From(GetHeap())->CollectStatistics(HeapStatistics::DetailLevel::kBrief)` 来收集简要统计信息。

**预期输出:**
- `brief_stats.detail_level` 等于 `HeapStatistics::DetailLevel::kBrief`。
- `brief_stats.used_size_bytes` 等于 `0u`。
- `brief_stats.pooled_memory_size_bytes` 等于 `0u`。
- `brief_stats.space_stats` 是空的。

**代码逻辑推理 (假设输入与输出) - `NonEmptyNormalPage` 简化版:**

**假设输入:**
- 创建一个 `cppgc::Heap` 实例。
- 使用 `MakeGarbageCollected<GCed<1>>(GetHeap()->GetAllocationHandle())` 在堆上分配一个小对象。

**代码逻辑:**
- 调用 `Heap::From(GetHeap())->CollectStatistics(HeapStatistics::DetailLevel::kDetailed)` 来收集详细统计信息。

**预期输出 (部分):**
- `detailed_stats.used_size_bytes` 将大于 0，具体数值取决于对象的大小和对齐。例如，如果 `sizeof(HeapObjectHeader)` 是 8，`kAllocationGranularity` 是 8，那么 `used_size` 可能是 `RoundUp<8>(1 + 8) = 16`。
- 至少有一个内存空间的 `space_stats` 的 `used_size_bytes` 会等于计算出的 `used_size`。
- 相应的内存空间的 `page_stats` 也会反映已用大小。

**涉及用户常见的编程错误 (与内存管理相关):**

虽然这个测试文件是关于 V8 内部的内存管理，但它所测试的功能与用户在编写 C++ 或 JavaScript 代码时可能遇到的内存管理问题息息相关：

1. **内存泄漏 (C++):**  在 C++ 中，如果使用 `cppgc` 管理对象，但忘记取消引用 `Persistent` 对象或在不再需要时释放相关资源，可能会导致内存泄漏。虽然 `cppgc` 会回收不再可达的对象，但如果持有不必要的引用，对象就无法被回收。

   ```c++
   // 假设 MyObject 是一个使用 cppgc 管理的类
   Persistent<MyObject> leakyObject = MakeGarbageCollected<MyObject>(GetHeap()->GetAllocationHandle());
   // ... 使用 leakyObject ...
   // 如果之后忘记释放 leakyObject 或者将其置空，MyObject 就可能无法被回收。
   // 常见的错误是没有正确管理 Persistent 对象的生命周期。
   ```

2. **意外的内存占用:** 用户可能创建了大量不必要的大对象或者持有了指向大对象的引用，导致内存占用超出预期。`HeapStatisticsCollector` 收集的信息可以帮助开发者诊断这类问题。

3. **过度依赖最终化器 (Finalizers):**  虽然 JavaScript 中有 finalizers (以及 C++ `cppgc` 中类似的概念)，但不应该依赖它们来进行关键资源的释放，因为 finalizers 的执行时机是不确定的。这可能导致资源延迟释放，从而影响内存使用。

4. **循环引用:**  在 JavaScript 中，循环引用可能导致对象无法被垃圾回收（对于某些旧的垃圾回收算法）。虽然现代的标记-清除算法可以处理循环引用，但理解对象的生命周期和引用关系仍然很重要，尤其是在涉及到性能敏感的应用时。

**总结:**

`v8/test/unittests/heap/cppgc/heap-statistics-collector-unittest.cc` 是一个关键的测试文件，用于确保 V8 的 C++ 垃圾回收器能够正确地报告堆的统计信息。这些统计信息对于理解和优化 V8 的内存管理至关重要，并且间接地与 JavaScript 开发者可能遇到的内存管理问题相关。虽然开发者通常不会直接使用 `HeapStatisticsCollector`，但了解其背后的原理有助于更好地理解 V8 的内存行为。

### 提示词
```
这是目录为v8/test/unittests/heap/cppgc/heap-statistics-collector-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/heap/cppgc/heap-statistics-collector-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/cppgc/heap-statistics-collector.h"

#include "include/cppgc/heap-statistics.h"
#include "include/cppgc/persistent.h"
#include "src/base/logging.h"
#include "src/base/macros.h"
#include "src/heap/cppgc/globals.h"
#include "test/unittests/heap/cppgc/tests.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace cppgc {
namespace internal {

class HeapStatisticsCollectorTest : public testing::TestWithHeap {};

TEST_F(HeapStatisticsCollectorTest, EmptyHeapBriefStatisitcs) {
  HeapStatistics brief_stats = Heap::From(GetHeap())->CollectStatistics(
      HeapStatistics::DetailLevel::kBrief);
  EXPECT_EQ(HeapStatistics::DetailLevel::kBrief, brief_stats.detail_level);
  EXPECT_EQ(0u, brief_stats.used_size_bytes);
  EXPECT_EQ(0u, brief_stats.used_size_bytes);
  EXPECT_EQ(0u, brief_stats.pooled_memory_size_bytes);
  EXPECT_TRUE(brief_stats.space_stats.empty());
}

TEST_F(HeapStatisticsCollectorTest, EmptyHeapDetailedStatisitcs) {
  HeapStatistics detailed_stats = Heap::From(GetHeap())->CollectStatistics(
      HeapStatistics::DetailLevel::kDetailed);
  EXPECT_EQ(HeapStatistics::DetailLevel::kDetailed,
            detailed_stats.detail_level);
  EXPECT_EQ(0u, detailed_stats.used_size_bytes);
  EXPECT_EQ(0u, detailed_stats.used_size_bytes);
  EXPECT_EQ(0u, detailed_stats.pooled_memory_size_bytes);
  EXPECT_EQ(RawHeap::kNumberOfRegularSpaces, detailed_stats.space_stats.size());
  for (HeapStatistics::SpaceStatistics& space_stats :
       detailed_stats.space_stats) {
    EXPECT_EQ(0u, space_stats.used_size_bytes);
    EXPECT_EQ(0u, space_stats.used_size_bytes);
    EXPECT_TRUE(space_stats.page_stats.empty());
    if (space_stats.name == "LargePageSpace") {
      // Large page space has no free list.
      EXPECT_TRUE(space_stats.free_list_stats.bucket_size.empty());
      EXPECT_TRUE(space_stats.free_list_stats.free_count.empty());
      EXPECT_TRUE(space_stats.free_list_stats.free_size.empty());
    } else {
      EXPECT_EQ(kPageSizeLog2, space_stats.free_list_stats.bucket_size.size());
      EXPECT_EQ(kPageSizeLog2, space_stats.free_list_stats.free_count.size());
      EXPECT_EQ(kPageSizeLog2, space_stats.free_list_stats.free_size.size());
    }
  }
}

namespace {
template <size_t Size>
class GCed : public GarbageCollected<GCed<Size>> {
 public:
  void Trace(Visitor*) const {}

 private:
  char array_[Size];
};
}  // namespace

TEST_F(HeapStatisticsCollectorTest, NonEmptyNormalPage) {
  MakeGarbageCollected<GCed<1>>(GetHeap()->GetAllocationHandle());
  static constexpr size_t used_size =
      RoundUp<kAllocationGranularity>(1 + sizeof(HeapObjectHeader));
  HeapStatistics detailed_stats = Heap::From(GetHeap())->CollectStatistics(
      HeapStatistics::DetailLevel::kDetailed);
  EXPECT_EQ(HeapStatistics::DetailLevel::kDetailed,
            detailed_stats.detail_level);
  EXPECT_EQ(kPageSize, detailed_stats.committed_size_bytes);
  EXPECT_EQ(kPageSize, detailed_stats.resident_size_bytes);
  EXPECT_EQ(used_size, detailed_stats.used_size_bytes);
  EXPECT_EQ(0u, detailed_stats.pooled_memory_size_bytes);
  EXPECT_EQ(RawHeap::kNumberOfRegularSpaces, detailed_stats.space_stats.size());
  bool found_non_empty_space = false;
  for (const HeapStatistics::SpaceStatistics& space_stats :
       detailed_stats.space_stats) {
    if (space_stats.page_stats.empty()) {
      EXPECT_EQ(0u, space_stats.committed_size_bytes);
      EXPECT_EQ(0u, space_stats.resident_size_bytes);
      EXPECT_EQ(0u, space_stats.used_size_bytes);
      continue;
    }
    EXPECT_NE("LargePageSpace", space_stats.name);
    EXPECT_FALSE(found_non_empty_space);
    found_non_empty_space = true;
    EXPECT_EQ(kPageSize, space_stats.committed_size_bytes);
    EXPECT_EQ(kPageSize, space_stats.resident_size_bytes);
    EXPECT_EQ(used_size, space_stats.used_size_bytes);
    EXPECT_EQ(1u, space_stats.page_stats.size());
    EXPECT_EQ(kPageSize, space_stats.page_stats.back().committed_size_bytes);
    EXPECT_EQ(kPageSize, space_stats.page_stats.back().resident_size_bytes);
    EXPECT_EQ(used_size, space_stats.page_stats.back().used_size_bytes);
  }
  EXPECT_TRUE(found_non_empty_space);
}

TEST_F(HeapStatisticsCollectorTest, NonEmptyLargePage) {
  MakeGarbageCollected<GCed<kLargeObjectSizeThreshold>>(
      GetHeap()->GetAllocationHandle());
  static constexpr size_t used_size = RoundUp<kAllocationGranularity>(
      kLargeObjectSizeThreshold + sizeof(HeapObjectHeader));
  static constexpr size_t committed_size =
      RoundUp<kAllocationGranularity>(used_size + LargePage::PageHeaderSize());
  HeapStatistics detailed_stats = Heap::From(GetHeap())->CollectStatistics(
      HeapStatistics::DetailLevel::kDetailed);
  EXPECT_EQ(HeapStatistics::DetailLevel::kDetailed,
            detailed_stats.detail_level);
  EXPECT_EQ(committed_size, detailed_stats.committed_size_bytes);
  EXPECT_EQ(committed_size, detailed_stats.resident_size_bytes);
  EXPECT_EQ(used_size, detailed_stats.used_size_bytes);
  EXPECT_EQ(0u, detailed_stats.pooled_memory_size_bytes);
  EXPECT_EQ(RawHeap::kNumberOfRegularSpaces, detailed_stats.space_stats.size());
  bool found_non_empty_space = false;
  for (const HeapStatistics::SpaceStatistics& space_stats :
       detailed_stats.space_stats) {
    if (space_stats.page_stats.empty()) {
      EXPECT_EQ(0u, space_stats.committed_size_bytes);
      EXPECT_EQ(0u, space_stats.used_size_bytes);
      continue;
    }
    EXPECT_EQ("LargePageSpace", space_stats.name);
    EXPECT_FALSE(found_non_empty_space);
    found_non_empty_space = true;
    EXPECT_EQ(committed_size, space_stats.committed_size_bytes);
    EXPECT_EQ(committed_size, space_stats.resident_size_bytes);
    EXPECT_EQ(used_size, space_stats.used_size_bytes);
    EXPECT_EQ(1u, space_stats.page_stats.size());
    EXPECT_EQ(committed_size,
              space_stats.page_stats.back().committed_size_bytes);
    EXPECT_EQ(committed_size,
              space_stats.page_stats.back().resident_size_bytes);
    EXPECT_EQ(used_size, space_stats.page_stats.back().used_size_bytes);
  }
  EXPECT_TRUE(found_non_empty_space);
}

TEST_F(HeapStatisticsCollectorTest, BriefStatisticsWithDiscardingOnNormalPage) {
  if (!Sweeper::CanDiscardMemory()) return;

  Persistent<GCed<1>> holder =
      MakeGarbageCollected<GCed<1>>(GetHeap()->GetAllocationHandle());
  ConservativeMemoryDiscardingGC();
  HeapStatistics brief_stats = Heap::From(GetHeap())->CollectStatistics(
      HeapStatistics::DetailLevel::kBrief);
  // Do not enforce exact resident_size_bytes here as this is an implementation
  // detail of the sweeper.
  EXPECT_GT(brief_stats.committed_size_bytes, brief_stats.resident_size_bytes);
  EXPECT_EQ(0u, brief_stats.pooled_memory_size_bytes);
}

TEST_F(HeapStatisticsCollectorTest,
       BriefStatisticsWithoutDiscardingOnNormalPage) {
  if (!Sweeper::CanDiscardMemory()) return;

  MakeGarbageCollected<GCed<1>>(GetHeap()->GetAllocationHandle());

  // kNoHeapPointers: make the test deterministic, not depend on what the
  // compiler does with the stack.
  internal::Heap::From(GetHeap())->CollectGarbage(
      {CollectionType::kMinor, Heap::StackState::kNoHeapPointers,
       cppgc::Heap::MarkingType::kAtomic, cppgc::Heap::SweepingType::kAtomic,
       GCConfig::FreeMemoryHandling::kDoNotDiscard});

  HeapStatistics brief_stats = Heap::From(GetHeap())->CollectStatistics(
      HeapStatistics::DetailLevel::kBrief);
  // Pooled memory, since it wasn't discarded by the sweeper.
  EXPECT_NE(brief_stats.pooled_memory_size_bytes, 0u);
  // Pooled memory is committed and resident.
  EXPECT_EQ(brief_stats.pooled_memory_size_bytes,
            brief_stats.resident_size_bytes);
  EXPECT_EQ(brief_stats.pooled_memory_size_bytes,
            brief_stats.committed_size_bytes);
  // But not allocated.
  EXPECT_EQ(brief_stats.used_size_bytes, 0u);

  // Pooled memory goes away when discarding, and is not accounted for once
  // discarded.
  internal::Heap::From(GetHeap())->CollectGarbage(
      {CollectionType::kMinor, Heap::StackState::kMayContainHeapPointers,
       cppgc::Heap::MarkingType::kAtomic, cppgc::Heap::SweepingType::kAtomic,
       GCConfig::FreeMemoryHandling::kDiscardWherePossible});
  brief_stats = Heap::From(GetHeap())->CollectStatistics(
      HeapStatistics::DetailLevel::kBrief);
  EXPECT_EQ(0u, brief_stats.pooled_memory_size_bytes);
  EXPECT_EQ(0u, brief_stats.resident_size_bytes);
  EXPECT_EQ(0u, brief_stats.committed_size_bytes);
  EXPECT_EQ(0u, brief_stats.used_size_bytes);
}

TEST_F(HeapStatisticsCollectorTest,
       DetailedStatisticsWithDiscardingOnNormalPage) {
  if (!Sweeper::CanDiscardMemory()) return;

  Persistent<GCed<1>> holder =
      MakeGarbageCollected<GCed<1>>(GetHeap()->GetAllocationHandle());
  ConservativeMemoryDiscardingGC();
  HeapStatistics detailed_stats = Heap::From(GetHeap())->CollectStatistics(
      HeapStatistics::DetailLevel::kDetailed);
  // Do not enforce exact resident_size_bytes here as this is an implementation
  // detail of the sweeper.
  EXPECT_GT(detailed_stats.committed_size_bytes,
            detailed_stats.resident_size_bytes);
  EXPECT_EQ(0u, detailed_stats.pooled_memory_size_bytes);
  bool found_page = false;
  for (const auto& space_stats : detailed_stats.space_stats) {
    if (space_stats.committed_size_bytes == 0) continue;

    // We should find a single page here that contains memory that was
    // discarded.
    EXPECT_EQ(1u, space_stats.page_stats.size());
    const auto& page_stats = space_stats.page_stats[0];
    EXPECT_GT(page_stats.committed_size_bytes, page_stats.resident_size_bytes);
    found_page = true;
  }
  EXPECT_TRUE(found_page);
}

}  // namespace internal
}  // namespace cppgc
```