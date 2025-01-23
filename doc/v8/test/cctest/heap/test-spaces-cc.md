Response:
My thinking process to analyze the provided C++ code snippet went something like this:

1. **Initial Skim for High-Level Understanding:** I first quickly scanned the code looking for keywords and patterns that would give me a general idea of its purpose. Keywords like `test`, `heap`, `spaces`, `allocate`, `free`, `size`, `memory`, `page`, and the various `TEST` macros immediately suggested this is a unit testing file focused on heap memory management within V8.

2. **Identify Key Components and Data Structures:** I started noting down the important classes and data structures involved. This included:
    * `Isolate`: Represents an isolated V8 instance.
    * `Heap`:  Manages the memory for an isolate.
    * `MemoryAllocator`:  Responsible for low-level memory allocation.
    * `PageAllocator`: An interface for allocating and managing OS-level memory pages.
    * `MemoryChunk`: Represents a contiguous block of memory within the heap.
    * `MutablePageMetadata`: Metadata associated with a memory chunk.
    * Different space types: `OldSpace`, `SemiSpaceNewSpace`, `PagedNewSpace`, `OldLargeObjectSpace`, `ReadOnlySpace`. The names themselves give clues about their purpose (e.g., "OldSpace" likely holds long-lived objects).
    * `AllocationResult`:  Indicates the success or failure of an allocation.
    * `AllocationObserver`:  A mechanism to track allocations.

3. **Analyze the `TEST` Macros:**  The `TEST` macros are the core of the functionality. I looked at the names of each test case to understand what specific aspect of heap spaces is being tested. For example:
    * `MutablePageMetadata`:  Likely tests the creation and properties of `MutablePageMetadata`.
    * `MemoryAllocator`:  Probably tests the basic allocation and management functionalities of `MemoryAllocator`.
    * `ComputeDiscardMemoryAreas`:  Focuses on a specific function related to memory discarding.
    * `SemiSpaceNewSpace`, `PagedNewSpace`, `OldSpace`, `OldLargeObjectSpace`: These clearly test the behavior of different heap space types.
    * `SizeOfInitialHeap`: Examines the initial memory footprint.
    * `Regress...`:  Indicates tests designed to prevent specific bugs from recurring.
    * `ShrinkPageToHighWaterMark...`: Tests the ability to shrink pages.
    * `NoMemoryForNewPage`:  Tests the behavior when page allocation fails.
    * `ReadOnlySpaceMetrics...`:  Tests the metrics tracking for read-only spaces.

4. **Examine Helper Classes:** The `TestMemoryAllocatorScope` and `TestCodePageAllocatorScope` classes caught my attention. Their constructors and destructors clearly indicate they are used to temporarily swap out the default memory and code page allocators for testing purposes, providing a controlled environment.

5. **Look for Specific Functionality Within Tests:**  Within each `TEST` block, I looked for the sequence of actions: setup (e.g., creating an `Isolate`, getting the `Heap`), the action being tested (e.g., calling `AllocatePage`, `AllocateRaw`, `ShrinkPageToHighWaterMark`), and the assertions (`CHECK`, `CHECK_EQ`, `CHECK_LT`, `CHECK_NOT_NULL`). These assertions are crucial for understanding the expected behavior.

6. **Identify Potential Connections to JavaScript:** I noted the presence of heap concepts like "New Space" and "Old Space," which directly correlate to how JavaScript engines manage object lifetimes. The allocation and garbage collection processes in V8 are fundamentally tied to these spaces.

7. **Look for Code Logic and Assumptions:**  The `ComputeDiscardMemoryAreas` test provided a good example of logic. I could see the function takes a start and end address and calculates a discardable area based on page boundaries. I could infer the assumptions about page sizes and alignment.

8. **Consider Common Programming Errors:**  The `Regress` tests hinted at potential pitfalls or bugs that developers might encounter when working with V8's heap. The manipulations of allocation pointers in those tests suggested issues related to pointer management and boundary conditions.

9. **Synthesize and Categorize:** Finally, I started grouping the observed functionalities into broader categories. This led to the summary points about testing different heap spaces, memory allocation, page management, error handling, and performance considerations.

10. **Address Specific Instructions:** I then went through each specific instruction in the prompt:
    * **Functionality Listing:** I created the bulleted list of functionalities based on the analysis of the `TEST` cases.
    * **Torque Check:** I confirmed that the filename extension `.cc` indicates C++, not Torque.
    * **JavaScript Connection:**  I provided the JavaScript example illustrating the concept of new and old generation garbage collection.
    * **Code Logic Example:** I used the `ComputeDiscardMemoryAreas` test as the example, providing potential inputs and outputs.
    * **Common Programming Errors:**  I linked the `Regress` tests to potential issues with manual memory management (though V8 mostly abstracts this away for JS developers, it's relevant in the C++ implementation).
    * **Summary:** I provided a concise summary of the file's purpose based on my analysis.

Throughout this process, I paid attention to the specific details of the code, cross-referencing different parts to build a coherent understanding of the file's overall role. The naming conventions used in V8's codebase (e.g., `OldSpace`, `AllocatePage`) were also helpful in quickly grasping the purpose of various components.
这是提供的 v8 源代码文件 `v8/test/cctest/heap/test-spaces.cc` 的第一部分，其主要功能是 **测试 V8 引擎堆内存空间管理的相关功能**。

**具体功能归纳如下：**

* **测试 `MutablePageMetadata` 的功能:**
    *  验证 `MutablePageMetadata` 对象（用于描述内存页的元数据）的创建和属性，例如大小、起始地址、结束地址等。
    *  模拟分配不同大小的内存区域，并检查 `MutablePageMetadata` 是否正确记录了这些信息。
    *  测试可执行内存页和不可执行内存页的分配。
* **测试 `MemoryAllocator` 的功能:**
    *  测试 `MemoryAllocator` 中内存页的分配和管理，例如 `AllocatePage` 函数。
    *  验证分配的内存页是否正确地链接到所属的内存空间（例如 `OldSpace`）。
    *  测试内存页的释放（虽然这部分代码在本段中没有显式调用释放，但测试了分配后的状态）。
* **测试 `Sweeper::ComputeDiscardMemoryArea` 的功能:**
    *  测试计算可以被丢弃的内存区域的函数，该函数可能用于垃圾回收过程中的内存回收。
    *  通过不同的输入参数（起始地址和结束地址）来验证计算结果的正确性，包括没有可丢弃区域的情况。
* **测试不同类型的内存空间 (Spaces) 的功能:**
    * **`SemiSpaceNewSpace` 和 `PagedNewSpace` (新生代空间):**
        * 测试新生代空间的分配行为，尝试分配多个对象直到空间接近满载。
        * 验证分配的对象是否位于新生代空间内。
    * **`OldSpace` (老年代空间):**
        * 测试老年代空间的分配行为，尝试分配多个对象直到空间接近满载。
        * 验证分配的对象是否位于老年代空间内。
    * **`OldLargeObjectSpace` (老年代大对象空间):**
        * 测试大对象空间的分配行为，分配固定大小的大对象。
        * 验证分配的对象是否位于大对象空间内，并检查对齐方式。
        * 验证当空间满时，分配会失败。
    * **`ReadOnlySpace` (只读空间):**
        * 测试只读空间的分配行为。
        * 测试只读空间在分配后收缩页面的功能，并验证其内存指标（大小、容量、已提交内存等）是否符合预期。
* **测试初始堆的大小 (`SizeOfInitialHeap`):**
    *  验证在 V8 引擎初始化后，各个内存空间（尤其是分页空间）的已提交内存大小是否在一个预期的较小范围内。
    *  这个测试通常在非 Debug 模式下运行，因为它会受到 Debug 构建中额外代码的影响。
* **测试分配观察者 (`AllocationObserver`) 的功能 (通过回归测试 `Regress777177` 和 `Regress791582`):**
    *  测试在特定场景下，分配观察者是否能正确工作，并防止已知的 bug 再次出现。
    *  这些回归测试模拟了特定的分配模式，可能会触发潜在的边界条件或错误。
* **测试页面收缩到高水位线的功能 (`ShrinkPageToHighWaterMark`):**
    *  测试当页面尾部存在 `FreeSpace` 填充对象或特定大小的填充对象时，能否正确地收缩页面，释放未使用的内存。
* **测试内存分配失败的处理 (`NoMemoryForNewPage`):**
    *  模拟内存分配失败的情况（通过使用一个总是分配失败的 `PageAllocator`），并验证 `AllocatePage` 函数返回 `nullptr`。

**关于文件类型和 JavaScript 关系：**

* `v8/test/cctest/heap/test-spaces.cc` 的后缀是 `.cc`，这表明它是一个 **C++ 源代码文件**。`.tq` 后缀通常用于 V8 的 **Torque 语言** 源代码。
* 该文件与 JavaScript 的功能有密切关系，因为它测试的是 V8 引擎的堆内存管理。JavaScript 对象的内存分配和垃圾回收都依赖于这些底层的堆空间管理机制。

**JavaScript 示例说明：**

当 JavaScript 代码创建对象时，V8 引擎会在堆内存中分配空间：

```javascript
// 在新生代空间分配
let obj1 = {};
let obj2 = { name: "example" };

// 经过多次垃圾回收后，可能被晋升到老年代空间
let longLivedObject = {};
// ... 持续使用 longLivedObject ...
```

在这个例子中，`obj1` 和 `obj2` 最初可能会分配在新生代空间 (`SemiSpaceNewSpace` 或 `PagedNewSpace`)。如果 `longLivedObject` 存活时间较长，经过多次新生代垃圾回收后，它可能会被移动到老年代空间 (`OldSpace`). 大的对象可能会直接分配到老年代大对象空间 (`OldLargeObjectSpace`)。

**代码逻辑推理和假设输入输出 (以 `Sweeper::ComputeDiscardMemoryArea` 为例):**

**假设输入：**

* `start_address`: 4096 (假设页大小为 4096)
* `end_address`: 8192

**代码逻辑推理：**

`ComputeDiscardMemoryArea` 函数会检查 `start_address` 和 `end_address` 是否跨越了页边界。如果存在完整的页可以被丢弃，则返回该页的地址范围。

**预期输出：**

返回一个 `std::optional<base::AddressRegion>`，其值为：

* `begin()`: 4096
* `size()`: 4096

**解释：**  从 4096 到 8192 刚好是一个完整的页，因此该页可以被丢弃。

**用户常见的编程错误（C++，虽然此文件是测试代码，但可以联想到相关概念）：**

* **内存泄漏：**  在 C++ 中，如果分配了内存而没有正确释放，会导致内存泄漏。在 V8 的堆管理中，虽然有垃圾回收机制，但在 C++ 层面编写 V8 内部代码时，仍然需要小心管理内存。
    ```c++
    // 错误示例
    void* ptr = malloc(1024);
    // ... 没有 free(ptr);
    ```
* **野指针：**  访问已经释放的内存会导致野指针错误。
    ```c++
    void* ptr = malloc(1024);
    free(ptr);
    // ... 尝试访问 ptr 指向的内存
    //*((int*)ptr) = 5; // 错误！
    ```
* **缓冲区溢出：**  向缓冲区写入超出其容量的数据，可能导致程序崩溃或安全漏洞。
    ```c++
    char buffer[10];
    strcpy(buffer, "This is too long"); // 错误！
    ```
* **错误的内存对齐：**  某些数据类型有特定的对齐要求。不正确的对齐可能导致性能下降或程序崩溃。

**总结：**

`v8/test/cctest/heap/test-spaces.cc` 的第一部分是一个全面的测试套件，用于验证 V8 引擎中各种堆内存空间管理机制的正确性和可靠性。它涵盖了不同类型的内存空间、内存分配器、页面元数据以及内存回收等关键组件，并包含了一些回归测试以防止已知 bug 的再次发生。这些测试对于确保 V8 引擎的稳定性和性能至关重要。

### 提示词
```
这是目录为v8/test/cctest/heap/test-spaces.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/heap/test-spaces.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2011 the V8 project authors. All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following
//       disclaimer in the documentation and/or other materials provided
//       with the distribution.
//     * Neither the name of Google Inc. nor the names of its
//       contributors may be used to endorse or promote products derived
//       from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <stdlib.h>

#include <memory>

#include "include/v8-initialization.h"
#include "include/v8-platform.h"
#include "src/base/bounded-page-allocator.h"
#include "src/base/macros.h"
#include "src/base/platform/platform.h"
#include "src/common/globals.h"
#include "src/heap/allocation-result.h"
#include "src/heap/factory.h"
#include "src/heap/heap.h"
#include "src/heap/large-spaces.h"
#include "src/heap/main-allocator.h"
#include "src/heap/memory-allocator.h"
#include "src/heap/mutable-page-metadata.h"
#include "src/heap/spaces-inl.h"
#include "src/heap/spaces.h"
#include "src/objects/free-space.h"
#include "src/objects/objects-inl.h"
#include "src/snapshot/snapshot.h"
#include "test/cctest/cctest.h"
#include "test/cctest/heap/heap-tester.h"
#include "test/cctest/heap/heap-utils.h"

namespace v8 {
namespace internal {
namespace heap {

// Temporarily sets a given allocator in an isolate.
class V8_NODISCARD TestMemoryAllocatorScope {
 public:
  TestMemoryAllocatorScope(Isolate* isolate, size_t max_capacity,
                           PageAllocator* page_allocator = nullptr)
      : isolate_(isolate),
        old_allocator_(std::move(isolate->heap()->memory_allocator_)) {
    // Save the code pages for restoring them later on because the constructor
    // of MemoryAllocator will change them.
    isolate->GetCodePages()->swap(code_pages_);
    isolate->heap()->memory_allocator_.reset(new MemoryAllocator(
        isolate,
        page_allocator != nullptr ? page_allocator : isolate->page_allocator(),
        page_allocator != nullptr ? page_allocator : isolate->page_allocator(),
        max_capacity));
    if (page_allocator != nullptr) {
      isolate->heap()->memory_allocator_->data_page_allocator_ = page_allocator;
    }
  }

  MemoryAllocator* allocator() { return isolate_->heap()->memory_allocator(); }

  ~TestMemoryAllocatorScope() {
    isolate_->heap()->memory_allocator()->TearDown();
    isolate_->heap()->memory_allocator_.swap(old_allocator_);
    isolate_->GetCodePages()->swap(code_pages_);
  }

  TestMemoryAllocatorScope(const TestMemoryAllocatorScope&) = delete;
  TestMemoryAllocatorScope& operator=(const TestMemoryAllocatorScope&) = delete;

 private:
  Isolate* isolate_;
  std::unique_ptr<MemoryAllocator> old_allocator_;
  std::vector<MemoryRange> code_pages_;
};

// Temporarily sets a given code page allocator in an isolate.
class V8_NODISCARD TestCodePageAllocatorScope {
 public:
  TestCodePageAllocatorScope(Isolate* isolate,
                             v8::PageAllocator* code_page_allocator)
      : isolate_(isolate),
        old_code_page_allocator_(
            isolate->heap()->memory_allocator()->code_page_allocator()) {
    isolate->heap()->memory_allocator()->code_page_allocator_ =
        code_page_allocator;
  }

  ~TestCodePageAllocatorScope() {
    isolate_->heap()->memory_allocator()->code_page_allocator_ =
        old_code_page_allocator_;
  }
  TestCodePageAllocatorScope(const TestCodePageAllocatorScope&) = delete;
  TestCodePageAllocatorScope& operator=(const TestCodePageAllocatorScope&) =
      delete;

 private:
  Isolate* isolate_;
  v8::PageAllocator* old_code_page_allocator_;
};

static void VerifyMemoryChunk(Isolate* isolate, Heap* heap,
                              v8::PageAllocator* code_page_allocator,
                              size_t area_size, Executability executable,
                              PageSize page_size, LargeObjectSpace* space) {
  TestMemoryAllocatorScope test_allocator_scope(isolate, heap->MaxReserved());
  MemoryAllocator* memory_allocator = test_allocator_scope.allocator();
  TestCodePageAllocatorScope test_code_page_allocator_scope(
      isolate, code_page_allocator);

  v8::PageAllocator* page_allocator =
      memory_allocator->page_allocator(space->identity());

  size_t allocatable_memory_area_offset =
      MemoryChunkLayout::ObjectStartOffsetInMemoryChunk(space->identity());

  MutablePageMetadata* memory_chunk =
      memory_allocator->AllocateLargePage(space, area_size, executable);
  size_t reserved_size =
      ((executable == EXECUTABLE))
          ? RoundUp(allocatable_memory_area_offset +
                        RoundUp(area_size, page_allocator->CommitPageSize()),
                    page_allocator->CommitPageSize())
          : RoundUp(allocatable_memory_area_offset + area_size,
                    page_allocator->CommitPageSize());
  CHECK(memory_chunk->size() == reserved_size);
  CHECK(memory_chunk->area_start() <
        memory_chunk->ChunkAddress() + memory_chunk->size());
  CHECK(memory_chunk->area_end() <=
        memory_chunk->ChunkAddress() + memory_chunk->size());
  CHECK(static_cast<size_t>(memory_chunk->area_size()) == area_size);

  memory_allocator->Free(MemoryAllocator::FreeMode::kImmediately, memory_chunk);
}

static unsigned int PseudorandomAreaSize() {
  static uint32_t lo = 2345;
  lo = 18273 * (lo & 0xFFFFF) + (lo >> 16);
  return lo & 0xFFFFF;
}

TEST(MutablePageMetadata) {
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = isolate->heap();
  IsolateSafepointScope safepoint(heap);

  v8::PageAllocator* page_allocator = GetPlatformPageAllocator();
  size_t area_size;

  for (int i = 0; i < 100; i++) {
    area_size =
        RoundUp(PseudorandomAreaSize(), page_allocator->CommitPageSize());

    const size_t code_range_size = 32 * MB;
#ifdef V8_ENABLE_SANDBOX
    // When the sandbox is enabled, the code assumes that there's only a single
    // code range for easy metadata lookup, so use the process wide code range
    // in this case.
    CodeRange* code_range =
        IsolateGroup::current()->EnsureCodeRange(code_range_size);
    base::BoundedPageAllocator* page_allocator = code_range->page_allocator();
#else
    // With CodeRange.
    bool jitless = isolate->jitless();
    VirtualMemory code_range_reservation(
        page_allocator, code_range_size, nullptr,
        MemoryChunk::GetAlignmentForAllocation(),
        jitless ? PageAllocator::Permission::kNoAccess
                : PageAllocator::Permission::kNoAccessWillJitLater);

    base::PageInitializationMode page_initialization_mode =
        base::PageInitializationMode::kAllocatedPagesCanBeUninitialized;
    base::PageFreeingMode page_freeing_mode =
        base::PageFreeingMode::kMakeInaccessible;

    if (!jitless) {
      page_initialization_mode = base::PageInitializationMode::kRecommitOnly;
      page_freeing_mode = base::PageFreeingMode::kDiscard;
      void* base = reinterpret_cast<void*>(code_range_reservation.address());
      CHECK(page_allocator->SetPermissions(base, code_range_size,
                                           PageAllocator::kReadWriteExecute));
      CHECK(page_allocator->DiscardSystemPages(base, code_range_size));
    }

    CHECK(code_range_reservation.IsReserved());

    base::BoundedPageAllocator code_page_allocator(
        page_allocator, code_range_reservation.address(),
        code_range_reservation.size(), MemoryChunk::GetAlignmentForAllocation(),
        page_initialization_mode, page_freeing_mode);
    base::BoundedPageAllocator* page_allocator = &code_page_allocator;
#endif

    VerifyMemoryChunk(isolate, heap, page_allocator, area_size, EXECUTABLE,
                      PageSize::kLarge, heap->code_lo_space());

    VerifyMemoryChunk(isolate, heap, page_allocator, area_size, NOT_EXECUTABLE,
                      PageSize::kLarge, heap->lo_space());
  }
}

TEST(MemoryAllocator) {
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = isolate->heap();

  TestMemoryAllocatorScope test_allocator_scope(isolate, heap->MaxReserved());
  MemoryAllocator* memory_allocator = test_allocator_scope.allocator();

  int total_pages = 0;
  OldSpace faked_space(heap);
  CHECK(!faked_space.first_page());
  CHECK(!faked_space.last_page());
  PageMetadata* first_page = memory_allocator->AllocatePage(
      MemoryAllocator::AllocationMode::kRegular,
      static_cast<PagedSpace*>(&faked_space), NOT_EXECUTABLE);

  faked_space.memory_chunk_list().PushBack(first_page);
  CHECK(first_page->next_page() == nullptr);
  total_pages++;

  for (PageMetadata* p = first_page; p != nullptr; p = p->next_page()) {
    CHECK(p->owner() == &faked_space);
  }

  // Again, we should get n or n - 1 pages.
  PageMetadata* other = memory_allocator->AllocatePage(
      MemoryAllocator::AllocationMode::kRegular,
      static_cast<PagedSpace*>(&faked_space), NOT_EXECUTABLE);
  total_pages++;
  faked_space.memory_chunk_list().PushBack(other);
  int page_count = 0;
  for (PageMetadata* p = first_page; p != nullptr; p = p->next_page()) {
    CHECK(p->owner() == &faked_space);
    page_count++;
  }
  CHECK(total_pages == page_count);

  PageMetadata* second_page = first_page->next_page();
  CHECK_NOT_NULL(second_page);

  // OldSpace's destructor will tear down the space and free up all pages.
}

TEST(ComputeDiscardMemoryAreas) {
  std::optional<base::AddressRegion> discard_area;
  size_t page_size = MemoryAllocator::GetCommitPageSize();

  discard_area = Sweeper::ComputeDiscardMemoryArea(0, 0);
  CHECK(!discard_area);

  discard_area = Sweeper::ComputeDiscardMemoryArea(0, page_size);
  CHECK_EQ(discard_area->begin(), 0);
  CHECK_EQ(discard_area->size(), page_size);

  discard_area = Sweeper::ComputeDiscardMemoryArea(page_size, 2 * page_size);
  CHECK_EQ(discard_area->begin(), page_size);
  CHECK_EQ(discard_area->size(), page_size);

  discard_area =
      Sweeper::ComputeDiscardMemoryArea(page_size - kTaggedSize, 2 * page_size);
  CHECK_EQ(discard_area->begin(), page_size);
  CHECK_EQ(discard_area->size(), page_size);

  discard_area =
      Sweeper::ComputeDiscardMemoryArea(page_size, 2 * page_size + kTaggedSize);
  CHECK_EQ(discard_area->begin(), page_size);
  CHECK_EQ(discard_area->size(), page_size);

  discard_area = Sweeper::ComputeDiscardMemoryArea(page_size, page_size);
  CHECK(!discard_area);

  discard_area = Sweeper::ComputeDiscardMemoryArea(page_size / 2,
                                                   page_size + page_size / 2);
  CHECK(!discard_area);

  discard_area = Sweeper::ComputeDiscardMemoryArea(page_size / 2,
                                                   page_size + page_size / 4);
  CHECK(!discard_area);

  discard_area =
      Sweeper::ComputeDiscardMemoryArea(page_size / 2, page_size * 3);
  CHECK_EQ(discard_area->begin(), page_size);
  CHECK_EQ(discard_area->size(), page_size * 2);
}

TEST(SemiSpaceNewSpace) {
  if (v8_flags.single_generation) return;
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = isolate->heap();
  TestMemoryAllocatorScope test_allocator_scope(isolate, heap->MaxReserved());
  MemoryAllocator* memory_allocator = test_allocator_scope.allocator();
  LinearAllocationArea allocation_info;

  auto new_space = std::make_unique<SemiSpaceNewSpace>(
      heap, heap->InitialSemiSpaceSize(), heap->InitialSemiSpaceSize());
  MainAllocator allocator(heap->main_thread_local_heap(), new_space.get(),
                          MainAllocator::IsNewGeneration::kYes,
                          &allocation_info);
  CHECK(new_space->MaximumCapacity());

  size_t successful_allocations = 0;
  while (new_space->Available() >= kMaxRegularHeapObjectSize) {
    AllocationResult allocation = allocator.AllocateRaw(
        kMaxRegularHeapObjectSize, kTaggedAligned, AllocationOrigin::kRuntime);
    if (allocation.IsFailure()) break;
    successful_allocations++;
    Tagged<Object> obj = allocation.ToObjectChecked();
    Tagged<HeapObject> ho = Cast<HeapObject>(obj);
    CHECK(new_space->Contains(ho));
  }
  CHECK_LT(0, successful_allocations);

  new_space.reset();
  memory_allocator->pool()->ReleasePooledChunks();
}

TEST(PagedNewSpace) {
  if (v8_flags.single_generation) return;
  ManualGCScope manual_gc_scope;
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = isolate->heap();
  TestMemoryAllocatorScope test_allocator_scope(isolate, heap->MaxReserved());
  MemoryAllocator* memory_allocator = test_allocator_scope.allocator();
  LinearAllocationArea allocation_info;

  auto new_space = std::make_unique<PagedNewSpace>(
      heap, heap->InitialSemiSpaceSize(), heap->InitialSemiSpaceSize());
  MainAllocator allocator(heap->main_thread_local_heap(), new_space.get(),
                          MainAllocator::IsNewGeneration::kYes,
                          &allocation_info);
  CHECK(new_space->MaximumCapacity());
  CHECK(new_space->EnsureCurrentCapacity());
  CHECK_LT(0, new_space->TotalCapacity());

  size_t successful_allocations = 0;
  while (true) {
    AllocationResult allocation = allocator.AllocateRaw(
        kMaxRegularHeapObjectSize, kTaggedAligned, AllocationOrigin::kRuntime);
    if (allocation.IsFailure()) break;
    successful_allocations++;
    Tagged<Object> obj = allocation.ToObjectChecked();
    Tagged<HeapObject> ho = Cast<HeapObject>(obj);
    CHECK(new_space->Contains(ho));
  }
  CHECK_LT(0, successful_allocations);

  new_space.reset();
  memory_allocator->pool()->ReleasePooledChunks();
}

TEST(OldSpace) {
  v8_flags.max_heap_size = 20;
  // This test uses its own old space, which confuses the incremental marker.
  v8_flags.incremental_marking = false;
  // This test doesn't expect GCs caused by concurrent allocations in the
  // background thread.
  v8_flags.stress_concurrent_allocation = false;

  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = isolate->heap();
  TestMemoryAllocatorScope test_allocator_scope(isolate, heap->MaxReserved());
  LinearAllocationArea allocation_info;

  auto old_space = std::make_unique<OldSpace>(heap);
  MainAllocator allocator(heap->main_thread_local_heap(), old_space.get(),
                          MainAllocator::IsNewGeneration::kNo,
                          &allocation_info);
  const int obj_size = kMaxRegularHeapObjectSize;

  size_t successful_allocations = 0;

  while (true) {
    AllocationResult allocation = allocator.AllocateRaw(
        obj_size, kTaggedAligned, AllocationOrigin::kRuntime);
    if (allocation.IsFailure()) break;
    successful_allocations++;
    Tagged<Object> obj = allocation.ToObjectChecked();
    Tagged<HeapObject> ho = Cast<HeapObject>(obj);
    CHECK(old_space->Contains(ho));
  }
  CHECK_LT(0, successful_allocations);
}

TEST(OldLargeObjectSpace) {
  v8_flags.max_heap_size = 20;
  // This test uses its own old large object space, which confuses the
  // incremental marker.
  v8_flags.incremental_marking = false;
  // This test doesn't expect GCs caused by concurrent allocations in the
  // background thread.
  v8_flags.stress_concurrent_allocation = false;

  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = isolate->heap();

  auto lo = std::make_unique<OldLargeObjectSpace>(heap);
  const int lo_size = PageMetadata::kPageSize;

  HandleScope handle_scope(isolate);
  Tagged<Map> map = ReadOnlyRoots(isolate).fixed_double_array_map();
  size_t successful_allocations = 0;

  while (true) {
    AllocationResult allocation =
        lo->AllocateRaw(heap->main_thread_local_heap(), lo_size);
    if (allocation.IsFailure()) break;
    successful_allocations++;
    Tagged<Object> obj = allocation.ToObjectChecked();
    CHECK(IsHeapObject(obj));
    Tagged<HeapObject> ho = Cast<HeapObject>(obj);
    CHECK(lo->Contains(ho));
    CHECK_EQ(0, Heap::GetFillToAlign(ho.address(), kTaggedAligned));
    // All large objects have the same alignment because they start at the
    // same offset within a page. Fixed double arrays have the most strict
    // alignment requirements.
    CHECK_EQ(0, Heap::GetFillToAlign(ho.address(),
                                     HeapObject::RequiredAlignment(map)));
    DirectHandle<HeapObject> keep_alive(ho, isolate);
  }
  CHECK_LT(0, successful_allocations);

  CHECK(!lo->IsEmpty());
  CHECK(lo->AllocateRaw(heap->main_thread_local_heap(), lo_size).IsFailure());
}

#ifndef DEBUG
// The test verifies that committed size of a space is less then some threshold.
// Debug builds pull in all sorts of additional instrumentation that increases
// heap sizes. E.g. CSA_DCHECK creates on-heap strings for error messages. These
// messages are also not stable if files are moved and modified during the build
// process (jumbo builds).
TEST(SizeOfInitialHeap) {
  ManualGCScope manual_gc_scope;
  if (i::v8_flags.always_turbofan) return;
  // Bootstrapping without a snapshot causes more allocations.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  if (!isolate->snapshot_available()) return;
  HandleScope scope(isolate);
  v8::Local<v8::Context> context = CcTest::isolate()->GetCurrentContext();
  // Skip this test on the custom snapshot builder.
  if (!CcTest::global()
           ->Get(context, v8_str("assertEquals"))
           .ToLocalChecked()
           ->IsUndefined()) {
    return;
  }
  // Initial size of LO_SPACE
  size_t initial_lo_space = isolate->heap()->lo_space()->Size();

// The limit for each space for an empty isolate containing just the
// snapshot.
// In PPC the page size is 64K, causing more internal fragmentation
// hence requiring a larger limit.
#if V8_OS_LINUX && V8_HOST_ARCH_PPC64
  const size_t kMaxInitialSizePerSpace = 3 * MB;
#else
  const size_t kMaxInitialSizePerSpace = 2 * MB;
#endif

  // Freshly initialized VM gets by with the snapshot size (which is below
  // kMaxInitialSizePerSpace per space).
  Heap* heap = isolate->heap();
  for (int i = FIRST_GROWABLE_PAGED_SPACE; i <= LAST_GROWABLE_PAGED_SPACE;
       i++) {
    if (!heap->paged_space(i)) continue;

    // Debug code can be very large, so skip CODE_SPACE if we are generating it.
    if (i == CODE_SPACE && i::v8_flags.debug_code) continue;

    // Check that the initial heap is also below the limit.
    CHECK_LE(heap->paged_space(i)->CommittedMemory(), kMaxInitialSizePerSpace);
  }

  CompileRun("/*empty*/");

  // No large objects required to perform the above steps.
  CHECK_EQ(initial_lo_space,
           static_cast<size_t>(isolate->heap()->lo_space()->Size()));
}
#endif  // DEBUG

class Observer : public AllocationObserver {
 public:
  explicit Observer(intptr_t step_size)
      : AllocationObserver(step_size), count_(0) {}

  void Step(int bytes_allocated, Address addr, size_t) override { count_++; }

  int count() const { return count_; }

 private:
  int count_;
};

HEAP_TEST(Regress777177) {
  v8_flags.stress_concurrent_allocation = false;  // For SimulateFullSpace.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = isolate->heap();
  HandleScope scope(isolate);
  OldSpace* old_space = heap->old_space();
  MainAllocator* old_space_allocator = heap->allocator()->old_space_allocator();
  Observer observer(128);
  old_space_allocator->FreeLinearAllocationArea();
  old_space_allocator->AddAllocationObserver(&observer);

  int area_size = old_space->AreaSize();
  int max_object_size = kMaxRegularHeapObjectSize;
  int filler_size = area_size - max_object_size;

  {
    // Ensure a new linear allocation area on a fresh page.
    AlwaysAllocateScopeForTesting always_allocate(heap);
    heap::SimulateFullSpace(old_space);
    AllocationResult result = old_space_allocator->AllocateRaw(
        filler_size, kTaggedAligned, AllocationOrigin::kRuntime);
    Tagged<HeapObject> obj = result.ToObjectChecked();
    heap->CreateFillerObjectAt(obj.address(), filler_size);
  }

  {
    // Allocate all bytes of the linear allocation area. This moves top_ and
    // top_on_previous_step_ to the next page.
    AllocationResult result = old_space_allocator->AllocateRaw(
        max_object_size, kTaggedAligned, AllocationOrigin::kRuntime);
    Tagged<HeapObject> obj = result.ToObjectChecked();
    // Simulate allocation folding moving the top pointer back.
    old_space_allocator->ResetLab(
        obj.address(), heap->allocator()->old_space_allocator()->limit(),
        heap->allocator()->old_space_allocator()->limit());
  }

  {
    // This triggers assert in crbug.com/777177.
    AllocationResult result = old_space_allocator->AllocateRaw(
        filler_size, kTaggedAligned, AllocationOrigin::kRuntime);
    Tagged<HeapObject> obj = result.ToObjectChecked();
    heap->CreateFillerObjectAt(obj.address(), filler_size);
  }
  old_space_allocator->RemoveAllocationObserver(&observer);
}

HEAP_TEST(Regress791582) {
  if (v8_flags.single_generation) return;
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = isolate->heap();
  HandleScope scope(isolate);
  MainAllocator* new_space_allocator = heap->allocator()->new_space_allocator();
  GrowNewSpace(heap);

  int until_page_end =
      static_cast<int>(heap->NewSpaceLimit() - heap->NewSpaceTop());

  if (!IsAligned(until_page_end, kTaggedSize)) {
    // The test works if the size of allocation area size is a multiple of
    // pointer size. This is usually the case unless some allocation observer
    // is already active (e.g. incremental marking observer).
    return;
  }

  Observer observer(128);
  new_space_allocator->FreeLinearAllocationArea();
  new_space_allocator->AddAllocationObserver(&observer);

  {
    AllocationResult result = new_space_allocator->AllocateRaw(
        until_page_end, kTaggedAligned, AllocationOrigin::kRuntime);
    Tagged<HeapObject> obj = result.ToObjectChecked();
    heap->CreateFillerObjectAt(obj.address(), until_page_end);
    // Simulate allocation folding moving the top pointer back.
    *heap->NewSpaceAllocationTopAddress() = obj.address();
  }

  {
    // This triggers assert in crbug.com/791582
    AllocationResult result = new_space_allocator->AllocateRaw(
        256, kTaggedAligned, AllocationOrigin::kRuntime);
    Tagged<HeapObject> obj = result.ToObjectChecked();
    heap->CreateFillerObjectAt(obj.address(), 256);
  }
  new_space_allocator->RemoveAllocationObserver(&observer);
}

TEST(ShrinkPageToHighWaterMarkFreeSpaceEnd) {
  v8_flags.stress_incremental_marking = false;
  v8_flags.stress_concurrent_allocation = false;  // For SealCurrentObjects.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  heap::SealCurrentObjects(CcTest::heap());

  // Prepare page that only contains a single object and a trailing FreeSpace
  // filler.
  DirectHandle<FixedArray> array =
      isolate->factory()->NewFixedArray(128, AllocationType::kOld);
  PageMetadata* page = PageMetadata::FromHeapObject(*array);

  // Reset space so high water mark is consistent.
  PagedSpace* old_space = CcTest::heap()->old_space();
  CcTest::heap()->FreeMainThreadLinearAllocationAreas();
  old_space->ResetFreeList();

  Tagged<HeapObject> filler =
      HeapObject::FromAddress(array->address() + array->Size());
  CHECK(IsFreeSpace(filler));
  size_t shrunk = old_space->ShrinkPageToHighWaterMark(page);
  size_t should_have_shrunk = RoundDown(
      static_cast<size_t>(MemoryChunkLayout::AllocatableMemoryInDataPage() -
                          array->Size()),
      CommitPageSize());
  CHECK_EQ(should_have_shrunk, shrunk);
}

TEST(ShrinkPageToHighWaterMarkNoFiller) {
  v8_flags.stress_concurrent_allocation = false;  // For SealCurrentObjects.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);
  heap::SealCurrentObjects(CcTest::heap());

  const int kFillerSize = 0;
  DirectHandleVector<FixedArray> arrays(isolate);
  heap::FillOldSpacePageWithFixedArrays(CcTest::heap(), kFillerSize, &arrays);
  DirectHandle<FixedArray> array = arrays.back();
  PageMetadata* page = PageMetadata::FromHeapObject(*array);
  CHECK_EQ(page->area_end(), array->address() + array->Size() + kFillerSize);

  // Reset space so high water mark and fillers are consistent.
  PagedSpace* old_space = CcTest::heap()->old_space();
  CcTest::heap()->FreeMainThreadLinearAllocationAreas();
  old_space->ResetFreeList();

  size_t shrunk = old_space->ShrinkPageToHighWaterMark(page);
  CHECK_EQ(0u, shrunk);
}

TEST(ShrinkPageToHighWaterMarkOneWordFiller) {
  v8_flags.stress_concurrent_allocation = false;  // For SealCurrentObjects.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  heap::SealCurrentObjects(CcTest::heap());

  const int kFillerSize = kTaggedSize;
  DirectHandleVector<FixedArray> arrays(isolate);
  heap::FillOldSpacePageWithFixedArrays(CcTest::heap(), kFillerSize, &arrays);
  DirectHandle<FixedArray> array = arrays.back();
  PageMetadata* page = PageMetadata::FromHeapObject(*array);
  CHECK_EQ(page->area_end(), array->address() + array->Size() + kFillerSize);

  // Reset space so high water mark and fillers are consistent.
  PagedSpace* old_space = CcTest::heap()->old_space();
  CcTest::heap()->FreeMainThreadLinearAllocationAreas();
  old_space->ResetFreeList();

  Tagged<HeapObject> filler =
      HeapObject::FromAddress(array->address() + array->Size());
  CHECK_EQ(filler->map(),
           ReadOnlyRoots(CcTest::heap()).one_pointer_filler_map());

  size_t shrunk = old_space->ShrinkPageToHighWaterMark(page);
  CHECK_EQ(0u, shrunk);
}

TEST(ShrinkPageToHighWaterMarkTwoWordFiller) {
  v8_flags.stress_concurrent_allocation = false;  // For SealCurrentObjects.
  CcTest::InitializeVM();
  Isolate* isolate = CcTest::i_isolate();
  HandleScope scope(isolate);

  heap::SealCurrentObjects(CcTest::heap());

  const int kFillerSize = 2 * kTaggedSize;
  DirectHandleVector<FixedArray> arrays(isolate);
  heap::FillOldSpacePageWithFixedArrays(CcTest::heap(), kFillerSize, &arrays);
  DirectHandle<FixedArray> array = arrays.back();
  PageMetadata* page = PageMetadata::FromHeapObject(*array);
  CHECK_EQ(page->area_end(), array->address() + array->Size() + kFillerSize);

  // Reset space so high water mark and fillers are consistent.
  PagedSpace* old_space = CcTest::heap()->old_space();
  CcTest::heap()->FreeMainThreadLinearAllocationAreas();
  old_space->ResetFreeList();

  Tagged<HeapObject> filler =
      HeapObject::FromAddress(array->address() + array->Size());
  CHECK_EQ(filler->map(),
           ReadOnlyRoots(CcTest::heap()).two_pointer_filler_map());

  size_t shrunk = old_space->ShrinkPageToHighWaterMark(page);
  CHECK_EQ(0u, shrunk);
}

namespace {
// PageAllocator that always fails.
class FailingPageAllocator : public v8::PageAllocator {
 public:
  size_t AllocatePageSize() override { return 1024; }
  size_t CommitPageSize() override { return 1024; }
  void SetRandomMmapSeed(int64_t seed) override {}
  void* GetRandomMmapAddr() override { return nullptr; }
  void* AllocatePages(void* address, size_t length, size_t alignment,
                      Permission permissions) override {
    return nullptr;
  }
  bool FreePages(void* address, size_t length) override { return false; }
  bool ReleasePages(void* address, size_t length, size_t new_length) override {
    return false;
  }
  bool SetPermissions(void* address, size_t length,
                      Permission permissions) override {
    return false;
  }
  bool RecommitPages(void* address, size_t length,
                     Permission permissions) override {
    return false;
  }
  bool DecommitPages(void* address, size_t length) override { return false; }
  bool SealPages(void* address, size_t length) override { return false; }
};
}  // namespace

TEST(NoMemoryForNewPage) {
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = isolate->heap();

  // Memory allocator that will fail to allocate any pages.
  FailingPageAllocator failing_allocator;
  TestMemoryAllocatorScope test_allocator_scope(isolate, 0, &failing_allocator);
  MemoryAllocator* memory_allocator = test_allocator_scope.allocator();
  OldSpace faked_space(heap);
  PageMetadata* page = memory_allocator->AllocatePage(
      MemoryAllocator::AllocationMode::kRegular,
      static_cast<PagedSpace*>(&faked_space), NOT_EXECUTABLE);

  CHECK_NULL(page);
}

namespace {
// ReadOnlySpace cannot be torn down by a destructor because the destructor
// cannot take an argument. Since these tests create ReadOnlySpaces not attached
// to the Heap directly, they need to be destroyed to ensure the
// MemoryAllocator's stats are all 0 at exit.
class V8_NODISCARD ReadOnlySpaceScope {
 public:
  explicit ReadOnlySpaceScope(Heap* heap) : ro_space_(heap) {}
  ~ReadOnlySpaceScope() {
    ro_space_.TearDown(CcTest::heap()->memory_allocator());
  }

  ReadOnlySpace* space() { return &ro_space_; }

 private:
  ReadOnlySpace ro_space_;
};
}  // namespace

TEST(ReadOnlySpaceMetrics_OnePage) {
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = isolate->heap();

  // Create a read-only space and allocate some memory, shrink the pages and
  // check the allocated object size is as expected.

  ReadOnlySpaceScope scope(heap);
  ReadOnlySpace* faked_space = scope.space();

  // Initially no memory.
  CHECK_EQ(faked_space->Size(), 0);
  CHECK_EQ(faked_space->Capacity(), 0);
  CHECK_EQ(faked_space->CommittedMemory(), 0);
  CHECK_EQ(faked_space->CommittedPhysicalMemory(), 0);

  faked_space->AllocateRaw(16, kTaggedAligned);

  faked_space->ShrinkPages();
  faked_space->Seal(ReadOnlySpace::SealMode::kDoNotDetachFromHeap);

  // Allocated objects size.
  CHECK_EQ(faked_space->Size(), 16);

  size_t committed_memory = RoundUp(
      MemoryChunkLayout::ObjectStartOffsetInDataPage() + faked_space->Size(),
      MemoryAllocator::GetCommitPageSize());

  // Amount of OS allocated memory.
  CHECK_EQ(faked_space->CommittedMemory(), committed_memory);
  CHECK_EQ(faked_space->CommittedPhysicalMemory(), committed_memory);

  // Capacity will be one OS page minus the page header.
  CHECK_EQ(faked_space->Capacity(),
           committed_memory - MemoryChunkLayout::ObjectStartOffsetInDataPage());
}

TEST(ReadOnlySpaceMetrics_AlignedAllocations) {
  Isolate* isolate = CcTest::i_isolate();
  Heap* heap = isolate->heap();

  // Create a read-only space and allocate some memory, shrink the pages and
  // check the allocated object size is as expected.

  ReadOnlySpaceScope scope(heap);
  ReadOnlySpace* faked_space = scope.space();

  // Initially no memory.
  CHECK_EQ(faked_space->Size(), 0);
  CHECK_EQ(faked_space->Capacity(), 0);
  CHECK_EQ(faked_space->CommittedMemory(), 0);
  CHECK_EQ(faked_space->CommittedPhysicalMemory(), 0);

  // Allocate an object just under an OS page in size.
  int object_size =
      static_cast<int>(MemoryAllocator::GetCommitPageSize() - kApiTaggedSize);

  int alignment = USE_ALLOCATION_ALIGNMENT_BOOL ? kDoubleSize : kTaggedSize;

  Tagged<HeapObject> object =
      faked_space->AllocateRaw(object_size, kDoubleAligned).ToObjectChecked();
  CHECK_EQ(object.address() % alignment, 0);
  object =
      faked_space->AllocateRaw(object_size, kDoubleAligned).ToObjectChecked();
  CHECK_EQ(object.address() % alignment, 0);

  // Calculate size of allocations based on area_start.
  Address area_start = faked_space->pages().back()->GetAreaStart();
  Address top = RoundUp(area_start, alignment) + object_size;
  top = RoundUp(top, alignment) + object_size;
  size_t expected_size = top - area_start;

  faked_space->ShrinkPages();
  faked_space->Seal(ReadOnlySpace::SealMode::kDoNotDetachFromHeap);

  // Allocated objects size may will contain 4 bytes of padding on 32-bit or
  // with pointer compression.
  CHECK_EQ(faked_space->Size(), expected_size);

  size_t committed_me
```