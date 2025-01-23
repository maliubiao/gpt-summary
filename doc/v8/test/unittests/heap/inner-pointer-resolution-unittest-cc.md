Response:
Let's break down the thought process for analyzing the C++ unittest code.

1. **Understand the Goal:** The primary goal is to understand the functionality of the provided C++ code, specifically `inner-pointer-resolution-unittest.cc`. This involves determining what it tests and how it does so.

2. **Initial Scan and Keywords:** Quickly scan the code for recognizable patterns and keywords. Things like `TEST_F`, class names (`InnerPointerResolutionTest`), method names (`ResolveInnerPointer`, `CreateObjectsInPage`), and comments (`// Tests with some objects...`) are good starting points. The `#include` directives at the top are also informative, indicating dependencies related to heap management, garbage collection, and testing.

3. **Identify the Core Functionality:** The class `InnerPointerResolutionTest` and its `ResolveInnerPointer` method are central. The name "inner-pointer-resolution" strongly suggests that the code is about finding the base address of an object given a pointer somewhere *within* that object. The `ResolveInnerPointer` method itself seems to implement this logic.

4. **Analyze the Test Structure:**  The code uses the Google Test framework (`TEST_F`). Each `TEST_F` defines a specific test case. Examine the names of these test cases (e.g., `EmptyPage`, `NothingMarked`, `ThreeMarkedObjectsInSameCell`). These names provide hints about the scenarios being tested.

5. **Examine Helper Methods:**  Methods like `CreateNormalPage`, `CreateLargePage`, `CreateObjectsInPage`, and `CreateLargeObjects` are clearly setup routines for creating test environments. Understanding how these methods work is crucial. Notice how `CreateObjectsInPage` takes a `std::vector<ObjectRequest>`, which defines the properties of the objects being created (size, type, marking status, etc.).

6. **Trace the Execution Flow within a Test:** Pick a simple test case (like `EmptyPage`). See what actions are performed: `CreateObjectsInPage({})` creates an empty page, and then `TestAll()` is called. `TestAll()` iterates through created objects (none in this case) and then calls `RunTestOutside` for addresses outside the page. This helps confirm the basic functionality: resolving pointers within objects and handling out-of-bounds pointers.

7. **Understand the `ObjectRequest` Structure:** The `ObjectRequest` struct is key to configuring the test scenarios. Pay attention to its members: `size`, `type` (REGULAR, FREE, LARGE), `marked` (UNMARKED, MARKED, MARKED_AREA), `index_in_cell`, and `padding`. These details allow for precise control over object placement and marking within memory pages. The comments within `CreateObjectsInPage` about padding and `index_in_cell` are important for understanding how specific memory layouts are achieved for testing.

8. **Connect to Heap Concepts:**  Recognize terms like "OldSpace," "LargePage," "MarkingBitmap," and "GarbageCollector." These indicate that the tests are dealing with low-level memory management within the V8 heap. The interaction with the marking bitmap suggests that the inner pointer resolution logic might depend on the garbage collection marking information.

9. **Infer Functionality from Test Cases:**  The various `TEST_F` cases illustrate different scenarios being tested.
    * **Marking variations:** `NothingMarked`, `AllMarked`, `SomeMarked`, `MarkedAreas` test how marking status affects pointer resolution.
    * **Object Layout:** Tests with `index_in_cell` and `padding` (`ThreeMarkedObjectsInSameCell`, `SmallMarkedAreaAtPageStart`) focus on how object placement within memory cells impacts resolution.
    * **Multiple Pages:** `TwoPages`, `OneLargePage`, `SeveralLargePages` test the logic across different memory pages and object sizes.
    * **Young Generation and GC:** `UnusedRegularYoungPages`, `UnusedLargeYoungPage` demonstrate how the inner pointer resolution works (or doesn't) after garbage collection, especially with weak references.

10. **Consider Edge Cases and Error Handling:** The tests with `RunTestOutside` and the checks for `kNullAddress` in `RunTestInside` indicate that the code is also verifying correct handling of invalid or out-of-bounds pointers.

11. **JavaScript Relevance (If Applicable):** If the code were `.tq`, it would be directly related to Torque, V8's internal language for implementing built-in JavaScript functions. Since this is C++, the connection is more indirect: this C++ code *tests* a core V8 heap functionality that is essential for the correct implementation of JavaScript's memory management. Think about how JavaScript's garbage collector needs to track objects in memory, and how finding the start of an object given a pointer to its interior is a fundamental operation.

12. **Code Logic Inference:** The `ResolveInnerPointer` method is the key to inferring the code's logic. The comment indicates it's using `ConservativeStackVisitor`. This hints at a process of scanning memory to find the beginning of an object. The use of `MarkingBitmap` suggests that the marking information is likely used to identify object boundaries.

13. **Common Programming Errors:**  Relate the functionality to common programming errors, such as accessing memory outside of allocated object boundaries. The inner pointer resolution mechanism is crucial for debugging and potentially recovering from such errors during garbage collection.

14. **Review and Refine:**  After going through the above steps, review the findings and structure them into a coherent explanation. Ensure the explanation covers the core functionality, the test setup, the different scenarios being tested, and any connections to JavaScript or common programming errors. The use of examples (even conceptual ones for C++ memory layouts) can significantly improve understanding.

This structured approach, starting with a high-level understanding and progressively diving into details, helps to effectively analyze and explain complex C++ code like this.
这个C++源代码文件 `v8/test/unittests/heap/inner-pointer-resolution-unittest.cc` 的主要功能是**测试 V8 堆中内联指针解析（Inner Pointer Resolution）的功能**。

**详细功能拆解:**

1. **测试核心功能：`ConservativeStackVisitor::FindBasePtr`**:
   -  该文件主要测试 `ConservativeStackVisitor::FindBasePtr` 这个方法的功能。这个方法的作用是，给定一个可能指向堆中对象内部的指针（内联指针），尝试找到该对象在堆中的起始地址（基地址）。
   -  这对于垃圾回收器（Garbage Collector, GC）非常重要，因为它需要能够识别堆中的对象，即使只有一个指向对象内部的指针。

2. **模拟不同的堆状态**:
   -  测试代码创建了各种不同的堆状态来覆盖不同的场景，包括：
      - **空页 (Empty Page)**: 堆中没有对象。
      - **不同标记状态的对象 (Nothing Marked, All Marked, Some Marked, Marked Areas)**:  测试当堆中的对象有不同的标记状态时，内联指针解析是否能正常工作。标记状态是 GC 追踪对象存活状态的关键。
      - **特定的对象布局 (Three Marked Objects In Same Cell, SmallMarkedAreaAtPageStart 等)**:  精心设计对象在内存页中的布局，包括在同一个标记单元 (Marking Cell) 中放置多个对象，以及在页面的起始或边界放置对象，来测试边界情况和特定布局下的解析能力。
      - **多个内存页 (Two Pages, One Large Page, Several Large Pages, Pages Of Both Kind)**: 测试跨多个普通大小的内存页和大型对象页的解析。
      - **已释放的内存页 (Free Pages)**: 测试指向已释放内存页内的指针是否能正确返回空地址。
      - **年轻代内存页 (UnusedRegularYoungPages, UnusedLargeYoungPage)**:  测试年轻代（新生代）内存页的内联指针解析，特别是当对象被回收后的情况。
      - **页尾之后的指针 (Regular Page After End, LargePageAfterEnd)**: 测试指向内存页末尾之后的指针是否能正确返回空地址。

3. **`InnerPointerResolutionTest` 类**:
   -  这是主要的测试类，继承自 `WithInnerPointerResolutionMixin` 和 `TestWithIsolate`。
   -  `WithInnerPointerResolutionMixin` 提供了一个方便的 `ResolveInnerPointer` 方法，它包装了 `ConservativeStackVisitor::ForTesting(...).FindBasePtr(...)` 的调用。
   -  `ObjectRequest` 结构体用于描述要创建的堆对象，包括大小、类型（普通对象、空闲空间、大型对象）、标记状态、在标记单元中的索引以及填充方式等。
   -  `CreateNormalPage`, `CreateLargePage`, `FreePage`, `LookupPage` 等方法用于管理测试中使用的内存页。
   -  `CreateObjectsInPage` 和 `CreateLargeObjects` 方法根据 `ObjectRequest` 的描述在内存页中创建对象。
   -  `RunTestInside` 方法测试指向已知对象内部的指针是否能正确解析到对象的起始地址。
   -  `RunTestOutside` 方法测试指向非对象区域的指针是否能正确返回空地址。
   -  `TestAll` 方法遍历所有创建的对象和内存页，运行 `RunTestInside` 和 `RunTestOutside` 进行全面的测试。

4. **`InnerPointerResolutionHeapTest` 类**:
   -  继承自 `WithInnerPointerResolutionMixin` 和 `TestWithHeapInternalsAndContext`，用于进行更底层的堆测试。
   -  `UnusedRegularYoungPages` 和 `UnusedLargeYoungPage` 测试了年轻代内存页在垃圾回收后的内联指针解析行为，特别是涉及到弱引用的对象被回收的情况。
   -  `RegularPageAfterEnd` 和 `LargePageAfterEnd` 测试了指向内存页尾部之后的指针的解析。

**关于文件后缀 `.tq`:**

你提到的 `.tq` 后缀通常用于 V8 的 **Torque** 源代码文件。 Torque 是一种用于实现 V8 内部函数（例如 JavaScript 内置函数）的领域特定语言。

**由于 `v8/test/unittests/heap/inner-pointer-resolution-unittest.cc` 的后缀是 `.cc`，这意味着它是一个标准的 C++ 源代码文件，而不是 Torque 文件。**

**与 JavaScript 的功能关系:**

虽然这个文件是 C++ 代码，但它直接测试了 V8 引擎的核心功能，而 V8 引擎是 JavaScript 的运行时环境。 **内联指针解析是垃圾回收机制的关键组成部分，而垃圾回收对于 JavaScript 的内存管理至关重要。**

**JavaScript 例子 (概念性):**

在 JavaScript 中，你无法直接控制内存地址或内联指针。但是，可以想象以下情景，虽然 V8 内部处理了这些细节：

```javascript
let obj = { a: 1, b: 2 };
// 假设 V8 内部有一个指向 obj.b 的“内联指针”

// 当垃圾回收器运行时，它需要判断 obj 是否仍然被引用。
// 即使只有一个指向 obj.b 的“内联指针”，
// 内联指针解析的功能能够让 GC 找到 obj 的起始地址，
// 并判断 obj 是否存活。

// 如果没有其他强引用指向 obj，即使有一个指向 obj.b 的“内联指针”，
// GC 仍然可以回收 obj 的内存。
```

**代码逻辑推理 (假设输入与输出):**

假设我们创建了一个大小为 `16 * kTaggedSize` 的对象，起始地址为 `0x1000`。

**假设输入:** `maybe_inner_ptr = 0x1008` (指向对象内部)

**预期输出:** `ResolveInnerPointer(0x1008)` 应该返回 `0x1000` (对象的起始地址)。

**假设输入:** `maybe_inner_ptr = 0x10100` (不指向任何已分配的对象)

**预期输出:** `ResolveInnerPointer(0x10100)` 应该返回 `kNullAddress` (通常是 0)。

**涉及用户常见的编程错误:**

虽然用户不能直接操作内联指针，但内联指针解析的功能在幕后帮助 V8 处理一些与内存管理相关的错误。一个相关的用户编程错误是**访问已释放的内存**（Use-After-Free）。

**例子 (JavaScript):**

```javascript
let obj = { a: 1 };
let ref = obj;
obj = null; // 解除 obj 的引用

// 在某些情况下，如果 V8 的内部机制出现问题，
// 可能会存在一个“悬挂指针”仍然指向原来 obj 的内存。

// 如果此时执行 ref.a，并且 V8 没有正确处理这种情况，
// 可能会尝试访问已经释放的内存，导致程序崩溃或出现未定义行为。

// 内联指针解析作为垃圾回收的一部分，
// 确保即使存在这样的“悬挂指针”，
// GC 也能正确识别并处理已释放的内存，
// 从而避免或减少 Use-After-Free 错误的影响。
```

总而言之，`v8/test/unittests/heap/inner-pointer-resolution-unittest.cc` 是一个非常重要的测试文件，它确保了 V8 垃圾回收器能够可靠地识别和管理堆中的对象，即使只有指向对象内部的指针，这对于 JavaScript 程序的稳定性和性能至关重要。

### 提示词
```
这是目录为v8/test/unittests/heap/inner-pointer-resolution-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/heap/inner-pointer-resolution-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/conservative-stack-visitor.h"
#include "src/heap/gc-tracer.h"
#include "test/unittests/heap/heap-utils.h"
#include "test/unittests/test-utils.h"

namespace v8 {
namespace internal {

namespace {

constexpr int FullCell = MarkingBitmap::kBitsPerCell * kTaggedSize;

template <typename TMixin>
class WithInnerPointerResolutionMixin : public TMixin {
 public:
  Address ResolveInnerPointer(Address maybe_inner_ptr) {
    // This can only resolve inner pointers in the regular cage.
    PtrComprCageBase cage_base{this->isolate()};
    return ConservativeStackVisitor::ForTesting(
               this->isolate(), GarbageCollector::MARK_COMPACTOR)
        .FindBasePtr(maybe_inner_ptr, cage_base);
  }
};

class InnerPointerResolutionTest
    : public WithInnerPointerResolutionMixin<TestWithIsolate> {
 public:
  struct ObjectRequest {
    int size;  // The only required field.
    enum { REGULAR, FREE, LARGE } type = REGULAR;
    enum { UNMARKED, MARKED, MARKED_AREA } marked = UNMARKED;
    // If index_in_cell >= 0, the object is placed at the lowest address s.t.
    // MarkingBitmap::IndexInCell(MarkingBitmap::AddressToIndex(address)) ==
    // index_in_cell. To achieve this, padding (i.e., introducing a free-space
    // object of the appropriate size) may be necessary. If padding ==
    // CONSECUTIVE, no such padding is allowed and it is just checked that
    // object layout is as intended.
    int index_in_cell = -1;
    enum { CONSECUTIVE, PAD_UNMARKED, PAD_MARKED } padding = CONSECUTIVE;
    // The id of the page on which the object was allocated and its address are
    // stored here.
    int page_id = -1;
    Address address = kNullAddress;
  };

  InnerPointerResolutionTest() = default;

  ~InnerPointerResolutionTest() override {
    for (auto [id, page] : pages_)
      allocator()->Free(MemoryAllocator::FreeMode::kImmediately, page);
  }

  InnerPointerResolutionTest(const InnerPointerResolutionTest&) = delete;
  InnerPointerResolutionTest& operator=(const InnerPointerResolutionTest&) =
      delete;

  Heap* heap() { return isolate()->heap(); }
  MemoryAllocator* allocator() { return heap()->memory_allocator(); }

  // Create, free and lookup pages, normal or large.

  int CreateNormalPage() {
    OldSpace* old_space = heap()->old_space();
    DCHECK_NE(nullptr, old_space);
    auto* page = allocator()->AllocatePage(
        MemoryAllocator::AllocationMode::kRegular, old_space, NOT_EXECUTABLE);
    EXPECT_NE(nullptr, page);
    int page_id = next_page_id_++;
    DCHECK_EQ(pages_.end(), pages_.find(page_id));
    pages_[page_id] = page;
    return page_id;
  }

  int CreateLargePage(size_t size) {
    OldLargeObjectSpace* lo_space = heap()->lo_space();
    EXPECT_NE(nullptr, lo_space);
    LargePageMetadata* page =
        allocator()->AllocateLargePage(lo_space, size, NOT_EXECUTABLE);
    EXPECT_NE(nullptr, page);
    int page_id = next_page_id_++;
    DCHECK_EQ(pages_.end(), pages_.find(page_id));
    pages_[page_id] = page;
    return page_id;
  }

  void FreePage(int page_id) {
    DCHECK_LE(0, page_id);
    auto it = pages_.find(page_id);
    DCHECK_NE(pages_.end(), it);
    allocator()->Free(MemoryAllocator::FreeMode::kImmediately, it->second);
    pages_.erase(it);
  }

  MutablePageMetadata* LookupPage(int page_id) {
    DCHECK_LE(0, page_id);
    auto it = pages_.find(page_id);
    DCHECK_NE(pages_.end(), it);
    return it->second;
  }

  bool IsPageAlive(int page_id) {
    DCHECK_LE(0, page_id);
    return pages_.find(page_id) != pages_.end();
  }

  // Creates a list of objects in a page and ensures that the page is iterable.
  int CreateObjectsInPage(const std::vector<ObjectRequest>& objects) {
    int page_id = CreateNormalPage();
    MutablePageMetadata* page = LookupPage(page_id);
    Address ptr = page->area_start();
    for (auto object : objects) {
      DCHECK_NE(ObjectRequest::LARGE, object.type);
      DCHECK_EQ(0, object.size % kTaggedSize);

      // Check if padding is needed.
      int index_in_cell =
          MarkingBitmap::IndexInCell(MarkingBitmap::AddressToIndex(ptr));
      if (object.index_in_cell < 0) {
        object.index_in_cell = index_in_cell;
      } else if (object.padding != ObjectRequest::CONSECUTIVE) {
        DCHECK_LE(0, object.index_in_cell);
        DCHECK_GT(MarkingBitmap::kBitsPerCell, object.index_in_cell);
        const int needed_padding_size =
            ((MarkingBitmap::kBitsPerCell + object.index_in_cell -
              index_in_cell) %
             MarkingBitmap::kBitsPerCell) *
            kTaggedSize;
        if (needed_padding_size > 0) {
          ObjectRequest pad{needed_padding_size,
                            ObjectRequest::FREE,
                            object.padding == ObjectRequest::PAD_MARKED
                                ? ObjectRequest::MARKED_AREA
                                : ObjectRequest::UNMARKED,
                            index_in_cell,
                            ObjectRequest::CONSECUTIVE,
                            page_id,
                            ptr};
          ptr += needed_padding_size;
          DCHECK_LE(ptr, page->area_end());
          CreateObject(pad);
          index_in_cell =
              MarkingBitmap::IndexInCell(MarkingBitmap::AddressToIndex(ptr));
        }
      }

      // This will fail if the marking bitmap's implementation parameters change
      // (e.g., MarkingBitmap::kBitsPerCell) or the size of the page header
      // changes. In this case, the tests will need to be revised accordingly.
      EXPECT_EQ(index_in_cell, object.index_in_cell);

      object.page_id = page_id;
      object.address = ptr;
      ptr += object.size;
      DCHECK_LE(ptr, page->area_end());
      CreateObject(object);
    }

    // Create one last object that uses the remaining space on the page; this
    // simulates freeing the page's LAB.
    const int remaining_size = static_cast<int>(page->area_end() - ptr);
    const auto index = MarkingBitmap::AddressToIndex(ptr);
    const auto index_in_cell = MarkingBitmap::IndexInCell(index);
    ObjectRequest last{remaining_size,
                       ObjectRequest::FREE,
                       ObjectRequest::UNMARKED,
                       static_cast<int>(index_in_cell),
                       ObjectRequest::CONSECUTIVE,
                       page_id,
                       ptr};
    CreateObject(last);
    return page_id;
  }

  std::vector<int> CreateLargeObjects(
      const std::vector<ObjectRequest>& objects) {
    std::vector<int> result;
    for (auto object : objects) {
      DCHECK_EQ(ObjectRequest::LARGE, object.type);
      int page_id = CreateLargePage(object.size);
      MutablePageMetadata* page = LookupPage(page_id);
      object.page_id = page_id;
      object.address = page->area_start();
      CHECK_EQ(object.address + object.size, page->area_end());
      CreateObject(object);
      result.push_back(page_id);
    }
    return result;
  }

  void CreateObject(const ObjectRequest& object) {
    objects_.push_back(object);

    // "Allocate" (i.e., manually place) the object in the page, set the map
    // and the size.
    switch (object.type) {
      case ObjectRequest::REGULAR:
      case ObjectRequest::LARGE: {
        DCHECK_LE(2 * kTaggedSize, object.size);
        ReadOnlyRoots roots(heap());
        Tagged<HeapObject> heap_object(HeapObject::FromAddress(object.address));
        heap_object->set_map_after_allocation(heap()->isolate(),
                                              roots.unchecked_fixed_array_map(),
                                              SKIP_WRITE_BARRIER);
        Tagged<FixedArray> arr(Cast<FixedArray>(heap_object));
        arr->set_length((object.size - FixedArray::SizeFor(0)) / kTaggedSize);
        DCHECK_EQ(object.size, arr->AllocatedSize());
        break;
      }
      case ObjectRequest::FREE:
        heap()->CreateFillerObjectAt(object.address, object.size);
        break;
    }

    // Mark the object in the bitmap, if necessary.
    switch (object.marked) {
      case ObjectRequest::UNMARKED:
        break;
      case ObjectRequest::MARKED:
        heap()->marking_state()->TryMark(
            HeapObject::FromAddress(object.address));
        break;
      case ObjectRequest::MARKED_AREA: {
        MutablePageMetadata* page = LookupPage(object.page_id);
        page->marking_bitmap()->SetRange<AccessMode::NON_ATOMIC>(
            MarkingBitmap::AddressToIndex(object.address),
            MarkingBitmap::LimitAddressToIndex(object.address + object.size));
        break;
      }
    }
  }

  // This must be called with a created object and an offset inside it.
  void RunTestInside(const ObjectRequest& object, int offset) {
    DCHECK_LE(0, offset);
    DCHECK_GT(object.size, offset);
    Address base_ptr = ResolveInnerPointer(object.address + offset);
    bool should_return_null =
        !IsPageAlive(object.page_id) || object.type == ObjectRequest::FREE;
    if (should_return_null)
      EXPECT_EQ(kNullAddress, base_ptr);
    else
      EXPECT_EQ(object.address, base_ptr);
  }

  // This must be called with an address not contained in any created object.
  void RunTestOutside(Address ptr) {
    Address base_ptr = ResolveInnerPointer(ptr);
    EXPECT_EQ(kNullAddress, base_ptr);
  }

  void TestAll() {
    for (auto object : objects_) {
      RunTestInside(object, 0);
      RunTestInside(object, 1);
      RunTestInside(object, object.size / 2);
      RunTestInside(object, object.size - 1);
    }
    for (auto [id, page] : pages_) {
      const Address outside_ptr = page->ChunkAddress() + 1;
      DCHECK_LE(page->ChunkAddress(), outside_ptr);
      RunTestOutside(outside_ptr);
    }
    RunTestOutside(kNullAddress);
    RunTestOutside(static_cast<Address>(42));
    RunTestOutside(static_cast<Address>(kZapValue));
  }

 private:
  std::map<int, MutablePageMetadata*> pages_;
  int next_page_id_ = 0;
  std::vector<ObjectRequest> objects_;
};

}  // namespace

TEST_F(InnerPointerResolutionTest, EmptyPage) {
  CreateObjectsInPage({});
  TestAll();
}

// Tests with some objects laid out randomly.

TEST_F(InnerPointerResolutionTest, NothingMarked) {
  CreateObjectsInPage({
      {16 * kTaggedSize},
      {12 * kTaggedSize},
      {13 * kTaggedSize},
      {128 * kTaggedSize},
      {1 * kTaggedSize, ObjectRequest::FREE},
      {15 * kTaggedSize},
      {2 * kTaggedSize, ObjectRequest::FREE},
      {2 * kTaggedSize},
      {10544 * kTaggedSize},
  });
  TestAll();
}

TEST_F(InnerPointerResolutionTest, AllMarked) {
  CreateObjectsInPage({
      {16 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED},
      {12 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED},
      {13 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED},
      {128 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED},
      {1 * kTaggedSize, ObjectRequest::FREE, ObjectRequest::MARKED},
      {15 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED},
      {2 * kTaggedSize, ObjectRequest::FREE, ObjectRequest::MARKED},
      {2 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED},
      {10544 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED},
  });
  TestAll();
}

TEST_F(InnerPointerResolutionTest, SomeMarked) {
  CreateObjectsInPage({
      {16 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::UNMARKED},
      {12 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::UNMARKED},
      {13 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED},
      {128 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::UNMARKED},
      {1 * kTaggedSize, ObjectRequest::FREE, ObjectRequest::MARKED},
      {15 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED},
      {2 * kTaggedSize, ObjectRequest::FREE, ObjectRequest::MARKED},
      {2 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::UNMARKED},
      {10544 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED},
  });
  TestAll();
}

TEST_F(InnerPointerResolutionTest, MarkedAreas) {
  CreateObjectsInPage({
      {16 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::UNMARKED},
      {12 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED_AREA},
      {13 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED},
      {128 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED_AREA},
      {1 * kTaggedSize, ObjectRequest::FREE, ObjectRequest::MARKED},
      {15 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED},
      {2 * kTaggedSize, ObjectRequest::FREE, ObjectRequest::MARKED},
      {2 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::UNMARKED},
      {10544 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED},
  });
  TestAll();
}

// Tests with specific object layout, to cover interesting and corner cases.

TEST_F(InnerPointerResolutionTest, ThreeMarkedObjectsInSameCell) {
  CreateObjectsInPage({
      // Some initial large unmarked object, followed by a small marked object
      // towards the end of the cell.
      {128 * kTaggedSize},
      {5 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED, 20,
       ObjectRequest::PAD_UNMARKED},
      // Then three marked objects in the same cell.
      {8 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED, 3,
       ObjectRequest::PAD_UNMARKED},
      {12 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED, 11},
      {5 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED, 23},
      // This marked object is in the next cell.
      {16 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED, 17,
       ObjectRequest::PAD_UNMARKED},
  });
  TestAll();
}

TEST_F(InnerPointerResolutionTest, ThreeMarkedAreasInSameCell) {
  CreateObjectsInPage({
      // Some initial large unmarked object, followed by a small marked area
      // towards the end of the cell.
      {128 * kTaggedSize},
      {5 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED_AREA, 20,
       ObjectRequest::PAD_UNMARKED},
      // Then three marked areas in the same cell.
      {8 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED_AREA, 3,
       ObjectRequest::PAD_UNMARKED},
      {12 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED_AREA,
       11},
      {5 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED_AREA, 23},
      // This marked area is in the next cell.
      {16 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED_AREA, 17,
       ObjectRequest::PAD_UNMARKED},
  });
  TestAll();
}

TEST_F(InnerPointerResolutionTest, SmallMarkedAreaAtPageStart) {
  CreateObjectsInPage({
      {16 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::UNMARKED, 30,
       ObjectRequest::PAD_MARKED},
  });
  TestAll();
}

TEST_F(InnerPointerResolutionTest,
       SmallMarkedAreaAtPageStartUntilCellBoundary) {
  CreateObjectsInPage({
      {2 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED_AREA},
      {16 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::UNMARKED, 0,
       ObjectRequest::PAD_MARKED},
  });
  TestAll();
}

TEST_F(InnerPointerResolutionTest, LargeMarkedAreaAtPageStart) {
  CreateObjectsInPage({
      {42 * FullCell, ObjectRequest::REGULAR, ObjectRequest::MARKED_AREA},
      {16 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::UNMARKED, 30,
       ObjectRequest::PAD_MARKED},
  });
  TestAll();
}

TEST_F(InnerPointerResolutionTest,
       LargeMarkedAreaAtPageStartUntilCellBoundary) {
  CreateObjectsInPage({
      {42 * FullCell, ObjectRequest::REGULAR, ObjectRequest::MARKED_AREA},
      {16 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::UNMARKED, 0,
       ObjectRequest::PAD_MARKED},
  });
  TestAll();
}

TEST_F(InnerPointerResolutionTest, SmallMarkedAreaStartingAtCellBoundary) {
  CreateObjectsInPage({
      {128 * kTaggedSize},
      {5 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED_AREA, 0,
       ObjectRequest::PAD_UNMARKED},
  });
  TestAll();
}

TEST_F(InnerPointerResolutionTest, LargeMarkedAreaStartingAtCellBoundary) {
  CreateObjectsInPage({
      {128 * kTaggedSize},
      {42 * FullCell + 16 * kTaggedSize, ObjectRequest::REGULAR,
       ObjectRequest::MARKED_AREA, 0, ObjectRequest::PAD_UNMARKED},
  });
  TestAll();
}

TEST_F(InnerPointerResolutionTest, SmallMarkedAreaEndingAtCellBoundary) {
  CreateObjectsInPage({
      {128 * kTaggedSize},
      {2 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED_AREA, 13,
       ObjectRequest::PAD_UNMARKED},
      {16 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::UNMARKED, 0,
       ObjectRequest::PAD_MARKED},
  });
  TestAll();
}

TEST_F(InnerPointerResolutionTest, LargeMarkedAreaEndingAtCellBoundary) {
  CreateObjectsInPage({
      {128 * kTaggedSize},
      {42 * FullCell + 16 * kTaggedSize, ObjectRequest::REGULAR,
       ObjectRequest::MARKED_AREA, 0, ObjectRequest::PAD_UNMARKED},
      {16 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::UNMARKED, 0,
       ObjectRequest::PAD_MARKED},
  });
  TestAll();
}

TEST_F(InnerPointerResolutionTest, TwoSmallMarkedAreasAtCellBoundaries) {
  CreateObjectsInPage({
      {128 * kTaggedSize},
      {6 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED_AREA, 0,
       ObjectRequest::PAD_UNMARKED},
      {2 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED_AREA, 25,
       ObjectRequest::PAD_UNMARKED},
      {16 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::UNMARKED, 0,
       ObjectRequest::PAD_MARKED},
  });
  TestAll();
}

TEST_F(InnerPointerResolutionTest, MarkedAreaOfOneCell) {
  CreateObjectsInPage({
      {128 * kTaggedSize},
      {1 * FullCell, ObjectRequest::REGULAR, ObjectRequest::MARKED_AREA, 0,
       ObjectRequest::PAD_UNMARKED},
  });
  TestAll();
}

TEST_F(InnerPointerResolutionTest, MarkedAreaOfManyCells) {
  CreateObjectsInPage({
      {128 * kTaggedSize},
      {17 * FullCell, ObjectRequest::REGULAR, ObjectRequest::MARKED_AREA, 0,
       ObjectRequest::PAD_UNMARKED},
  });
  TestAll();
}

// Test with more pages, normal and large.

TEST_F(InnerPointerResolutionTest, TwoPages) {
  CreateObjectsInPage({
      {16 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::UNMARKED},
      {13 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED},
      {128 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::UNMARKED},
      {15 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED},
      {10544 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED},
  });
  CreateObjectsInPage({
      {128 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED_AREA},
      {16 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::UNMARKED},
      {12 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED_AREA},
      {13 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED},
      {1 * kTaggedSize, ObjectRequest::FREE, ObjectRequest::MARKED},
      {2 * kTaggedSize, ObjectRequest::FREE, ObjectRequest::MARKED},
      {2 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::UNMARKED},
      {15 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED},
  });
  TestAll();
}

TEST_F(InnerPointerResolutionTest, OneLargePage) {
  CreateLargeObjects({
      {1 * MB, ObjectRequest::LARGE, ObjectRequest::UNMARKED},
  });
  TestAll();
}

TEST_F(InnerPointerResolutionTest, SeveralLargePages) {
  CreateLargeObjects({
      {1 * MB, ObjectRequest::LARGE, ObjectRequest::UNMARKED},
      {32 * MB, ObjectRequest::LARGE, ObjectRequest::MARKED},
  });
  TestAll();
}

TEST_F(InnerPointerResolutionTest, PagesOfBothKind) {
  CreateObjectsInPage({
      {16 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::UNMARKED},
      {13 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED},
      {128 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::UNMARKED},
      {15 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED},
      {10544 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED},
  });
  CreateObjectsInPage({
      {128 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED_AREA},
      {16 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::UNMARKED},
      {12 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED_AREA},
      {13 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED},
      {1 * kTaggedSize, ObjectRequest::FREE, ObjectRequest::MARKED},
      {2 * kTaggedSize, ObjectRequest::FREE, ObjectRequest::MARKED},
      {2 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::UNMARKED},
      {15 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED},
  });
  CreateLargeObjects({
      {1 * MB, ObjectRequest::LARGE, ObjectRequest::UNMARKED},
      {32 * MB, ObjectRequest::LARGE, ObjectRequest::MARKED},
  });
  TestAll();
}

TEST_F(InnerPointerResolutionTest, FreePages) {
  int some_normal_page = CreateObjectsInPage({
      {16 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::UNMARKED},
      {13 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED},
      {128 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::UNMARKED},
      {15 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED},
      {10544 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED},
  });
  CreateObjectsInPage({
      {128 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED_AREA},
      {16 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::UNMARKED},
      {12 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED_AREA},
      {13 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED},
      {1 * kTaggedSize, ObjectRequest::FREE, ObjectRequest::MARKED},
      {2 * kTaggedSize, ObjectRequest::FREE, ObjectRequest::MARKED},
      {2 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::UNMARKED},
      {15 * kTaggedSize, ObjectRequest::REGULAR, ObjectRequest::MARKED},
  });
  auto large_pages = CreateLargeObjects({
      {1 * MB, ObjectRequest::LARGE, ObjectRequest::UNMARKED},
      {32 * MB, ObjectRequest::LARGE, ObjectRequest::MARKED},
  });
  TestAll();
  FreePage(some_normal_page);
  TestAll();
  FreePage(large_pages[0]);
  TestAll();
}

using InnerPointerResolutionHeapTest =
    WithInnerPointerResolutionMixin<TestWithHeapInternalsAndContext>;

TEST_F(InnerPointerResolutionHeapTest, UnusedRegularYoungPages) {
  ManualGCScope manual_gc_scope(isolate());
  DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap());

  Persistent<v8::FixedArray> weak1, weak2, strong;
  Address inner_ptr1, inner_ptr2, inner_ptr3, outside_ptr1, outside_ptr2;
  MemoryChunk *page1, *page2;

  auto allocator = heap()->memory_allocator();

  {
    PtrComprCageBase cage_base{isolate()};
    HandleScope scope(isolate());

    // Allocate two objects, large enough that they fall in two different young
    // generation pages. Keep weak references to these objects.
    const int length =
        (heap()->MaxRegularHeapObjectSize(AllocationType::kYoung) -
         FixedArray::SizeFor(0)) /
        kTaggedSize;
    auto h1 = factory()->NewFixedArray(length, AllocationType::kYoung);
    auto h2 = factory()->NewFixedArray(length, AllocationType::kYoung);
    weak1.Reset(v8_isolate(), Utils::FixedArrayToLocal(h1));
    weak2.Reset(v8_isolate(), Utils::FixedArrayToLocal(h2));
    weak1.SetWeak();
    weak2.SetWeak();
    auto obj1 = *h1;
    auto obj2 = *h2;
    page1 = MemoryChunk::FromHeapObject(obj1);
    EXPECT_TRUE(!page1->IsLargePage());
    EXPECT_TRUE(v8_flags.minor_ms || page1->IsToPage());
    page2 = MemoryChunk::FromHeapObject(obj2);
    EXPECT_TRUE(!page2->IsLargePage());
    EXPECT_TRUE(v8_flags.minor_ms || page2->IsToPage());
    EXPECT_NE(page1, page2);

    // Allocate one more object, small enough that it fits in either page1 or
    // page2. Keep a strong reference to this object.
    auto h3 = factory()->NewFixedArray(16, AllocationType::kYoung);
    strong.Reset(v8_isolate(), Utils::FixedArrayToLocal(h3));
    auto obj3 = *h3;
    auto page3 = MemoryChunk::FromHeapObject(obj3);
    EXPECT_TRUE(page3 == page1 || page3 == page2);
    if (page3 == page1) {
      EXPECT_EQ(obj3.address(), obj1.address() + obj1->Size());
    } else {
      EXPECT_EQ(obj3.address(), obj2.address() + obj2->Size());
    }

    // Keep inner pointers to all objects.
    inner_ptr1 = obj1.address() + 17 * kTaggedSize;
    inner_ptr2 = obj2.address() + 37 * kTaggedSize;
    inner_ptr3 = obj3.address() + 7 * kTaggedSize;

    // Keep pointers to the end of the pages, after the objects.
    outside_ptr1 = page1->Metadata()->area_end() - 3 * kTaggedSize;
    outside_ptr2 = page2->Metadata()->area_end() - 2 * kTaggedSize;
    EXPECT_LE(obj1.address() + obj1->Size(), outside_ptr1);
    EXPECT_LE(obj2.address() + obj2->Size(), outside_ptr2);
    if (page3 == page1) {
      EXPECT_LE(obj3.address() + obj3->Size(), outside_ptr1);
    } else {
      EXPECT_LE(obj3.address() + obj3->Size(), outside_ptr2);
    }

    // Ensure the young generation space is iterable.
    heap()
        ->allocator()
        ->new_space_allocator()
        ->MakeLinearAllocationAreaIterable();

    // Inner pointer resolution should work now, finding the objects in the
    // case of the inner pointers.
    EXPECT_EQ(obj1.address(), ResolveInnerPointer(inner_ptr1));
    EXPECT_EQ(obj2.address(), ResolveInnerPointer(inner_ptr2));
    EXPECT_EQ(obj3.address(), ResolveInnerPointer(inner_ptr3));
    EXPECT_EQ(kNullAddress, ResolveInnerPointer(outside_ptr1));
    EXPECT_EQ(kNullAddress, ResolveInnerPointer(outside_ptr2));

    // Start incremental marking and mark the third object.
    i::IncrementalMarking* marking = heap()->incremental_marking();
    if (marking->IsStopped()) {
      IsolateSafepointScope scope(heap());
      heap()->tracer()->StartCycle(
          GarbageCollector::MARK_COMPACTOR, GarbageCollectionReason::kTesting,
          "unit test", GCTracer::MarkingType::kIncremental);
      marking->Start(GarbageCollector::MARK_COMPACTOR,
                     i::GarbageCollectionReason::kTesting);
    }
    MarkingState* marking_state = heap()->marking_state();
    marking_state->TryMarkAndAccountLiveBytes(obj3);
  }

  // Garbage collection should reclaim the two large objects with the weak
  // references, but not the small one with the strong reference.
  InvokeAtomicMinorGC();
  EXPECT_TRUE(weak1.IsEmpty());
  EXPECT_TRUE(weak2.IsEmpty());
  EXPECT_TRUE(!strong.IsEmpty());
  // The two pages should still be around, in the new space.
  EXPECT_EQ(page1, allocator->LookupChunkContainingAddress(inner_ptr1));
  EXPECT_EQ(page2, allocator->LookupChunkContainingAddress(inner_ptr2));
  EXPECT_EQ(AllocationSpace::NEW_SPACE,
            MutablePageMetadata::cast(page1->Metadata())->owner_identity());
  EXPECT_EQ(AllocationSpace::NEW_SPACE,
            MutablePageMetadata::cast(page2->Metadata())->owner_identity());
  EXPECT_TRUE(v8_flags.minor_ms || page1->IsFromPage());
  EXPECT_TRUE(v8_flags.minor_ms || page2->IsFromPage());

  // Inner pointer resolution should work with pointers to unused young
  // generation pages (in case of the scavenger, the two pages are now in the
  // "from" semispace). There are no objects to be found.
  EXPECT_EQ(kNullAddress, ResolveInnerPointer(inner_ptr1));
  EXPECT_EQ(kNullAddress, ResolveInnerPointer(inner_ptr2));
  EXPECT_EQ(kNullAddress, ResolveInnerPointer(inner_ptr3));
  EXPECT_EQ(kNullAddress, ResolveInnerPointer(outside_ptr1));
  EXPECT_EQ(kNullAddress, ResolveInnerPointer(outside_ptr2));

  // Garbage collection once more.
  InvokeAtomicMinorGC();
  EXPECT_EQ(AllocationSpace::NEW_SPACE,
            MutablePageMetadata::cast(page1->Metadata())->owner_identity());
  EXPECT_EQ(AllocationSpace::NEW_SPACE,
            MutablePageMetadata::cast(page2->Metadata())->owner_identity());
  // The two pages should still be around, in the new space.
  EXPECT_EQ(page1, allocator->LookupChunkContainingAddress(inner_ptr1));
  EXPECT_EQ(page2, allocator->LookupChunkContainingAddress(inner_ptr2));
  EXPECT_TRUE(v8_flags.minor_ms || page1->IsToPage());
  EXPECT_TRUE(v8_flags.minor_ms || page2->IsToPage());

  // Inner pointer resolution should work with pointers to unused young
  // generation pages (in case of the scavenger, the two pages are now in the
  // "to" semispace). There are no objects to be found.
  EXPECT_EQ(kNullAddress, ResolveInnerPointer(inner_ptr1));
  EXPECT_EQ(kNullAddress, ResolveInnerPointer(inner_ptr2));
  EXPECT_EQ(kNullAddress, ResolveInnerPointer(inner_ptr3));
  EXPECT_EQ(kNullAddress, ResolveInnerPointer(outside_ptr1));
  EXPECT_EQ(kNullAddress, ResolveInnerPointer(outside_ptr2));
}

TEST_F(InnerPointerResolutionHeapTest, UnusedLargeYoungPage) {
  ManualGCScope manual_gc_scope(isolate());
  DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap());

  Global<v8::FixedArray> weak;
  Address inner_ptr;

  {
    PtrComprCageBase cage_base{isolate()};
    HandleScope scope(isolate());

    // Allocate a large object in the young generation.
    const int length =
        std::max(1 << kPageSizeBits,
                 2 * heap()->MaxRegularHeapObjectSize(AllocationType::kYoung)) /
        kTaggedSize;
    auto h = factory()->NewFixedArray(length, AllocationType::kYoung);
    weak.Reset(v8_isolate(), Utils::FixedArrayToLocal(h));
    weak.SetWeak();
    auto obj = *h;
    auto page = MemoryChunk::FromHeapObject(obj);
    EXPECT_TRUE(page->IsLargePage());
    EXPECT_EQ(AllocationSpace::NEW_LO_SPACE,
              MutablePageMetadata::cast(page->Metadata())->owner_identity());
    EXPECT_TRUE(v8_flags.minor_ms || page->IsToPage());

    // Keep inner pointer.
    inner_ptr = obj.address() + 17 * kTaggedSize;

    // Inner pointer resolution should work now, finding the object.
    EXPECT_EQ(obj.address(), ResolveInnerPointer(inner_ptr));
  }

  // Garbage collection should reclaim the object.
  InvokeAtomicMinorGC();
  EXPECT_TRUE(weak.IsEmpty());

  // Inner pointer resolution should work with a pointer to an unused young
  // generation large page. There is no object to be found.
  EXPECT_EQ(kNullAddress, ResolveInnerPointer(inner_ptr));
}

TEST_F(InnerPointerResolutionHeapTest, RegularPageAfterEnd) {
  auto allocator = heap()->memory_allocator();

  // Allocate a regular page.
  OldSpace* old_space = heap()->old_space();
  DCHECK_NE(nullptr, old_space);
  auto* page = allocator->AllocatePage(
      MemoryAllocator::AllocationMode::kRegular, old_space, NOT_EXECUTABLE);
  EXPECT_NE(nullptr, page);

  // The end of the page area is expected not to coincide with the beginning of
  // the next page.
  const int size = (1 << kPageSizeBits) / 2;
  const Address mark = page->area_start() + size;
  heap()->CreateFillerObjectAt(page->area_start(), size);
  heap()->CreateFillerObjectAt(mark, static_cast<int>(page->area_end() - mark));
  PageMetadata::UpdateHighWaterMark(mark);
  page->ShrinkToHighWaterMark();
  EXPECT_FALSE(PageMetadata::IsAlignedToPageSize(page->area_end()));

  // Inner pointer resolution after the end of the page area should work.
  Address inner_ptr = page->area_end() + kTaggedSize;
  EXPECT_FALSE(PageMetadata::IsAlignedToPageSize(inner_ptr));
  EXPECT_EQ(kNullAddress, ResolveInnerPointer(inner_ptr));

  // Deallocate the page.
  allocator->Free(MemoryAllocator::FreeMode::kImmediately, page);
}

TEST_F(InnerPointerResolutionHeapTest, LargePageAfterEnd) {
  auto allocator = heap()->memory_allocator();

  // Allocate a large page.
  OldLargeObjectSpace* lo_space = heap()->lo_space();
  EXPECT_NE(nullptr, lo_space);
  const int size = 3 * (1 << kPageSizeBits) / 2;
  LargePageMetadata* page =
      allocator->AllocateLargePage(lo_space, size, NOT_EXECUTABLE);
  EXPECT_NE(nullptr, page);

  // The end of the page area is expected not to coincide with the beginning of
  // the next page.
  EXPECT_FALSE(PageMetadata::IsAlignedToPageSize(page->area_end()));

  // Inner pointer resolution after the end of the pare area should work.
  Address inner_ptr = page->area_end() + kTaggedSize;
  EXPECT_FALSE(PageMetadata::IsAlignedToPageSize(inner_ptr));
  EXPECT_EQ(kNullAddress, ResolveInnerPointer(inner_ptr));

  // Deallocate the page.
  allocator->Free(MemoryAllocator::FreeMode::kImmediately, page);
}

}  // namespace internal
}  // namespace v8
```