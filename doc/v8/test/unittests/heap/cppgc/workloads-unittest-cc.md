Response:
Let's break down the thought process for analyzing this C++ code and generating the response.

1. **Understanding the Goal:** The request asks for an analysis of the C++ code, focusing on its functionality, potential relationship with JavaScript, logical deductions with examples, and common programming errors.

2. **Initial Scan for Keywords and Structure:**  The first step is to quickly scan the code for relevant keywords and structural elements. Things that jump out are:

    * `#include`:  Indicates standard C++ libraries and specific V8 headers related to memory management (`cppgc`, `heap`).
    * `namespace cppgc::internal`:  Clearly part of the V8's C++ garbage collection system.
    * `class WorkloadsTest : public testing::TestWithHeap`:  Confirms this is a unit test, likely focusing on testing the heap functionality.
    * `ConservativeGC()`, `PreciseGC()`:  Methods indicating different garbage collection strategies.
    * Classes like `PointsBack`, `SuperClass`, `SubClass`, `SubData`, `DynamicallySizedObject`: These define the data structures being managed by the garbage collector.
    * `Persistent<>`, `Member<>`, `WeakMember<>`: These are key types from `cppgc` for managing object lifetimes and relationships under garbage collection.
    * `Trace(Visitor*)`:  A standard pattern in garbage collection for marking reachable objects.
    * `TEST_F(WorkloadsTest, ...)`:  gtest macros defining individual test cases.
    * `alive_count_`:  Static members used to track object creation and destruction.
    * `ObjectSizeCounter`: A custom class for calculating the total size of live objects on the heap.

3. **Deconstructing the Functionality (Test Cases):** The core of the functionality is revealed by examining the `TEST_F` blocks.

    * **`Transition` Test:** This test focuses on how objects are managed during garbage collection cycles (both precise and conservative). It creates a chain of objects (`PointsBack`, `SuperClass`, `SubClass`) and examines their lifecycles when `Persistent` handles are released and garbage collection is triggered. The `alive_count_` variables are crucial for verifying object creation and destruction.

    * **`BasicFunctionality` Test:** This test explores more general heap operations:
        * Allocation of dynamically sized objects using `DynamicallySizedObject`.
        * Use of `memset` to initialize memory.
        * Verification of allocated memory size using `ObjectSizeCounter`.
        * Testing the effect of conservative and precise garbage collection on dynamically sized objects, both regular and persistent.
        * Looping through allocations and checking memory usage.

4. **Identifying Potential JavaScript Relevance:**  Since this is part of V8, the garbage collector has a direct and critical relationship with JavaScript. JavaScript's automatic memory management relies on the garbage collector. Therefore, any code testing the garbage collector's core functionality is inherently relevant to JavaScript. The key link is that the `cppgc` library *is* the C++ implementation of a core component that makes JavaScript's garbage collection work.

5. **Creating JavaScript Examples (Hypothetical):**  Even though the C++ code isn't *directly* called from JavaScript, we can create illustrative JavaScript examples that demonstrate the *concepts* being tested: object creation, relationships between objects, and the idea of memory management happening behind the scenes. It's important to emphasize that the JavaScript examples are *analogous* to the C++ tests, not direct equivalents.

6. **Logical Deduction and Examples:** The test cases themselves provide the basis for logical deduction. The `Transition` test, for instance, demonstrates how releasing `Persistent` handles makes objects eligible for garbage collection. The `BasicFunctionality` test shows that even with conservative GC, explicitly allocated and referenced objects remain alive. We can formulate simple "if-then" statements to illustrate these deductions. We can also create small input/output scenarios based on the `alive_count_` variables.

7. **Identifying Common Programming Errors:**  Based on the concepts being tested (memory management, object lifetimes, pointers), we can identify common errors related to manual memory management that the garbage collector aims to prevent in higher-level languages like JavaScript. These include memory leaks (forgetting to `delete`), dangling pointers (accessing memory after it's freed), and double frees (trying to free the same memory twice). While these aren't direct errors within *this specific test code* (which is *testing* the GC), they are the *problems* the GC is designed to solve.

8. **Torque Analysis:**  The request specifically asks about `.tq` files. A quick check of the filename reveals it ends in `.cc`, not `.tq`. Therefore, this code is standard C++, not Torque.

9. **Structuring the Response:** Finally, the information needs to be organized clearly into the requested categories: Functionality, JavaScript Relation, Logical Deduction, and Common Errors. Using clear headings and bullet points makes the analysis easier to understand. It's important to be precise in the language, distinguishing between what the code *does* and the *purpose* behind it.

This systematic approach, combining code analysis with an understanding of the underlying concepts of garbage collection and V8's architecture, allows for a comprehensive and accurate response to the request.
这个C++源代码文件 `v8/test/unittests/heap/cppgc/workloads-unittest.cc` 是 V8 引擎中 `cppgc` (C++ garbage collection) 组件的单元测试文件。它的主要功能是：

**核心功能：测试 cppgc 垃圾回收器的在不同工作负载下的行为和正确性。**

更具体地说，它包含了一系列单元测试用例（使用 Google Test 框架），用于验证 `cppgc` 在各种场景下的内存管理功能，例如：

* **对象的创建和销毁:** 测试 `cppgc` 管理的对象的生命周期，包括构造和析构。
* **垃圾回收的触发和效果:** 测试不同类型的垃圾回收（精确 GC 和保守 GC）对对象存活的影响。
* **对象之间的引用关系:** 测试 `Member<>` (强引用), `WeakMember<>` (弱引用), 和 `Persistent<>` (持久引用) 等智能指针在垃圾回收中的作用。
* **继承关系的处理:** 测试 `cppgc` 如何处理继承结构中的对象。
* **动态大小对象的分配和管理:** 测试分配具有运行时确定大小的对象的能力。
* **内存统计和跟踪:** 测试 `cppgc` 提供的内存统计和对象大小计算功能。

**以下是更详细的功能点：**

1. **定义测试辅助类:**
   - `WorkloadsTest`:  作为所有测试用例的基类，提供了触发精确和保守垃圾回收的辅助方法 (`PreciseGC`, `ConservativeGC`)。
   - `PointsBack`, `SuperClass`, `SubClass`, `SubData`:  定义了具有不同引用关系和继承关系的测试用对象。这些类都继承自 `GarbageCollected<>`，表明它们由 `cppgc` 管理。
   - `DynamicallySizedObject`:  用于测试动态大小对象的分配。
   - `ObjectSizeCounter`:  一个用于计算当前堆上所有可达对象大小的辅助类。

2. **实现具体的测试用例:**
   - **`Transition` 测试用例:**
     - 创建 `PointsBack`, `SuperClass`, `SubClass` 对象，并建立相互引用。
     - 使用 `Persistent<>` 来持有对象，防止它们被立即回收。
     - 模拟 `Persistent<>` 的释放，并触发不同类型的垃圾回收。
     - 通过检查静态成员 `alive_count_` 来验证对象的创建和销毁情况。
     - 验证弱引用 `back_pointer_` 在对象被回收后是否变为空指针。
     - 测试保守 GC 和精确 GC 对对象存活的不同影响。
   - **`BasicFunctionality` 测试用例:**
     - 测试动态大小对象的分配和初始化 (`DynamicallySizedObject`)。
     - 使用 `memset` 初始化分配的内存。
     - 验证分配的对象的内容是否正确。
     - 跟踪堆上的对象大小变化 (`ObjectSizeCounter`)。
     - 测试大量持久对象的分配和回收。
     - 验证垃圾回收后内存是否被正确释放。

**关于 `.tq` 文件：**

如果 `v8/test/unittests/heap/cppgc/workloads-unittest.cc` 以 `.tq` 结尾，那么它将是一个 **Torque** 源代码文件。Torque 是 V8 使用的一种领域特定语言，用于生成高效的 C++ 代码，特别是用于实现内置函数和运行时功能。然而，根据你提供的文件名，它以 `.cc` 结尾，因此是标准的 C++ 代码文件。

**与 JavaScript 功能的关系：**

这个测试文件直接关系到 JavaScript 的内存管理。`cppgc` 是 V8 引擎中用于管理 C++ 对象（V8 内部结构）的垃圾回收器。JavaScript 的垃圾回收机制依赖于对 JavaScript 堆和 C++ 堆的管理。`cppgc` 的正确性和效率直接影响着 JavaScript 应用程序的性能和稳定性。

**JavaScript 示例说明（概念上的关联）：**

虽然这个 C++ 代码本身不是 JavaScript，但它测试的 `cppgc` 功能支撑着 JavaScript 的垃圾回收。以下 JavaScript 例子可以类比说明一些概念：

```javascript
// 类似于 C++ 中的 SuperClass 和 PointsBack 的关系
class PointsBackJS {
  constructor() {
    this.backPointer = null;
    PointsBackJS.aliveCount++;
  }
  setBackPointer(superClass) {
    this.backPointer = superClass;
  }
  destroy() {
    PointsBackJS.aliveCount--;
  }
}
PointsBackJS.aliveCount = 0;

class SuperClassJS {
  constructor() {
    this.pointsBack = new PointsBackJS();
    this.pointsBack.setBackPointer(this);
    SuperClassJS.aliveCount++;
  }
  destroy() {
    this.pointsBack.destroy();
    SuperClassJS.aliveCount--;
  }
}
SuperClassJS.aliveCount = 0;

let obj1 = new SuperClassJS();
console.log(SuperClassJS.aliveCount); // 输出 1
console.log(PointsBackJS.aliveCount); // 输出 1

// 当 obj1 不再被引用时，JavaScript 的垃圾回收器最终会回收它
obj1 = null;

// 理论上，经过垃圾回收后，aliveCount 应该变为 0 (无法直接在 JS 中准确预测 GC 的时机)
// 这里的 C++ 测试就是确保 cppgc 能够正确回收类似的 C++ 对象
```

这个 JavaScript 例子展示了对象之间的引用关系，类似于 C++ 代码中的 `SuperClass` 和 `PointsBack`。JavaScript 的垃圾回收器会自动回收不再被引用的对象，这与 `cppgc` 在 C++ 侧的工作原理类似。

**代码逻辑推理与假设输入/输出：**

**例子：`Transition` 测试用例中的一部分**

**假设输入：**
- 执行 `Transition` 测试用例的开始。

**代码逻辑：**
1. 创建 `points_back1` 和 `points_back2` (类型为 `Persistent<PointsBack>`)。`PointsBack::alive_count_` 变为 2。
2. 创建 `super_class` (类型为 `Persistent<SuperClass>`)，它持有 `points_back1` 的引用。`SuperClass::alive_count_` 变为 1。
3. 创建 `sub_class` (类型为 `Persistent<SubClass>`)，它持有 `points_back2` 的引用，并内部创建了一个 `SubData` 对象。 `SuperClass::alive_count_` 变为 2 (因为 `SubClass` 继承自 `SuperClass`)，`SubClass::alive_count_` 变为 1， `SubData::alive_count_` 变为 1。
4. 调用 `PreciseGC()`。由于所有对象都被 `Persistent<>` 持有，所以没有对象会被回收。

**预期输出：**
- `PointsBack::alive_count_` 仍然是 2。
- `SuperClass::alive_count_` 仍然是 2。
- `SubClass::alive_count_` 仍然是 1。
- `SubData::alive_count_` 仍然是 1。

**后续的逻辑推理可以类似地分析 `Release()` 和 `ConservativeGC()` 的效果。**

**用户常见的编程错误举例说明：**

虽然 `cppgc` 旨在简化 C++ 的内存管理，但用户仍然可能犯一些与内存管理相关的错误，即使在使用 `cppgc` 的情况下：

1. **循环引用导致内存泄漏（在没有使用 `WeakMember` 的情况下）：** 如果两个或多个 `cppgc` 管理的对象相互持有强引用，并且没有外部强引用指向这个循环中的任何对象，那么垃圾回收器可能无法回收它们。

   ```c++
   class A : public GarbageCollected<A> {
    public:
     Member<B> b;
     void Trace(Visitor* visitor) const { visitor->Trace(b); }
   };

   class B : public GarbageCollected<B> {
    public:
     Member<A> a;
     void Trace(Visitor* visitor) const { visitor->Trace(a); }
   };

   void Example(AllocationHandle& handle) {
     auto objA = MakeGarbageCollected<A>(handle);
     auto objB = MakeGarbageCollected<B>(handle);
     objA->b = objB;
     objB->a = objA;
     // objA 和 objB 之间形成循环引用，如果没有其他引用指向它们，
     // 即使 Example 函数结束，这两个对象也可能不会被立即回收，
     // 除非垃圾回收器执行了特殊的循环检测机制。
   }
   ```

2. **错误地使用裸指针与 `cppgc` 管理的对象交互：**  直接使用裸指针指向 `cppgc` 管理的对象，而不通过 `Member<>`, `WeakMember<>`, 或 `Persistent<>` 进行管理，可能导致悬挂指针。当 `cppgc` 回收对象时，裸指针会变成无效。

   ```c++
   class MyObject : public GarbageCollected<MyObject> {};

   void Example(AllocationHandle& handle) {
     MyObject* obj = MakeGarbageCollected<MyObject>(handle);
     MyObject* raw_ptr = obj; // 存储裸指针

     // ... 一段时间后，可能触发垃圾回收 ...

     // 如果 obj 被回收，raw_ptr 就变成了悬挂指针
     // 访问 raw_ptr 会导致未定义行为
     // raw_ptr->...
   }
   ```

3. **在析构函数中访问已经被回收的对象：**  如果一个对象持有指向另一个 `cppgc` 管理的对象的 `Member<>`，并且在自己的析构函数中访问该成员，但该成员指向的对象已经被提前回收，则会导致错误。 这通常需要仔细考虑对象的析构顺序。

4. **忘记在 `Trace` 方法中标记对象：** 如果一个 `cppgc` 管理的对象包含指向其他 `cppgc` 管理的对象的指针（使用裸指针或非 `cppgc` 的智能指针），并且没有在 `Trace` 方法中告知垃圾回收器这些引用，那么被引用的对象可能会被错误地回收。

   ```c++
   class Container : public GarbageCollected<Container> {
    public:
     MyObject* ptr; // 错误：应该使用 Member<MyObject>

     void Trace(Visitor* visitor) const {
       // 忘记标记 ptr 指向的对象
     }
   };
   ```

这个单元测试文件通过模拟各种场景来帮助发现和防止这些类型的错误，确保 `cppgc` 能够可靠地管理 V8 引擎的 C++ 对象。

### 提示词
```
这是目录为v8/test/unittests/heap/cppgc/workloads-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/heap/cppgc/workloads-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <iterator>
#include <numeric>

#include "include/cppgc/allocation.h"
#include "include/cppgc/heap-consistency.h"
#include "include/cppgc/persistent.h"
#include "include/cppgc/prefinalizer.h"
#include "src/heap/cppgc/globals.h"
#include "src/heap/cppgc/heap-visitor.h"
#include "src/heap/cppgc/heap.h"
#include "src/heap/cppgc/object-view.h"
#include "test/unittests/heap/cppgc/tests.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace cppgc {
namespace internal {

namespace {

class WorkloadsTest : public testing::TestWithHeap {
 public:
  void ConservativeGC() {
    internal::Heap::From(GetHeap())->CollectGarbage(
        GCConfig::ConservativeAtomicConfig());
  }
  void PreciseGC() {
    internal::Heap::From(GetHeap())->CollectGarbage(
        GCConfig::PreciseAtomicConfig());
  }
};

class SuperClass;

class PointsBack final : public GarbageCollected<PointsBack> {
 public:
  PointsBack() { ++alive_count_; }
  ~PointsBack() { --alive_count_; }

  void SetBackPointer(SuperClass* back_pointer) {
    back_pointer_ = back_pointer;
  }

  SuperClass* BackPointer() const { return back_pointer_; }

  void Trace(Visitor* visitor) const { visitor->Trace(back_pointer_); }

  static int alive_count_;

 private:
  WeakMember<SuperClass> back_pointer_;
};
int PointsBack::alive_count_ = 0;

class SuperClass : public GarbageCollected<SuperClass> {
 public:
  explicit SuperClass(PointsBack* points_back) : points_back_(points_back) {
    points_back_->SetBackPointer(this);
    ++alive_count_;
  }
  virtual ~SuperClass() { --alive_count_; }

  void InvokeConservativeGCAndExpect(WorkloadsTest* test, SuperClass* target,
                                     PointsBack* points_back,
                                     int super_class_count) {
    test->ConservativeGC();
    EXPECT_EQ(points_back, target->GetPointsBack());
    EXPECT_EQ(super_class_count, SuperClass::alive_count_);
  }

  virtual void Trace(Visitor* visitor) const { visitor->Trace(points_back_); }

  PointsBack* GetPointsBack() const { return points_back_.Get(); }

  static int alive_count_;

 private:
  Member<PointsBack> points_back_;
};
int SuperClass::alive_count_ = 0;

class SubData final : public GarbageCollected<SubData> {
 public:
  SubData() { ++alive_count_; }
  ~SubData() { --alive_count_; }

  void Trace(Visitor* visitor) const {}

  static int alive_count_;
};
int SubData::alive_count_ = 0;

class SubClass final : public SuperClass {
 public:
  explicit SubClass(AllocationHandle& allocation_handle,
                    PointsBack* points_back)
      : SuperClass(points_back),
        data_(MakeGarbageCollected<SubData>(allocation_handle)) {
    ++alive_count_;
  }
  ~SubClass() final { --alive_count_; }

  void Trace(Visitor* visitor) const final {
    visitor->Trace(data_);
    SuperClass::Trace(visitor);
  }

  static int alive_count_;

 private:
  Member<SubData> data_;
};
int SubClass::alive_count_ = 0;

}  // namespace

TEST_F(WorkloadsTest, Transition) {
  PointsBack::alive_count_ = 0;
  SuperClass::alive_count_ = 0;
  SubClass::alive_count_ = 0;
  SubData::alive_count_ = 0;

  Persistent<PointsBack> points_back1 =
      MakeGarbageCollected<PointsBack>(GetAllocationHandle());
  Persistent<PointsBack> points_back2 =
      MakeGarbageCollected<PointsBack>(GetAllocationHandle());
  Persistent<SuperClass> super_class =
      MakeGarbageCollected<SuperClass>(GetAllocationHandle(), points_back1);
  Persistent<SubClass> sub_class = MakeGarbageCollected<SubClass>(
      GetAllocationHandle(), GetAllocationHandle(), points_back2);
  EXPECT_EQ(2, PointsBack::alive_count_);
  EXPECT_EQ(2, SuperClass::alive_count_);
  EXPECT_EQ(1, SubClass::alive_count_);
  EXPECT_EQ(1, SubData::alive_count_);

  PreciseGC();
  EXPECT_EQ(2, PointsBack::alive_count_);
  EXPECT_EQ(2, SuperClass::alive_count_);
  EXPECT_EQ(1, SubClass::alive_count_);
  EXPECT_EQ(1, SubData::alive_count_);

  super_class->InvokeConservativeGCAndExpect(this, super_class.Release(),
                                             points_back1.Get(), 2);
  PreciseGC();
  EXPECT_EQ(2, PointsBack::alive_count_);
  EXPECT_EQ(1, SuperClass::alive_count_);
  EXPECT_EQ(1, SubClass::alive_count_);
  EXPECT_EQ(1, SubData::alive_count_);
  EXPECT_EQ(nullptr, points_back1->BackPointer());

  points_back1.Release();
  PreciseGC();
  EXPECT_EQ(1, PointsBack::alive_count_);
  EXPECT_EQ(1, SuperClass::alive_count_);
  EXPECT_EQ(1, SubClass::alive_count_);
  EXPECT_EQ(1, SubData::alive_count_);

  sub_class->InvokeConservativeGCAndExpect(this, sub_class.Release(),
                                           points_back2.Get(), 1);
  PreciseGC();
  EXPECT_EQ(1, PointsBack::alive_count_);
  EXPECT_EQ(0, SuperClass::alive_count_);
  EXPECT_EQ(0, SubClass::alive_count_);
  EXPECT_EQ(0, SubData::alive_count_);
  EXPECT_EQ(nullptr, points_back2->BackPointer());

  points_back2.Release();
  PreciseGC();
  EXPECT_EQ(0, PointsBack::alive_count_);
  EXPECT_EQ(0, SuperClass::alive_count_);
  EXPECT_EQ(0, SubClass::alive_count_);
  EXPECT_EQ(0, SubData::alive_count_);

  EXPECT_EQ(super_class, sub_class);
}

namespace {

class DynamicallySizedObject final
    : public GarbageCollected<DynamicallySizedObject> {
 public:
  static DynamicallySizedObject* Create(AllocationHandle& allocation_handle,
                                        size_t size) {
    CHECK_GT(size, sizeof(DynamicallySizedObject));
    return MakeGarbageCollected<DynamicallySizedObject>(
        allocation_handle,
        AdditionalBytes(size - sizeof(DynamicallySizedObject)));
  }

  uint8_t Get(int i) { return *(reinterpret_cast<uint8_t*>(this) + i); }

  void Trace(Visitor* visitor) const {}
};

class ObjectSizeCounter final : private HeapVisitor<ObjectSizeCounter> {
  friend class HeapVisitor<ObjectSizeCounter>;

 public:
  size_t GetSize(RawHeap& heap) {
    Traverse(heap);
    return accumulated_size_;
  }

 private:
  static size_t ObjectSize(const HeapObjectHeader& header) {
    return ObjectView<>(header).Size();
  }

  bool VisitHeapObjectHeader(HeapObjectHeader& header) {
    if (header.IsFree()) return true;
    accumulated_size_ += ObjectSize(header);
    return true;
  }

  size_t accumulated_size_ = 0;
};

}  // namespace

TEST_F(WorkloadsTest, BasicFunctionality) {
  static_assert(kAllocationGranularity % 4 == 0,
                "Allocation granularity is expected to be a multiple of 4");
  Heap* heap = internal::Heap::From(GetHeap());
  size_t initial_object_payload_size =
      ObjectSizeCounter().GetSize(heap->raw_heap());
  {
    // When the test starts there may already have been leaked some memory
    // on the heap, so we establish a base line.
    size_t base_level = initial_object_payload_size;
    bool test_pages_allocated = !base_level;
    if (test_pages_allocated) {
      EXPECT_EQ(0ul, heap->stats_collector()->allocated_memory_size());
    }

    // This allocates objects on the general heap which should add a page of
    // memory.
    DynamicallySizedObject* alloc32 =
        DynamicallySizedObject::Create(GetAllocationHandle(), 32);
    memset(alloc32, 40, 32);
    DynamicallySizedObject* alloc64 =
        DynamicallySizedObject::Create(GetAllocationHandle(), 64);
    memset(alloc64, 27, 64);

    size_t total = 96;

    EXPECT_EQ(base_level + total,
              ObjectSizeCounter().GetSize(heap->raw_heap()));
    if (test_pages_allocated) {
      EXPECT_EQ(kPageSize * 2,
                heap->stats_collector()->allocated_memory_size());
    }

    EXPECT_EQ(alloc32->Get(0), 40);
    EXPECT_EQ(alloc32->Get(31), 40);
    EXPECT_EQ(alloc64->Get(0), 27);
    EXPECT_EQ(alloc64->Get(63), 27);

    ConservativeGC();

    EXPECT_EQ(alloc32->Get(0), 40);
    EXPECT_EQ(alloc32->Get(31), 40);
    EXPECT_EQ(alloc64->Get(0), 27);
    EXPECT_EQ(alloc64->Get(63), 27);
  }

  PreciseGC();
  size_t total = 0;
  size_t base_level = ObjectSizeCounter().GetSize(heap->raw_heap());
  bool test_pages_allocated = !base_level;
  if (test_pages_allocated) {
    EXPECT_EQ(0ul, heap->stats_collector()->allocated_memory_size());
  }

  size_t big = 1008;
  Persistent<DynamicallySizedObject> big_area =
      DynamicallySizedObject::Create(GetAllocationHandle(), big);
  total += big;

  size_t persistent_count = 0;
  const size_t kNumPersistents = 100000;
  Persistent<DynamicallySizedObject>* persistents[kNumPersistents];

  for (int i = 0; i < 1000; i++) {
    size_t size = 128 + i * 8;
    total += size;
    persistents[persistent_count++] = new Persistent<DynamicallySizedObject>(
        DynamicallySizedObject::Create(GetAllocationHandle(), size));
    // The allocations in the loop may trigger GC with lazy sweeping.
    heap->sweeper().FinishIfRunning();
    EXPECT_EQ(base_level + total,
              ObjectSizeCounter().GetSize(heap->raw_heap()));
    if (test_pages_allocated) {
      EXPECT_EQ(0ul, heap->stats_collector()->allocated_memory_size() &
                         (kPageSize - 1));
    }
  }

  {
    DynamicallySizedObject* alloc32b(
        DynamicallySizedObject::Create(GetAllocationHandle(), 32));
    memset(alloc32b, 40, 32);
    DynamicallySizedObject* alloc64b(
        DynamicallySizedObject::Create(GetAllocationHandle(), 64));
    memset(alloc64b, 27, 64);
    EXPECT_TRUE(alloc32b != alloc64b);

    total += 96;
    EXPECT_EQ(base_level + total,
              ObjectSizeCounter().GetSize(heap->raw_heap()));
    if (test_pages_allocated) {
      EXPECT_EQ(0ul, heap->stats_collector()->allocated_memory_size() &
                         (kPageSize - 1));
    }
  }

  PreciseGC();
  total -= 96;
  if (test_pages_allocated) {
    EXPECT_EQ(0ul, heap->stats_collector()->allocated_memory_size() &
                       (kPageSize - 1));
  }

  // Clear the persistent, so that the big area will be garbage collected.
  big_area.Release();
  PreciseGC();

  total -= big;
  EXPECT_EQ(base_level + total, ObjectSizeCounter().GetSize(heap->raw_heap()));
  if (test_pages_allocated) {
    EXPECT_EQ(0ul, heap->stats_collector()->allocated_memory_size() &
                       (kPageSize - 1));
  }

  EXPECT_EQ(base_level + total, ObjectSizeCounter().GetSize(heap->raw_heap()));
  if (test_pages_allocated) {
    EXPECT_EQ(0ul, heap->stats_collector()->allocated_memory_size() &
                       (kPageSize - 1));
  }

  for (size_t i = 0; i < persistent_count; i++) {
    delete persistents[i];
    persistents[i] = nullptr;
  }
}

}  // namespace internal
}  // namespace cppgc
```