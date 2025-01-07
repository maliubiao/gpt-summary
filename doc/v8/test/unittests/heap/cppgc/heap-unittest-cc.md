Response:
My thinking process to analyze the C++ unittest code and fulfill the prompt's requirements goes like this:

1. **Understand the Goal:** The request asks for an explanation of the provided C++ code's functionality, specifically focusing on a V8 heap unittest file. It also asks for specific contextual information related to Torque, JavaScript, logic, and common errors.

2. **Initial Code Scan (Keywords and Structure):** I'll first scan the code for keywords and structural elements to get a high-level understanding:
    * `#include`:  Indicates this is C++ code. The included headers (`cppgc/heap.h`, `cppgc/allocation.h`, `gtest/gtest.h`) point to it being a C++ garbage collection (cppgc) test using Google Test.
    * `namespace cppgc::internal`:  Confirms it's related to cppgc's internal implementation.
    * `class GCHeapTest : public testing::TestWithHeap`: This is the core test fixture. `TestWithHeap` likely sets up a cppgc heap for testing.
    * `TEST_F(GCHeapTest, ...)`:  These are individual test cases within the `GCHeapTest` fixture.
    * Class definitions like `Foo`, `GCed`, `GCedWithFinalizer`, `LargeObjectGCDuringCtor`, `Cloner`: These represent objects that will be managed by the garbage collector. Their methods (`Trace`, destructor) and static members are important for the tests.
    * Calls to `MakeGarbageCollected`, `PreciseGC`, `ConservativeGC`, `Terminate`: These are key functions for interacting with the cppgc heap.
    * Assertions like `EXPECT_EQ`, `EXPECT_LE`, `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_DEATH_IF_SUPPORTED`:  These are Google Test macros used to verify the behavior of the code under test.

3. **Analyze Individual Test Cases (Functionality):**  I'll go through each `TEST_F` and deduce its purpose:

    * **`PreciseGCReclaimsObjectOnStack`**: Tests if a precise garbage collection reclaims an object that's only referenced on the stack.
    * **`ConservativeGCRetainsObjectOnStack`**: Tests if a conservative garbage collection *retains* an object on the stack. This highlights the difference between precise and conservative GC.
    * **`ConservativeGCFromLargeObjectCtorFindsObject`**: Checks if a conservative GC triggered during the constructor of a large object correctly handles nested object creation.
    * **`ObjectPayloadSize`**: Examines the reported size of allocated objects after allocations and garbage collection.
    * **`AllocateWithAdditionalBytes`**:  Verifies that allocating objects with extra bytes works correctly.
    * **`AllocatedSizeDependOnAdditionalBytes`**: Checks if the allocated size reflects the additional bytes requested.
    * **`Epoch`**: Tests if the heap's epoch counter increments after a garbage collection.
    * **`NoGarbageCollectionScope`**:  Confirms that garbage collection is skipped within a `NoGarbageCollectionScope`.
    * **`IsGarbageCollectionAllowed`**:  Checks the `IsGarbageCollectionAllowed` flag within and outside a `DisallowGarbageCollectionScope`.
    * **`IsMarking`**, **`IsSweeping`**, **`IsSweepingOnOwningThread`**:  Test the flags indicating the current phase of garbage collection.
    * **`IsInAtomicPause`**: Checks if the `IsInAtomicPause` flag is set during specific GC phases.
    * **`TerminateEmptyHeap`**, **`TerminateClearsPersistent`**, **`TerminateInvokesDestructor`**: Verify the behavior of the `Terminate` function.
    * **`TerminateReclaimsNewState`**: Tests if `Terminate` correctly handles objects created during destruction (related to persistent handles).
    * **`TerminateProhibitsAllocation`**: Checks that allocation is disallowed after termination.
    * **`LargeChainOfNewStatesPersistent`**, **`LargeChainOfNewStatesCrossThreadPersistent`**: Test the termination behavior when destructors create new persistent objects, expecting a death test.

4. **Address Specific Requirements:**

    * **`.tq` extension:** I know `.tq` files are for Torque, V8's internal type definition and code generation language. The code is `.cc`, so it's standard C++. I'll explicitly state this.
    * **JavaScript Relevance:** The tests are about cppgc, V8's C++ garbage collector. While the *purpose* is to manage memory for V8, there's no direct, runnable JavaScript equivalent for these specific *tests*. However, I can explain the *concept* of garbage collection in JavaScript and how cppgc supports it. I'll give a simple JS example of object creation and rely on the built-in GC.
    * **Logic and Assumptions:** For tests with clear logic (like epoch incrementing), I'll explicitly state the assumptions and the expected input/output. For example, before GC, epoch is X; after GC, epoch is X+1.
    * **Common Programming Errors:** I'll think about common errors related to manual memory management that garbage collection aims to prevent, like dangling pointers, memory leaks, and double frees. I'll provide simple C++ examples demonstrating these, highlighting how cppgc helps avoid them.

5. **Structure and Refine:**  I'll organize the information logically, starting with a general overview, then detailing the functionality of each test case. I'll then address the specific requirements in separate sections. I'll use clear and concise language. I'll double-check that I haven't missed any important aspects of the code or the prompt.

6. **Self-Correction/Improvements:**  Initially, I might focus too much on the low-level C++ details. I'll need to step back and ensure the explanation is accessible and answers the user's implied question: "What does this test *do* and why is it important in the context of V8?". I'll also ensure I clearly distinguish between what the C++ code *tests* and the broader concepts of garbage collection and JavaScript memory management. I will also make sure to explicitly mention that the provided code is a *unit test* and not the actual implementation of the garbage collector.

By following these steps, I can systematically analyze the code and generate a comprehensive and informative response that addresses all aspects of the prompt.
这个文件 `v8/test/unittests/heap/cppgc/heap-unittest.cc` 是 V8 JavaScript 引擎中 cppgc (C++ garbage collector) 的单元测试文件。它使用 Google Test 框架来测试 `cppgc::Heap` 类的各种功能和特性。

**功能列表:**

这个文件主要测试了以下 `cppgc::Heap` 的功能：

1. **精确垃圾回收 (Precise GC):**
   - 测试精确 GC 能否回收栈上的对象。
   - 验证精确 GC 多次执行的效果。

2. **保守垃圾回收 (Conservative GC):**
   - 测试保守 GC 能否保留栈上的对象。
   - 演示保守 GC 和精确 GC 的区别。
   - 测试在大型对象的构造函数中执行保守 GC 的场景。

3. **对象内存占用 (Object Payload Size):**
   - 测试 `Heap::ObjectPayloadSize()` 方法，该方法返回堆上所有对象的有效负载大小。
   - 验证在分配和垃圾回收后该值的变化。

4. **额外字节分配 (Allocate With Additional Bytes):**
   - 测试使用 `AdditionalBytes()` 选项分配对象时，分配的内存大小是否正确。
   - 验证分配的实际大小是否大于请求的基础大小加上额外字节。

5. **分配大小依赖于额外字节 (Allocated Size Depend On Additional Bytes):**
   - 验证使用不同额外字节数分配的对象，其分配的大小是否不同。

6. **垃圾回收周期 (Epoch):**
   - 测试每次垃圾回收后，堆的 epoch 计数器是否会递增。

7. **禁用垃圾回收 (NoGarbageCollectionScope):**
   - 测试在 `NoGarbageCollectionScope` 作用域内，垃圾回收是否会被阻止。

8. **是否允许垃圾回收 (IsGarbageCollectionAllowed):**
   - 测试 `DisallowGarbageCollectionScope` 能否正确地禁止垃圾回收。

9. **标记阶段检测 (IsMarking):**
   - 测试 `HeapState::IsMarking()` 方法，用于检查堆是否处于标记阶段。

10. **清理阶段检测 (IsSweeping):**
    - 测试 `HeapState::IsSweeping()` 方法，用于检查堆是否处于清理阶段。

11. **在拥有线程上清理的检测 (IsSweepingOnOwningThread):**
    - 测试 `HeapState::IsSweepingOnOwningThread()` 方法，用于检查清理是否在拥有该堆的线程上进行。

12. **原子暂停阶段检测 (IsInAtomicPause):**
    - 测试 `HeapState::IsInAtomicPause()` 方法，用于检查堆是否处于原子暂停阶段。

13. **终止堆 (Terminate Heap):**
    - 测试终止一个空堆。
    - 测试终止堆后，持久句柄 (Persistent) 是否会被清除。
    - 测试终止堆后，对象的析构函数是否会被调用。
    - 测试终止堆后，是否会回收新分配的对象。
    - 测试终止堆后是否禁止分配新对象。
    - 测试在析构函数中创建大量新对象的情况下终止堆的行为（预期会触发断言）。

**关于文件后缀 `.tq`：**

`v8/test/unittests/heap/cppgc/heap-unittest.cc` 的后缀是 `.cc`，这表明它是一个标准的 C++ 源文件。如果文件以 `.tq` 结尾，那么它才是一个 V8 Torque 源代码文件。 Torque 是一种用于定义 V8 内部运行时代码的领域特定语言。

**与 JavaScript 的关系：**

这个测试文件直接测试的是 V8 引擎的 C++ 垃圾回收器 cppgc 的功能，而 cppgc 是 JavaScript 内存管理的基础。虽然这个文件本身不是 JavaScript 代码，但它验证了 V8 如何正确地回收不再使用的 JavaScript 对象。

**JavaScript 举例说明：**

```javascript
// 这是一个简单的 JavaScript 例子，展示了垃圾回收的基本概念

let myObject = { data: "一些数据" };

// myObject 被使用

myObject = null; // 此时，之前 myObject 指向的对象变得不可达，
                 // cppgc 会在适当的时候回收这块内存。

function createAndReleaseObject() {
  let tempObject = { largeData: new Array(100000).fill(0) };
  // tempObject 在函数结束时超出作用域，变得不可达，
  // cppgc 会回收其占用的内存。
}

createAndReleaseObject();
```

在这个 JavaScript 例子中，当 `myObject` 被赋值为 `null` 或当 `tempObject` 超出其作用域时，之前这些变量引用的对象就不再被需要了。 V8 的 cppgc 负责检测这些不可达的对象，并回收它们占用的内存，防止内存泄漏。  `heap-unittest.cc` 中的测试正是为了确保 cppgc 能够正确地执行这些回收操作。

**代码逻辑推理 (假设输入与输出):**

以 `TEST_F(GCHeapTest, PreciseGCReclaimsObjectOnStack)` 为例：

**假设输入:**
- 在栈上创建一个 `Foo` 类型的对象，并将其地址赋值给 `do_not_access` 变量。
- 此时 `Foo::destructor_callcount` 为 0。

**代码逻辑:**
1. 调用 `PreciseGC()` 执行一次精确垃圾回收。
2. 再次调用 `PreciseGC()` 执行第二次精确垃圾回收。

**预期输出:**
- 第一次 `PreciseGC()` 后，由于 `do_not_access` 是栈上的唯一引用，且 GC 是精确的，该对象会被回收，`Foo` 的析构函数会被调用一次，因此 `Foo::destructor_callcount` 变为 1。
- 第二次 `PreciseGC()` 后，由于对象已经被回收，不会再次调用析构函数，`Foo::destructor_callcount` 仍然是 1。

**涉及用户常见的编程错误：**

虽然 cppgc 负责自动内存管理，减少了手动内存管理带来的错误，但了解 cppgc 的行为有助于避免一些与对象生命周期相关的潜在问题。

1. **意外的对象提前回收：**
   - **错误示例 (C++ 手动内存管理的概念，cppgc 可以避免)：**
     ```c++
     Foo* foo = new Foo();
     // ... 使用 foo
     delete foo;
     // 之后如果再次访问 foo，就会导致悬挂指针错误。
     // foo->SomeMethod(); // 错误！
     ```
   - cppgc 通过跟踪对象的引用来管理生命周期。只要对象是可达的，就不会被回收。`heap-unittest.cc` 中的测试确保了在有引用的情况下，对象不会被过早回收。

2. **内存泄漏 (在某些特殊情况下可能发生，但 cppgc 大大减少了可能性)：**
   - **错误场景 (虽然 cppgc 会处理大多数情况，但理解概念很重要)：** 如果存在循环引用，且外部没有强引用指向这个循环引用中的对象，理论上可能会发生内存泄漏。 但 cppgc 具有标记-清除等机制来处理这种情况。
   - `heap-unittest.cc` 中关于 `Persistent` 的测试，特别是 `TerminateReclaimsNewState` 和 `LargeChainOfNewStatesPersistent`，涉及到对象生命周期和回收，可以帮助理解如何避免与持久句柄相关的泄漏问题。

3. **在对象析构后访问其成员：**
   - **错误示例 (类似于悬挂指针)：**
     ```c++
     Foo* foo = MakeGarbageCollected<Foo>(GetAllocationHandle());
     cppgc::WeakPersistent<Foo> weak_foo = foo;
     PreciseGC(); // 可能回收 foo
     if (weak_foo.Get()) {
       // weak_foo.Get() 返回 nullptr，所以这里不会执行，避免了错误
       // weak_foo.Get()->SomeMethod(); // 如果不检查，可能会导致错误
     }
     ```
   - `heap-unittest.cc` 中关于垃圾回收后对象状态的测试，例如 `PreciseGCReclaimsObjectOnStack`，验证了对象在被回收后确实不再有效。

总而言之，`v8/test/unittests/heap/cppgc/heap-unittest.cc` 是一个关键的测试文件，它确保了 V8 的 C++ 垃圾回收器 cppgc 能够按照预期工作，从而保证 JavaScript 程序的内存管理是安全和高效的。

Prompt: 
```
这是目录为v8/test/unittests/heap/cppgc/heap-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/heap/cppgc/heap-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2020 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/heap/cppgc/heap.h"

#include <algorithm>
#include <iterator>
#include <numeric>

#include "include/cppgc/allocation.h"
#include "include/cppgc/cross-thread-persistent.h"
#include "include/cppgc/heap-consistency.h"
#include "include/cppgc/heap-state.h"
#include "include/cppgc/persistent.h"
#include "include/cppgc/prefinalizer.h"
#include "src/heap/cppgc/globals.h"
#include "test/unittests/heap/cppgc/tests.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace cppgc {
namespace internal {

namespace {

class GCHeapTest : public testing::TestWithHeap {
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

class GCHeapDeathTest : public GCHeapTest {};

class Foo : public GarbageCollected<Foo> {
 public:
  static size_t destructor_callcount;

  Foo() { destructor_callcount = 0; }
  ~Foo() { destructor_callcount++; }

  void Trace(cppgc::Visitor*) const {}
};

size_t Foo::destructor_callcount;

template <size_t Size>
class GCed : public GarbageCollected<GCed<Size>> {
 public:
  void Trace(cppgc::Visitor*) const {}
  char buf[Size];
};

}  // namespace

TEST_F(GCHeapTest, PreciseGCReclaimsObjectOnStack) {
  Foo* volatile do_not_access =
      MakeGarbageCollected<Foo>(GetAllocationHandle());
  USE(do_not_access);
  EXPECT_EQ(0u, Foo::destructor_callcount);
  PreciseGC();
  EXPECT_EQ(1u, Foo::destructor_callcount);
  PreciseGC();
  EXPECT_EQ(1u, Foo::destructor_callcount);
}

namespace {

const void* ConservativeGCReturningObject(cppgc::Heap* heap,
                                          const void* object) {
  internal::Heap::From(heap)->CollectGarbage(
      GCConfig::ConservativeAtomicConfig());
  return object;
}

}  // namespace

TEST_F(GCHeapTest, ConservativeGCRetainsObjectOnStack) {
  Foo* volatile object = MakeGarbageCollected<Foo>(GetAllocationHandle());
  EXPECT_EQ(0u, Foo::destructor_callcount);
  EXPECT_EQ(object, ConservativeGCReturningObject(GetHeap(), object));
  EXPECT_EQ(0u, Foo::destructor_callcount);
  PreciseGC();
  EXPECT_EQ(1u, Foo::destructor_callcount);
  PreciseGC();
  EXPECT_EQ(1u, Foo::destructor_callcount);
}

namespace {

class GCedWithFinalizer final : public GarbageCollected<GCedWithFinalizer> {
 public:
  static size_t destructor_counter;

  GCedWithFinalizer() { destructor_counter = 0; }
  ~GCedWithFinalizer() { destructor_counter++; }
  void Trace(Visitor* visitor) const {}
};
// static
size_t GCedWithFinalizer::destructor_counter = 0;

class LargeObjectGCDuringCtor final
    : public GarbageCollected<LargeObjectGCDuringCtor> {
 public:
  static constexpr size_t kDataSize = kLargeObjectSizeThreshold + 1;

  explicit LargeObjectGCDuringCtor(cppgc::Heap* heap)
      : child_(MakeGarbageCollected<GCedWithFinalizer>(
            heap->GetAllocationHandle())) {
    internal::Heap::From(heap)->CollectGarbage(
        GCConfig::ConservativeAtomicConfig());
  }

  void Trace(Visitor* visitor) const { visitor->Trace(child_); }

  char data[kDataSize];
  Member<GCedWithFinalizer> child_;
};

}  // namespace

TEST_F(GCHeapTest, ConservativeGCFromLargeObjectCtorFindsObject) {
  GCedWithFinalizer::destructor_counter = 0;
  MakeGarbageCollected<LargeObjectGCDuringCtor>(GetAllocationHandle(),
                                                GetHeap());
  EXPECT_EQ(0u, GCedWithFinalizer::destructor_counter);
}

TEST_F(GCHeapTest, ObjectPayloadSize) {
  static constexpr size_t kNumberOfObjectsPerArena = 16;
  static constexpr size_t kObjectSizes[] = {1, 32, 64, 128,
                                            2 * kLargeObjectSizeThreshold};

  EXPECT_EQ(0u, Heap::From(GetHeap())->ObjectPayloadSize());

  {
    subtle::NoGarbageCollectionScope no_gc(*Heap::From(GetHeap()));

    for (size_t k = 0; k < kNumberOfObjectsPerArena; ++k) {
      MakeGarbageCollected<GCed<kObjectSizes[0]>>(GetAllocationHandle());
      MakeGarbageCollected<GCed<kObjectSizes[1]>>(GetAllocationHandle());
      MakeGarbageCollected<GCed<kObjectSizes[2]>>(GetAllocationHandle());
      MakeGarbageCollected<GCed<kObjectSizes[3]>>(GetAllocationHandle());
      MakeGarbageCollected<GCed<kObjectSizes[4]>>(GetAllocationHandle());
    }

    size_t aligned_object_sizes[arraysize(kObjectSizes)];
    std::transform(std::cbegin(kObjectSizes), std::cend(kObjectSizes),
                   std::begin(aligned_object_sizes), [](size_t size) {
                     return RoundUp(size, kAllocationGranularity);
                   });
    const size_t expected_size = std::accumulate(
        std::cbegin(aligned_object_sizes), std::cend(aligned_object_sizes), 0u,
        [](size_t acc, size_t size) {
          return acc + kNumberOfObjectsPerArena * size;
        });
    // TODO(chromium:1056170): Change to EXPECT_EQ when proper sweeping is
    // implemented.
    EXPECT_LE(expected_size, Heap::From(GetHeap())->ObjectPayloadSize());
  }

  PreciseGC();
  EXPECT_EQ(0u, Heap::From(GetHeap())->ObjectPayloadSize());
}

TEST_F(GCHeapTest, AllocateWithAdditionalBytes) {
  static constexpr size_t kBaseSize = sizeof(HeapObjectHeader) + sizeof(Foo);
  static constexpr size_t kAdditionalBytes = 10u * kAllocationGranularity;
  {
    Foo* object = MakeGarbageCollected<Foo>(GetAllocationHandle());
    EXPECT_LE(kBaseSize, HeapObjectHeader::FromObject(object).AllocatedSize());
  }
  {
    Foo* object = MakeGarbageCollected<Foo>(GetAllocationHandle(),
                                            AdditionalBytes(kAdditionalBytes));
    EXPECT_LE(kBaseSize + kAdditionalBytes,
              HeapObjectHeader::FromObject(object).AllocatedSize());
  }
  {
    Foo* object = MakeGarbageCollected<Foo>(
        GetAllocationHandle(),
        AdditionalBytes(kAdditionalBytes * kAdditionalBytes));
    EXPECT_LE(kBaseSize + kAdditionalBytes * kAdditionalBytes,
              HeapObjectHeader::FromObject(object).AllocatedSize());
  }
}

TEST_F(GCHeapTest, AllocatedSizeDependOnAdditionalBytes) {
  static constexpr size_t kAdditionalBytes = 10u * kAllocationGranularity;
  Foo* object = MakeGarbageCollected<Foo>(GetAllocationHandle());
  Foo* object_with_bytes = MakeGarbageCollected<Foo>(
      GetAllocationHandle(), AdditionalBytes(kAdditionalBytes));
  Foo* object_with_more_bytes = MakeGarbageCollected<Foo>(
      GetAllocationHandle(),
      AdditionalBytes(kAdditionalBytes * kAdditionalBytes));
  EXPECT_LT(HeapObjectHeader::FromObject(object).AllocatedSize(),
            HeapObjectHeader::FromObject(object_with_bytes).AllocatedSize());
  EXPECT_LT(
      HeapObjectHeader::FromObject(object_with_bytes).AllocatedSize(),
      HeapObjectHeader::FromObject(object_with_more_bytes).AllocatedSize());
}

TEST_F(GCHeapTest, Epoch) {
  const size_t epoch_before = internal::Heap::From(GetHeap())->epoch();
  PreciseGC();
  const size_t epoch_after_gc = internal::Heap::From(GetHeap())->epoch();
  EXPECT_EQ(epoch_after_gc, epoch_before + 1);
}

TEST_F(GCHeapTest, NoGarbageCollectionScope) {
  const size_t epoch_before = internal::Heap::From(GetHeap())->epoch();
  {
    subtle::NoGarbageCollectionScope scope(GetHeap()->GetHeapHandle());
    PreciseGC();
  }
  const size_t epoch_after_gc = internal::Heap::From(GetHeap())->epoch();
  EXPECT_EQ(epoch_after_gc, epoch_before);
}

TEST_F(GCHeapTest, IsGarbageCollectionAllowed) {
  EXPECT_TRUE(
      subtle::DisallowGarbageCollectionScope::IsGarbageCollectionAllowed(
          GetHeap()->GetHeapHandle()));
  {
    subtle::DisallowGarbageCollectionScope disallow_gc(*Heap::From(GetHeap()));
    EXPECT_FALSE(
        subtle::DisallowGarbageCollectionScope::IsGarbageCollectionAllowed(
            GetHeap()->GetHeapHandle()));
  }
}

TEST_F(GCHeapTest, IsMarking) {
  GCConfig config =
      GCConfig::PreciseIncrementalMarkingConcurrentSweepingConfig();
  auto* heap = Heap::From(GetHeap());
  EXPECT_FALSE(subtle::HeapState::IsMarking(*heap));
  heap->StartIncrementalGarbageCollection(config);
  EXPECT_TRUE(subtle::HeapState::IsMarking(*heap));
  heap->FinalizeIncrementalGarbageCollectionIfRunning(config);
  EXPECT_FALSE(subtle::HeapState::IsMarking(*heap));
  heap->AsBase().sweeper().FinishIfRunning();
  EXPECT_FALSE(subtle::HeapState::IsMarking(*heap));
}

TEST_F(GCHeapTest, IsSweeping) {
  GCConfig config =
      GCConfig::PreciseIncrementalMarkingConcurrentSweepingConfig();
  auto* heap = Heap::From(GetHeap());
  EXPECT_FALSE(subtle::HeapState::IsSweeping(*heap));
  heap->StartIncrementalGarbageCollection(config);
  EXPECT_FALSE(subtle::HeapState::IsSweeping(*heap));
  heap->FinalizeIncrementalGarbageCollectionIfRunning(config);
  EXPECT_TRUE(subtle::HeapState::IsSweeping(*heap));
  heap->AsBase().sweeper().FinishIfRunning();
  EXPECT_FALSE(subtle::HeapState::IsSweeping(*heap));
}

namespace {

class GCedExpectSweepingOnOwningThread final
    : public GarbageCollected<GCedExpectSweepingOnOwningThread> {
 public:
  explicit GCedExpectSweepingOnOwningThread(const HeapHandle& heap_handle)
      : heap_handle_(heap_handle) {}
  ~GCedExpectSweepingOnOwningThread() {
    EXPECT_TRUE(subtle::HeapState::IsSweepingOnOwningThread(heap_handle_));
  }

  void Trace(Visitor*) const {}

 private:
  const HeapHandle& heap_handle_;
};

}  // namespace

TEST_F(GCHeapTest, IsSweepingOnOwningThread) {
  GCConfig config =
      GCConfig::PreciseIncrementalMarkingConcurrentSweepingConfig();
  auto* heap = Heap::From(GetHeap());
  MakeGarbageCollected<GCedExpectSweepingOnOwningThread>(
      heap->GetAllocationHandle(), *heap);
  EXPECT_FALSE(subtle::HeapState::IsSweepingOnOwningThread(*heap));
  heap->StartIncrementalGarbageCollection(config);
  EXPECT_FALSE(subtle::HeapState::IsSweepingOnOwningThread(*heap));
  heap->FinalizeIncrementalGarbageCollectionIfRunning(config);
  EXPECT_FALSE(subtle::HeapState::IsSweepingOnOwningThread(*heap));
  heap->AsBase().sweeper().FinishIfRunning();
  EXPECT_FALSE(subtle::HeapState::IsSweepingOnOwningThread(*heap));
}

namespace {

class ExpectAtomicPause final : public GarbageCollected<ExpectAtomicPause> {
  CPPGC_USING_PRE_FINALIZER(ExpectAtomicPause, PreFinalizer);

 public:
  explicit ExpectAtomicPause(HeapHandle& handle) : handle_(handle) {}
  ~ExpectAtomicPause() {
    EXPECT_TRUE(subtle::HeapState::IsInAtomicPause(handle_));
  }
  void PreFinalizer() {
    EXPECT_TRUE(subtle::HeapState::IsInAtomicPause(handle_));
  }
  void Trace(Visitor*) const {}

 private:
  HeapHandle& handle_;
};

}  // namespace

TEST_F(GCHeapTest, IsInAtomicPause) {
  GCConfig config = GCConfig::PreciseIncrementalConfig();
  auto* heap = Heap::From(GetHeap());
  MakeGarbageCollected<ExpectAtomicPause>(heap->object_allocator(), *heap);
  EXPECT_FALSE(subtle::HeapState::IsInAtomicPause(*heap));
  heap->StartIncrementalGarbageCollection(config);
  EXPECT_FALSE(subtle::HeapState::IsInAtomicPause(*heap));
  heap->FinalizeIncrementalGarbageCollectionIfRunning(config);
  EXPECT_FALSE(subtle::HeapState::IsInAtomicPause(*heap));
  heap->AsBase().sweeper().FinishIfRunning();
  EXPECT_FALSE(subtle::HeapState::IsInAtomicPause(*heap));
}

TEST_F(GCHeapTest, TerminateEmptyHeap) { Heap::From(GetHeap())->Terminate(); }

TEST_F(GCHeapTest, TerminateClearsPersistent) {
  Persistent<Foo> foo = MakeGarbageCollected<Foo>(GetAllocationHandle());
  EXPECT_TRUE(foo.Get());
  Heap::From(GetHeap())->Terminate();
  EXPECT_FALSE(foo.Get());
}

TEST_F(GCHeapTest, TerminateInvokesDestructor) {
  Persistent<Foo> foo = MakeGarbageCollected<Foo>(GetAllocationHandle());
  EXPECT_EQ(0u, Foo::destructor_callcount);
  Heap::From(GetHeap())->Terminate();
  EXPECT_EQ(1u, Foo::destructor_callcount);
}

namespace {

template <template <typename> class PersistentType>
class Cloner final : public GarbageCollected<Cloner<PersistentType>> {
 public:
  static size_t destructor_count;

  Cloner(cppgc::AllocationHandle& handle, size_t count)
      : handle_(handle), count_(count) {}

  ~Cloner() {
    EXPECT_FALSE(new_instance_);
    destructor_count++;
    if (count_) {
      new_instance_ =
          MakeGarbageCollected<Cloner>(handle_, handle_, count_ - 1);
    }
  }

  void Trace(Visitor*) const {}

 private:
  static PersistentType<Cloner> new_instance_;

  cppgc::AllocationHandle& handle_;
  size_t count_;
};

// static
template <template <typename> class PersistentType>
PersistentType<Cloner<PersistentType>> Cloner<PersistentType>::new_instance_;
// static
template <template <typename> class PersistentType>
size_t Cloner<PersistentType>::destructor_count;

}  // namespace

template <template <typename> class PersistentType>
void TerminateReclaimsNewState(std::shared_ptr<Platform> platform) {
  auto heap = cppgc::Heap::Create(platform);
  using ClonerImpl = Cloner<PersistentType>;
  Persistent<ClonerImpl> cloner = MakeGarbageCollected<ClonerImpl>(
      heap->GetAllocationHandle(), heap->GetAllocationHandle(), 1);
  ClonerImpl::destructor_count = 0;
  EXPECT_TRUE(cloner.Get());
  Heap::From(heap.get())->Terminate();
  EXPECT_FALSE(cloner.Get());
  EXPECT_EQ(2u, ClonerImpl::destructor_count);
}

TEST_F(GCHeapTest, TerminateReclaimsNewState) {
  TerminateReclaimsNewState<Persistent>(GetPlatformHandle());
  TerminateReclaimsNewState<WeakPersistent>(GetPlatformHandle());
  TerminateReclaimsNewState<cppgc::subtle::CrossThreadPersistent>(
      GetPlatformHandle());
  TerminateReclaimsNewState<cppgc::subtle::WeakCrossThreadPersistent>(
      GetPlatformHandle());
}

TEST_F(GCHeapDeathTest, TerminateProhibitsAllocation) {
  Heap::From(GetHeap())->Terminate();
  EXPECT_DEATH_IF_SUPPORTED(MakeGarbageCollected<Foo>(GetAllocationHandle()),
                            "");
}

template <template <typename> class PersistentType>
void LargeChainOfNewStates(cppgc::Heap& heap) {
  using ClonerImpl = Cloner<PersistentType>;
  Persistent<ClonerImpl> cloner = MakeGarbageCollected<ClonerImpl>(
      heap.GetAllocationHandle(), heap.GetAllocationHandle(), 1000);
  ClonerImpl::destructor_count = 0;
  EXPECT_TRUE(cloner.Get());
  // Terminate() requires destructors to stop creating new state within a few
  // garbage collections.
  EXPECT_DEATH_IF_SUPPORTED(Heap::From(&heap)->Terminate(), "");
}

TEST_F(GCHeapDeathTest, LargeChainOfNewStatesPersistent) {
  LargeChainOfNewStates<Persistent>(*GetHeap());
}

TEST_F(GCHeapDeathTest, LargeChainOfNewStatesCrossThreadPersistent) {
  LargeChainOfNewStates<subtle::CrossThreadPersistent>(*GetHeap());
}

}  // namespace internal
}  // namespace cppgc

"""

```