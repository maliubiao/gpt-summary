Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Understand the Core Purpose:**  The filename `concurrent_marking_test.cc` immediately suggests it's a test file related to concurrent marking in Blink's garbage collection system. The presence of `#if defined(THREAD_SANITIZER)` reinforces this, as thread sanitizers are used to detect data races, which are a major concern in concurrent operations like concurrent garbage collection.

2. **Identify Key Components:** Scan the code for important classes, namespaces, and patterns.
    * `ConcurrentMarkingTest`:  The main test fixture.
    * `concurrent_marking_test` namespace:  Encapsulates test-related code.
    * `CollectionWrapper`: A wrapper around various collection types for easier GC management in tests.
    * `MethodAdapter`: A template class to provide a uniform interface for operations like `insert`, `erase`, and `swap` across different collection types. This is a strong indicator the tests are designed to be generic across different collections.
    * Concrete collection types: `HeapHashMap`, `HeapHashSet`, `HeapLinkedHashSet`, `HeapHashCountedSet`, `HeapVector`, `HeapDeque`. The presence of "Heap" prefix suggests these are custom, garbage-collected versions of standard C++ containers.
    * `ConcurrentMarkingTestDriver`:  Likely a utility class to simulate and control the concurrent marking process during tests.
    * `IntegerObject`: A simple garbage-collected object used as data in the collections.
    * `Persistent`, `Member`: Smart pointers used in Blink's garbage collection system to manage object lifetimes.
    * `Trace(Visitor*)`: A method crucial for garbage collection, indicating how an object's references are discovered.
    * `GarbageCollected`, `GarbageCollectedMixin`: Base classes for objects managed by the garbage collector.

3. **Infer Test Logic:** Analyze the structure of the test functions (e.g., `AddToHashMap`, `RemoveFromBeginningOfHashSet`). The pattern is consistent:
    * Create a `ConcurrentMarkingTestDriver`.
    * Create a `Persistent` pointer to a `CollectionWrapper` holding a collection.
    * Start the garbage collection (`driver.StartGC()`).
    * Repeatedly trigger marking steps (`driver.TriggerMarkingSteps()`) while concurrently modifying the collection (inserting, removing, clearing, swapping).
    * Finish the garbage collection (`driver.FinishGC()`).

4. **Focus on the "Concurrency" Aspect:** The core idea is to test for data races that might occur when the garbage collector's marking phase is running concurrently with modifications to the garbage-collected objects (specifically, collections). The `TriggerMarkingSteps()` simulates the marking process happening alongside the collection modifications.

5. **Relate to Web Technologies (JavaScript, HTML, CSS):**  This is where you connect the low-level implementation to the high-level concepts.
    * **JavaScript:** JavaScript relies heavily on dynamic object creation and manipulation. Blink's GC is responsible for managing the memory of these JavaScript objects. The collections being tested (like `HeapHashMap`) are likely used internally to store JavaScript objects and their properties. Modifying these internal structures while GC is running could lead to crashes or incorrect behavior.
    * **HTML/CSS:**  The DOM (Document Object Model) and CSSOM (CSS Object Model) are complex tree structures. Blink's rendering engine uses these structures extensively. These structures are composed of many interconnected objects that need garbage collection. Collections like `HeapVector` could be used to store lists of child nodes or CSS rules. Concurrent modification during GC could corrupt these structures.

6. **Consider Potential Errors:** Think about what could go wrong during concurrent operations on collections. Standard data race scenarios come to mind:
    * **Iterator invalidation:** Removing an element while iterating can lead to crashes.
    * **Double-freeing/use-after-free:** The GC might try to free an object that's still being accessed or has already been freed if the collection state is inconsistent.
    * **Inconsistent internal state:**  Modifying the collection structure while the GC is traversing it could lead to the GC missing objects or traversing memory that's no longer valid.

7. **Hypothesize Inputs and Outputs (even though it's a test):** While this isn't a functional unit producing specific output, the *intent* is to have a stable system.
    * **Input (Hypothetical):** A series of JavaScript operations that create and modify DOM elements and their properties, triggering allocation and modification of Blink's internal data structures (like the tested collections). Simultaneously, the garbage collector starts its marking phase.
    * **Expected Output:** The garbage collection completes successfully, freeing unused memory without crashing or corrupting the DOM or any internal data structures. The application continues to function correctly. The tests in this file are designed to *verify* this expected output by detecting data races that would prevent it.

8. **Structure the Explanation:** Organize the findings into logical sections: functionality, relationship to web technologies, logical reasoning (assumptions about input/output), and common errors. Use clear and concise language, providing examples where appropriate.

9. **Refine and Elaborate:** Review the explanation for clarity and completeness. Add details and examples to make the explanation more understandable for someone who might not be familiar with Blink's internals. For instance, explicitly mentioning the Thread Sanitizer's role or detailing the types of data races being targeted.
这个文件 `concurrent_marking_test.cc` 是 Chromium Blink 渲染引擎中的一个测试文件，其主要功能是 **测试在并发标记垃圾回收 (Garbage Collection, GC) 过程中，对各种堆分配的数据结构进行并发修改时是否会发生数据竞争 (data races) 或其他内存安全问题。**

更具体地说，它通过以下方式进行测试：

1. **模拟并发标记过程:**  使用了 `ConcurrentMarkingTestDriver` 类来模拟垃圾回收的并发标记阶段。这个驱动会启动 GC，并在执行一系列对数据结构的操作之间，模拟标记步骤。
2. **测试多种堆分配的数据结构:** 文件中针对 Blink 中常用的多种基于堆分配的集合类进行了测试，包括：
    * `HeapHashMap`
    * `HeapHashSet`
    * `HeapLinkedHashSet`
    * `HeapHashCountedSet`
    * `HeapVector` (包括带内联存储的版本)
    * `HeapDeque`
3. **测试各种修改操作:**  针对每种数据结构，测试了在并发标记期间进行的不同类型的修改操作，例如：
    * `AddToCollection`: 向集合中添加元素。
    * `RemoveFromBeginningOfCollection`: 从集合开头移除元素。
    * `RemoveFromMiddleOfCollection`: 从集合中间移除元素。
    * `RemoveFromEndOfCollection`: 从集合末尾移除元素。
    * `ClearCollection`: 清空集合。
    * `SwapCollections`: 交换两个集合的内容。
    * `PopFromCollection` (针对 `HeapVector` 和 `HeapDeque`): 从集合末尾弹出元素。
4. **使用 `ThreadSanitizer` 进行检测:** 该测试文件只在定义了 `THREAD_SANITIZER` 宏的情况下编译。ThreadSanitizer (TSan) 是一种用于检测 C/C++ 程序中数据竞争的工具。通过在并发标记期间进行修改操作，TSan 可以检测到是否有多个线程同时访问并修改同一块内存，从而暴露潜在的并发问题。

**与 JavaScript, HTML, CSS 的关系：**

虽然这个测试文件本身是用 C++ 编写的，并且直接测试的是 Blink 内部的数据结构，但它与 JavaScript, HTML, CSS 的功能有着密切的关系，因为：

* **JavaScript 对象的内存管理:**  JavaScript 是一种动态类型的语言，其对象的生命周期由垃圾回收器管理。Blink 的 GC 负责回收不再被 JavaScript 代码引用的对象。这些被回收的对象可能存储在像 `HeapHashMap` 这样的数据结构中，用于存储 JavaScript 对象的属性。如果在 GC 的标记阶段，JavaScript 代码仍然在修改这些对象的属性（例如添加新的属性），就可能发生数据竞争。
    * **举例说明:** 假设一个 JavaScript 对象 `obj` 有一个属性 `name`。在 GC 的并发标记阶段，GC 线程可能正在标记 `obj` 的内存，而同时 JavaScript 代码执行了 `obj.name = "new name"`。如果 `HeapHashMap` 内部的实现没有正确处理并发访问，就可能导致数据竞争。
* **DOM 和 CSSOM 的内存管理:**  HTML 的 DOM 树和 CSS 的 CSSOM 树也是由 Blink 维护的，它们由大量的 C++ 对象组成，这些对象的内存也由 GC 管理。这些树形结构内部可能使用 `HeapVector` 或 `HeapDeque` 这样的数据结构来存储子节点或样式规则。在 GC 标记的同时，JavaScript 代码可能正在修改 DOM 结构（例如添加或删除节点）或者修改元素的样式。
    * **举例说明:**  一个 HTML 元素可能在内部使用 `HeapVector` 来存储其子元素。在 GC 标记期间，JavaScript 代码执行了 `element.appendChild(newChild)`。如果 `HeapVector` 的并发修改没有得到妥善处理，可能会导致 GC 访问到不一致的状态。
* **Blink 内部数据结构的运用:**  Blink 内部使用了大量的基于堆分配的集合类来管理各种信息，例如：
    * 渲染树的结构
    * 样式信息的存储
    * 事件监听器的管理
    * 等等

    这些数据结构在运行期间会被频繁地修改。确保在 GC 并发标记期间对这些数据结构的修改是线程安全的，是保证 Blink 稳定性和正确性的关键。

**逻辑推理 (假设输入与输出):**

由于这是一个测试文件，它的主要目的是 **验证** 某些假设，而不是基于输入产生特定的输出。其隐含的逻辑推理是：

* **假设输入:** 在开启并发标记的垃圾回收过程中，有另一个线程并发地对堆分配的集合数据结构进行添加、删除、清空或交换等修改操作。
* **预期输出:** 在测试运行过程中，`ThreadSanitizer` 不会报告任何数据竞争错误。这意味着 Blink 的堆分配数据结构和并发标记算法能够正确地处理并发修改，保证内存安全。

**用户或编程常见的使用错误 (针对开发者):**

虽然普通用户不会直接接触到这些底层的 C++ 代码，但对于 Blink 的开发者来说，这个测试文件可以帮助他们避免以下常见的编程错误：

1. **在并发标记期间，直接修改未进行同步保护的堆分配数据结构:**  这是最常见也是最危险的错误。如果没有使用适当的锁或其他同步机制，并发的读写操作很容易导致数据竞争，最终导致程序崩溃或数据损坏。
    * **举例:**  一个开发者可能在某个回调函数中直接向一个 `HeapVector` 中添加元素，而没有意识到此时 GC 可能正在并发地遍历这个 vector。
2. **不正确地使用迭代器进行删除操作:**  在并发修改集合时，需要特别小心迭代器的使用。如果在标记线程正在遍历集合时，修改线程删除了当前迭代器指向的元素，可能会导致迭代器失效，进而引发崩溃。
    * **举例:**  在遍历一个 `HeapHashSet` 时，错误地使用了 `erase(iterator)`，而没有考虑到此时 GC 可能正在访问该迭代器。
3. **在并发标记期间，持有指向堆分配对象的原始指针，并进行修改:**  应该尽量使用 `Member` 或 `Persistent` 等智能指针来管理堆分配对象的生命周期。持有原始指针并在并发操作中修改，很容易导致悬挂指针 (dangling pointer) 或 use-after-free 的问题。
    * **举例:**  在并发标记期间，持有指向 `IntegerObject` 的原始指针，并尝试修改其值。
4. **忘记在 `Trace` 函数中遍历所有需要被 GC 管理的成员:**  `Trace` 函数是 GC 识别对象间引用关系的关键。如果开发者在自定义的垃圾回收对象中添加了新的成员，但忘记在 `Trace` 函数中调用 `visitor->Trace()` 来追踪这些成员，会导致这些成员指向的对象无法被正确标记和回收，最终可能导致内存泄漏或 use-after-free。

总而言之，`concurrent_marking_test.cc` 是一个至关重要的测试文件，用于确保 Blink 渲染引擎在进行垃圾回收时，能够安全地处理对内部数据结构的并发修改，从而保证了 Web 内容的正确渲染和运行。它主要面向 Blink 的开发者，帮助他们避免并发编程中常见的内存安全问题。

Prompt: 
```
这是目录为blink/renderer/platform/heap/test/concurrent_marking_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#if defined(THREAD_SANITIZER)

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/bindings/script_forbidden_scope.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_deque.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_hash_counted_set.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_hash_map.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_hash_set.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_linked_hash_set.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_vector.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/heap_test_objects.h"
#include "third_party/blink/renderer/platform/heap/heap_test_utilities.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"

namespace blink {

class ConcurrentMarkingTest : public TestSupportingGC {};

namespace concurrent_marking_test {

template <typename T>
class CollectionWrapper : public GarbageCollected<CollectionWrapper<T>> {
 public:
  CollectionWrapper() : collection_(MakeGarbageCollected<T>()) {}

  void Trace(Visitor* visitor) const { visitor->Trace(collection_); }

  T* GetCollection() { return collection_.Get(); }

 private:
  Member<T> collection_;
};

// =============================================================================
// Tests that expose data races when modifying collections =====================
// =============================================================================

template <typename T>
struct MethodAdapterBase {
  template <typename U>
  static void insert(T& t, U&& u) {
    t.insert(std::forward<U>(u));
  }

  static void erase(T& t, typename T::iterator&& it) {
    t.erase(std::forward<typename T::iterator>(it));
  }

  static void Swap(T& a, T& b) { a.swap(b); }
};

template <typename T>
struct MethodAdapter : public MethodAdapterBase<T> {};

template <typename C>
void AddToCollection() {
  constexpr int kIterations = 10;
  ConcurrentMarkingTestDriver driver(ThreadState::Current());
  Persistent<CollectionWrapper<C>> persistent =
      MakeGarbageCollected<CollectionWrapper<C>>();
  C* collection = persistent->GetCollection();
  driver.StartGC();
  for (int i = 0; i < kIterations; ++i) {
    driver.TriggerMarkingSteps();
    for (int j = 0; j < kIterations; ++j) {
      int num = kIterations * i + j;
      MethodAdapter<C>::insert(*collection,
                               MakeGarbageCollected<IntegerObject>(num));
    }
  }
  driver.FinishGC();
}

template <typename C, typename GetLocation>
void RemoveFromCollectionAtLocation(GetLocation location) {
  constexpr int kIterations = 10;
  ConcurrentMarkingTestDriver driver(ThreadState::Current());
  Persistent<CollectionWrapper<C>> persistent =
      MakeGarbageCollected<CollectionWrapper<C>>();
  C* collection = persistent->GetCollection();
  for (int i = 0; i < (kIterations * kIterations); ++i) {
    MethodAdapter<C>::insert(*collection,
                             MakeGarbageCollected<IntegerObject>(i));
  }
  driver.StartGC();
  for (int i = 0; i < kIterations; ++i) {
    driver.TriggerMarkingSteps();
    for (int j = 0; j < kIterations; ++j) {
      MethodAdapter<C>::erase(*collection, location(collection));
    }
  }
  driver.FinishGC();
}

template <typename C>
void RemoveFromBeginningOfCollection() {
  RemoveFromCollectionAtLocation<C>(
      [](C* collection) { return collection->begin(); });
}

template <typename C>
void RemoveFromMiddleOfCollection() {
  RemoveFromCollectionAtLocation<C>([](C* collection) {
    auto iterator = collection->begin();
    // Move iterator to middle of collection.
    for (size_t i = 0; i < collection->size() / 2; ++i) {
      ++iterator;
    }
    return iterator;
  });
}

template <typename C>
void RemoveFromEndOfCollection() {
  RemoveFromCollectionAtLocation<C>([](C* collection) {
    auto iterator = collection->end();
    return --iterator;
  });
}

template <typename C>
void ClearCollection() {
  constexpr int kIterations = 10;
  ConcurrentMarkingTestDriver driver(ThreadState::Current());
  Persistent<CollectionWrapper<C>> persistent =
      MakeGarbageCollected<CollectionWrapper<C>>();
  C* collection = persistent->GetCollection();
  driver.StartGC();
  for (int i = 0; i < kIterations; ++i) {
    driver.TriggerMarkingSteps();
    for (int j = 0; j < kIterations; ++j) {
      MethodAdapter<C>::insert(*collection,
                               MakeGarbageCollected<IntegerObject>(i));
    }
    collection->clear();
  }
  driver.FinishGC();
}

template <typename C>
void SwapCollections() {
  constexpr int kIterations = 10;
  ConcurrentMarkingTestDriver driver(ThreadState::Current());
  Persistent<CollectionWrapper<C>> persistent =
      MakeGarbageCollected<CollectionWrapper<C>>();
  C* collection = persistent->GetCollection();
  driver.StartGC();
  for (int i = 0; i < (kIterations * kIterations); ++i) {
    C* new_collection = MakeGarbageCollected<C>();
    for (int j = 0; j < kIterations * i; ++j) {
      MethodAdapter<C>::insert(*new_collection,
                               MakeGarbageCollected<IntegerObject>(j));
    }
    driver.TriggerMarkingSteps();
    MethodAdapter<C>::Swap(*collection, *new_collection);
  }
  driver.FinishGC();
}

// HeapHashMap

template <typename T>
using IdentityHashMap = HeapHashMap<T, T>;

template <typename T>
struct MethodAdapter<HeapHashMap<T, T>>
    : public MethodAdapterBase<HeapHashMap<T, T>> {
  template <typename U>
  static void insert(HeapHashMap<T, T>& map, U&& u) {
    map.insert(u, u);
  }
};

TEST_F(ConcurrentMarkingTest, AddToHashMap) {
  AddToCollection<IdentityHashMap<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, RemoveFromBeginningOfHashMap) {
  RemoveFromBeginningOfCollection<IdentityHashMap<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, RemoveFromMiddleOfHashMap) {
  RemoveFromMiddleOfCollection<IdentityHashMap<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, RemoveFromEndOfHashMap) {
  RemoveFromEndOfCollection<IdentityHashMap<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, ClearHashMap) {
  ClearCollection<IdentityHashMap<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, SwapHashMap) {
  SwapCollections<IdentityHashMap<Member<IntegerObject>>>();
}

// HeapHashSet

TEST_F(ConcurrentMarkingTest, AddToHashSet) {
  AddToCollection<HeapHashSet<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, RemoveFromBeginningOfHashSet) {
  RemoveFromBeginningOfCollection<HeapHashSet<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, RemoveFromMiddleOfHashSet) {
  RemoveFromMiddleOfCollection<HeapHashSet<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, RemoveFromEndOfHashSet) {
  RemoveFromEndOfCollection<HeapHashSet<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, ClearHashSet) {
  ClearCollection<HeapHashSet<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, SwapHashSet) {
  SwapCollections<HeapHashSet<Member<IntegerObject>>>();
}

template <typename T>
struct MethodAdapter<HeapLinkedHashSet<T>>
    : public MethodAdapterBase<HeapLinkedHashSet<T>> {
  static void Swap(HeapLinkedHashSet<T>& a, HeapLinkedHashSet<T>& b) {
    a.Swap(b);
  }
};

TEST_F(ConcurrentMarkingTest, AddToLinkedHashSet) {
  AddToCollection<HeapLinkedHashSet<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, RemoveFromBeginningOfLinkedHashSet) {
  RemoveFromBeginningOfCollection<HeapLinkedHashSet<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, RemoveFromMiddleOfLinkedHashSet) {
  RemoveFromMiddleOfCollection<HeapLinkedHashSet<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, RemoveFromEndOfLinkedHashSet) {
  RemoveFromEndOfCollection<HeapLinkedHashSet<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, ClearLinkedHashSet) {
  ClearCollection<HeapLinkedHashSet<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, SwapLinkedHashSet) {
  SwapCollections<HeapLinkedHashSet<Member<IntegerObject>>>();
}

// HeapHashCountedSet

TEST_F(ConcurrentMarkingTest, AddToHashCountedSet) {
  AddToCollection<HeapHashCountedSet<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, RemoveFromBeginningOfHashCountedSet) {
  RemoveFromBeginningOfCollection<HeapHashCountedSet<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, RemoveFromMiddleOfHashCountedSet) {
  RemoveFromMiddleOfCollection<HeapHashCountedSet<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, RemoveFromEndOfHashCountedSet) {
  RemoveFromEndOfCollection<HeapHashCountedSet<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, ClearHashCountedSet) {
  ClearCollection<HeapHashCountedSet<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, SwapHashCountedSet) {
  SwapCollections<HeapHashCountedSet<Member<IntegerObject>>>();
}

// HeapVector

// Additional test for vectors and deques
template <typename V>
void PopFromCollection() {
  constexpr int kIterations = 10;
  ConcurrentMarkingTestDriver driver(ThreadState::Current());
  Persistent<CollectionWrapper<V>> persistent =
      MakeGarbageCollected<CollectionWrapper<V>>();
  V* vector = persistent->GetCollection();
  for (int i = 0; i < (kIterations * kIterations); ++i) {
    MethodAdapter<V>::insert(*vector, MakeGarbageCollected<IntegerObject>(i));
  }
  driver.StartGC();
  for (int i = 0; i < kIterations; ++i) {
    driver.TriggerMarkingSteps();
    for (int j = 0; j < kIterations; ++j) {
      vector->pop_back();
    }
  }
  driver.FinishGC();
}

template <typename T, wtf_size_t inlineCapacity>
struct MethodAdapter<HeapVector<T, inlineCapacity>>
    : public MethodAdapterBase<HeapVector<T, inlineCapacity>> {
  template <typename U>
  static void insert(HeapVector<T, inlineCapacity>& vector, U&& u) {
    vector.push_back(std::forward<U>(u));
  }
};

TEST_F(ConcurrentMarkingTest, AddToVector) {
  AddToCollection<HeapVector<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, RemoveFromBeginningOfVector) {
  RemoveFromBeginningOfCollection<HeapVector<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, RemoveFromMiddleOfVector) {
  RemoveFromMiddleOfCollection<HeapVector<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, RemoveFromEndOfVector) {
  RemoveFromEndOfCollection<HeapVector<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, ClearVector) {
  ClearCollection<HeapVector<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, SwapVector) {
  SwapCollections<HeapVector<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, PopFromVector) {
  PopFromCollection<HeapVector<Member<IntegerObject>>>();
}

// HeapVector with inlined buffer

template <typename T>
using HeapVectorWithInlineStorage = HeapVector<T, 10>;

TEST_F(ConcurrentMarkingTest, AddToInlinedVector) {
  AddToCollection<HeapVectorWithInlineStorage<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, RemoveFromBeginningOfInlinedVector) {
  RemoveFromBeginningOfCollection<
      HeapVectorWithInlineStorage<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, RemoveFromMiddleOfInlinedVector) {
  RemoveFromMiddleOfCollection<
      HeapVectorWithInlineStorage<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, RemoveFromEndOfInlinedVector) {
  RemoveFromEndOfCollection<
      HeapVectorWithInlineStorage<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, ClearInlinedVector) {
  ClearCollection<HeapVectorWithInlineStorage<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, SwapInlinedVector) {
  SwapCollections<HeapVectorWithInlineStorage<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, PopFromInlinedVector) {
  PopFromCollection<HeapVectorWithInlineStorage<Member<IntegerObject>>>();
}

// HeapVector of std::pairs

template <typename T>
using HeapVectorOfPairs = HeapVector<std::pair<T, T>>;

template <typename T, wtf_size_t inlineCapacity>
struct MethodAdapter<HeapVector<std::pair<T, T>, inlineCapacity>>
    : public MethodAdapterBase<HeapVector<std::pair<T, T>, inlineCapacity>> {
  template <typename U>
  static void insert(HeapVector<std::pair<T, T>, inlineCapacity>& vector,
                     U&& u) {
    vector.push_back(std::make_pair<U&, U&>(u, u));
  }
};

TEST_F(ConcurrentMarkingTest, AddToVectorOfPairs) {
  AddToCollection<HeapVectorOfPairs<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, RemoveFromBeginningOfVectorOfPairs) {
  RemoveFromBeginningOfCollection<HeapVectorOfPairs<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, RemoveFromMiddleOfVectorOfPairs) {
  RemoveFromMiddleOfCollection<HeapVectorOfPairs<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, RemoveFromEndOfVectorOfPairs) {
  RemoveFromEndOfCollection<HeapVectorOfPairs<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, ClearVectorOfPairs) {
  ClearCollection<HeapVectorOfPairs<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, SwapVectorOfPairs) {
  SwapCollections<HeapVectorOfPairs<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, PopFromVectorOfPairs) {
  PopFromCollection<HeapVectorOfPairs<Member<IntegerObject>>>();
}

// HeapDeque

template <typename T>
struct MethodAdapter<HeapDeque<T>> : public MethodAdapterBase<HeapDeque<T>> {
  template <typename U>
  static void insert(HeapDeque<T>& deque, U&& u) {
    deque.push_back(std::forward<U>(u));
  }

  static void erase(HeapDeque<T>& deque, typename HeapDeque<T>::iterator&& it) {
    deque.pop_back();
  }

  static void Swap(HeapDeque<T>& a, HeapDeque<T>& b) { a.Swap(b); }
};

TEST_F(ConcurrentMarkingTest, AddToDeque) {
  AddToCollection<HeapDeque<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, RemoveFromBeginningOfDeque) {
  RemoveFromBeginningOfCollection<HeapDeque<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, RemoveFromMiddleOfDeque) {
  RemoveFromMiddleOfCollection<HeapDeque<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, RemoveFromEndOfDeque) {
  RemoveFromEndOfCollection<HeapDeque<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, ClearDeque) {
  ClearCollection<HeapDeque<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, SwapDeque) {
  SwapCollections<HeapDeque<Member<IntegerObject>>>();
}
TEST_F(ConcurrentMarkingTest, PopFromDeque) {
  PopFromCollection<HeapDeque<Member<IntegerObject>>>();
}

namespace {

class RegisteredMixin;

class CollectsMixins : public GarbageCollected<CollectsMixins> {
  using MixinSet = HeapHashSet<Member<RegisteredMixin>>;

 public:
  CollectsMixins() : set_(MakeGarbageCollected<MixinSet>()) {}
  void RegisterMixin(RegisteredMixin* mixin) { set_->insert(mixin); }
  void Trace(Visitor* visitor) const { visitor->Trace(set_); }

 private:
  Member<MixinSet> set_;
};

class RegisteredMixin : public GarbageCollectedMixin {
 public:
  RegisteredMixin(CollectsMixins* collector) { collector->RegisterMixin(this); }
};

class GCedWithRegisteredMixin
    : public GarbageCollected<GCedWithRegisteredMixin>,
      public RegisteredMixin {
 public:
  GCedWithRegisteredMixin(CollectsMixins* collector)
      : RegisteredMixin(collector) {}
  void Trace(Visitor*) const override {}
};

}  // namespace

TEST_F(ConcurrentMarkingTest, MarkingInConstructionMixin) {
  constexpr int kIterations = 10;
  ConcurrentMarkingTestDriver driver(ThreadState::Current());
  Persistent<CollectsMixins> collector = MakeGarbageCollected<CollectsMixins>();
  driver.StartGC();
  for (int i = 0; i < kIterations; ++i) {
    driver.TriggerMarkingSteps();
    for (int j = 0; j < kIterations; ++j) {
      MakeGarbageCollected<GCedWithRegisteredMixin>(collector.Get());
    }
  }
  driver.FinishGC();
}

}  // namespace concurrent_marking_test
}  // namespace blink

#endif  // defined(THREAD_SANITIZER)

"""

```