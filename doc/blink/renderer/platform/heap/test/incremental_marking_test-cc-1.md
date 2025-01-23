Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a larger file. This snippet contains a series of unit tests for an incremental garbage collection mechanism in the Blink rendering engine.

Here's a breakdown of how to approach this:

1. **Identify the Core Functionality:** The primary goal of these tests is to verify the correctness of incremental marking during garbage collection. This includes how different types of object references (Member, WeakMember, Persistent, WeakPersistent) and data structures (HeapHashMap, HeapVector, HeapHashSet) interact with the incremental marker.

2. **Categorize the Tests:** The tests can be broadly categorized by the data structures and operations they are testing. For example, there are tests for `HeapHashMap` covering copy, move, swap operations with different combinations of `Member` and `WeakMember`. There are also tests focused on `HeapVector` and `HeapHashSet`.

3. **Analyze Individual Test Cases:** For each test case, understand the setup, the action performed (e.g., copying a `HeapHashMap`), and the assertions made. The assertions typically check if objects are still alive after garbage collection.

4. **Look for Connections to Web Technologies:**  Consider how the tested concepts relate to JavaScript, HTML, and CSS. Garbage collection is crucial for managing the memory of JavaScript objects. The `Member` and `WeakMember` types are ways of referencing objects in the engine, and their correct handling during GC is essential for preventing memory leaks and ensuring stability. HTML elements and CSS styles are represented as objects in the engine's memory.

5. **Identify Logic and Assumptions:**  Pay attention to the use of `IncrementalMarkingTestDriver`. This indicates that the tests simulate incremental garbage collection cycles. The `EXPECT_TRUE` and `EXPECT_FALSE` assertions reveal the expected outcomes based on the GC behavior.

6. **Spot Potential Usage Errors:**  While these are unit tests and not direct user code, consider the scenarios they test. For instance, the tests with `WeakMember` demonstrate how weak references behave during GC, which is important for developers who use such constructs in their engine code. Incorrect handling of weak references could lead to dangling pointers.

7. **Structure the Summary:** Organize the findings logically, starting with the main purpose of the code and then detailing the specific areas covered by the tests.

**Thinking about the code snippet itself:**

*   The code uses the `testing::TEST_F` framework, indicating these are Google Test unit tests.
*   `IncrementalMarkingTestDriver` is a utility for controlling and simulating incremental garbage collection.
*   `MakeGarbageCollected` allocates objects on the heap managed by the garbage collector.
*   `Member` and `WeakMember` are smart pointers that represent strong and weak references, respectively.
*   `Persistent` and `WeakPersistent` provide handles to garbage-collected objects that survive GC cycles under certain conditions.
*   The tests often create objects, insert them into data structures, trigger a GC cycle, and then check if the objects are still alive based on the type of reference held.
*   There are specific tests for copy constructors, move constructors, and swap operations for `HeapHashMap`.
*   Some tests focus on the interaction between `HeapHashMap` and `HeapVector` during copying of keys and values.
*   The later tests cover complete incremental GC cycles and edge cases like dropping backing stores, handling weak members, and scenarios during object construction.
*   The presence of comments mentioning `crbug.com` links suggests these tests are often added to address specific bug fixes.

By following these steps, a comprehensive summary of the code's functionality can be generated, addressing all the user's requirements.
这是对`blink/renderer/platform/heap/test/incremental_marking_test.cc`文件第二部分的分析归纳，延续了第一部分的功能介绍。

**归纳总结：**

这部分代码延续了第一部分的功能，主要对 Blink 渲染引擎中增量标记垃圾回收机制的正确性进行测试，尤其关注在增量标记过程中各种数据结构的操作行为，以及特定场景下的垃圾回收表现。

**具体功能点包括：**

1. **`HeapHashMap` 的拷贝、移动和交换操作测试 (续):**  延续了第一部分的测试，继续覆盖了 `HeapHashMap` 在增量标记期间的拷贝构造、移动构造以及 `swap` 操作。
    *   测试了不同类型的键值对组合（`Member<LinkedObject>` 和 `WeakMember<LinkedObject>` 的各种组合）在拷贝、移动和交换操作下的对象存活情况。

2. **`HeapHashMap` 键值复制到 `HeapVector` 的测试:**
    *   测试了在增量标记期间，将 `HeapHashMap` 的键或值复制到 `HeapVector` 中的行为，并验证了只有键或值会触发写屏障，暗示了高效的实现。

3. **完整的增量垃圾回收周期测试:**
    *   测试了 `IncrementalMarkingTestDriver` 驱动器模拟完整的增量垃圾回收周期的能力，包括启动、执行标记步骤和完成垃圾回收。

4. **回归测试，修复特定 Bug:**
    *   包含多个针对特定 Bug 的回归测试，通过模拟导致 Bug 的场景，验证修复后的代码行为正确。这些 Bug 包括：
        *   在增量标记期间丢弃 backing store (`DropBackingStore`, `NoBackingFreeDuringIncrementalMarking`)。
        *   堆压缩期间丢弃引用 (`DropReferenceWithHeapCompaction`)。
        *   `WeakMember` 的处理 (`WeakMember`)。
        *   `MemberBase::Swap` 可能导致的 stale 指针问题 (`MemberSwap`)。
        *   在对象构造过程中触发增量标记步骤 (`StepDuringObjectConstruction`, `StepDuringMixinObjectConstruction`)，确保未完全构造的对象被正确处理。
        *   增量标记期间收缩 backing store 导致的问题 (`IncrementalMarkingShrinkingBackingCompaction`)。
        *   payload 写屏障为压缩注册无效槽位的问题 (`InPayloadWriteBarrierRegistersInvalidSlotForCompaction`)。
        *   标记的 backing store 调整标记字节数的问题 (`AdjustMarkedBytesOnMarkedBackingStore`)。
        *   嵌套容器中 stale slot 导致的堆压缩问题 (`HeapCompactWithStaleSlotInNestedContainer`)。
        *   `HeapLinkedHashSet` 的移动回调 (`LinkedHashSetMovingCallback`)。
        *   弱容器的保守垃圾回收 (`ConservativeGCOfWeakContainer`)，确保栈上的弱容器引用能强制容器重新追踪。
        *   弱容器的写屏障强化 backing store (`WriteBarrierOfWeakContainersStrongifiesBackingStore`)。
        *   栈上嵌套向量的 backing slot 注册问题 (`NestedVectorsWithInlineCapacityOnStack`)。

**与 JavaScript, HTML, CSS 的关系：**

这部分测试依然与 JavaScript, HTML, CSS 的内存管理息息相关。

*   **JavaScript 对象生命周期管理:**  增量标记垃圾回收是 V8 引擎（Blink 使用 V8 作为 JavaScript 引擎）管理 JavaScript 对象内存的关键机制。这些测试确保了在增量回收过程中，各种持有 JavaScript 对象引用的数据结构能够正确地维护对象的生命周期。
*   **DOM 节点和 CSS 样式对象:** HTML DOM 节点和 CSS 样式规则在 Blink 内部以 C++ 对象的形式存在，并由垃圾回收器管理。测试中使用的 `LinkedObject` 可以看作是对这些内部对象的抽象。
*   **`Member` 和 `WeakMember` 的应用:**  `Member` 类似于 JavaScript 中的强引用，保持对象存活。`WeakMember` 类似于 JavaScript 中的 WeakRef，允许在没有强引用时回收对象。这些测试验证了 Blink 内部正确使用了这些引用类型来管理内存。

**逻辑推理 (假设输入与输出):**

由于这部分主要是单元测试代码，其主要逻辑是通过断言 (`EXPECT_TRUE`, `EXPECT_FALSE`) 来验证预期结果。以下举例说明：

**假设输入:** 一个 `HeapHashMap` 包含一个 `Member<LinkedObject>` 类型的键和一个 `Member<LinkedObject>` 类型的值。增量标记垃圾回收开始并完成。

**预期输出:** 在垃圾回收完成后，键和值指向的 `LinkedObject` 对象仍然存活 (`EXPECT_TRUE(obj1)`, `EXPECT_TRUE(obj2)`，如果 `obj1` 和 `obj2` 是键和值指向的对象)。这是因为 `Member` 是强引用，会阻止对象被回收。

**用户或编程常见的使用错误举例：**

虽然这是引擎内部的测试，但可以推断出一些编程中可能出现的错误：

*   **错误地使用弱引用:** 如果开发者错误地认为弱引用会始终保持对象存活，可能会导致在增量回收期间对象被意外回收，引发悬空指针等问题。测试中 `WeakMember` 的行为就展示了这一点。
*   **在增量回收期间进行不安全的操作:** 例如，在增量标记尚未完成时就释放了某些数据结构的 backing store，可能会导致垃圾回收器在后续步骤中访问到无效内存。相关的回归测试就覆盖了这类场景。
*   **对对象生命周期的错误假设:**  不理解增量回收的原理，可能会错误地假设对象的生命周期，导致在对象仍然被标记为使用中时就尝试释放或访问它。

总而言之，这部分代码通过大量的单元测试，细致地检验了 Blink 引擎在进行增量标记垃圾回收时，各种数据结构和引用类型的行为，确保了引擎在内存管理方面的稳定性和正确性。 修复特定 bug 的回归测试也体现了开发者对潜在问题的重视和解决。

### 提示词
```
这是目录为blink/renderer/platform/heap/test/incremental_marking_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
j1.Get(), obj2.Get());
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  EXPECT_TRUE(map1->Contains(obj1));
  HeapHashMap<Member<LinkedObject>, Member<LinkedObject>>* map2 =
      MakeGarbageCollected<
          HeapHashMap<Member<LinkedObject>, Member<LinkedObject>>>(*map1);
  EXPECT_TRUE(map1->Contains(obj1));
  EXPECT_TRUE(map2->Contains(obj1));
  driver.FinishGC();
  EXPECT_TRUE(obj1);
  EXPECT_TRUE(obj2);
}

TEST_F(IncrementalMarkingTest, HeapHashMapCopyWeakMemberWeakMember) {
  WeakPersistent<LinkedObject> obj1 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj2 = MakeGarbageCollected<LinkedObject>();
  HeapHashMap<WeakMember<LinkedObject>, WeakMember<LinkedObject>>* map1 =
      MakeGarbageCollected<
          HeapHashMap<WeakMember<LinkedObject>, WeakMember<LinkedObject>>>();
  map1->insert(obj1.Get(), obj2.Get());
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  EXPECT_TRUE(map1->Contains(obj1));
  // Weak references are strongified for the current cycle.
  HeapHashMap<WeakMember<LinkedObject>, WeakMember<LinkedObject>>* map2 =
      MakeGarbageCollected<
          HeapHashMap<WeakMember<LinkedObject>, WeakMember<LinkedObject>>>(
          *map1);
  EXPECT_TRUE(map1->Contains(obj1));
  EXPECT_TRUE(map2->Contains(obj1));
  driver.FinishGC();
  EXPECT_TRUE(obj1);
  EXPECT_TRUE(obj2);
}

TEST_F(IncrementalMarkingTest, HeapHashMapCopyMemberWeakMember) {
  WeakPersistent<LinkedObject> obj1 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj2 = MakeGarbageCollected<LinkedObject>();
  HeapHashMap<Member<LinkedObject>, WeakMember<LinkedObject>>* map1 =
      MakeGarbageCollected<
          HeapHashMap<Member<LinkedObject>, WeakMember<LinkedObject>>>();
  map1->insert(obj1.Get(), obj2.Get());
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  EXPECT_TRUE(map1->Contains(obj1));
  // Weak references are strongified for the current cycle.
  HeapHashMap<Member<LinkedObject>, WeakMember<LinkedObject>>* map2 =
      MakeGarbageCollected<
          HeapHashMap<Member<LinkedObject>, WeakMember<LinkedObject>>>(*map1);
  EXPECT_TRUE(map1->Contains(obj1));
  EXPECT_TRUE(map2->Contains(obj1));
  driver.FinishGC();
  EXPECT_TRUE(obj1);
  EXPECT_TRUE(obj2);
}

TEST_F(IncrementalMarkingTest, HeapHashMapCopyWeakMemberMember) {
  WeakPersistent<LinkedObject> obj1 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj2 = MakeGarbageCollected<LinkedObject>();
  HeapHashMap<WeakMember<LinkedObject>, Member<LinkedObject>>* map1 =
      MakeGarbageCollected<
          HeapHashMap<WeakMember<LinkedObject>, Member<LinkedObject>>>();
  map1->insert(obj1.Get(), obj2.Get());
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  EXPECT_TRUE(map1->Contains(obj1));
  // Weak references are strongified for the current cycle.
  HeapHashMap<WeakMember<LinkedObject>, Member<LinkedObject>>* map2 =
      MakeGarbageCollected<
          HeapHashMap<WeakMember<LinkedObject>, Member<LinkedObject>>>(*map1);
  EXPECT_TRUE(map1->Contains(obj1));
  EXPECT_TRUE(map2->Contains(obj1));
  driver.FinishGC();
  EXPECT_TRUE(obj1);
  EXPECT_TRUE(obj2);
}

TEST_F(IncrementalMarkingTest, HeapHashMapMoveMember) {
  WeakPersistent<LinkedObject> obj1 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj2 = MakeGarbageCollected<LinkedObject>();
  HeapHashMap<Member<LinkedObject>, Member<LinkedObject>>* map =
      MakeGarbageCollected<
          HeapHashMap<Member<LinkedObject>, Member<LinkedObject>>>();
  map->insert(obj1.Get(), obj2.Get());
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  MakeGarbageCollected<HeapHashMap<Member<LinkedObject>, Member<LinkedObject>>>(
      std::move(*map));
  driver.FinishGC();
  EXPECT_TRUE(obj1);
  EXPECT_TRUE(obj2);
}

TEST_F(IncrementalMarkingTest, HeapHashMapMoveWeakMember) {
  WeakPersistent<LinkedObject> obj1 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj2 = MakeGarbageCollected<LinkedObject>();
  HeapHashMap<WeakMember<LinkedObject>, WeakMember<LinkedObject>>* map =
      MakeGarbageCollected<
          HeapHashMap<WeakMember<LinkedObject>, WeakMember<LinkedObject>>>();
  map->insert(obj1.Get(), obj2.Get());
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  MakeGarbageCollected<
      HeapHashMap<WeakMember<LinkedObject>, WeakMember<LinkedObject>>>(
      std::move(*map));
  driver.FinishGC();
  EXPECT_TRUE(obj1);
  EXPECT_TRUE(obj2);
}

TEST_F(IncrementalMarkingTest, HeapHashMapMoveMemberWeakMember) {
  WeakPersistent<LinkedObject> obj1 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj2 = MakeGarbageCollected<LinkedObject>();
  HeapHashMap<Member<LinkedObject>, WeakMember<LinkedObject>>* map =
      MakeGarbageCollected<
          HeapHashMap<Member<LinkedObject>, WeakMember<LinkedObject>>>();
  map->insert(obj1.Get(), obj2.Get());
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  MakeGarbageCollected<
      HeapHashMap<Member<LinkedObject>, WeakMember<LinkedObject>>>(
      std::move(*map));
  driver.FinishGC();
  EXPECT_TRUE(obj1);
  EXPECT_TRUE(obj2);
}

TEST_F(IncrementalMarkingTest, HeapHashMapMoveWeakMemberMember) {
  WeakPersistent<LinkedObject> obj1 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj2 = MakeGarbageCollected<LinkedObject>();
  HeapHashMap<WeakMember<LinkedObject>, Member<LinkedObject>>* map =
      MakeGarbageCollected<
          HeapHashMap<WeakMember<LinkedObject>, Member<LinkedObject>>>();
  map->insert(obj1.Get(), obj2.Get());
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  MakeGarbageCollected<
      HeapHashMap<WeakMember<LinkedObject>, Member<LinkedObject>>>(
      std::move(*map));
  driver.FinishGC();
  EXPECT_TRUE(obj1);
  EXPECT_TRUE(obj2);
}

TEST_F(IncrementalMarkingTest, HeapHashMapSwapMemberMember) {
  WeakPersistent<LinkedObject> obj1 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj2 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj3 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj4 = MakeGarbageCollected<LinkedObject>();
  HeapHashMap<Member<LinkedObject>, Member<LinkedObject>>* map1 =
      MakeGarbageCollected<
          HeapHashMap<Member<LinkedObject>, Member<LinkedObject>>>();
  map1->insert(obj1.Get(), obj2.Get());
  HeapHashMap<Member<LinkedObject>, Member<LinkedObject>>* map2 =
      MakeGarbageCollected<
          HeapHashMap<Member<LinkedObject>, Member<LinkedObject>>>();
  map2->insert(obj3.Get(), obj4.Get());
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  std::swap(*map1, *map2);
  driver.FinishGC();
  EXPECT_TRUE(obj1);
  EXPECT_TRUE(obj2);
  EXPECT_TRUE(obj3);
  EXPECT_TRUE(obj4);
}

TEST_F(IncrementalMarkingTest, HeapHashMapSwapWeakMemberWeakMember) {
  WeakPersistent<LinkedObject> obj1 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj2 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj3 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj4 = MakeGarbageCollected<LinkedObject>();
  HeapHashMap<WeakMember<LinkedObject>, WeakMember<LinkedObject>>* map1 =
      MakeGarbageCollected<
          HeapHashMap<WeakMember<LinkedObject>, WeakMember<LinkedObject>>>();
  map1->insert(obj1.Get(), obj2.Get());
  HeapHashMap<WeakMember<LinkedObject>, WeakMember<LinkedObject>>* map2 =
      MakeGarbageCollected<
          HeapHashMap<WeakMember<LinkedObject>, WeakMember<LinkedObject>>>();
  map2->insert(obj3.Get(), obj4.Get());
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  std::swap(*map1, *map2);
  driver.FinishGC();
  EXPECT_TRUE(obj1);
  EXPECT_TRUE(obj2);
  EXPECT_TRUE(obj3);
  EXPECT_TRUE(obj4);
}

TEST_F(IncrementalMarkingTest, HeapHashMapSwapMemberWeakMember) {
  WeakPersistent<LinkedObject> obj1 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj2 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj3 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj4 = MakeGarbageCollected<LinkedObject>();
  HeapHashMap<Member<LinkedObject>, WeakMember<LinkedObject>>* map1 =
      MakeGarbageCollected<
          HeapHashMap<Member<LinkedObject>, WeakMember<LinkedObject>>>();
  map1->insert(obj1.Get(), obj2.Get());
  HeapHashMap<Member<LinkedObject>, WeakMember<LinkedObject>>* map2 =
      MakeGarbageCollected<
          HeapHashMap<Member<LinkedObject>, WeakMember<LinkedObject>>>();
  map2->insert(obj3.Get(), obj4.Get());
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  std::swap(*map1, *map2);
  driver.FinishGC();
  EXPECT_TRUE(obj1);
  EXPECT_TRUE(obj2);
  EXPECT_TRUE(obj3);
  EXPECT_TRUE(obj4);
}

TEST_F(IncrementalMarkingTest, HeapHashMapSwapWeakMemberMember) {
  WeakPersistent<LinkedObject> obj1 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj2 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj3 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj4 = MakeGarbageCollected<LinkedObject>();
  HeapHashMap<WeakMember<LinkedObject>, Member<LinkedObject>>* map1 =
      MakeGarbageCollected<
          HeapHashMap<WeakMember<LinkedObject>, Member<LinkedObject>>>();
  map1->insert(obj1.Get(), obj2.Get());
  HeapHashMap<WeakMember<LinkedObject>, Member<LinkedObject>>* map2 =
      MakeGarbageCollected<
          HeapHashMap<WeakMember<LinkedObject>, Member<LinkedObject>>>();
  map2->insert(obj3.Get(), obj4.Get());
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  std::swap(*map1, *map2);
  driver.FinishGC();
  EXPECT_TRUE(obj1);
  EXPECT_TRUE(obj2);
  EXPECT_TRUE(obj3);
  EXPECT_TRUE(obj4);
}

TEST_F(IncrementalMarkingTest, HeapHashMapCopyKeysToVectorMember) {
  WeakPersistent<LinkedObject> obj1 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj2 = MakeGarbageCollected<LinkedObject>();
  HeapHashMap<Member<LinkedObject>, Member<LinkedObject>>* map =
      MakeGarbageCollected<
          HeapHashMap<Member<LinkedObject>, Member<LinkedObject>>>();
  map->insert(obj1.Get(), obj2.Get());
  HeapVector<Member<LinkedObject>>* vec =
      MakeGarbageCollected<HeapVector<Member<LinkedObject>>>();
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  // Only key should have its write barrier fired. A write barrier call for
  // value hints to an inefficient implementation.
  CopyKeysToVector(*map, *vec);
  driver.FinishGC();
  EXPECT_TRUE(obj1);
  EXPECT_FALSE(obj2);
}

TEST_F(IncrementalMarkingTest, HeapHashMapCopyValuesToVectorMember) {
  WeakPersistent<LinkedObject> obj1 = MakeGarbageCollected<LinkedObject>();
  WeakPersistent<LinkedObject> obj2 = MakeGarbageCollected<LinkedObject>();
  HeapHashMap<Member<LinkedObject>, Member<LinkedObject>>* map =
      MakeGarbageCollected<
          HeapHashMap<Member<LinkedObject>, Member<LinkedObject>>>();
  map->insert(obj1.Get(), obj2.Get());
  HeapVector<Member<LinkedObject>>* vec =
      MakeGarbageCollected<HeapVector<Member<LinkedObject>>>();
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  // Only value should have its write barrier fired. A write barrier call for
  // key hints to an inefficient implementation.
  CopyValuesToVector(*map, *vec);
  driver.FinishGC();
  EXPECT_FALSE(obj1);
  EXPECT_TRUE(obj2);
}

// =============================================================================
// Tests that execute complete incremental garbage collections. ================
// =============================================================================

TEST_F(IncrementalMarkingTest, TestDriver) {
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  EXPECT_TRUE(ThreadState::Current()->IsIncrementalMarking());
  driver.TriggerMarkingSteps();
  EXPECT_TRUE(ThreadState::Current()->IsIncrementalMarking());
  driver.FinishGC();
  EXPECT_FALSE(ThreadState::Current()->IsIncrementalMarking());
}

TEST_F(IncrementalMarkingTest, DropBackingStore) {
  // Regression test: https://crbug.com/828537
  using WeakStore = HeapHashCountedSet<WeakMember<LinkedObject>>;

  Persistent<WeakStore> persistent(MakeGarbageCollected<WeakStore>());
  persistent->insert(MakeGarbageCollected<LinkedObject>());
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  driver.TriggerMarkingSteps();
  persistent->clear();
  // Marking verifier should not crash on a black backing store with all
  // black->white edges.
  driver.FinishGC();
}

TEST_F(IncrementalMarkingTest, NoBackingFreeDuringIncrementalMarking) {
  // Regression test: https://crbug.com/870306
  // Only reproduces in ASAN configurations.
  using WeakStore = HeapHashCountedSet<WeakMember<LinkedObject>>;

  Persistent<WeakStore> persistent(MakeGarbageCollected<WeakStore>());
  // Prefill the collection to grow backing store. A new backing store
  // allocationwould trigger the write barrier, mitigating the bug where
  // a backing store is promptly freed.
  for (size_t i = 0; i < 8; i++) {
    persistent->insert(MakeGarbageCollected<LinkedObject>());
  }
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  persistent->insert(MakeGarbageCollected<LinkedObject>());
  // Is not allowed to free the backing store as the previous insert may have
  // registered a slot.
  persistent->clear();
  driver.TriggerMarkingSteps();
  driver.FinishGC();
}

TEST_F(IncrementalMarkingTest, DropReferenceWithHeapCompaction) {
  using Store = HeapHashCountedSet<Member<LinkedObject>>;

  Persistent<Store> persistent(MakeGarbageCollected<Store>());
  persistent->insert(MakeGarbageCollected<LinkedObject>());
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  CompactionTestDriver(ThreadState::Current()).ForceCompactionForNextGC();
  driver.StartGC();
  driver.TriggerMarkingSteps();
  persistent->clear();
  driver.FinishGC();
}

namespace {

class ObjectWithWeakMember : public GarbageCollected<ObjectWithWeakMember> {
 public:
  ObjectWithWeakMember() = default;

  void set_object(LinkedObject* object) { object_ = object; }

  void Trace(Visitor* visitor) const { visitor->Trace(object_); }

 private:
  WeakMember<LinkedObject> object_ = nullptr;
};

}  // namespace

TEST_F(IncrementalMarkingTest, WeakMember) {
  // Regression test: https://crbug.com/913431

  Persistent<ObjectWithWeakMember> persistent(
      MakeGarbageCollected<ObjectWithWeakMember>());
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  driver.TriggerMarkingSteps();
  persistent->set_object(MakeGarbageCollected<LinkedObject>());
  driver.FinishGC();
  ConservativelyCollectGarbage();
}

TEST_F(IncrementalMarkingTest, MemberSwap) {
  // Regression test: https://crbug.com/913431
  //
  // MemberBase::Swap may be used to swap in a not-yet-processed member into an
  // already-processed member. This leads to a stale pointer that is not marked.

  Persistent<LinkedObject> object1(MakeGarbageCollected<LinkedObject>());
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  // The repro leverages the fact that initializing stores do not emit a barrier
  // (because they are still reachable from stack) to simulate the problematic
  // interleaving.
  driver.TriggerMarkingSteps();
  LinkedObject* object2 =
      MakeGarbageCollected<LinkedObject>(MakeGarbageCollected<LinkedObject>());
  object2->next_ref().Swap(object1->next_ref());
  driver.FinishGC();
  ConservativelyCollectGarbage();
}

namespace {

template <typename T>
class ObjectHolder : public GarbageCollected<ObjectHolder<T>> {
 public:
  ObjectHolder() = default;

  virtual void Trace(Visitor* visitor) const { visitor->Trace(holder_); }

  void set_value(T* value) { holder_ = value; }
  T* value() const { return holder_.Get(); }

 private:
  Member<T> holder_;
};

}  // namespace

TEST_F(IncrementalMarkingTest, StepDuringObjectConstruction) {
  // Test ensures that objects in construction are delayed for processing to
  // allow omitting write barriers on initializing stores.

  using O = ObjectWithCallbackBeforeInitializer<LinkedObject>;
  using Holder = ObjectHolder<O>;
  Persistent<Holder> holder(MakeGarbageCollected<Holder>());
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  MakeGarbageCollected<O>(
      WTF::BindOnce(
          [](IncrementalMarkingTestDriver* driver, Holder* holder, O* thiz) {
            // Publish not-fully-constructed object |thiz| by triggering write
            // barrier for the object.
            holder->set_value(thiz);
            // Finish call incremental steps.
            driver->TriggerMarkingStepsWithStack();
          },
          WTF::Unretained(&driver), WrapWeakPersistent(holder.Get())),
      MakeGarbageCollected<LinkedObject>());
  driver.FinishGC();
  PreciselyCollectGarbage();
}

TEST_F(IncrementalMarkingTest, StepDuringMixinObjectConstruction) {
  // Test ensures that mixin objects in construction are delayed for processing
  // to allow omitting write barriers on initializing stores.

  using Parent = ObjectWithMixinWithCallbackBeforeInitializer<LinkedObject>;
  using Mixin = MixinWithCallbackBeforeInitializer<LinkedObject>;
  using Holder = ObjectHolder<Mixin>;
  Persistent<Holder> holder(MakeGarbageCollected<Holder>());
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  MakeGarbageCollected<Parent>(
      WTF::BindOnce(
          [](IncrementalMarkingTestDriver* driver, Holder* holder,
             Mixin* thiz) {
            // Publish not-fully-constructed object
            // |thiz| by triggering write barrier for
            // the object.
            holder->set_value(thiz);
            // Finish call incremental steps.
            driver->TriggerMarkingStepsWithStack();
          },
          WTF::Unretained(&driver), WrapWeakPersistent(holder.Get())),
      MakeGarbageCollected<LinkedObject>());
  driver.FinishGC();
  PreciselyCollectGarbage();
}

TEST_F(IncrementalMarkingTest, IncrementalMarkingShrinkingBackingCompaction) {
  // Regression test: https://crbug.com/918064

  using Nested = HeapVector<HeapVector<Member<LinkedObject>>>;
  // The following setup will ensure that the outer HeapVector's backing store
  // contains slots to other to-be-compacted backings.
  Persistent<Nested> holder(MakeGarbageCollected<Nested>());
  for (int i = 0; i < 32; i++) {
    holder->emplace_back();
    holder->at(i).emplace_back(MakeGarbageCollected<LinkedObject>());
  }
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  CompactionTestDriver(ThreadState::Current()).ForceCompactionForNextGC();
  driver.StartGC();
  driver.TriggerMarkingSteps();
  // Reduce size of the outer backing store.
  for (int i = 0; i < 16; i++) {
    holder->pop_back();
  }
  // Ensure that shrinking the backing does not crash in compaction as there may
  // be registered slots left in the area that is already freed.
  holder->shrink_to_fit();
  driver.FinishGC();
}

TEST_F(IncrementalMarkingTest,
       InPayloadWriteBarrierRegistersInvalidSlotForCompaction) {
  // Regression test: https://crbug.com/918064

  using Nested = HeapVector<HeapVector<Member<LinkedObject>>>;
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  CompactionTestDriver(ThreadState::Current()).ForceCompactionForNextGC();
  // Allocate a vector and reserve a buffer to avoid triggering the write
  // barrier during incremental marking.
  WeakPersistent<Nested> nested = MakeGarbageCollected<Nested>();
  nested->reserve(32);
  driver.StartGC();
  // Initialize the inner vector, triggering tracing and slots registration.
  // This could be an object using DISALLOW_NEW() but HeapVector is easier to
  // test.
  nested->emplace_back(1);
  // Use the inner vector as otherwise the slot would not be registered due to
  // not having a backing store itself.
  nested->at(0).emplace_back(MakeGarbageCollected<LinkedObject>());
  driver.TriggerMarkingSteps();
  // GCs here are without stack. This is just to show that we don't want this
  // object marked.
  driver.FinishGC();
  EXPECT_FALSE(nested);
}

TEST_F(IncrementalMarkingTest, AdjustMarkedBytesOnMarkedBackingStore) {
  // Regression test: https://crbug.com/966456
  //
  // Test ensures that backing expansion does not crash in trying to adjust
  // marked bytes when the page is actually about to be swept and marking is not
  // in progress.

  // Disable concurrent sweeping to check that sweeping is not in progress after
  // the FinishGC call.
  using Container = HeapVector<Member<LinkedObject>>;
  Persistent<Container> holder(MakeGarbageCollected<Container>());
  WeakPersistent<Container> canary(holder.Get());
  holder->push_back(MakeGarbageCollected<LinkedObject>());
  holder->Grow(16);
  PreciselyCollectGarbage();
  // Slowly shrink down the backing, only adjusting capacity without performing
  // free as the resulting memory block is too small for a free list entry.
  for (int i = 15; i > 0; i--) {
    holder->Shrink(i);
    holder->shrink_to_fit();
  }
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  driver.TriggerMarkingSteps();
  driver.FinishGC();
  CHECK(canary);
  // Re-grow to some size within the initial payload size (capacity=16).
  holder->Grow(8);
}

TEST_F(IncrementalMarkingTest, HeapCompactWithStaleSlotInNestedContainer) {
  // Regression test: https://crbug.com/980962
  //
  // Test ensures that interior pointers are updated even if the backing store
  // itself is not referenced anymore. Consider the case where a |B| is
  // references a value |V| through slot |B.x|. Even if |B| is not referred to
  // from an actual object any more, the slot |B.x| needs to be in valid state
  // when |V| is moved.

  using Nested = HeapVector<HeapVector<Member<LinkedObject>>>;

  // Allocate dummy storage so that other vector backings are actually moved.
  HeapVector<Member<LinkedObject>> unused{MakeGarbageCollected<LinkedObject>()};

  IncrementalMarkingTestDriver driver(ThreadState::Current());
  CompactionTestDriver(ThreadState::Current()).ForceCompactionForNextGC();
  driver.StartGC();
  Nested* outer = MakeGarbageCollected<Nested>();
  outer->push_back(HeapVector<Member<LinkedObject>>());
  outer->at(0).push_back(MakeGarbageCollected<LinkedObject>());
  // The outer HeapVector object is not marked, which leaves the backing store
  // as marked with a valid slot inside. Now, if the outer backing store moves
  // first and its page is freed, then referring to the slot when the inner
  // backing store is moved may crash.
  outer = nullptr;
  driver.TriggerMarkingSteps();
  driver.FinishGC();
}

class Destructed final : public GarbageCollected<Destructed> {
 public:
  ~Destructed() { n_destructed++; }

  void Trace(Visitor*) const {}

  static size_t n_destructed;
};

size_t Destructed::n_destructed = 0;

class LinkedHashSetWrapper final
    : public GarbageCollected<LinkedHashSetWrapper> {
 public:
  using HashType = HeapLinkedHashSet<Member<Destructed>>;

  LinkedHashSetWrapper() {
    for (size_t i = 0; i < 10; ++i) {
      hash_set_.insert(MakeGarbageCollected<Destructed>());
    }
  }

  void Trace(Visitor* v) const { v->Trace(hash_set_); }

  void Swap() {
    HashType hash_set;
    hash_set_.Swap(hash_set);
  }

  HashType hash_set_;
};

TEST_F(IncrementalMarkingTest, LinkedHashSetMovingCallback) {
  ClearOutOldGarbage();

  Destructed::n_destructed = 0;
  {
    HeapHashSet<Member<Destructed>> to_be_destroyed;
    to_be_destroyed.ReserveCapacityForSize(100);
  }
  Persistent<LinkedHashSetWrapper> wrapper =
      MakeGarbageCollected<LinkedHashSetWrapper>();

  IncrementalMarkingTestDriver driver(ThreadState::Current());
  CompactionTestDriver(ThreadState::Current()).ForceCompactionForNextGC();
  driver.StartGC();
  driver.TriggerMarkingSteps();

  // Destroy the link between original HeapLinkedHashSet object and its backing
  // store.
  wrapper->Swap();
  DCHECK(wrapper->hash_set_.empty());

  PreciselyCollectGarbage();

  EXPECT_EQ(10u, Destructed::n_destructed);
}

class DestructedAndTraced final : public GarbageCollected<DestructedAndTraced> {
 public:
  ~DestructedAndTraced() { n_destructed++; }

  void Trace(Visitor*) const { n_traced++; }

  static size_t n_destructed;
  static size_t n_traced;
};

size_t DestructedAndTraced::n_destructed = 0;
size_t DestructedAndTraced::n_traced = 0;

// Flaky <https://crbug.com/1351511>.
#if BUILDFLAG(IS_LINUX)
#define MAYBE_ConservativeGCOfWeakContainer \
  DISABLED_ConservativeGCOfWeakContainer
#else
#define MAYBE_ConservativeGCOfWeakContainer ConservativeGCOfWeakContainer
#endif
TEST_F(IncrementalMarkingTest, MAYBE_ConservativeGCOfWeakContainer) {
  // Regression test: https://crbug.com/1108676
  //
  // Test ensures that on-stack references to weak containers (e.g. iterators)
  // force re-tracing of the entire container. Otherwise, if the container was
  // previously traced and is not re-traced, some bucket might be deleted which
  // will make existing iterators invalid.

  using WeakContainer = HeapHashMap<WeakMember<DestructedAndTraced>, size_t>;
  Persistent<WeakContainer> map = MakeGarbageCollected<WeakContainer>();
  static constexpr size_t kNumObjects = 10u;
  for (size_t i = 0; i < kNumObjects; ++i) {
    map->insert(MakeGarbageCollected<DestructedAndTraced>(), i);
  }
  DestructedAndTraced::n_destructed = 0;

  for (auto it = map->begin(); it != map->end(); ++it) {
    size_t value = it->value;
    DestructedAndTraced::n_traced = 0;
    IncrementalMarkingTestDriver driver(ThreadState::Current());
    driver.StartGC();
    driver.TriggerMarkingSteps();
    // map should now be marked, but has not been traced since it's weak.
    EXPECT_EQ(0u, DestructedAndTraced::n_traced);
    ConservativelyCollectGarbage();
    // map buckets were traced (at least once).
    EXPECT_NE(kNumObjects, DestructedAndTraced::n_traced);
    // Check that iterator is still valid.
    EXPECT_EQ(value, it->value);
  }

  // All buckets were kept alive.
  EXPECT_EQ(0u, DestructedAndTraced::n_destructed);
}

TEST_F(IncrementalMarkingTest,
       WriteBarrierOfWeakContainersStrongifiesBackingStore) {
  // Regression test: https://crbug.com/1244057
  //
  // Test ensures that weak backing stores are strongified as part of their
  // write barrier.
  using WeakMap = HeapHashMap<WeakMember<DestructedAndTraced>, size_t>;
  Persistent<WeakMap> map = MakeGarbageCollected<WeakMap>();
  map->insert(MakeGarbageCollected<DestructedAndTraced>(), 0);
  DestructedAndTraced::n_destructed = 0;
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  driver.StartGC();
  driver.TriggerMarkingSteps();
  {
    WeakMap tmp_map;
    map->swap(tmp_map);
  }
  driver.FinishGC();
  // All buckets were kept alive.
  EXPECT_EQ(0u, DestructedAndTraced::n_destructed);
}

TEST_F(IncrementalMarkingTest, NestedVectorsWithInlineCapacityOnStack) {
  // Regression test: https://crbug.com/339967265
  //
  // Regression test ensures that on-stack nested vectors do not have their
  // backing slot registered for compaction. Registering the slot would result
  // in a nullptr crash.
  IncrementalMarkingTestDriver driver(ThreadState::Current());
  CompactionTestDriver(ThreadState::Current()).ForceCompactionForNextGC();
  // Pre-filled vector to trigger write barrier for backing below.
  HeapVector<int> inner_vector({1});
  driver.StartGC();
  // Vector with inline capacity on stack.
  HeapVector<HeapVector<int>, 1> vector;
  vector.push_back(inner_vector);
  driver.FinishGC();
}

}  // namespace incremental_marking_test
}  // namespace blink
```