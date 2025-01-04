Response:
The user wants a summary of the provided C++ code snippet, which is part of a test file for the Blink rendering engine's heap management.

I need to identify the main functionalities being tested in this code and relate them to web technologies (JavaScript, HTML, CSS) if applicable. I also need to look for examples of logical reasoning with hypothetical inputs and outputs, as well as common user/programming errors.

The code seems to focus on testing the behavior of different types of garbage-collected collections (maps, sets, deques, vectors) under various conditions, especially concerning weak references and the timing of object destruction.

Here's a breakdown of the key areas I see:

1. **Weak Pointers and Collections:**  The code extensively tests `WeakMember`, `WeakHashSet`, `WeakHashMap`, `WeakSet`, and `WeakOrderedSet`. This relates to how the browser manages objects that might be garbage collected while still being referenced.

2. **Garbage Collection Triggers:** The tests use `PreciselyCollectGarbage()` and `ConservativelyCollectGarbage()` to explicitly trigger garbage collection, allowing verification of collection behavior.

3. **Reference Counting and Garbage Collection Interaction:** The `RefCountedAndGarbageCollected` class demonstrates how reference counting interacts with the garbage collector.

4. **Nested Collections:** The code tests scenarios where garbage-collected collections are nested within each other (e.g., a `HeapVector` inside a `HeapHashMap`).

5. **Element Destruction and Finalization:** The tests check if destructors are called at the expected times during garbage collection.

6. **Ephemerons:**  The code includes tests for "ephemerons," which are weak key-value pairs where the presence of the key determines the liveness of the value.

7. **Binding with Garbage-Collected Objects:**  The `Bind` test verifies that `WTF::BindOnce` correctly handles garbage-collected objects.

8. **Collection Iteration and Modification:** The tests verify the behavior of iterators over garbage-collected collections, particularly after garbage collection cycles.

9. **Move Semantics and Inlined Vectors:** Tests examine the behavior of `HeapVector` with move semantics and inlined storage.

10. **Hash Map Operations with Garbage Collection:** The `GCInHashMapOperations` test checks how hash map operations behave when garbage collection might occur during the operation (e.g., during a copy constructor).

11. **Deque Expansion:**  The `DequeExpand` test verifies the dynamic resizing of `HeapDeque`.

Now, I can start drafting the summary, including connections to web technologies and examples.
这是`blink/renderer/platform/heap/test/heap_test.cc`文件的第三部分，主要集中在测试 Blink 引擎的堆管理机制，特别是关于垃圾回收、弱引用、嵌套集合以及特定数据结构的行为。

**功能归纳:**

这部分代码主要测试了以下 Blink 堆管理和数据结构功能：

1. **弱引用的集合（Weak Collections）的垃圾回收行为:**
   - 测试了 `WeakStrongHashMap`、`StrongWeakHashMap`、`WeakWeakHashMap`、`WeakHashSet` 和 `WeakOrderedSet` 在垃圾回收期间的表现。
   - 验证了当弱引用指向的对象被回收后，这些集合如何更新其内容。
   - 测试了在垃圾回收前后，以及在垃圾回收期间插入和删除元素时，这些集合的大小和迭代器行为。

2. **将堆管理的集合转换为向量 (ToVector):**
   - 测试了如何将 `HeapHashCountedSet` 和 `WeakHeapHashCountedSet` 的内容复制到 `HeapVector` 中。
   - 验证了复制过程中元素的正确性和顺序 (对于 `HeapHashCountedSet`)。

3. **引用计数与垃圾回收的交互:**
   - 通过 `RefCountedAndGarbageCollected` 类测试了引用计数对象如何与垃圾回收机制协同工作。
   - 验证了当引用计数降为零且没有持久引用时，对象最终会被垃圾回收。

4. **嵌套集合的垃圾回收:**
   - 测试了在 `HeapHashMap` 中嵌套 `HeapVector` 和 `HeapDeque` 的情况下，垃圾回收的行为。
   - 验证了内部集合的元素在外部集合被保持存活时不会被回收。
   - 测试了在嵌套 `HeapHashSet` 的场景下的垃圾回收。
   - 测试了 `HeapVector` 中嵌套 `HeapVector` 的情况。

5. **嵌入在向量中的垃圾回收对象:**
   - 测试了当垃圾回收对象直接作为 `HeapVector` 的元素时，垃圾回收的行为。
   - 包括了内联存储和非内联存储的 `HeapVector` 的测试。
   - 涉及继承自含有垃圾回收对象的类的向量。

6. **向量析构函数的调用:**
   - 测试了 `HeapVector` 中元素的析构函数何时被调用。
   - 涵盖了带有虚函数的元素的向量的情况。

7. **析构函数的调用时机:**
   - 测试了当 `HeapHashMap` 清空时，存储的 `unique_ptr` 指向的对象的析构函数是否会被调用。

8. **弱引用的哈希映射的并发修改问题回归测试:**
   - 这是一个回归测试，用于确保在弱引用的哈希映射中插入空值不会导致并发修改问题。

9. **绑定 (Binding) 与垃圾回收对象:**
   - 测试了 `WTF::BindOnce` 如何正确地捕获和管理垃圾回收的对象，确保在闭包执行前对象不会被回收。

10. **嵌套的 Ephemerons (弱键值对):**
    - 测试了 Ephemerons 嵌套在其他 Ephemerons 中的情况。
    - 验证了内部和外部 Ephemerons 的依赖关系和垃圾回收行为。

11. **指向 Ephemerons 的 Ephemerons:**
    - 测试了 Ephemerons 的值是指向其他 Ephemerons 的情况，形成一个链式结构。
    - 验证了当键被回收时，链式 Ephemerons 如何被逐步回收。

12. **Ephemeron 的基本行为:**
    - 测试了 `HeapHashSet` 中存储的弱引用的基本 Ephemeron 行为。
    - 验证了当弱引用指向的对象被回收时，集合中的对应条目会被移除。

13. **间接强引用到弱引用:**
    - 测试了 `HeapHashMap` 中，键是弱引用，值是一个包含强引用成员的对象的场景。
    - 验证了即使通过强引用间接引用，当弱引用指向的对象被回收时，映射中的条目也会被移除。

14. **哈希映射操作中的垃圾回收:**
    - 测试了在 `HeapHashMap` 的插入和删除操作中，如果涉及到分配内存（通过复制构造函数），垃圾回收是否能够正常工作，避免程序崩溃。

15. **双端队列 (Deque) 的扩展:**
    - 测试了 `HeapDeque` 的动态扩展能力。
    - 验证了在频繁添加和删除元素导致缓冲区需要扩展时，`HeapDeque` 能够正确地管理内存和元素。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

虽然这些测试直接针对的是 Blink 引擎的底层堆管理机制，但这些机制对于 JavaScript、HTML 和 CSS 的正常运行至关重要：

* **JavaScript 的垃圾回收:** JavaScript 引擎依赖 Blink 提供的垃圾回收机制来自动管理对象的生命周期。例如，当一个 JavaScript 对象不再被引用时，Blink 的垃圾回收器会回收其内存。这里测试的弱引用集合就与 JavaScript 中 WeakMap 和 WeakSet 的实现原理密切相关，用于存储那些不会阻止垃圾回收的对象引用。
    * **假设输入:** 一个 JavaScript函数创建了一个对象并将其存储在一个 WeakMap 中，之后该对象不再被其他强引用持有。
    * **预期输出:**  经过垃圾回收后，WeakMap 中对应的条目会被移除。

* **HTML 元素的生命周期管理:**  Blink 使用垃圾回收来管理 HTML DOM 元素的生命周期。当一个 HTML 元素从 DOM 树中移除且没有其他强引用时，它最终会被垃圾回收。这里测试的引用计数与垃圾回收的交互，类似于 Blink 如何管理 DOM 节点的引用，确保在不再需要时释放内存。
    * **假设输入:** 一个 HTML 元素通过 JavaScript 从 DOM 中移除。
    * **预期输出:** 如果没有其他 JavaScript 代码持有该元素的引用，该元素最终会被 Blink 的垃圾回收器回收。

* **CSS 样式对象的管理:** 类似地，CSS 样式对象也由 Blink 的垃圾回收器管理。当一个 CSS 规则不再被任何 HTML 元素引用时，其对应的样式对象也应该被回收。
    * **假设输入:**  一个 CSS 样式规则被移除，不再应用于任何 DOM 元素。
    * **预期输出:** 如果没有其他内部引用，与该规则相关的样式对象最终会被垃圾回收。

* **事件监听器:**  弱引用集合也可能用于管理事件监听器，避免因为监听器持有目标对象的强引用而导致内存泄漏。
    * **假设输入:** 一个事件监听器使用弱引用指向监听的目标对象。
    * **预期输出:** 当目标对象被垃圾回收后，即使监听器仍然存在，也不会阻止目标对象的回收。

**逻辑推理的假设输入与输出:**

在测试弱引用集合的垃圾回收行为时，可以进行逻辑推理：

* **假设输入:**
    1. 创建一个 `WeakHashSet`。
    2. 创建两个垃圾回收对象 A 和 B。
    3. 将 A 和 B 的弱引用插入到 `WeakHashSet` 中。
    4. 清除对对象 A 的所有强引用。
    5. 执行垃圾回收。
* **预期输出:**
    1. 垃圾回收后，`WeakHashSet` 的大小应该为 1。
    2. `WeakHashSet` 中应该包含对象 B 的弱引用。
    3. 尝试从 `WeakHashSet` 中强转对象 A 的弱引用应该返回空。

**用户或编程常见的使用错误及举例说明:**

* **忘记清除强引用导致内存泄漏:**  在使用弱引用时，一个常见的错误是仍然持有对原始对象的强引用，导致即使使用了弱引用，对象也无法被垃圾回收，造成内存泄漏。
    * **错误示例:**  一个 JavaScript 对象被存储在一个 WeakMap 中，但同时被一个全局变量引用。即使在 WeakMap 中该对象的引用应该失效，但由于全局变量的强引用，该对象不会被回收。

* **错误地假设弱引用总是立即失效:** 垃圾回收的发生是不确定的，依赖于浏览器的实现和当前内存压力。错误地假设当强引用消失后，弱引用会立即失效，可能会导致程序行为不符合预期。
    * **错误示例:**  一个程序在清除一个对象的强引用后，立即访问该对象在 WeakMap 中对应的值，期望得到 `undefined`，但实际上可能仍然能访问到该对象，直到下一次垃圾回收发生。

* **在析构函数中访问可能已被回收的对象:** 如果一个对象持有另一个对象的弱引用，并在其析构函数中尝试访问该弱引用指向的对象，可能会导致崩溃，因为被弱引用的对象可能已经被回收。

这部分代码通过详尽的测试用例，确保 Blink 引擎的堆管理机制能够正确、高效地工作，这对于构建稳定可靠的 Web 浏览器至关重要。

Prompt: 
```
这是目录为blink/renderer/platform/heap/test/heap_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能

"""
CT_EQ(64u, weak_set->size());
          SetIteratorCheck(it4, weak_set->end(), 64);
        } else if (collection_number == kWeakOrderedSetIndex) {
          EXPECT_EQ(64u, weak_ordered_set->size());
          SetIteratorCheck(it5, weak_ordered_set->end(), 64);
        }
      } else {
        // Collect garbage. This causes weak processing to remove
        // things from the collections.
        PreciselyCollectGarbage();
        unsigned count = 0;
        for (int i = 0; i < 128; i += 2) {
          bool first_alive = keep_numbers_alive->at(i) != nullptr;
          bool second_alive = keep_numbers_alive->at(i + 1) != nullptr;
          if (first_alive && (collection_number == kWeakStrongIndex ||
                              collection_number == kStrongWeakIndex))
            second_alive = true;
          if (first_alive && second_alive &&
              collection_number < kNumberOfMapIndices) {
            if (collection_number == kWeakStrongIndex) {
              if (delete_afterwards) {
                EXPECT_EQ(
                    i + 1,
                    weak_strong->Take(keep_numbers_alive->at(i))->Value());
              }
            } else if (collection_number == kStrongWeakIndex) {
              if (delete_afterwards) {
                EXPECT_EQ(
                    i,
                    strong_weak->Take(keep_numbers_alive->at(i + 1))->Value());
              }
            } else if (collection_number == kWeakWeakIndex) {
              if (delete_afterwards) {
                EXPECT_EQ(i + 1,
                          weak_weak->Take(keep_numbers_alive->at(i))->Value());
              }
            }
            if (!delete_afterwards)
              count++;
          } else if (collection_number == kWeakSetIndex && first_alive) {
            ASSERT_TRUE(weak_set->Contains(keep_numbers_alive->at(i)));
            if (delete_afterwards)
              weak_set->erase(keep_numbers_alive->at(i));
            else
              count++;
          } else if (collection_number == kWeakOrderedSetIndex && first_alive) {
            ASSERT_TRUE(weak_ordered_set->Contains(keep_numbers_alive->at(i)));
            if (delete_afterwards)
              weak_ordered_set->erase(keep_numbers_alive->at(i));
            else
              count++;
          }
        }
        if (add_afterwards) {
          for (int i = 1000; i < 1100; i++) {
            auto* wrapped = MakeGarbageCollected<IntWrapper>(i);
            keep_numbers_alive->push_back(wrapped);
            weak_strong->insert(wrapped, wrapped);
            strong_weak->insert(wrapped, wrapped);
            weak_weak->insert(wrapped, wrapped);
            weak_set->insert(wrapped);
            weak_ordered_set->insert(wrapped);
          }
        }
        if (collection_number == kWeakStrongIndex)
          EXPECT_EQ(count + added, weak_strong->size());
        else if (collection_number == kStrongWeakIndex)
          EXPECT_EQ(count + added, strong_weak->size());
        else if (collection_number == kWeakWeakIndex)
          EXPECT_EQ(count + added, weak_weak->size());
        else if (collection_number == kWeakSetIndex)
          EXPECT_EQ(count + added, weak_set->size());
        else if (collection_number == kWeakOrderedSetIndex)
          EXPECT_EQ(count + added, weak_ordered_set->size());
        WeakStrong::iterator it1 = weak_strong->begin();
        StrongWeak::iterator it2 = strong_weak->begin();
        WeakWeak::iterator it3 = weak_weak->begin();
        WeakSet::iterator it4 = weak_set->begin();
        WeakOrderedSet::iterator it5 = weak_ordered_set->begin();
        MapIteratorCheck(
            it1, weak_strong->end(),
            (collection_number == kWeakStrongIndex ? count : 0) + added);
        MapIteratorCheck(
            it2, strong_weak->end(),
            (collection_number == kStrongWeakIndex ? count : 0) + added);
        MapIteratorCheck(
            it3, weak_weak->end(),
            (collection_number == kWeakWeakIndex ? count : 0) + added);
        SetIteratorCheck(
            it4, weak_set->end(),
            (collection_number == kWeakSetIndex ? count : 0) + added);
        SetIteratorCheck(
            it5, weak_ordered_set->end(),
            (collection_number == kWeakOrderedSetIndex ? count : 0) + added);
      }
      for (unsigned i = 0; i < 128 + added; i++)
        keep_numbers_alive->at(i) = nullptr;
      PreciselyCollectGarbage();
      EXPECT_EQ(0u, weak_strong->size());
      EXPECT_EQ(0u, strong_weak->size());
      EXPECT_EQ(0u, weak_weak->size());
      EXPECT_EQ(0u, weak_set->size());
      EXPECT_EQ(0u, weak_ordered_set->size());
    }
  }
}

TEST_F(HeapTest, HeapHashCountedSetToVector) {
  HeapHashCountedSet<Member<IntWrapper>> set;
  HeapVector<Member<IntWrapper>> vector;
  set.insert(MakeGarbageCollected<IntWrapper>(1));
  set.insert(MakeGarbageCollected<IntWrapper>(1));
  set.insert(MakeGarbageCollected<IntWrapper>(2));

  CopyToVector(set, vector);
  EXPECT_EQ(3u, vector.size());

  Vector<int> int_vector;
  for (const auto& i : vector)
    int_vector.push_back(i->Value());
  std::sort(int_vector.begin(), int_vector.end());
  ASSERT_EQ(3u, int_vector.size());
  EXPECT_EQ(1, int_vector[0]);
  EXPECT_EQ(1, int_vector[1]);
  EXPECT_EQ(2, int_vector[2]);
}

TEST_F(HeapTest, WeakHeapHashCountedSetToVector) {
  HeapHashCountedSet<WeakMember<IntWrapper>> set;
  HeapVector<Member<IntWrapper>> vector;
  set.insert(MakeGarbageCollected<IntWrapper>(1));
  set.insert(MakeGarbageCollected<IntWrapper>(1));
  set.insert(MakeGarbageCollected<IntWrapper>(2));

  CopyToVector(set, vector);
  EXPECT_LE(3u, vector.size());
  for (const auto& i : vector)
    EXPECT_TRUE(i->Value() == 1 || i->Value() == 2);
}

TEST_F(HeapTest, RefCountedGarbageCollected) {
  RefCountedAndGarbageCollected::destructor_calls_ = 0;
  {
    scoped_refptr<RefCountedAndGarbageCollected> ref_ptr3;
    {
      Persistent<RefCountedAndGarbageCollected> persistent;
      {
        Persistent<RefCountedAndGarbageCollected> ref_ptr1 =
            MakeGarbageCollected<RefCountedAndGarbageCollected>();
        Persistent<RefCountedAndGarbageCollected> ref_ptr2 =
            MakeGarbageCollected<RefCountedAndGarbageCollected>();
        PreciselyCollectGarbage();
        EXPECT_EQ(0, RefCountedAndGarbageCollected::destructor_calls_);
        persistent = ref_ptr1.Get();
      }
      // Reference count is zero for both objects but one of
      // them is kept alive by a persistent handle.
      PreciselyCollectGarbage();
      EXPECT_EQ(1, RefCountedAndGarbageCollected::destructor_calls_);
      ref_ptr3 = persistent.Get();
    }
    // The persistent handle is gone but the ref count has been
    // increased to 1.
    PreciselyCollectGarbage();
    EXPECT_EQ(1, RefCountedAndGarbageCollected::destructor_calls_);
  }
  // Both persistent handle is gone and ref count is zero so the
  // object can be collected.
  PreciselyCollectGarbage();
  EXPECT_EQ(2, RefCountedAndGarbageCollected::destructor_calls_);
}

TEST_F(HeapTest, CollectionNesting) {
  ClearOutOldGarbage();
  int k;
  int* key = &k;
  IntWrapper::destructor_calls_ = 0;
  typedef HeapVector<Member<IntWrapper>> IntVector;
  typedef HeapDeque<Member<IntWrapper>> IntDeque;
  HeapHashMap<void*, Member<IntVector>>* map =
      MakeGarbageCollected<HeapHashMap<void*, Member<IntVector>>>();
  HeapHashMap<void*, Member<IntDeque>>* map2 =
      MakeGarbageCollected<HeapHashMap<void*, Member<IntDeque>>>();
  static_assert(WTF::IsTraceable<IntVector>::value,
                "Failed to recognize HeapVector as traceable");
  static_assert(WTF::IsTraceable<IntDeque>::value,
                "Failed to recognize HeapDeque as traceable");

  map->insert(key, MakeGarbageCollected<IntVector>());
  map2->insert(key, MakeGarbageCollected<IntDeque>());

  HeapHashMap<void*, Member<IntVector>>::iterator it = map->find(key);
  EXPECT_EQ(0u, map->at(key)->size());

  HeapHashMap<void*, Member<IntDeque>>::iterator it2 = map2->find(key);
  EXPECT_EQ(0u, map2->at(key)->size());

  it->value->push_back(MakeGarbageCollected<IntWrapper>(42));
  EXPECT_EQ(1u, map->at(key)->size());

  it2->value->push_back(MakeGarbageCollected<IntWrapper>(42));
  EXPECT_EQ(1u, map2->at(key)->size());

  Persistent<HeapHashMap<void*, Member<IntVector>>> keep_alive(map);
  Persistent<HeapHashMap<void*, Member<IntDeque>>> keep_alive2(map2);

  for (int i = 0; i < 100; i++) {
    map->insert(key + 1 + i, MakeGarbageCollected<IntVector>());
    map2->insert(key + 1 + i, MakeGarbageCollected<IntDeque>());
  }

  PreciselyCollectGarbage();

  EXPECT_EQ(1u, map->at(key)->size());
  EXPECT_EQ(1u, map2->at(key)->size());
  EXPECT_EQ(0, IntWrapper::destructor_calls_);

  keep_alive = nullptr;
  PreciselyCollectGarbage();
  EXPECT_EQ(1, IntWrapper::destructor_calls_);
}

TEST_F(HeapTest, CollectionNesting2) {
  ClearOutOldGarbage();
  void* key = &IntWrapper::destructor_calls_;
  IntWrapper::destructor_calls_ = 0;
  typedef HeapHashSet<Member<IntWrapper>> IntSet;
  HeapHashMap<void*, Member<IntSet>>* map =
      MakeGarbageCollected<HeapHashMap<void*, Member<IntSet>>>();

  map->insert(key, MakeGarbageCollected<IntSet>());

  HeapHashMap<void*, Member<IntSet>>::iterator it = map->find(key);
  EXPECT_EQ(0u, map->at(key)->size());

  it->value->insert(MakeGarbageCollected<IntWrapper>(42));
  EXPECT_EQ(1u, map->at(key)->size());

  Persistent<HeapHashMap<void*, Member<IntSet>>> keep_alive(map);
  PreciselyCollectGarbage();
  EXPECT_EQ(1u, map->at(key)->size());
  EXPECT_EQ(0, IntWrapper::destructor_calls_);
}

TEST_F(HeapTest, CollectionNesting3) {
  ClearOutOldGarbage();
  IntWrapper::destructor_calls_ = 0;
  typedef HeapVector<Member<IntWrapper>> IntVector;
  HeapVector<IntVector>* vector = MakeGarbageCollected<HeapVector<IntVector>>();

  vector->push_back(IntVector());

  HeapVector<IntVector>::iterator it = vector->begin();
  EXPECT_EQ(0u, it->size());

  it->push_back(MakeGarbageCollected<IntWrapper>(42));
  EXPECT_EQ(1u, it->size());

  Persistent<HeapVector<IntVector>> keep_alive(vector);
  PreciselyCollectGarbage();
  EXPECT_EQ(1u, it->size());
  EXPECT_EQ(0, IntWrapper::destructor_calls_);
}

namespace {
class SimpleFinalizedObject final
    : public GarbageCollected<SimpleFinalizedObject> {
 public:
  SimpleFinalizedObject() = default;
  ~SimpleFinalizedObject() { ++destructor_calls_; }

  static int destructor_calls_;

  void Trace(Visitor* visitor) const {}
};
int SimpleFinalizedObject::destructor_calls_ = 0;

class VectorObject {
  DISALLOW_NEW();

 public:
  VectorObject() { value_ = MakeGarbageCollected<SimpleFinalizedObject>(); }

  void Trace(Visitor* visitor) const { visitor->Trace(value_); }

 private:
  Member<SimpleFinalizedObject> value_;
};

class VectorObjectInheritedTrace : public VectorObject {};
}  // namespace

}  // namespace blink

WTF_ALLOW_MOVE_INIT_AND_COMPARE_WITH_MEM_FUNCTIONS(blink::VectorObject)
WTF_ALLOW_MOVE_INIT_AND_COMPARE_WITH_MEM_FUNCTIONS(
    blink::VectorObjectInheritedTrace)

namespace blink {

TEST_F(HeapTest, EmbeddedInVector) {
  ClearOutOldGarbage();
  SimpleFinalizedObject::destructor_calls_ = 0;
  {
    Persistent<HeapVector<VectorObject, 2>> inline_vector =
        MakeGarbageCollected<HeapVector<VectorObject, 2>>();
    Persistent<HeapVector<VectorObject>> outline_vector =
        MakeGarbageCollected<HeapVector<VectorObject>>();
    VectorObject i1, i2;
    inline_vector->push_back(i1);
    inline_vector->push_back(i2);

    VectorObject o1, o2;
    outline_vector->push_back(o1);
    outline_vector->push_back(o2);

    Persistent<HeapVector<VectorObjectInheritedTrace>> vector_inherited_trace =
        MakeGarbageCollected<HeapVector<VectorObjectInheritedTrace>>();
    VectorObjectInheritedTrace it1, it2;
    vector_inherited_trace->push_back(it1);
    vector_inherited_trace->push_back(it2);

    PreciselyCollectGarbage();
    EXPECT_EQ(0, SimpleFinalizedObject::destructor_calls_);
  }
  PreciselyCollectGarbage();
  EXPECT_EQ(6, SimpleFinalizedObject::destructor_calls_);
}

namespace {
class InlinedVectorObject {
  DISALLOW_NEW();

 public:
  InlinedVectorObject() = default;
  ~InlinedVectorObject() { destructor_calls_++; }
  void Trace(Visitor* visitor) const {}

  static int destructor_calls_;
};
int InlinedVectorObject::destructor_calls_ = 0;
}  // namespace

}  // namespace blink

WTF_ALLOW_MOVE_AND_INIT_WITH_MEM_FUNCTIONS(blink::InlinedVectorObject)

namespace blink {

namespace {
class InlinedVectorObjectWrapper final
    : public GarbageCollected<InlinedVectorObjectWrapper> {
 public:
  InlinedVectorObjectWrapper() {
    InlinedVectorObject i1, i2;
    vector1_.push_back(i1);
    vector1_.push_back(i2);
    vector2_.push_back(i1);
    vector2_.push_back(i2);  // This allocates an out-of-line buffer.
    vector3_.push_back(i1);
    vector3_.push_back(i2);
  }

  void Trace(Visitor* visitor) const {
    visitor->Trace(vector1_);
    visitor->Trace(vector2_);
    visitor->Trace(vector3_);
  }

 private:
  HeapVector<InlinedVectorObject> vector1_;
  HeapVector<InlinedVectorObject, 1> vector2_;
  HeapVector<InlinedVectorObject, 2> vector3_;
};
}  // namespace

TEST_F(HeapTest, VectorDestructors) {
  ClearOutOldGarbage();
  InlinedVectorObject::destructor_calls_ = 0;
  {
    HeapVector<InlinedVectorObject> vector;
    InlinedVectorObject i1, i2;
    vector.push_back(i1);
    vector.push_back(i2);
  }
  PreciselyCollectGarbage();
  // This is not EXPECT_EQ but EXPECT_LE because a HeapVectorBacking calls
  // destructors for all elements in (not the size but) the capacity of
  // the vector. Thus the number of destructors called becomes larger
  // than the actual number of objects in the vector.
  EXPECT_LE(4, InlinedVectorObject::destructor_calls_);

  InlinedVectorObject::destructor_calls_ = 0;
  {
    HeapVector<InlinedVectorObject, 1> vector;
    InlinedVectorObject i1, i2;
    vector.push_back(i1);
    vector.push_back(i2);  // This allocates an out-of-line buffer.
  }
  PreciselyCollectGarbage();
  EXPECT_LE(4, InlinedVectorObject::destructor_calls_);

  InlinedVectorObject::destructor_calls_ = 0;
  {
    HeapVector<InlinedVectorObject, 2> vector;
    InlinedVectorObject i1, i2;
    vector.push_back(i1);
    vector.push_back(i2);
  }
  PreciselyCollectGarbage();
  EXPECT_LE(4, InlinedVectorObject::destructor_calls_);

  InlinedVectorObject::destructor_calls_ = 0;
  {
    Persistent<InlinedVectorObjectWrapper> vector_wrapper =
        MakeGarbageCollected<InlinedVectorObjectWrapper>();
    ConservativelyCollectGarbage();
    EXPECT_LE(2, InlinedVectorObject::destructor_calls_);
  }
  PreciselyCollectGarbage();
  EXPECT_LE(8, InlinedVectorObject::destructor_calls_);
}

namespace {
class InlinedVectorObjectWithVtable {
  DISALLOW_NEW();

 public:
  InlinedVectorObjectWithVtable() = default;
  virtual ~InlinedVectorObjectWithVtable() { destructor_calls_++; }
  virtual void VirtualMethod() {}
  void Trace(Visitor* visitor) const {}

  static int destructor_calls_;
};
int InlinedVectorObjectWithVtable::destructor_calls_ = 0;

class InlinedVectorObjectWithVtableWrapper final
    : public GarbageCollected<InlinedVectorObjectWithVtableWrapper> {
 public:
  InlinedVectorObjectWithVtableWrapper() {
    InlinedVectorObjectWithVtable i1, i2;
    vector1_.push_back(i1);
    vector1_.push_back(i2);
    vector2_.push_back(i1);
    vector2_.push_back(i2);  // This allocates an out-of-line buffer.
    vector3_.push_back(i1);
    vector3_.push_back(i2);
  }

  void Trace(Visitor* visitor) const {
    visitor->Trace(vector1_);
    visitor->Trace(vector2_);
    visitor->Trace(vector3_);
  }

 private:
  HeapVector<InlinedVectorObjectWithVtable> vector1_;
  HeapVector<InlinedVectorObjectWithVtable, 1> vector2_;
  HeapVector<InlinedVectorObjectWithVtable, 2> vector3_;
};
}  // namespace

// TODO(Oilpan): when Vector.h's contiguous container support no longer disables
// Vector<>s with inline capacity, enable this test.
#if !defined(ANNOTATE_CONTIGUOUS_CONTAINER)
TEST_F(HeapTest, VectorDestructorsWithVtable) {
  ClearOutOldGarbage();
  InlinedVectorObjectWithVtable::destructor_calls_ = 0;
  {
    HeapVector<InlinedVectorObjectWithVtable> vector;
    InlinedVectorObjectWithVtable i1, i2;
    vector.push_back(i1);
    vector.push_back(i2);
  }
  PreciselyCollectGarbage();
  EXPECT_LE(4, InlinedVectorObjectWithVtable::destructor_calls_);

  InlinedVectorObjectWithVtable::destructor_calls_ = 0;
  {
    HeapVector<InlinedVectorObjectWithVtable, 1> vector;
    InlinedVectorObjectWithVtable i1, i2;
    vector.push_back(i1);
    vector.push_back(i2);  // This allocates an out-of-line buffer.
  }
  PreciselyCollectGarbage();
  EXPECT_LE(5, InlinedVectorObjectWithVtable::destructor_calls_);

  InlinedVectorObjectWithVtable::destructor_calls_ = 0;
  {
    HeapVector<InlinedVectorObjectWithVtable, 2> vector;
    InlinedVectorObjectWithVtable i1, i2;
    vector.push_back(i1);
    vector.push_back(i2);
  }
  PreciselyCollectGarbage();
  EXPECT_LE(4, InlinedVectorObjectWithVtable::destructor_calls_);

  InlinedVectorObjectWithVtable::destructor_calls_ = 0;
  {
    Persistent<InlinedVectorObjectWithVtableWrapper> vector_wrapper =
        MakeGarbageCollected<InlinedVectorObjectWithVtableWrapper>();
    ConservativelyCollectGarbage();
    EXPECT_LE(3, InlinedVectorObjectWithVtable::destructor_calls_);
  }
  PreciselyCollectGarbage();
  EXPECT_LE(9, InlinedVectorObjectWithVtable::destructor_calls_);
}
#endif

namespace {
class SimpleClassWithDestructor {
 public:
  SimpleClassWithDestructor() = default;
  ~SimpleClassWithDestructor() { was_destructed_ = true; }
  static bool was_destructed_;
};
bool SimpleClassWithDestructor::was_destructed_;
}  // namespace

TEST_F(HeapTest, DestructorsCalled) {
  HeapHashMap<Member<IntWrapper>, std::unique_ptr<SimpleClassWithDestructor>>
      map;
  SimpleClassWithDestructor* has_destructor = new SimpleClassWithDestructor();
  map.insert(MakeGarbageCollected<IntWrapper>(1),
             base::WrapUnique(has_destructor));
  SimpleClassWithDestructor::was_destructed_ = false;
  map.clear();
  EXPECT_TRUE(SimpleClassWithDestructor::was_destructed_);
}

namespace {
static void AddElementsToWeakMap(
    HeapHashMap<int, WeakMember<IntWrapper>>* map) {
  // Key cannot be zero in hashmap.
  for (int i = 1; i < 11; i++)
    map->insert(i, MakeGarbageCollected<IntWrapper>(i));
}
}  // namespace

// crbug.com/402426
// If it doesn't assert a concurrent modification to the map, then it's passing.
TEST_F(HeapTest, RegressNullIsStrongified) {
  Persistent<HeapHashMap<int, WeakMember<IntWrapper>>> map =
      MakeGarbageCollected<HeapHashMap<int, WeakMember<IntWrapper>>>();
  AddElementsToWeakMap(map);
  HeapHashMap<int, WeakMember<IntWrapper>>::AddResult result =
      map->insert(800, nullptr);
  ConservativelyCollectGarbage();
  result.stored_value->value = MakeGarbageCollected<IntWrapper>(42);
}

namespace {
class SimpleObject : public GarbageCollected<SimpleObject> {
 public:
  SimpleObject() = default;
  virtual void Trace(Visitor* visitor) const {}
  char GetPayload(int i) { return payload[i]; }
  // This virtual method is unused but it is here to make sure
  // that this object has a vtable. This object is used
  // as the super class for objects that also have garbage
  // collected mixins and having a virtual here makes sure
  // that adjustment is needed both for marking and for isAlive
  // checks.
  virtual void VirtualMethod() {}

 protected:
  char payload[64];
};

class Mixin : public GarbageCollectedMixin {
 public:
  void Trace(Visitor* visitor) const override {}

  virtual char GetPayload(int i) { return padding_[i]; }

 protected:
  int padding_[8];
};

class UseMixin : public SimpleObject, public Mixin {
 public:
  UseMixin() {
    // Verify that WTF::IsGarbageCollectedType<> works as expected for mixins.
    static_assert(WTF::IsGarbageCollectedType<UseMixin>::value,
                  "IsGarbageCollectedType<> sanity check failed for GC mixin.");
    trace_count_ = 0;
  }

  static int trace_count_;
  void Trace(Visitor* visitor) const override {
    SimpleObject::Trace(visitor);
    Mixin::Trace(visitor);
    ++trace_count_;
  }
};
int UseMixin::trace_count_ = 0;

class Bar : public GarbageCollected<Bar> {
 public:
  Bar() : magic_(kMagic) { live_++; }

  virtual ~Bar() {
    EXPECT_TRUE(magic_ == kMagic);
    magic_ = 0;
    live_--;
  }
  bool HasBeenFinalized() const { return !magic_; }

  virtual void Trace(Visitor* visitor) const {}
  static unsigned live_;

 protected:
  static const int kMagic = 1337;
  int magic_;
};
unsigned Bar::live_ = 0;

class OffHeapInt : public RefCounted<OffHeapInt> {
  USING_FAST_MALLOC(OffHeapInt);

 public:
  static scoped_refptr<OffHeapInt> Create(int x) {
    return base::AdoptRef(new OffHeapInt(x));
  }

  virtual ~OffHeapInt() { ++destructor_calls_; }

  static int destructor_calls_;

  int Value() const { return x_; }

  bool operator==(const OffHeapInt& other) const {
    return other.Value() == Value();
  }

  unsigned GetHash() { return WTF::GetHash(x_); }
  void VoidFunction() {}

  OffHeapInt() = delete;

 protected:
  explicit OffHeapInt(int x) : x_(x) {}

 private:
  int x_;
};
int OffHeapInt::destructor_calls_ = 0;
}  // namespace

TEST_F(HeapTest, Bind) {
  base::OnceClosure closure =
      WTF::BindOnce(static_cast<void (Bar::*)(Visitor*) const>(&Bar::Trace),
                    WrapPersistent(MakeGarbageCollected<Bar>()), nullptr);
  // OffHeapInt* should not make Persistent.
  base::OnceClosure closure2 =
      WTF::BindOnce(&OffHeapInt::VoidFunction, OffHeapInt::Create(1));
  PreciselyCollectGarbage();
  // The closure should have a persistent handle to the Bar.
  EXPECT_EQ(1u, Bar::live_);

  UseMixin::trace_count_ = 0;
  auto* mixin = MakeGarbageCollected<UseMixin>();
  base::OnceClosure mixin_closure =
      WTF::BindOnce(static_cast<void (Mixin::*)(Visitor*) const>(&Mixin::Trace),
                    WrapPersistent(mixin), nullptr);
  PreciselyCollectGarbage();
  // The closure should have a persistent handle to the mixin.
  EXPECT_LE(1, UseMixin::trace_count_);
}

TEST_F(HeapTest, EphemeronsInEphemerons) {
  typedef HeapHashMap<WeakMember<IntWrapper>, Member<IntWrapper>> InnerMap;
  typedef HeapHashMap<WeakMember<IntWrapper>, Member<InnerMap>> OuterMap;

  for (int keep_outer_alive = 0; keep_outer_alive <= 1; keep_outer_alive++) {
    for (int keep_inner_alive = 0; keep_inner_alive <= 1; keep_inner_alive++) {
      Persistent<OuterMap> outer = MakeGarbageCollected<OuterMap>();
      Persistent<IntWrapper> one = MakeGarbageCollected<IntWrapper>(1);
      Persistent<IntWrapper> two = MakeGarbageCollected<IntWrapper>(2);
      outer->insert(one, MakeGarbageCollected<InnerMap>());
      outer->begin()->value->insert(two, MakeGarbageCollected<IntWrapper>(3));
      EXPECT_EQ(1u, outer->at(one)->size());
      if (!keep_outer_alive)
        one.Clear();
      if (!keep_inner_alive)
        two.Clear();
      PreciselyCollectGarbage();
      if (keep_outer_alive) {
        const InnerMap* inner = outer->at(one);
        if (keep_inner_alive) {
          EXPECT_EQ(1u, inner->size());
          IntWrapper* three = inner->at(two);
          EXPECT_EQ(3, three->Value());
        } else {
          EXPECT_EQ(0u, inner->size());
        }
      } else {
        EXPECT_EQ(0u, outer->size());
      }
      outer->clear();
      Persistent<IntWrapper> deep = MakeGarbageCollected<IntWrapper>(42);
      Persistent<IntWrapper> home = MakeGarbageCollected<IntWrapper>(103);
      Persistent<IntWrapper> composite = MakeGarbageCollected<IntWrapper>(91);
      Persistent<HeapVector<Member<IntWrapper>>> keep_alive =
          MakeGarbageCollected<HeapVector<Member<IntWrapper>>>();
      for (int i = 0; i < 10000; i++) {
        auto* value = MakeGarbageCollected<IntWrapper>(i);
        keep_alive->push_back(value);
        OuterMap::AddResult new_entry =
            outer->insert(value, MakeGarbageCollected<InnerMap>());
        new_entry.stored_value->value->insert(deep, home);
        new_entry.stored_value->value->insert(composite, home);
      }
      composite.Clear();
      PreciselyCollectGarbage();
      EXPECT_EQ(10000u, outer->size());
      for (int i = 0; i < 10000; i++) {
        IntWrapper* value = keep_alive->at(i);
        EXPECT_EQ(1u,
                  outer->at(value)
                      ->size());  // Other one was deleted by weak handling.
        if (i & 1)
          keep_alive->at(i) = nullptr;
      }
      PreciselyCollectGarbage();
      EXPECT_EQ(5000u, outer->size());
    }
  }
}

namespace {
class EphemeronWrapper : public GarbageCollected<EphemeronWrapper> {
 public:
  void Trace(Visitor* visitor) const { visitor->Trace(map_); }

  typedef HeapHashMap<WeakMember<IntWrapper>, Member<EphemeronWrapper>> Map;
  Map& GetMap() { return map_; }

 private:
  Map map_;
};
}  // namespace

TEST_F(HeapTest, EphemeronsPointToEphemerons) {
  Persistent<IntWrapper> key = MakeGarbageCollected<IntWrapper>(42);
  Persistent<IntWrapper> key2 = MakeGarbageCollected<IntWrapper>(103);

  Persistent<EphemeronWrapper> chain;
  for (int i = 0; i < 100; i++) {
    EphemeronWrapper* old_head = chain;
    chain = MakeGarbageCollected<EphemeronWrapper>();
    if (i == 50)
      chain->GetMap().insert(key2, old_head);
    else
      chain->GetMap().insert(key, old_head);
    chain->GetMap().insert(MakeGarbageCollected<IntWrapper>(103),
                           MakeGarbageCollected<EphemeronWrapper>());
  }

  PreciselyCollectGarbage();

  EphemeronWrapper* wrapper = chain;
  for (int i = 0; i < 100; i++) {
    EXPECT_EQ(1u, wrapper->GetMap().size());

    EphemeronWrapper::Map::iterator it;
    if (i == 49)
      it = wrapper->GetMap().find(key2);
    else
      it = wrapper->GetMap().find(key);
    wrapper = it != wrapper->GetMap().end() ? it->value : nullptr;
  }
  EXPECT_EQ(nullptr, wrapper);

  key2.Clear();
  PreciselyCollectGarbage();

  wrapper = chain;
  for (int i = 0; i < 50; i++) {
    EXPECT_EQ(i == 49 ? 0u : 1u, wrapper->GetMap().size());
    auto it = wrapper->GetMap().find(key);
    wrapper = it != wrapper->GetMap().end() ? it->value : nullptr;
  }
  EXPECT_EQ(nullptr, wrapper);

  key.Clear();
  PreciselyCollectGarbage();
  EXPECT_EQ(0u, chain->GetMap().size());
}

TEST_F(HeapTest, Ephemeron) {
  typedef HeapHashSet<WeakMember<IntWrapper>> Set;

  Persistent<Set> set = MakeGarbageCollected<Set>();

  Persistent<IntWrapper> wp1 = MakeGarbageCollected<IntWrapper>(1);
  Persistent<IntWrapper> wp2 = MakeGarbageCollected<IntWrapper>(2);
  Persistent<IntWrapper> pw1 = MakeGarbageCollected<IntWrapper>(3);
  Persistent<IntWrapper> pw2 = MakeGarbageCollected<IntWrapper>(4);

  set->insert(wp1);
  set->insert(wp2);
  set->insert(pw1);
  set->insert(pw2);

  PreciselyCollectGarbage();

  EXPECT_EQ(4u, set->size());

  wp2.Clear();  // Kills all entries in the weakPairMaps except the first.
  pw2.Clear();  // Kills all entries in the pairWeakMaps except the first.

  for (int i = 0; i < 2; i++) {
    PreciselyCollectGarbage();

    EXPECT_EQ(2u, set->size());  // wp1 and pw1.
  }

  wp1.Clear();
  pw1.Clear();

  PreciselyCollectGarbage();

  EXPECT_EQ(0u, set->size());
}

namespace {
class Link1 : public GarbageCollected<Link1> {
 public:
  Link1(IntWrapper* link) : link_(link) {}

  void Trace(Visitor* visitor) const { visitor->Trace(link_); }

  IntWrapper* Link() { return link_.Get(); }

 private:
  Member<IntWrapper> link_;
};
}  // namespace

TEST_F(HeapTest, IndirectStrongToWeak) {
  typedef HeapHashMap<WeakMember<IntWrapper>, Member<Link1>> Map;
  Persistent<Map> map = MakeGarbageCollected<Map>();
  Persistent<IntWrapper> dead_object = MakeGarbageCollected<IntWrapper>(
      100);  // Named for "Drowning by Numbers" (1988).
  Persistent<IntWrapper> life_object = MakeGarbageCollected<IntWrapper>(42);
  map->insert(dead_object, MakeGarbageCollected<Link1>(dead_object));
  map->insert(life_object, MakeGarbageCollected<Link1>(life_object));
  EXPECT_EQ(2u, map->size());
  PreciselyCollectGarbage();
  EXPECT_EQ(2u, map->size());
  EXPECT_EQ(dead_object, map->at(dead_object)->Link());
  EXPECT_EQ(life_object, map->at(life_object)->Link());
  dead_object.Clear();  // Now it can live up to its name.
  PreciselyCollectGarbage();
  EXPECT_EQ(1u, map->size());
  EXPECT_EQ(life_object, map->at(life_object)->Link());
  life_object.Clear();  // Despite its name.
  PreciselyCollectGarbage();
  EXPECT_EQ(0u, map->size());
}

class AllocatesOnAssignment : public GarbageCollected<AllocatesOnAssignment> {
  static constexpr auto kHashTableDeletedValue = cppgc::kSentinelPointer;

 public:
  AllocatesOnAssignment(std::nullptr_t) : value_(nullptr) {}
  AllocatesOnAssignment(int x) : value_(MakeGarbageCollected<IntWrapper>(x)) {}
  AllocatesOnAssignment(IntWrapper* x) : value_(x) {}

  AllocatesOnAssignment& operator=(const AllocatesOnAssignment& x) {
    value_ = x.value_;
    return *this;
  }

  enum DeletedMarker { kDeletedValue };

  AllocatesOnAssignment(const AllocatesOnAssignment& other) {
    TestSupportingGC::ConservativelyCollectGarbage();
    value_ = MakeGarbageCollected<IntWrapper>(other.value_->Value());
  }

  explicit AllocatesOnAssignment(DeletedMarker)
      : value_(kHashTableDeletedValue) {}

  inline bool IsDeleted() const {
    return value_ == cppgc::kSentinelPointer;
  }

  void Trace(Visitor* visitor) const { visitor->Trace(value_); }

  int Value() { return value_->Value(); }

 private:
  Member<IntWrapper> value_;

  friend bool operator==(const AllocatesOnAssignment&,
                         const AllocatesOnAssignment&);
  friend void swap(AllocatesOnAssignment&, AllocatesOnAssignment&);
};

bool operator==(const AllocatesOnAssignment& a,
                const AllocatesOnAssignment& b) {
  if (a.value_)
    return b.value_ && a.value_->Value() == b.value_->Value();
  return !b.value_;
}

void swap(AllocatesOnAssignment& a, AllocatesOnAssignment& b) {
  std::swap(a.value_, b.value_);
}

TEST_F(HeapTest, GCInHashMapOperations) {
  typedef HeapHashMap<Member<AllocatesOnAssignment>,
                      Member<AllocatesOnAssignment>>
      Map;
  Persistent<Map> map = MakeGarbageCollected<Map>();
  IntWrapper* key = MakeGarbageCollected<IntWrapper>(42);
  AllocatesOnAssignment* object =
      MakeGarbageCollected<AllocatesOnAssignment>(key);
  map->insert(object, MakeGarbageCollected<AllocatesOnAssignment>(103));
  map->erase(object);
  for (int i = 0; i < 10; i++) {
    map->insert(MakeGarbageCollected<AllocatesOnAssignment>(i),
                MakeGarbageCollected<AllocatesOnAssignment>(i));
  }
  for (Map::iterator it = map->begin(); it != map->end(); ++it)
    EXPECT_EQ(it->key->Value(), it->value->Value());
}

TEST_F(HeapTest, DequeExpand) {
  // Test expansion of a HeapDeque<>'s buffer.

  typedef HeapDeque<Member<IntWrapper>> IntDeque;

  Persistent<IntDeque> deque = MakeGarbageCollected<IntDeque>();

  // Append a sequence, bringing about repeated expansions of the
  // deque's buffer.
  int i = 0;
  for (; i < 60; ++i)
    deque->push_back(MakeGarbageCollected<IntWrapper>(i));

  EXPECT_EQ(60u, deque->size());
  i = 0;
  for (const auto& int_wrapper : *deque) {
    EXPECT_EQ(i, int_wrapper->Value());
    i++;
  }

  // Remove most of the queued objects and have the buffer's start index
  // 'point' somewhere into the buffer, just behind the end index.
  for (i = 0; i < 50; ++i)
    deque->TakeFirst();

  EXPECT_EQ(10u, deque->size());
  i = 0;
  for (const auto& int_wrapper : *deque) {
    EXPECT_EQ(50 + i, int_wrapper->Value());
    i++;
  }

  // Append even more, eventually causing an expansion of the underlying
  // buffer once the end index wraps around and reaches the start index.
  for (i = 0; i < 70; ++i)
    deque->push_back(MakeGarbageCollected<IntWrapper>(60 + i));

  // Verify that the final buffer expansion copied the start and end segments
  // of the old buffer to both ends of the expanded buffer, along with
  // re-adjusting both start&end indices in terms of that expanded buffer.
  EXPECT_EQ(80u, deque->size());
  i = 0;
  for (const auto& int_wrapper : *deque) {
    EXPECT_EQ(i + 50, int_wrapper->Value());
    i++;
  }
}

namespace {
class SimpleRefValue : public RefCounted<SimpleRefValue> {
 public:
  static scoped_refptr<SimpleRefValue> Create(int i) {
    return base::AdoptRef(new SimpleRefValue(i));
  }

  int Value() const { return value_; }

 private:
  explicit SimpleRefValue(int value) : value_(value) {}

  int value_;
};

class PartObjectWithRef {
  DISALLOW_NEW();

 public:
  PartObjectWithRef(int i) : value_(SimpleRefValue::Create(i)) {}

  void Trace(Visitor* visitor) const {}

  int Value() const { return value_->Value(); }

 private:
  scoped_refptr<SimpleRefValue> value_;
};
}  // namespace

}  // namespa
"""


```