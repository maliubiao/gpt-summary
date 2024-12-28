Response:
The user wants a summary of the provided C++ code snippet. The code seems to be a test file (`heap_test.cc`) for a garbage collection mechanism, likely the one used in the Chromium Blink engine.

Here's a breakdown of how to approach this:

1. **Identify the main purpose:** The file tests the functionality of the heap and various data structures that interact with it, such as `HeapHashMap`, `HeapHashSet`, `HeapVector`, etc. It also tests concepts like `Persistent` and `CrossThreadPersistent` which are likely related to keeping objects alive across garbage collection cycles and thread boundaries.

2. **Look for core functionalities being tested:**  The tests involve inserting, deleting, swapping elements in different container types. They also test garbage collection with different levels of aggressiveness (`ConservativelyCollectGarbage`, `PreciselyCollectGarbage`). The presence of `WeakMember` suggests testing weak references and how they behave during garbage collection.

3. **Check for connections to web technologies (JavaScript, HTML, CSS):**  While this is a low-level C++ test, the concepts of memory management and object lifetime are fundamental to JavaScript execution in a browser. Specifically, the garbage collector reclaims memory no longer needed by JavaScript objects. The `Persistent` and `CrossThreadPersistent` concepts might relate to how Blink handles objects shared between the main thread and worker threads, which are common in web applications.

4. **Analyze the test cases and examples:** The code provides numerous test cases. Each `TEST_F` function focuses on a specific aspect of the heap or a container. For example, `TEST_F(HeapTest, MemberContainers)` tests containers with `Member` pointers, `TEST_F(HeapTest, PersistentVector)` tests persistent vectors, etc.

5. **Infer logic and assumptions:** The tests make assertions using `EXPECT_TRUE`, `EXPECT_EQ`, etc. By looking at the operations performed before these assertions, we can infer the expected behavior and the assumptions the tests are making about how the heap and garbage collector should work.

6. **Identify potential user/programmer errors:** The tests implicitly highlight potential errors. For example, not using `Persistent` or `CrossThreadPersistent` correctly might lead to premature garbage collection of objects. Memory leaks could also be a concern if object ownership is not managed correctly.

7. **Focus on the provided snippet (part 2):** The request specifically asks for a summary of the *current* part of the code. Therefore, prioritize summarizing the functionality within this specific section, while keeping the broader context in mind.

**Plan for generating the response:**

* Start with a high-level summary of the file's purpose.
* Detail the specific functionalities tested in this section (container manipulation, garbage collection, `Persistent`, etc.).
* Explain the potential connection to web technologies, focusing on JavaScript garbage collection and cross-thread object management.
* Provide examples of logic and assumptions based on the test cases.
* Give examples of common user/programmer errors related to the tested functionalities.
* Conclude with a concise summary of the provided code snippet (part 2).
这是 blink/renderer/platform/heap/test/heap_test.cc 文件的第 2 部分，主要功能是 **测试 Blink 引擎的堆内存管理机制，特别是各种容器类型在垃圾回收场景下的行为。**  它涵盖了以下几个关键方面：

**1. 测试成员容器（Member Containers）的行为:**

* **功能:**  测试 `HeapHashMap`, `HeapHashSet`, `HeapVector`, `HeapDeque`, `HeapHashCountedSet` 等容器在存储 `Member` 类型（指向垃圾回收对象的智能指针）时的行为。
* **与 JavaScript/HTML/CSS 的关系:** 这些容器是 Blink 引擎内部用于管理各种 DOM 节点、CSS 样式和其他需要在垃圾回收机制下生存的对象的重要数据结构。 例如，一个 `HeapHashMap` 可能被用来存储 CSS 选择器到对应样式规则的映射。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:** 创建几个垃圾回收对象（`IntWrapper`），并将它们添加到不同的成员容器中，例如 `member_member2` (HeapHashMap<Member<IntWrapper>, Member<IntWrapper>>)。
    * **预期输出:** 在进行垃圾回收后，由于存在栈上的指针引用这些对象，它们应该仍然存活。容器的大小和内容应该保持不变。在后续的操作中，测试了 `swap` 操作对容器内容的影响，以及垃圾回收后内容的变化。
* **用户/编程常见的使用错误:**
    * **错误使用 `swap`:**  错误地使用 `swap` 可能会导致容器内部数据错乱，或者意外地释放了本不应该释放的对象。例如，在测试中故意进行了多次 `swap` 来验证其正确性。
    * **未考虑垃圾回收的影响:**  如果开发者直接持有原始指针，而不是使用 `Member` 等智能指针，垃圾回收可能会在对象仍然被使用时释放它们，导致悬 dangling 指针。

**2. 测试持久容器（Persistent Containers）的行为:**

* **功能:** 测试 `Persistent<T>` 模板类，它允许在垃圾回收周期中保持对垃圾回收对象的引用，即使没有栈上的直接引用。
* **与 JavaScript/HTML/CSS 的关系:**  `Persistent` 用于在某些情况下，例如跨越多个 JavaScript 执行阶段或在某些缓存机制中，确保对象不会被过早回收。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:** 创建几个垃圾回收对象，并将它们包装在 `Persistent` 对象中，然后添加到 `Vector<Persistent<IntWrapper>>` 中。
    * **预期输出:**  即使在执行 `ConservativelyCollectGarbage()` 后，由于 `Persistent` 对象的存在，这些 `IntWrapper` 对象仍然存活在容器中。测试还验证了 `swap` 操作在 `Persistent` 容器中的行为。
* **用户/编程常见的使用错误:**
    * **过度使用 `Persistent`:**  如果不必要地使用 `Persistent`，可能会阻止垃圾回收器回收不再使用的对象，导致内存泄漏。
    * **忘记释放 `Persistent`:**  虽然 `Persistent` 可以防止对象被过早回收，但当不再需要时，应该确保 `Persistent` 对象本身被释放，以便它引用的对象最终可以被回收。

**3. 测试跨线程持久容器（CrossThreadPersistent Containers）的行为:**

* **功能:** 测试 `CrossThreadPersistent<T>` 模板类，它类似于 `Persistent`，但被设计为可以在不同的线程之间安全地传递和使用，并保持对垃圾回收对象的引用。
* **与 JavaScript/HTML/CSS 的关系:** 在 Web Workers 等多线程场景中，需要在不同的线程之间传递和共享对象。`CrossThreadPersistent` 确保这些共享对象在垃圾回收时不会出现问题。
* **逻辑推理 (假设输入与输出):**  与 `Persistent` 的测试类似，只是强调了跨线程的安全性。
* **用户/编程常见的使用错误:**
    * **在非线程安全的环境中使用 `Persistent`:**  如果在多线程环境中使用 `Persistent`，可能会导致数据竞争。应该使用 `CrossThreadPersistent`。
    * **忘记在不再需要时清除 `CrossThreadPersistent`:** 类似于 `Persistent`，需要确保及时释放。

**4. 测试堆弱集合（Heap Weak Collections）的行为:**

* **功能:** 测试使用 `WeakMember<T>` 的容器，例如 `HeapHashMap<WeakMember<IntWrapper>, Member<IntWrapper>>`。 `WeakMember` 允许引用一个垃圾回收对象，但不会阻止该对象被回收。当对象被回收后，`WeakMember` 会变为空。
* **与 JavaScript/HTML/CSS 的关系:**  弱引用在实现某些缓存机制、避免循环引用等方面非常有用。例如，一个事件监听器可能对目标 DOM 节点有一个弱引用，以便在 DOM 节点被移除后，监听器也能被清理。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:** 创建 `WeakMember` 指向的垃圾回收对象，并将其添加到弱集合中。
    * **预期输出:** 当没有其他强引用指向这些对象时，执行垃圾回收后，弱集合会自动移除这些已回收的对象。测试验证了不同类型的弱集合（`HeapHashMap`, `HeapHashSet`, `HeapHashCountedSet`) 的行为。
* **用户/编程常见的使用错误:**
    * **错误地认为弱引用会阻止回收:**  弱引用不会阻止垃圾回收。开发者需要理解这一点，并确保在需要对象存活时持有强引用。
    * **访问空的 `WeakMember`:**  在使用 `WeakMember` 之前，需要检查它是否仍然指向一个有效的对象。

**5. 测试 `SelfKeepAlive` 的机制:**

* **功能:**  测试 `SelfKeepAlive` 模板类，它允许垃圾回收对象在自身内部维护一个持久引用，以确保在某些特定场景下不会被过早回收，例如在 RefCountedGarbageCollected 对象中。
* **与 JavaScript/HTML/CSS 的关系:** 这种机制可能用于处理一些特殊的生命周期管理场景，例如需要同时进行引用计数和垃圾回收的对象。
* **逻辑推理 (假设输入与输出):**  测试创建 `RefCountedAndGarbageCollected` 对象，并验证其引用计数和垃圾回收行为。
* **用户/编程常见的使用错误:**
    * **不理解 `SelfKeepAlive` 的用途:**  `SelfKeepAlive` 应该谨慎使用，因为它引入了额外的复杂性。

**6. 测试迭代器对弱集合的影响:**

* **功能:**  测试当迭代器正在遍历弱集合时，是否会阻止垃圾回收器回收这些集合中的对象。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:**  创建一个弱集合并获取其迭代器。在迭代器仍然有效的情况下进行垃圾回收。
    * **预期输出:**  迭代器应该会暂时“增强”对集合中对象的引用，防止它们在迭代期间被回收。

**总结第 2 部分的功能:**

这段代码主要集中于 **测试 Blink 引擎中各种容器类型与垃圾回收机制的集成**。 它深入测试了 `Member` 指针容器、`Persistent` 和 `CrossThreadPersistent` 容器，以及各种弱引用容器的行为，并验证了 `swap` 操作、迭代器以及 `SelfKeepAlive` 机制在垃圾回收场景下的正确性。 这些测试对于确保 Blink 引擎的内存管理稳定性和防止因错误的内存管理导致的崩溃至关重要。 这部分代码体现了 Blink 引擎对内存管理的严谨性，以及对各种复杂场景的充分考虑。

Prompt: 
```
这是目录为blink/renderer/platform/heap/test/heap_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
tWrapper>(4));
      auto* five_c(MakeGarbageCollected<IntWrapper>(5));
      auto* five_d(MakeGarbageCollected<IntWrapper>(5));

      // Member Collections.
      member_member2->insert(one, two);
      member_member2->insert(two, three);
      member_member2->insert(three, four);
      member_member2->insert(four, one);
      primitive_member->insert(1, two);
      primitive_member->insert(2, three);
      primitive_member->insert(3, four);
      primitive_member->insert(4, one);
      member_primitive->insert(one, 2);
      member_primitive->insert(two, 3);
      member_primitive->insert(three, 4);
      member_primitive->insert(four, 1);
      set2->insert(one);
      set2->insert(two);
      set2->insert(three);
      set2->insert(four);
      set->insert(one_b);
      set3->insert(one_b);
      set3->insert(one_b);
      vector->push_back(one_b);
      deque->push_back(one_b);
      vector2->push_back(three_b);
      vector2->push_back(four_b);
      deque2->push_back(three_e);
      deque2->push_back(four_e);
      vector_wu->push_back(PairWrappedUnwrapped(&*one_c, 42));
      vector_wu2->push_back(PairWrappedUnwrapped(&*three_c, 43));
      vector_wu2->push_back(PairWrappedUnwrapped(&*four_c, 44));
      vector_wu2->push_back(PairWrappedUnwrapped(&*five_c, 45));
      vector_uw->push_back(PairUnwrappedWrapped(1, &*one_d));
      vector_uw2->push_back(PairUnwrappedWrapped(103, &*three_d));
      vector_uw2->push_back(PairUnwrappedWrapped(104, &*four_d));
      vector_uw2->push_back(PairUnwrappedWrapped(105, &*five_d));

      EXPECT_TRUE(DequeContains(*deque, one_b));

      // Collect garbage. This should change nothing since we are keeping
      // alive the IntWrapper objects with on-stack pointers.
      ConservativelyCollectGarbage();

      EXPECT_TRUE(DequeContains(*deque, one_b));

      EXPECT_EQ(0u, member_member->size());
      EXPECT_EQ(4u, member_member2->size());
      EXPECT_EQ(4u, primitive_member->size());
      EXPECT_EQ(4u, member_primitive->size());
      EXPECT_EQ(1u, set->size());
      EXPECT_EQ(4u, set2->size());
      EXPECT_EQ(1u, set3->size());
      EXPECT_EQ(1u, vector->size());
      EXPECT_EQ(2u, vector2->size());
      EXPECT_EQ(1u, vector_wu->size());
      EXPECT_EQ(3u, vector_wu2->size());
      EXPECT_EQ(1u, vector_uw->size());
      EXPECT_EQ(3u, vector_uw2->size());
      EXPECT_EQ(1u, deque->size());
      EXPECT_EQ(2u, deque2->size());

      MemberVector& cvec = container->vector;
      cvec.swap(*vector.Get());
      vector2->swap(cvec);
      vector->swap(cvec);

      VectorWU& cvec_wu = container->vector_wu;
      cvec_wu.swap(*vector_wu.Get());
      vector_wu2->swap(cvec_wu);
      vector_wu->swap(cvec_wu);

      VectorUW& cvec_uw = container->vector_uw;
      cvec_uw.swap(*vector_uw.Get());
      vector_uw2->swap(cvec_uw);
      vector_uw->swap(cvec_uw);

      MemberDeque& c_deque = container->deque;
      c_deque.Swap(*deque.Get());
      deque2->Swap(c_deque);
      deque->Swap(c_deque);

      // Swap set and set2 in a roundabout way.
      MemberSet& cset1 = container->set;
      MemberSet& cset2 = container->set2;
      set->swap(cset1);
      set2->swap(cset2);
      set->swap(cset2);
      cset1.swap(cset2);
      cset2.swap(*set2);

      MemberCountedSet& c_counted_set = container->set3;
      set3->swap(c_counted_set);
      EXPECT_EQ(0u, set3->size());
      set3->swap(c_counted_set);

      // Triple swap.
      container->map.swap(*member_member2);
      MemberMember& contained_map = container->map;
      member_member3->swap(contained_map);
      member_member3->swap(*member_member);

      EXPECT_TRUE(member_member->at(one) == two);
      EXPECT_TRUE(member_member->at(two) == three);
      EXPECT_TRUE(member_member->at(three) == four);
      EXPECT_TRUE(member_member->at(four) == one);
      EXPECT_TRUE(primitive_member->at(1) == two);
      EXPECT_TRUE(primitive_member->at(2) == three);
      EXPECT_TRUE(primitive_member->at(3) == four);
      EXPECT_TRUE(primitive_member->at(4) == one);
      EXPECT_EQ(1, member_primitive->at(four));
      EXPECT_EQ(2, member_primitive->at(one));
      EXPECT_EQ(3, member_primitive->at(two));
      EXPECT_EQ(4, member_primitive->at(three));
      EXPECT_TRUE(set->Contains(one));
      EXPECT_TRUE(set->Contains(two));
      EXPECT_TRUE(set->Contains(three));
      EXPECT_TRUE(set->Contains(four));
      EXPECT_TRUE(set2->Contains(one_b));
      EXPECT_TRUE(set3->Contains(one_b));
      EXPECT_TRUE(vector->Contains(three_b));
      EXPECT_TRUE(vector->Contains(four_b));
      EXPECT_TRUE(DequeContains(*deque, three_e));
      EXPECT_TRUE(DequeContains(*deque, four_e));
      EXPECT_TRUE(vector2->Contains(one_b));
      EXPECT_FALSE(vector2->Contains(three_b));
      EXPECT_TRUE(DequeContains(*deque2, one_b));
      EXPECT_FALSE(DequeContains(*deque2, three_e));
      EXPECT_TRUE(vector_wu->Contains(PairWrappedUnwrapped(&*three_c, 43)));
      EXPECT_TRUE(vector_wu->Contains(PairWrappedUnwrapped(&*four_c, 44)));
      EXPECT_TRUE(vector_wu->Contains(PairWrappedUnwrapped(&*five_c, 45)));
      EXPECT_TRUE(vector_wu2->Contains(PairWrappedUnwrapped(&*one_c, 42)));
      EXPECT_FALSE(vector_wu2->Contains(PairWrappedUnwrapped(&*three_c, 43)));
      EXPECT_TRUE(vector_uw->Contains(PairUnwrappedWrapped(103, &*three_d)));
      EXPECT_TRUE(vector_uw->Contains(PairUnwrappedWrapped(104, &*four_d)));
      EXPECT_TRUE(vector_uw->Contains(PairUnwrappedWrapped(105, &*five_d)));
      EXPECT_TRUE(vector_uw2->Contains(PairUnwrappedWrapped(1, &*one_d)));
      EXPECT_FALSE(vector_uw2->Contains(PairUnwrappedWrapped(103, &*three_d)));
    }

    PreciselyCollectGarbage();

    EXPECT_EQ(4u, member_member->size());
    EXPECT_EQ(0u, member_member2->size());
    EXPECT_EQ(4u, primitive_member->size());
    EXPECT_EQ(4u, member_primitive->size());
    EXPECT_EQ(4u, set->size());
    EXPECT_EQ(1u, set2->size());
    EXPECT_EQ(1u, set3->size());
    EXPECT_EQ(2u, vector->size());
    EXPECT_EQ(1u, vector2->size());
    EXPECT_EQ(3u, vector_uw->size());
    EXPECT_EQ(1u, vector2->size());
    EXPECT_EQ(2u, deque->size());
    EXPECT_EQ(1u, deque2->size());
    EXPECT_EQ(1u, deque2->size());

    EXPECT_TRUE(member_member->at(one) == two);
    EXPECT_TRUE(primitive_member->at(1) == two);
    EXPECT_TRUE(primitive_member->at(4) == one);
    EXPECT_EQ(2, member_primitive->at(one));
    EXPECT_EQ(3, member_primitive->at(two));
    EXPECT_TRUE(set->Contains(one));
    EXPECT_TRUE(set->Contains(two));
    EXPECT_FALSE(set->Contains(one_b));
    EXPECT_TRUE(set2->Contains(one_b));
    EXPECT_TRUE(set3->Contains(one_b));
    EXPECT_EQ(2u, set3->find(one_b)->value);
    EXPECT_EQ(3, vector->at(0)->Value());
    EXPECT_EQ(4, vector->at(1)->Value());
    EXPECT_EQ(3, deque->begin()->Get()->Value());
  }

  PreciselyCollectGarbage();
  PreciselyCollectGarbage();

  EXPECT_EQ(4u, member_member->size());
  EXPECT_EQ(4u, primitive_member->size());
  EXPECT_EQ(4u, member_primitive->size());
  EXPECT_EQ(4u, set->size());
  EXPECT_EQ(1u, set2->size());
  EXPECT_EQ(2u, vector->size());
  EXPECT_EQ(1u, vector2->size());
  EXPECT_EQ(3u, vector_wu->size());
  EXPECT_EQ(1u, vector_wu2->size());
  EXPECT_EQ(3u, vector_uw->size());
  EXPECT_EQ(1u, vector_uw2->size());
  EXPECT_EQ(2u, deque->size());
  EXPECT_EQ(1u, deque2->size());
}

TEST_F(HeapTest, PersistentVector) {
  IntWrapper::destructor_calls_ = 0;

  typedef Vector<Persistent<IntWrapper>> PersistentVector;

  Persistent<IntWrapper> one(MakeGarbageCollected<IntWrapper>(1));
  Persistent<IntWrapper> two(MakeGarbageCollected<IntWrapper>(2));
  Persistent<IntWrapper> three(MakeGarbageCollected<IntWrapper>(3));
  Persistent<IntWrapper> four(MakeGarbageCollected<IntWrapper>(4));
  Persistent<IntWrapper> five(MakeGarbageCollected<IntWrapper>(5));
  Persistent<IntWrapper> six(MakeGarbageCollected<IntWrapper>(6));
  {
    PersistentVector vector;
    vector.push_back(one);
    vector.push_back(two);
    ConservativelyCollectGarbage();
    EXPECT_TRUE(vector.Contains(one));
    EXPECT_TRUE(vector.Contains(two));

    vector.push_back(three);
    vector.push_back(four);
    ConservativelyCollectGarbage();
    EXPECT_TRUE(vector.Contains(one));
    EXPECT_TRUE(vector.Contains(two));
    EXPECT_TRUE(vector.Contains(three));
    EXPECT_TRUE(vector.Contains(four));

    vector.Shrink(1);
    ConservativelyCollectGarbage();
    EXPECT_TRUE(vector.Contains(one));
    EXPECT_FALSE(vector.Contains(two));
    EXPECT_FALSE(vector.Contains(three));
    EXPECT_FALSE(vector.Contains(four));
  }
  {
    PersistentVector vector1;
    PersistentVector vector2;

    vector1.push_back(one);
    vector2.push_back(two);
    vector1.swap(vector2);
    ConservativelyCollectGarbage();
    EXPECT_TRUE(vector1.Contains(two));
    EXPECT_TRUE(vector2.Contains(one));
  }
  {
    PersistentVector vector1;
    PersistentVector vector2;

    vector1.push_back(one);
    vector1.push_back(two);
    vector2.push_back(three);
    vector2.push_back(four);
    vector2.push_back(five);
    vector2.push_back(six);
    vector1.swap(vector2);
    ConservativelyCollectGarbage();
    EXPECT_TRUE(vector1.Contains(three));
    EXPECT_TRUE(vector1.Contains(four));
    EXPECT_TRUE(vector1.Contains(five));
    EXPECT_TRUE(vector1.Contains(six));
    EXPECT_TRUE(vector2.Contains(one));
    EXPECT_TRUE(vector2.Contains(two));
  }
}

TEST_F(HeapTest, CrossThreadPersistentVector) {
  IntWrapper::destructor_calls_ = 0;

  typedef Vector<CrossThreadPersistent<IntWrapper>> CrossThreadPersistentVector;

  CrossThreadPersistent<IntWrapper> one(MakeGarbageCollected<IntWrapper>(1));
  CrossThreadPersistent<IntWrapper> two(MakeGarbageCollected<IntWrapper>(2));
  CrossThreadPersistent<IntWrapper> three(MakeGarbageCollected<IntWrapper>(3));
  CrossThreadPersistent<IntWrapper> four(MakeGarbageCollected<IntWrapper>(4));
  CrossThreadPersistent<IntWrapper> five(MakeGarbageCollected<IntWrapper>(5));
  CrossThreadPersistent<IntWrapper> six(MakeGarbageCollected<IntWrapper>(6));
  {
    CrossThreadPersistentVector vector;
    vector.push_back(one);
    vector.push_back(two);
    ConservativelyCollectGarbage();
    EXPECT_TRUE(vector.Contains(one));
    EXPECT_TRUE(vector.Contains(two));

    vector.push_back(three);
    vector.push_back(four);
    ConservativelyCollectGarbage();
    EXPECT_TRUE(vector.Contains(one));
    EXPECT_TRUE(vector.Contains(two));
    EXPECT_TRUE(vector.Contains(three));
    EXPECT_TRUE(vector.Contains(four));

    vector.Shrink(1);
    ConservativelyCollectGarbage();
    EXPECT_TRUE(vector.Contains(one));
    EXPECT_FALSE(vector.Contains(two));
    EXPECT_FALSE(vector.Contains(three));
    EXPECT_FALSE(vector.Contains(four));
  }
  {
    CrossThreadPersistentVector vector1;
    CrossThreadPersistentVector vector2;

    vector1.push_back(one);
    vector2.push_back(two);
    vector1.swap(vector2);
    ConservativelyCollectGarbage();
    EXPECT_TRUE(vector1.Contains(two));
    EXPECT_TRUE(vector2.Contains(one));
  }
  {
    CrossThreadPersistentVector vector1;
    CrossThreadPersistentVector vector2;

    vector1.push_back(one);
    vector1.push_back(two);
    vector2.push_back(three);
    vector2.push_back(four);
    vector2.push_back(five);
    vector2.push_back(six);
    vector1.swap(vector2);
    ConservativelyCollectGarbage();
    EXPECT_TRUE(vector1.Contains(three));
    EXPECT_TRUE(vector1.Contains(four));
    EXPECT_TRUE(vector1.Contains(five));
    EXPECT_TRUE(vector1.Contains(six));
    EXPECT_TRUE(vector2.Contains(one));
    EXPECT_TRUE(vector2.Contains(two));
  }
}

TEST_F(HeapTest, PersistentSet) {
  IntWrapper::destructor_calls_ = 0;

  typedef HashSet<Persistent<IntWrapper>> PersistentSet;

  auto* one_raw = MakeGarbageCollected<IntWrapper>(1);
  Persistent<IntWrapper> one(one_raw);
  Persistent<IntWrapper> one2(one_raw);
  Persistent<IntWrapper> two(MakeGarbageCollected<IntWrapper>(2));
  Persistent<IntWrapper> three(MakeGarbageCollected<IntWrapper>(3));
  Persistent<IntWrapper> four(MakeGarbageCollected<IntWrapper>(4));
  Persistent<IntWrapper> five(MakeGarbageCollected<IntWrapper>(5));
  Persistent<IntWrapper> six(MakeGarbageCollected<IntWrapper>(6));
  {
    PersistentSet set;
    set.insert(one);
    set.insert(two);
    ConservativelyCollectGarbage();
    EXPECT_TRUE(set.Contains(one));
    EXPECT_TRUE(set.Contains(one2));
    EXPECT_TRUE(set.Contains(two));

    set.insert(three);
    set.insert(four);
    ConservativelyCollectGarbage();
    EXPECT_TRUE(set.Contains(one));
    EXPECT_TRUE(set.Contains(two));
    EXPECT_TRUE(set.Contains(three));
    EXPECT_TRUE(set.Contains(four));

    set.clear();
    ConservativelyCollectGarbage();
    EXPECT_FALSE(set.Contains(one));
    EXPECT_FALSE(set.Contains(two));
    EXPECT_FALSE(set.Contains(three));
    EXPECT_FALSE(set.Contains(four));
  }
  {
    PersistentSet set1;
    PersistentSet set2;

    set1.insert(one);
    set2.insert(two);
    set1.swap(set2);
    ConservativelyCollectGarbage();
    EXPECT_TRUE(set1.Contains(two));
    EXPECT_TRUE(set2.Contains(one));
    EXPECT_TRUE(set2.Contains(one2));
  }
}

TEST_F(HeapTest, CrossThreadPersistentSet) {
  IntWrapper::destructor_calls_ = 0;

  typedef HashSet<CrossThreadPersistent<IntWrapper>> CrossThreadPersistentSet;

  auto* one_raw = MakeGarbageCollected<IntWrapper>(1);
  CrossThreadPersistent<IntWrapper> one(one_raw);
  CrossThreadPersistent<IntWrapper> one2(one_raw);
  CrossThreadPersistent<IntWrapper> two(MakeGarbageCollected<IntWrapper>(2));
  CrossThreadPersistent<IntWrapper> three(MakeGarbageCollected<IntWrapper>(3));
  CrossThreadPersistent<IntWrapper> four(MakeGarbageCollected<IntWrapper>(4));
  CrossThreadPersistent<IntWrapper> five(MakeGarbageCollected<IntWrapper>(5));
  CrossThreadPersistent<IntWrapper> six(MakeGarbageCollected<IntWrapper>(6));
  {
    CrossThreadPersistentSet set;
    set.insert(one);
    set.insert(two);
    ConservativelyCollectGarbage();
    EXPECT_TRUE(set.Contains(one));
    EXPECT_TRUE(set.Contains(one2));
    EXPECT_TRUE(set.Contains(two));

    set.insert(three);
    set.insert(four);
    ConservativelyCollectGarbage();
    EXPECT_TRUE(set.Contains(one));
    EXPECT_TRUE(set.Contains(two));
    EXPECT_TRUE(set.Contains(three));
    EXPECT_TRUE(set.Contains(four));

    set.clear();
    ConservativelyCollectGarbage();
    EXPECT_FALSE(set.Contains(one));
    EXPECT_FALSE(set.Contains(two));
    EXPECT_FALSE(set.Contains(three));
    EXPECT_FALSE(set.Contains(four));
  }
  {
    CrossThreadPersistentSet set1;
    CrossThreadPersistentSet set2;

    set1.insert(one);
    set2.insert(two);
    set1.swap(set2);
    ConservativelyCollectGarbage();
    EXPECT_TRUE(set1.Contains(two));
    EXPECT_TRUE(set2.Contains(one));
    EXPECT_TRUE(set2.Contains(one2));
  }
}

namespace {
class NonTrivialObject final : public GarbageCollected<NonTrivialObject> {
 public:
  NonTrivialObject() = default;
  explicit NonTrivialObject(int num) {
    deque_.push_back(MakeGarbageCollected<IntWrapper>(num));
    vector_.push_back(MakeGarbageCollected<IntWrapper>(num));
  }
  void Trace(Visitor* visitor) const {
    visitor->Trace(deque_);
    visitor->Trace(vector_);
  }

 private:
  HeapDeque<Member<IntWrapper>> deque_;
  HeapVector<Member<IntWrapper>> vector_;
};
}  // namespace

TEST_F(HeapTest, HeapHashMapWithInlinedObject) {
  HeapHashMap<int, Member<NonTrivialObject>> map;
  for (int num = 1; num < 1000; num++) {
    NonTrivialObject* object = MakeGarbageCollected<NonTrivialObject>(num);
    map.insert(num, object);
  }
}

TEST_F(HeapTest, HeapWeakCollectionSimple) {
  ClearOutOldGarbage();
  IntWrapper::destructor_calls_ = 0;

  Persistent<HeapVector<Member<IntWrapper>>> keep_numbers_alive =
      MakeGarbageCollected<HeapVector<Member<IntWrapper>>>();

  typedef HeapHashMap<WeakMember<IntWrapper>, Member<IntWrapper>> WeakStrong;
  typedef HeapHashMap<Member<IntWrapper>, WeakMember<IntWrapper>> StrongWeak;
  typedef HeapHashMap<WeakMember<IntWrapper>, WeakMember<IntWrapper>> WeakWeak;
  typedef HeapHashSet<WeakMember<IntWrapper>> WeakSet;
  typedef HeapHashCountedSet<WeakMember<IntWrapper>> WeakCountedSet;

  Persistent<WeakStrong> weak_strong = MakeGarbageCollected<WeakStrong>();
  Persistent<StrongWeak> strong_weak = MakeGarbageCollected<StrongWeak>();
  Persistent<WeakWeak> weak_weak = MakeGarbageCollected<WeakWeak>();
  Persistent<WeakSet> weak_set = MakeGarbageCollected<WeakSet>();
  Persistent<WeakCountedSet> weak_counted_set =
      MakeGarbageCollected<WeakCountedSet>();

  Persistent<IntWrapper> two = MakeGarbageCollected<IntWrapper>(2);

  keep_numbers_alive->push_back(MakeGarbageCollected<IntWrapper>(103));
  keep_numbers_alive->push_back(MakeGarbageCollected<IntWrapper>(10));

  {
    weak_strong->insert(MakeGarbageCollected<IntWrapper>(1), two);
    strong_weak->insert(two, MakeGarbageCollected<IntWrapper>(1));
    weak_weak->insert(two, MakeGarbageCollected<IntWrapper>(42));
    weak_weak->insert(MakeGarbageCollected<IntWrapper>(42), two);
    weak_set->insert(MakeGarbageCollected<IntWrapper>(0));
    weak_set->insert(two);
    weak_set->insert(keep_numbers_alive->at(0));
    weak_set->insert(keep_numbers_alive->at(1));
    weak_counted_set->insert(MakeGarbageCollected<IntWrapper>(0));
    weak_counted_set->insert(two);
    weak_counted_set->insert(two);
    weak_counted_set->insert(two);
    weak_counted_set->insert(keep_numbers_alive->at(0));
    weak_counted_set->insert(keep_numbers_alive->at(1));
    EXPECT_EQ(1u, weak_strong->size());
    EXPECT_EQ(1u, strong_weak->size());
    EXPECT_EQ(2u, weak_weak->size());
    EXPECT_EQ(4u, weak_set->size());
    EXPECT_EQ(4u, weak_counted_set->size());
    EXPECT_EQ(3u, weak_counted_set->find(two)->value);
    weak_counted_set->erase(two);
    EXPECT_EQ(2u, weak_counted_set->find(two)->value);
  }

  keep_numbers_alive->at(0) = nullptr;

  PreciselyCollectGarbage();

  EXPECT_EQ(0u, weak_strong->size());
  EXPECT_EQ(0u, strong_weak->size());
  EXPECT_EQ(0u, weak_weak->size());
  EXPECT_EQ(2u, weak_set->size());
  EXPECT_EQ(2u, weak_counted_set->size());
}

namespace {
template <typename Set>
void OrderedSetHelper(bool strong) {
  IntWrapper::destructor_calls_ = 0;

  Persistent<HeapVector<Member<IntWrapper>>> keep_numbers_alive =
      MakeGarbageCollected<HeapVector<Member<IntWrapper>>>();

  Persistent<Set> set1 = MakeGarbageCollected<Set>();
  Persistent<Set> set2 = MakeGarbageCollected<Set>();

  const Set& const_set = *set1.Get();

  keep_numbers_alive->push_back(MakeGarbageCollected<IntWrapper>(2));
  keep_numbers_alive->push_back(MakeGarbageCollected<IntWrapper>(103));
  keep_numbers_alive->push_back(MakeGarbageCollected<IntWrapper>(10));

  set1->insert(MakeGarbageCollected<IntWrapper>(0));
  set1->insert(keep_numbers_alive->at(0));
  set1->insert(keep_numbers_alive->at(1));
  set1->insert(keep_numbers_alive->at(2));

  set2->clear();
  set2->insert(MakeGarbageCollected<IntWrapper>(42));
  set2->clear();

  EXPECT_EQ(4u, set1->size());
  typename Set::iterator it(set1->begin());
  typename Set::reverse_iterator reverse(set1->rbegin());
  typename Set::const_iterator cit(const_set.begin());
  typename Set::const_reverse_iterator creverse(const_set.rbegin());

  EXPECT_EQ(0, (*it)->Value());
  EXPECT_EQ(0, (*cit)->Value());
  ++it;
  ++cit;
  EXPECT_EQ(2, (*it)->Value());
  EXPECT_EQ(2, (*cit)->Value());
  --it;
  --cit;
  EXPECT_EQ(0, (*it)->Value());
  EXPECT_EQ(0, (*cit)->Value());
  ++it;
  ++cit;
  ++it;
  ++cit;
  EXPECT_EQ(103, (*it)->Value());
  EXPECT_EQ(103, (*cit)->Value());
  ++it;
  ++cit;
  EXPECT_EQ(10, (*it)->Value());
  EXPECT_EQ(10, (*cit)->Value());
  ++it;
  ++cit;

  EXPECT_EQ(10, (*reverse)->Value());
  EXPECT_EQ(10, (*creverse)->Value());
  ++reverse;
  ++creverse;
  EXPECT_EQ(103, (*reverse)->Value());
  EXPECT_EQ(103, (*creverse)->Value());
  --reverse;
  --creverse;
  EXPECT_EQ(10, (*reverse)->Value());
  EXPECT_EQ(10, (*creverse)->Value());
  ++reverse;
  ++creverse;
  ++reverse;
  ++creverse;
  EXPECT_EQ(2, (*reverse)->Value());
  EXPECT_EQ(2, (*creverse)->Value());
  ++reverse;
  ++creverse;
  EXPECT_EQ(0, (*reverse)->Value());
  EXPECT_EQ(0, (*creverse)->Value());
  ++reverse;
  ++creverse;

  EXPECT_EQ(set1->end(), it);
  EXPECT_EQ(const_set.end(), cit);
  EXPECT_EQ(set1->rend(), reverse);
  EXPECT_EQ(const_set.rend(), creverse);

  typename Set::iterator i_x(set2->begin());
  EXPECT_EQ(set2->end(), i_x);

  if (strong)
    set1->erase(keep_numbers_alive->at(0));

  keep_numbers_alive->at(0) = nullptr;

  TestSupportingGC::PreciselyCollectGarbage();

  EXPECT_EQ(2u + (strong ? 1u : 0u), set1->size());

  EXPECT_EQ(2 + (strong ? 0 : 1), IntWrapper::destructor_calls_);

  typename Set::iterator i2(set1->begin());
  if (strong) {
    EXPECT_EQ(0, (*i2)->Value());
    ++i2;
    EXPECT_NE(set1->end(), i2);
  }
  EXPECT_EQ(103, (*i2)->Value());
  ++i2;
  EXPECT_NE(set1->end(), i2);
  EXPECT_EQ(10, (*i2)->Value());
  ++i2;
  EXPECT_EQ(set1->end(), i2);
}
}  // namespace

TEST_F(HeapTest, HeapWeakLinkedHashSet) {
  ClearOutOldGarbage();
  OrderedSetHelper<HeapLinkedHashSet<Member<IntWrapper>>>(true);
  ClearOutOldGarbage();
  OrderedSetHelper<HeapLinkedHashSet<WeakMember<IntWrapper>>>(false);
}

namespace {
template <typename Set>
class SetOwner final : public GarbageCollected<SetOwner<Set>> {
 public:
  SetOwner() = default;
  bool operator==(const SetOwner& other) const { return false; }

  void Trace(Visitor* visitor) const {
    visitor->RegisterWeakCallbackMethod<SetOwner,
                                        &SetOwner::ProcessCustomWeakness>(this);
    visitor->Trace(set_);
  }

  void ProcessCustomWeakness(const LivenessBroker& info) { set_.clear(); }

  Set set_;
};

template <typename Set>
void ClearInWeakProcessingHelper() {
  Persistent<SetOwner<Set>> set = MakeGarbageCollected<SetOwner<Set>>();
  TestSupportingGC::PreciselyCollectGarbage();
}
}  // namespace

TEST_F(HeapTest, ClearInWeakProcessing) {
  ClearOutOldGarbage();
  ClearInWeakProcessingHelper<HeapLinkedHashSet<Member<IntWrapper>>>();
  ClearOutOldGarbage();
  ClearInWeakProcessingHelper<HeapLinkedHashSet<WeakMember<IntWrapper>>>();
}

namespace {
class ThingWithDestructor {
  DISALLOW_NEW();

 public:
  ThingWithDestructor() : x_(kEmptyValue) { live_things_with_destructor_++; }

  ThingWithDestructor(int x) : x_(x) { live_things_with_destructor_++; }

  ThingWithDestructor(const ThingWithDestructor& other) {
    *this = other;
    live_things_with_destructor_++;
  }

  ~ThingWithDestructor() { live_things_with_destructor_--; }

  int Value() { return x_; }

  static int live_things_with_destructor_;

  unsigned GetHash() { return WTF::GetHash(x_); }

 private:
  static const int kEmptyValue = 0;
  int x_;
};
int ThingWithDestructor::live_things_with_destructor_;

// This test class served a more important role while Blink
// was transitioned over to using Oilpan. That required classes
// that were hybrid, both ref-counted and on the Oilpan heap
// (the RefCountedGarbageCollected<> class providing just that.)
//
// There's no current need for having a ref-counted veneer on
// top of a GCed class, but we preserve it here to exercise the
// implementation technique that it used -- keeping an internal
// "keep alive" persistent reference that is set & cleared across
// ref-counting operations.
//
class RefCountedAndGarbageCollected final
    : public GarbageCollected<RefCountedAndGarbageCollected> {
 public:
  RefCountedAndGarbageCollected() = default;
  ~RefCountedAndGarbageCollected() { ++destructor_calls_; }

  void AddRef() {
    if (!ref_count_) [[unlikely]] {
      keep_alive_ = this;
    }
    ++ref_count_;
  }

  void Release() {
    DCHECK_GT(ref_count_, 0);
    if (!--ref_count_)
      keep_alive_.Clear();
  }

  void Trace(Visitor* visitor) const {}

  static int destructor_calls_;

 private:
  int ref_count_ = 0;
  SelfKeepAlive<RefCountedAndGarbageCollected> keep_alive_;
};
int RefCountedAndGarbageCollected::destructor_calls_ = 0;

static void HeapMapDestructorHelper(bool clear_maps) {
  ThingWithDestructor::live_things_with_destructor_ = 0;

  typedef HeapHashMap<WeakMember<IntWrapper>,
                      Member<RefCountedAndGarbageCollected>>
      RefMap;

  typedef HeapHashMap<WeakMember<IntWrapper>, ThingWithDestructor> Map;

  Persistent<Map> map(MakeGarbageCollected<Map>());
  Persistent<RefMap> ref_map(MakeGarbageCollected<RefMap>());

  Persistent<IntWrapper> luck(MakeGarbageCollected<IntWrapper>(103));

  int base_line, ref_base_line;

  {
    Map stack_map;
    RefMap stack_ref_map;

    TestSupportingGC::PreciselyCollectGarbage();
    TestSupportingGC::PreciselyCollectGarbage();

    stack_map.insert(MakeGarbageCollected<IntWrapper>(42),
                     ThingWithDestructor(1729));
    stack_map.insert(luck, ThingWithDestructor(8128));
    stack_ref_map.insert(MakeGarbageCollected<IntWrapper>(42),
                         MakeGarbageCollected<RefCountedAndGarbageCollected>());
    stack_ref_map.insert(luck,
                         MakeGarbageCollected<RefCountedAndGarbageCollected>());

    base_line = ThingWithDestructor::live_things_with_destructor_;
    ref_base_line = RefCountedAndGarbageCollected::destructor_calls_;

    // Although the heap maps are on-stack, we can't expect prompt
    // finalization of the elements, so when they go out of scope here we
    // will not necessarily have called the relevant destructors.
  }

  // The RefCountedAndGarbageCollected things need an extra GC to discover
  // that they are no longer ref counted.
  TestSupportingGC::PreciselyCollectGarbage();
  TestSupportingGC::PreciselyCollectGarbage();
  EXPECT_EQ(base_line - 2, ThingWithDestructor::live_things_with_destructor_);
  EXPECT_EQ(ref_base_line + 2,
            RefCountedAndGarbageCollected::destructor_calls_);

  // Now use maps kept alive with persistents. Here we don't expect any
  // destructors to be called before there have been GCs.

  map->insert(MakeGarbageCollected<IntWrapper>(42), ThingWithDestructor(1729));
  map->insert(luck, ThingWithDestructor(8128));
  ref_map->insert(MakeGarbageCollected<IntWrapper>(42),
                  MakeGarbageCollected<RefCountedAndGarbageCollected>());
  ref_map->insert(luck, MakeGarbageCollected<RefCountedAndGarbageCollected>());

  base_line = ThingWithDestructor::live_things_with_destructor_;
  ref_base_line = RefCountedAndGarbageCollected::destructor_calls_;

  luck.Clear();
  if (clear_maps) {
    map->clear();      // Clear map.
    ref_map->clear();  // Clear map.
  } else {
    map.Clear();      // Clear Persistent handle, not map.
    ref_map.Clear();  // Clear Persistent handle, not map.
    TestSupportingGC::PreciselyCollectGarbage();
    TestSupportingGC::PreciselyCollectGarbage();
  }

  EXPECT_EQ(base_line - 2, ThingWithDestructor::live_things_with_destructor_);

  // Need a GC to make sure that the RefCountedAndGarbageCollected thing
  // noticies it's been decremented to zero.
  TestSupportingGC::PreciselyCollectGarbage();
  EXPECT_EQ(ref_base_line + 2,
            RefCountedAndGarbageCollected::destructor_calls_);
}
}  // namespace

TEST_F(HeapTest, HeapMapDestructor) {
  ClearOutOldGarbage();
  HeapMapDestructorHelper(true);
  ClearOutOldGarbage();
  HeapMapDestructorHelper(false);
}

namespace {
template <typename T>
void MapIteratorCheck(T& it, const T& end, int expected) {
  int found = 0;
  while (it != end) {
    found++;
    int key = it->key->Value();
    int value = it->value->Value();
    EXPECT_TRUE(key >= 0 && key < 1100);
    EXPECT_TRUE(value >= 0 && value < 1100);
    ++it;
  }
  EXPECT_EQ(expected, found);
}

template <typename T>
void SetIteratorCheck(T& it, const T& end, int expected) {
  int found = 0;
  while (it != end) {
    found++;
    int value = (*it)->Value();
    EXPECT_TRUE(value >= 0 && value < 1100);
    ++it;
  }
  EXPECT_EQ(expected, found);
}
}  // namespace

TEST_F(HeapTest, HeapWeakCollectionTypes) {
  IntWrapper::destructor_calls_ = 0;

  typedef HeapHashMap<WeakMember<IntWrapper>, Member<IntWrapper>> WeakStrong;
  typedef HeapHashMap<Member<IntWrapper>, WeakMember<IntWrapper>> StrongWeak;
  typedef HeapHashMap<WeakMember<IntWrapper>, WeakMember<IntWrapper>> WeakWeak;
  typedef HeapHashSet<WeakMember<IntWrapper>> WeakSet;
  typedef HeapLinkedHashSet<WeakMember<IntWrapper>> WeakOrderedSet;

  ClearOutOldGarbage();

  const int kWeakStrongIndex = 0;
  const int kStrongWeakIndex = 1;
  const int kWeakWeakIndex = 2;
  const int kNumberOfMapIndices = 3;
  const int kWeakSetIndex = 3;
  const int kWeakOrderedSetIndex = 4;
  const int kNumberOfCollections = 5;

  for (int test_run = 0; test_run < 4; test_run++) {
    for (int collection_number = 0; collection_number < kNumberOfCollections;
         collection_number++) {
      bool delete_afterwards = (test_run == 1);
      bool add_afterwards = (test_run == 2);
      bool test_that_iterators_make_strong = (test_run == 3);

      // The test doesn't work for strongWeak with deleting because we lost
      // the key from the keepNumbersAlive array, so we can't do the lookup.
      if (delete_afterwards && collection_number == kStrongWeakIndex)
        continue;

      unsigned added = add_afterwards ? 100 : 0;

      Persistent<WeakStrong> weak_strong = MakeGarbageCollected<WeakStrong>();
      Persistent<StrongWeak> strong_weak = MakeGarbageCollected<StrongWeak>();
      Persistent<WeakWeak> weak_weak = MakeGarbageCollected<WeakWeak>();

      Persistent<WeakSet> weak_set = MakeGarbageCollected<WeakSet>();
      Persistent<WeakOrderedSet> weak_ordered_set =
          MakeGarbageCollected<WeakOrderedSet>();

      Persistent<HeapVector<Member<IntWrapper>>> keep_numbers_alive =
          MakeGarbageCollected<HeapVector<Member<IntWrapper>>>();
      for (int i = 0; i < 128; i += 2) {
        auto* wrapped = MakeGarbageCollected<IntWrapper>(i);
        auto* wrapped2 = MakeGarbageCollected<IntWrapper>(i + 1);
        keep_numbers_alive->push_back(wrapped);
        keep_numbers_alive->push_back(wrapped2);
        weak_strong->insert(wrapped, wrapped2);
        strong_weak->insert(wrapped2, wrapped);
        weak_weak->insert(wrapped, wrapped2);
        weak_set->insert(wrapped);
        weak_ordered_set->insert(wrapped);
      }

      EXPECT_EQ(64u, weak_strong->size());
      EXPECT_EQ(64u, strong_weak->size());
      EXPECT_EQ(64u, weak_weak->size());
      EXPECT_EQ(64u, weak_set->size());
      EXPECT_EQ(64u, weak_ordered_set->size());

      // Collect garbage. This should change nothing since we are keeping
      // alive the IntWrapper objects.
      PreciselyCollectGarbage();

      EXPECT_EQ(64u, weak_strong->size());
      EXPECT_EQ(64u, strong_weak->size());
      EXPECT_EQ(64u, weak_weak->size());
      EXPECT_EQ(64u, weak_set->size());
      EXPECT_EQ(64u, weak_ordered_set->size());

      for (int i = 0; i < 128; i += 2) {
        IntWrapper* wrapped = keep_numbers_alive->at(i);
        IntWrapper* wrapped2 = keep_numbers_alive->at(i + 1);
        EXPECT_EQ(wrapped2, weak_strong->at(wrapped));
        EXPECT_EQ(wrapped, strong_weak->at(wrapped2));
        EXPECT_EQ(wrapped2, weak_weak->at(wrapped));
        EXPECT_TRUE(weak_set->Contains(wrapped));
        EXPECT_TRUE(weak_ordered_set->Contains(wrapped));
      }

      for (int i = 0; i < 128; i += 3)
        keep_numbers_alive->at(i) = nullptr;

      if (collection_number != kWeakStrongIndex)
        weak_strong->clear();
      if (collection_number != kStrongWeakIndex)
        strong_weak->clear();
      if (collection_number != kWeakWeakIndex)
        weak_weak->clear();
      if (collection_number != kWeakSetIndex)
        weak_set->clear();
      if (collection_number != kWeakOrderedSetIndex)
        weak_ordered_set->clear();

      if (test_that_iterators_make_strong) {
        WeakStrong::iterator it1 = weak_strong->begin();
        StrongWeak::iterator it2 = strong_weak->begin();
        WeakWeak::iterator it3 = weak_weak->begin();
        WeakSet::iterator it4 = weak_set->begin();
        WeakOrderedSet::iterator it5 = weak_ordered_set->begin();
        // Collect garbage. This should change nothing since the
        // iterators make the collections strong.
        ConservativelyCollectGarbage();
        if (collection_number == kWeakStrongIndex) {
          EXPECT_EQ(64u, weak_strong->size());
          MapIteratorCheck(it1, weak_strong->end(), 64);
        } else if (collection_number == kStrongWeakIndex) {
          EXPECT_EQ(64u, strong_weak->size());
          MapIteratorCheck(it2, strong_weak->end(), 64);
        } else if (collection_number == kWeakWeakIndex) {
          EXPECT_EQ(64u, weak_weak->size());
          MapIteratorCheck(it3, weak_weak->end(), 64);
        } else if (collection_number == kWeakSetIndex) {
          EXPE
"""


```