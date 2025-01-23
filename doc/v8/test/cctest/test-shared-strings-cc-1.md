Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/test/cctest/test-shared-strings.cc`.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The file name `test-shared-strings.cc` strongly suggests the code is testing functionalities related to shared strings in V8.

2. **Analyze individual test cases:** Go through each `UNINITIALIZED_TEST` function. The names of these functions usually hint at the specific feature being tested. Look for keywords like "Promotion", "Transition", "External", "Internalize", "Share".

3. **Group related tests:**  Notice patterns and group tests based on the actions they perform on shared strings (e.g., promotion during GC, transitioning between string types, externalizing, internalizing).

4. **Infer underlying mechanisms:**  Connect the test cases to V8's memory management and string representation. Keywords like "SharedHeap", "NEW_SPACE", "OLD_SPACE", "ExternalString", "ThinString" are important.

5. **Look for setup and checks:** Pay attention to the setup within each test case, including flags being set (`v8_flags.shared_string_table`), object creation (`factory->NewStringFromAsciiChecked`), and assertions (`CHECK`, `CHECK_EQ`). These reveal the preconditions and expected outcomes.

6. **Relate to JavaScript:** Think about how these low-level string manipulations in V8 might manifest in JavaScript behavior. Sharing strings is an optimization, so the JavaScript impact is usually about performance and memory usage, not direct functional differences.

7. **Consider potential errors:**  Based on the tested scenarios (e.g., externalizing, internalizing), think about common mistakes a programmer might make when dealing with external resources or string interning.

8. **Address specific instructions:**  Remember to handle the user's specific questions about `.tq` files, JavaScript examples, input/output, and common errors.

**Self-Correction/Refinement during thought process:**

* **Initial thought:**  Focus heavily on the specific GC types (MinorGC, MajorGC). **Correction:** While important, the core theme is *shared strings* and how they interact with GC. Adjust the focus accordingly.
* **Initial thought:**  Try to provide concrete JavaScript examples for every test. **Correction:** Some tests are very low-level and don't have a direct, simple JavaScript equivalent. Focus on illustrating the *concept* where possible.
* **Initial thought:**  Treat each test case completely independently. **Correction:** Notice the recurring themes and group related tests for a more coherent summary.

By following this process, I can generate a comprehensive and accurate summary of the provided code.
这是对 `v8/test/cctest/test-shared-strings.cc` 源代码的第二部分功能的归纳。

**总功能归纳 (基于提供的第二部分代码片段):**

这部分代码主要测试了 V8 中**共享字符串**在不同垃圾回收 (GC) 场景下的**晋升 (Promotion)**、**转换 (Transition)** 和 **外部化/内部化 (Externalize/Internalize)** 的行为。它验证了当启用共享字符串表 (`v8_flags.shared_string_table = true`) 时，特定类型的字符串（例如，可以原地内部化的字符串）如何在新生代、老年代和共享堆之间移动和转换其表示形式。

**具体功能点:**

* **共享字符串在不同 GC 阶段的晋升:**
    * **`PromotionScavengeToShared`:**  测试新生代 GC (Scavenge) 是否能将可以原地内部化的字符串晋升到共享堆。
    * **`PromotionScavengeOldToShared`:**  测试当老年代对象引用新生代中可以原地内部化的字符串时，新生代 GC 是否能将该字符串晋升到共享堆，并正确记录 OLD_TO_SHARED 的 remember set。
    * **`PromotionMarkCompactNewToShared`:** 测试在标记压缩 (Mark-Compact) 垃圾回收中，当老年代对象引用新生代中可以原地内部化的字符串时，该字符串是否能晋升到共享堆，并正确记录 OLD_TO_SHARED 的 remember set。
    * **`PromotionMarkCompactOldToShared`:** 测试在开启页晋升的标记压缩垃圾回收中，当字符串先从新生代晋升到老年代，然后被引用的情况下，是否能正确晋升到共享堆，并记录 OLD_TO_SHARED 的 remember set。
    * **`PagePromotionRecordingOldToShared`:**  测试在页晋升的情况下，当一个新生代对象引用一个已经存在于共享堆中的字符串时，能否正确记录 OLD_TO_SHARED 的 remember set。

* **共享字符串在 GC 期间的类型转换:**
    * **`InternalizedSharedStringsTransitionDuringGC`:** 测试在垃圾回收期间，已内部化的共享字符串是否会转换为 `ThinString`，并且内部的转发表会被清除。

* **共享和外部化字符串:**
    * **`ShareExternalString`:** 测试是否可以将老年代的外部字符串共享。
    * **`ExternalizeSharedString`:** 测试是否可以将共享字符串外部化，并验证 API 调用是否能正确返回外部资源。

* **外部化和内部化共享字符串的不同组合场景:**
    * **`ExternalizedSharedStringsTransitionDuringGC`:** 测试当共享字符串被外部化后，在 GC 期间是否会转换成 `ExternalString`。
    * **`ExternalizeInternalizedString`:** 测试是否可以将已经内部化的字符串外部化，并验证其哈希值和 API 行为。
    * **`InternalizeSharedExternalString`:** 测试将共享的外部字符串内部化的行为，包括缓存和非缓存的外部字符串的处理，以及后续 GC 后的状态转换（例如，转换为 `EXTERNAL_INTERNALIZED_STRING_TYPE` 或 `ThinString`）。
    * **`ExternalizeAndInternalizeMissSharedString`:** 测试在内部化共享字符串时未命中缓存，然后将其外部化的行为。
    * **`InternalizeHitAndExternalizeSharedString`:** 测试在内部化共享字符串时命中缓存，然后将其外部化的行为。
    * **`InternalizeMissAndExternalizeSharedString`:** 测试在内部化共享字符串时未命中缓存，然后将其外部化的行为。

* **并发外部化共享字符串:**
    * 提供了 `ConcurrentExternalizationThread` 类，用于测试并发地外部化共享字符串的场景，验证在多线程环境下的正确性。

**如果 `v8/test/cctest/test-shared-strings.cc` 以 `.tq` 结尾：**

如果文件以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。Torque 是一种用于定义 V8 内部运行时函数的领域特定语言。在这种情况下，该文件将包含使用 Torque 编写的测试用例或函数实现，用于测试共享字符串的相关功能。

**与 JavaScript 的功能关系：**

这些测试用例验证了 V8 引擎内部如何管理和优化字符串的存储。虽然 JavaScript 开发者通常不会直接接触这些底层的实现细节，但这些优化直接影响着 JavaScript 代码的性能和内存使用。

例如，共享字符串的机制允许在多个上下文或 Isolate 之间共享相同的字符串实例，从而减少内存消耗。字符串的外部化则允许 V8 使用外部的 C++ 缓冲区来存储字符串数据，避免不必要的内存复制。

**JavaScript 例子说明:**

```javascript
// 假设我们创建了两个包含相同字符串的变量
const str1 = "hello";
const str2 = "hello";

// 在 V8 内部，如果启用了共享字符串，并且字符串满足共享的条件，
// 那么 str1 和 str2 可能会指向同一个共享的字符串对象。

// 外部化可以理解为某种程度上的优化，让 V8 可以使用外部资源来存储字符串。
// 这在处理大量文本数据时可能会很有用。

// 内部化可以理解为 V8 维护一个字符串池，确保相同的字符串只有一个实例。
const str3 = "world";
const str4 = "w" + "o" + "r" + "l" + "d";

// 内部化机制会尝试让 str3 和 str4 指向同一个字符串对象。
```

**代码逻辑推理和假设输入输出：**

以 `PromotionScavengeToShared` 测试为例：

* **假设输入:**
    * 启用了共享字符串表 (`v8_flags.shared_string_table = true`)。
    * 创建了一个可以原地内部化的字符串 `"foo"`，分配在新生代。
* **代码逻辑:**
    * 执行新生代 GC (`heap::InvokeMinorGC`)。
* **预期输出:**
    * 字符串 `"foo"` 会被晋升到共享堆 (`heap->SharedHeapContains(*one_byte_seq)` 为真)。

**用户常见的编程错误举例：**

与这部分代码相关的用户常见编程错误可能不多，因为它主要测试 V8 内部机制。但是，理解这些机制可以帮助避免一些潜在的性能问题：

1. **过度创建重复字符串:**  虽然 V8 有共享字符串和内部化机制，但如果程序中大量创建内容相同的字符串，仍然可能对性能产生影响。了解 V8 的这些机制可以帮助开发者意识到字符串重用的重要性。

2. **不理解字符串的生命周期:**  在涉及外部字符串的场景中，如果用户错误地管理外部资源的生命周期（例如，过早释放外部缓冲区），可能会导致 V8 尝试访问无效内存。

**总结本部分功能:**

这部分 `test-shared-strings.cc` 源代码专注于测试 V8 引擎中共享字符串在各种垃圾回收和内存管理场景下的行为，包括晋升、类型转换以及与外部字符串的交互。这些测试确保了 V8 内部字符串管理的正确性和效率，从而间接提升 JavaScript 代码的性能和内存利用率。

### 提示词
```
这是目录为v8/test/cctest/test-shared-strings.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-shared-strings.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
_table = true;
  i::FlagList::EnforceFlagImplications();

  MultiClientIsolateTest test;
  Isolate* i_isolate = test.i_main_isolate();
  Factory* factory = i_isolate->factory();
  Heap* heap = i_isolate->heap();
  // Heap* shared_heap = test.i_shared_isolate()->heap();

  const char raw_one_byte[] = "foo";

  {
    HandleScope scope(i_isolate);

    // heap::SealCurrentObjects(heap);
    // heap::SealCurrentObjects(shared_heap);

    DirectHandle<String> one_byte_seq = factory->NewStringFromAsciiChecked(
        raw_one_byte, AllocationType::kYoung);

    CHECK(String::IsInPlaceInternalizable(*one_byte_seq));
    CHECK(heap->InSpace(*one_byte_seq, NEW_SPACE));

    for (int i = 0; i < 2; i++) {
      heap::InvokeMinorGC(heap);
    }

    // In-place-internalizable strings are promoted into the shared heap when
    // sharing.
    CHECK(heap->SharedHeapContains(*one_byte_seq));
  }
}

UNINITIALIZED_TEST(PromotionScavengeOldToShared) {
  if (v8_flags.minor_ms) {
    // Promoting from new space directly to shared heap is not implemented in
    // MinorMS.
    return;
  }
  if (v8_flags.single_generation) return;
  if (v8_flags.stress_concurrent_allocation) return;

  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  MultiClientIsolateTest test;
  Isolate* i_isolate = test.i_main_isolate();
  Factory* factory = i_isolate->factory();
  Heap* heap = i_isolate->heap();
  ManualGCScope manual_gc(i_isolate);

  const char raw_one_byte[] = "foo";

  {
    HandleScope scope(i_isolate);

    DirectHandle<FixedArray> old_object =
        factory->NewFixedArray(1, AllocationType::kOld);
    MemoryChunk* old_object_chunk = MemoryChunk::FromHeapObject(*old_object);
    CHECK(!old_object_chunk->InYoungGeneration());

    DirectHandle<String> one_byte_seq = factory->NewStringFromAsciiChecked(
        raw_one_byte, AllocationType::kYoung);
    CHECK(String::IsInPlaceInternalizable(*one_byte_seq));
    CHECK(MemoryChunk::FromHeapObject(*one_byte_seq)->InYoungGeneration());

    old_object->set(0, *one_byte_seq);
    ObjectSlot slot = old_object->RawFieldOfFirstElement();
    CHECK(RememberedSet<OLD_TO_NEW>::Contains(
        MutablePageMetadata::cast(
            MutablePageMetadata::cast(old_object_chunk->Metadata())),
        slot.address()));

    for (int i = 0; i < 2; i++) {
      heap::InvokeMinorGC(heap);
    }

    // In-place-internalizable strings are promoted into the shared heap when
    // sharing.
    CHECK(heap->SharedHeapContains(*one_byte_seq));

    // Since the GC promoted that string into shared heap, it also needs to
    // create an OLD_TO_SHARED slot.
    CHECK(RememberedSet<OLD_TO_SHARED>::Contains(
        MutablePageMetadata::cast(old_object_chunk->Metadata()),
        slot.address()));
  }
}

UNINITIALIZED_TEST(PromotionMarkCompactNewToShared) {
  if (v8_flags.single_generation) return;
  if (v8_flags.stress_concurrent_allocation) return;

  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  ManualGCScope manual_gc_scope;
  heap::ManualEvacuationCandidatesSelectionScope
      manual_evacuation_candidate_selection_scope(manual_gc_scope);
  v8_flags.page_promotion = false;

  MultiClientIsolateTest test;
  Isolate* i_isolate = test.i_main_isolate();
  Factory* factory = i_isolate->factory();
  Heap* heap = i_isolate->heap();

  const char raw_one_byte[] = "foo";

  {
    HandleScope scope(i_isolate);

    IndirectHandle<FixedArray> old_object =
        factory->NewFixedArray(1, AllocationType::kOld);
    MemoryChunk* old_object_chunk = MemoryChunk::FromHeapObject(*old_object);
    CHECK(!old_object_chunk->InYoungGeneration());

    IndirectHandle<String> one_byte_seq = factory->NewStringFromAsciiChecked(
        raw_one_byte, AllocationType::kYoung);
    CHECK(String::IsInPlaceInternalizable(*one_byte_seq));
    CHECK(MemoryChunk::FromHeapObject(*one_byte_seq)->InYoungGeneration());

    old_object->set(0, *one_byte_seq);
    ObjectSlot slot = old_object->RawFieldOfFirstElement();
    CHECK(RememberedSet<OLD_TO_NEW>::Contains(
        MutablePageMetadata::cast(old_object_chunk->Metadata()),
        slot.address()));

    {
      // We need to invoke GC without stack, otherwise no compaction is
      // performed.
      DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
      heap::InvokeMajorGC(heap);
    }

    // In-place-internalizable strings are promoted into the shared heap when
    // sharing.
    CHECK(heap->SharedHeapContains(*one_byte_seq));

    // Since the GC promoted that string into shared heap, it also needs to
    // create an OLD_TO_SHARED slot.
    CHECK(RememberedSet<OLD_TO_SHARED>::Contains(
        MutablePageMetadata::cast(old_object_chunk->Metadata()),
        slot.address()));
  }
}

UNINITIALIZED_TEST(PromotionMarkCompactOldToShared) {
  if (v8_flags.stress_concurrent_allocation) return;
  if (!v8_flags.page_promotion) return;
  if (v8_flags.single_generation) {
    // String allocated in old space may be "pretenured" to the shared heap.
    return;
  }

  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  ManualGCScope manual_gc_scope;
  heap::ManualEvacuationCandidatesSelectionScope
      manual_evacuation_candidate_selection_scope(manual_gc_scope);

  MultiClientIsolateTest test;
  Isolate* i_isolate = test.i_main_isolate();
  Factory* factory = i_isolate->factory();
  Heap* heap = i_isolate->heap();

  const char raw_one_byte[] = "foo";

  {
    HandleScope scope(i_isolate);

    IndirectHandle<FixedArray> old_object =
        factory->NewFixedArray(1, AllocationType::kOld);
    MemoryChunk* old_object_chunk = MemoryChunk::FromHeapObject(*old_object);
    CHECK(!old_object_chunk->InYoungGeneration());

    IndirectHandle<String> one_byte_seq = factory->NewStringFromAsciiChecked(
        raw_one_byte, AllocationType::kYoung);
    CHECK(String::IsInPlaceInternalizable(*one_byte_seq));
    CHECK(MemoryChunk::FromHeapObject(*one_byte_seq)->InYoungGeneration());

    DirectHandleVector<FixedArray> handles(i_isolate);
    // Fill the page and do a full GC. Page promotion should kick in and promote
    // the page as is to old space.
    heap::FillCurrentPage(heap->new_space(), &handles);
    heap::InvokeMajorGC(heap);
    // Make sure 'one_byte_seq' is in old space.
    CHECK(!MemoryChunk::FromHeapObject(*one_byte_seq)->InYoungGeneration());
    CHECK(heap->Contains(*one_byte_seq));

    old_object->set(0, *one_byte_seq);
    ObjectSlot slot = old_object->RawFieldOfFirstElement();
    CHECK(!RememberedSet<OLD_TO_NEW>::Contains(
        MutablePageMetadata::cast(old_object_chunk->Metadata()),
        slot.address()));

    heap::ForceEvacuationCandidate(PageMetadata::FromHeapObject(*one_byte_seq));
    {
      // We need to invoke GC without stack, otherwise no compaction is
      // performed.
      DisableConservativeStackScanningScopeForTesting no_stack_scanning(heap);
      heap::InvokeMajorGC(heap);
    }

    // In-place-internalizable strings are promoted into the shared heap when
    // sharing.
    CHECK(heap->SharedHeapContains(*one_byte_seq));

    // Since the GC promoted that string into shared heap, it also needs to
    // create an OLD_TO_SHARED slot.
    CHECK(RememberedSet<OLD_TO_SHARED>::Contains(
        MutablePageMetadata::cast(old_object_chunk->Metadata()),
        slot.address()));
  }
}

UNINITIALIZED_TEST(PagePromotionRecordingOldToShared) {
  if (v8_flags.single_generation) return;
  if (v8_flags.stress_concurrent_allocation) return;

  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  ManualGCScope manual_gc_scope;
  heap::ManualEvacuationCandidatesSelectionScope
      manual_evacuation_candidate_selection_scope(manual_gc_scope);

  MultiClientIsolateTest test;
  Isolate* i_isolate = test.i_main_isolate();
  Factory* factory = i_isolate->factory();
  Heap* heap = i_isolate->heap();

  const char raw_one_byte[] = "foo";

  {
    HandleScope scope(i_isolate);

    DirectHandle<FixedArray> young_object =
        factory->NewFixedArray(1, AllocationType::kYoung);
    CHECK(HeapLayout::InYoungGeneration(*young_object));
    Address young_object_address = young_object->address();

    DirectHandleVector<FixedArray> handles(i_isolate);
    // Make the whole page transition from new->old, getting the buffers
    // processed in the sweeper (relying on marking information) instead of
    // processing during newspace evacuation.
    heap::FillCurrentPage(heap->new_space(), &handles);

    DirectHandle<String> shared_string = factory->NewStringFromAsciiChecked(
        raw_one_byte, AllocationType::kSharedOld);
    CHECK(HeapLayout::InWritableSharedSpace(*shared_string));

    young_object->set(0, *shared_string);

    heap::EmptyNewSpaceUsingGC(heap);

    // Object should get promoted using page promotion, so address should remain
    // the same.
    CHECK(!HeapLayout::InYoungGeneration(*shared_string));
    CHECK_EQ(young_object_address, young_object->address());

    // Since the GC promoted that string into shared heap, it also needs to
    // create an OLD_TO_SHARED slot.
    ObjectSlot slot = young_object->RawFieldOfFirstElement();
    CHECK(RememberedSet<OLD_TO_SHARED>::Contains(
        MutablePageMetadata::FromHeapObject(*young_object), slot.address()));
  }
}

namespace {

void TriggerGCWithTransitions(Heap* heap) {
  v8_flags.transition_strings_during_gc_with_stack = true;
  heap::CollectSharedGarbage(heap);
  v8_flags.transition_strings_during_gc_with_stack = false;
}

}  // namespace

UNINITIALIZED_TEST(InternalizedSharedStringsTransitionDuringGC) {
  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  constexpr int kStrings = 4096;
  constexpr int kLOStrings = 16;

  MultiClientIsolateTest test;
  Isolate* i_isolate = test.i_main_isolate();
  Factory* factory = i_isolate->factory();

  HandleScope scope(i_isolate);

  // Run two times to test that everything is reset correctly during GC.
  for (int run = 0; run < 2; run++) {
    DirectHandle<FixedArray> shared_strings = CreateSharedOneByteStrings(
        i_isolate, factory, kStrings - kLOStrings, kLOStrings, 2, run == 0);

    // Check strings are in the forwarding table after internalization.
    for (int i = 0; i < shared_strings->length(); i++) {
      Handle<String> input_string(Cast<String>(shared_strings->get(i)),
                                  i_isolate);
      Handle<String> interned = factory->InternalizeString(input_string);
      CHECK(input_string->IsShared());
      CHECK(!IsThinString(*input_string));
      CHECK(input_string->HasForwardingIndex(kAcquireLoad));
      CHECK(String::Equals(i_isolate, input_string, interned));
    }

    // Trigger garbage collection on the shared isolate.
    TriggerGCWithTransitions(i_isolate->heap());

    // Check that GC cleared the forwarding table.
    CHECK_EQ(i_isolate->string_forwarding_table()->size(), 0);

    // Check all strings are transitioned to ThinStrings
    for (int i = 0; i < shared_strings->length(); i++) {
      DirectHandle<String> input_string(Cast<String>(shared_strings->get(i)),
                                        i_isolate);
      CHECK(IsThinString(*input_string));
    }
  }
}

UNINITIALIZED_TEST(ShareExternalString) {
  if (v8_flags.single_generation) return;

  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  ExternalResourceFactory resource_factory;
  MultiClientIsolateTest test;
  Isolate* i_isolate1 = test.i_main_isolate();
  Factory* factory1 = i_isolate1->factory();

  HandleScope handle_scope(i_isolate1);

  const char raw_one_byte[] = "external string";

  // External strings in old space can be shared in-place.
  Handle<String> one_byte =
      factory1->NewStringFromAsciiChecked(raw_one_byte, AllocationType::kOld);
  CHECK(!one_byte->IsShared());

  OneByteResource* resource = resource_factory.CreateOneByte(raw_one_byte);
  one_byte->MakeExternal(i_isolate1, resource);
  if (v8_flags.always_use_string_forwarding_table) {
    i_isolate1->heap()->CollectGarbageShared(
        i_isolate1->main_thread_local_heap(),
        GarbageCollectionReason::kTesting);
  }
  CHECK(IsExternalString(*one_byte));
  Handle<ExternalOneByteString> one_byte_external =
      Cast<ExternalOneByteString>(one_byte);
  DirectHandle<String> shared_one_byte =
      ShareAndVerify(i_isolate1, one_byte_external);
  CHECK_EQ(*shared_one_byte, *one_byte);
}

namespace {

void CheckExternalStringResource(
    Handle<String> string, v8::String::ExternalStringResourceBase* resource) {
  const bool is_one_byte = string->IsOneByteRepresentation();
  Local<v8::String> api_string = Utils::ToLocal(string);
  v8::String::Encoding encoding;
  CHECK_EQ(resource, api_string->GetExternalStringResourceBase(&encoding));
  if (is_one_byte) {
    CHECK_EQ(encoding, v8::String::Encoding::ONE_BYTE_ENCODING);
    CHECK_EQ(resource, api_string->GetExternalOneByteStringResource());
  } else {
    CHECK(string->IsTwoByteRepresentation());
    CHECK_EQ(encoding, v8::String::Encoding::TWO_BYTE_ENCODING);
    CHECK_EQ(resource, api_string->GetExternalStringResource());
  }
}

}  // namespace

UNINITIALIZED_TEST(ExternalizeSharedString) {
  if (v8_flags.single_generation) return;

  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  ExternalResourceFactory resource_factory;
  MultiClientIsolateTest test;
  Isolate* i_isolate1 = test.i_main_isolate();
  Factory* factory1 = i_isolate1->factory();

  HandleScope handle_scope(i_isolate1);

  const char raw_one_byte[] = "external string";
  base::uc16 raw_two_byte[] = {2001, 2002, 2003};
  base::Vector<base::uc16> two_byte_vec(raw_two_byte, 3);

  Handle<String> one_byte =
      factory1->NewStringFromAsciiChecked(raw_one_byte, AllocationType::kOld);
  Handle<String> two_byte =
      factory1->NewStringFromTwoByte(two_byte_vec, AllocationType::kOld)
          .ToHandleChecked();
  CHECK(one_byte->IsOneByteRepresentation());
  CHECK(two_byte->IsTwoByteRepresentation());
  CHECK(!one_byte->IsShared());
  CHECK(!two_byte->IsShared());

  Handle<String> shared_one_byte = ShareAndVerify(i_isolate1, one_byte);
  Handle<String> shared_two_byte = ShareAndVerify(i_isolate1, two_byte);

  OneByteResource* one_byte_res = resource_factory.CreateOneByte(raw_one_byte);
  TwoByteResource* two_byte_res = resource_factory.CreateTwoByte(two_byte_vec);
  shared_one_byte->MakeExternal(i_isolate1, one_byte_res);
  shared_two_byte->MakeExternal(i_isolate1, two_byte_res);
  CHECK(!IsExternalString(*shared_one_byte));
  CHECK(!IsExternalString(*shared_two_byte));
  CHECK(shared_one_byte->HasExternalForwardingIndex(kAcquireLoad));
  CHECK(shared_two_byte->HasExternalForwardingIndex(kAcquireLoad));

  // Check that API calls return the resource from the forwarding table.
  CheckExternalStringResource(shared_one_byte, one_byte_res);
  CheckExternalStringResource(shared_two_byte, two_byte_res);
}

UNINITIALIZED_TEST(ExternalizedSharedStringsTransitionDuringGC) {
  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  ExternalResourceFactory resource_factory;
  MultiClientIsolateTest test;

  constexpr int kStrings = 4096;
  constexpr int kLOStrings = 16;

  Isolate* i_isolate = test.i_main_isolate();
  Factory* factory = i_isolate->factory();

  HandleScope scope(i_isolate);

  // Run two times to test that everything is reset correctly during GC.
  for (int run = 0; run < 2; run++) {
    DirectHandle<FixedArray> shared_strings = CreateSharedOneByteStrings(
        i_isolate, factory, kStrings - kLOStrings, kLOStrings,
        sizeof(UncachedExternalString), run == 0);

    // Check strings are in the forwarding table after internalization.
    for (int i = 0; i < shared_strings->length(); i++) {
      DirectHandle<String> input_string(Cast<String>(shared_strings->get(i)),
                                        i_isolate);
      const int length = input_string->length();
      char* buffer = new char[length + 1];
      String::WriteToFlat(*input_string, reinterpret_cast<uint8_t*>(buffer), 0,
                          length);
      OneByteResource* resource =
          resource_factory.CreateOneByte(buffer, length, false);
      CHECK(input_string->MakeExternal(i_isolate, resource));
      CHECK(input_string->IsShared());
      CHECK(!IsExternalString(*input_string));
      CHECK(input_string->HasExternalForwardingIndex(kAcquireLoad));
    }

    // Trigger garbage collection on the shared isolate.
    TriggerGCWithTransitions(i_isolate->heap());

    // Check that GC cleared the forwarding table.
    CHECK_EQ(i_isolate->string_forwarding_table()->size(), 0);

    // Check all strings are transitioned to ExternalStrings
    for (int i = 0; i < shared_strings->length(); i++) {
      DirectHandle<String> input_string(Cast<String>(shared_strings->get(i)),
                                        i_isolate);
      CHECK(IsExternalString(*input_string));
    }
  }
}

UNINITIALIZED_TEST(ExternalizeInternalizedString) {
  if (v8_flags.single_generation) return;

  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  ExternalResourceFactory resource_factory;
  MultiClientIsolateTest test;
  Isolate* i_isolate1 = test.i_main_isolate();
  Factory* factory1 = i_isolate1->factory();

  HandleScope handle_scope(i_isolate1);

  const char raw_one_byte[] = "external string";
  base::uc16 raw_two_byte[] = {2001, 2002, 2003};
  base::Vector<base::uc16> two_byte_vec(raw_two_byte, 3);

  Handle<String> one_byte =
      factory1->NewStringFromAsciiChecked(raw_one_byte, AllocationType::kOld);
  Handle<String> two_byte =
      factory1->NewStringFromTwoByte(two_byte_vec, AllocationType::kOld)
          .ToHandleChecked();
  // Internalize copies, s.t. internalizing the original strings creates a
  // forwarding entry.
  factory1->InternalizeString(
      factory1->NewStringFromAsciiChecked(raw_one_byte));
  factory1->InternalizeString(
      factory1->NewStringFromTwoByte(two_byte_vec).ToHandleChecked());
  Handle<String> one_byte_intern = factory1->InternalizeString(one_byte);
  Handle<String> two_byte_intern = factory1->InternalizeString(two_byte);
  if (v8_flags.always_use_string_forwarding_table) {
    i_isolate1->heap()->CollectGarbageShared(
        i_isolate1->main_thread_local_heap(),
        GarbageCollectionReason::kTesting);
  }
  CHECK(IsThinString(*one_byte));
  CHECK(IsThinString(*two_byte));
  CHECK(one_byte_intern->IsOneByteRepresentation());
  CHECK(two_byte_intern->IsTwoByteRepresentation());
  CHECK(one_byte_intern->IsShared());
  CHECK(two_byte_intern->IsShared());

  uint32_t one_byte_hash = one_byte_intern->hash();
  uint32_t two_byte_hash = two_byte_intern->hash();

  OneByteResource* one_byte_res = resource_factory.CreateOneByte(raw_one_byte);
  TwoByteResource* two_byte_res = resource_factory.CreateTwoByte(two_byte_vec);
  CHECK(one_byte_intern->MakeExternal(i_isolate1, one_byte_res));
  CHECK(two_byte_intern->MakeExternal(i_isolate1, two_byte_res));
  CHECK(!IsExternalString(*one_byte_intern));
  CHECK(!IsExternalString(*two_byte_intern));
  CHECK(one_byte_intern->HasExternalForwardingIndex(kAcquireLoad));
  CHECK(two_byte_intern->HasExternalForwardingIndex(kAcquireLoad));
  // The hash of internalized strings is stored in the forwarding table.
  CHECK_EQ(one_byte_intern->hash(), one_byte_hash);
  CHECK_EQ(two_byte_intern->hash(), two_byte_hash);

  // Check that API calls return the resource from the forwarding table.
  CheckExternalStringResource(one_byte_intern, one_byte_res);
  CheckExternalStringResource(two_byte_intern, two_byte_res);
}

UNINITIALIZED_TEST(InternalizeSharedExternalString) {
  if (v8_flags.single_generation) return;

  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  ExternalResourceFactory resource_factory;
  MultiClientIsolateTest test;
  Isolate* i_isolate1 = test.i_main_isolate();
  Factory* factory1 = i_isolate1->factory();

  HandleScope handle_scope(i_isolate1);

  const char raw_one_byte[] = "external string";
  base::uc16 raw_two_byte[] = {2001, 2002, 2003};
  base::Vector<base::uc16> two_byte_vec(raw_two_byte, 3);

  Handle<String> one_byte =
      factory1->NewStringFromAsciiChecked(raw_one_byte, AllocationType::kOld);
  Handle<String> two_byte =
      factory1->NewStringFromTwoByte(two_byte_vec, AllocationType::kOld)
          .ToHandleChecked();

  Handle<String> shared_one_byte = ShareAndVerify(i_isolate1, one_byte);
  DirectHandle<String> shared_two_byte = ShareAndVerify(i_isolate1, two_byte);

  OneByteResource* one_byte_res = resource_factory.CreateOneByte(raw_one_byte);
  TwoByteResource* two_byte_res = resource_factory.CreateTwoByte(two_byte_vec);
  CHECK(shared_one_byte->MakeExternal(i_isolate1, one_byte_res));
  CHECK(shared_two_byte->MakeExternal(i_isolate1, two_byte_res));
  CHECK(shared_one_byte->HasExternalForwardingIndex(kAcquireLoad));
  CHECK(shared_two_byte->HasExternalForwardingIndex(kAcquireLoad));

  // Trigger GC to externalize the shared string.
  TriggerGCWithTransitions(i_isolate1->heap());

  CHECK(shared_one_byte->IsShared());
  CHECK(IsExternalString(*shared_one_byte));
  CHECK(shared_two_byte->IsShared());
  CHECK(IsExternalString(*shared_two_byte));

  // Shared cached external strings are in-place internalizable.
  DirectHandle<String> one_byte_intern =
      factory1->InternalizeString(shared_one_byte);
  CHECK_EQ(*one_byte_intern, *shared_one_byte);
  CHECK(IsExternalString(*shared_one_byte));
  CHECK(IsInternalizedString(*shared_one_byte));

  // Depending on the architecture/build options the two byte string might be
  // cached or uncached.
  const bool is_uncached =
      two_byte->Size() < static_cast<int>(sizeof(ExternalString));

  if (is_uncached) {
    // Shared uncached external strings are not internalizable. A new internal
    // copy will be created.
    DirectHandle<String> two_byte_intern =
        factory1->InternalizeString(two_byte);
    CHECK_NE(*two_byte_intern, *shared_two_byte);
    CHECK(shared_two_byte->HasInternalizedForwardingIndex(kAcquireLoad));
    CHECK(IsInternalizedString(*two_byte_intern));
    CHECK(!IsExternalString(*two_byte_intern));
  } else {
    DirectHandle<String> two_byte_intern =
        factory1->InternalizeString(two_byte);
    CHECK_EQ(*two_byte_intern, *shared_two_byte);
    CHECK(IsExternalString(*shared_two_byte));
    CHECK(IsInternalizedString(*shared_two_byte));
  }

  // Another GC should create an externalized internalized string of the cached
  // (one byte) string and turn the uncached (two byte) string into a
  // ThinString, disposing the external resource.
  TriggerGCWithTransitions(i_isolate1->heap());

  CHECK_EQ(shared_one_byte->map()->instance_type(),
           InstanceType::EXTERNAL_INTERNALIZED_ONE_BYTE_STRING_TYPE);
  if (is_uncached) {
    CHECK(IsThinString(*shared_two_byte));
    CHECK(two_byte_res->IsDisposed());
  } else {
    CHECK_EQ(shared_two_byte->map()->instance_type(),
             InstanceType::EXTERNAL_INTERNALIZED_TWO_BYTE_STRING_TYPE);
  }
}

UNINITIALIZED_TEST(ExternalizeAndInternalizeMissSharedString) {
  if (v8_flags.single_generation) return;

  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  ExternalResourceFactory resource_factory;
  MultiClientIsolateTest test;
  Isolate* i_isolate1 = test.i_main_isolate();
  Factory* factory1 = i_isolate1->factory();

  HandleScope handle_scope(i_isolate1);

  const char raw_one_byte[] = "external string";

  Handle<String> one_byte =
      factory1->NewStringFromAsciiChecked(raw_one_byte, AllocationType::kOld);
  uint32_t one_byte_hash = one_byte->EnsureHash();

  Handle<String> shared_one_byte = ShareAndVerify(i_isolate1, one_byte);

  OneByteResource* one_byte_res = resource_factory.CreateOneByte(raw_one_byte);

  CHECK(shared_one_byte->MakeExternal(i_isolate1, one_byte_res));
  CHECK(shared_one_byte->HasExternalForwardingIndex(kAcquireLoad));

  DirectHandle<String> one_byte_intern =
      factory1->InternalizeString(shared_one_byte);
  CHECK_EQ(*one_byte_intern, *shared_one_byte);
  CHECK(IsInternalizedString(*shared_one_byte));
  // Check that we have both, a forwarding index and an accessible hash.
  CHECK(shared_one_byte->HasExternalForwardingIndex(kAcquireLoad));
  CHECK(shared_one_byte->HasHashCode());
  CHECK_EQ(shared_one_byte->hash(), one_byte_hash);
}

UNINITIALIZED_TEST(InternalizeHitAndExternalizeSharedString) {
  if (v8_flags.single_generation) return;

  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  ExternalResourceFactory resource_factory;
  MultiClientIsolateTest test;
  Isolate* i_isolate1 = test.i_main_isolate();
  Factory* factory1 = i_isolate1->factory();

  HandleScope handle_scope(i_isolate1);

  const char raw_one_byte[] = "external string";
  base::uc16 raw_two_byte[] = {2001, 2002, 2003};
  base::Vector<base::uc16> two_byte_vec(raw_two_byte, 3);

  Handle<String> one_byte =
      factory1->NewStringFromAsciiChecked(raw_one_byte, AllocationType::kOld);
  Handle<String> two_byte =
      factory1->NewStringFromTwoByte(two_byte_vec, AllocationType::kOld)
          .ToHandleChecked();
  Handle<String> shared_one_byte = ShareAndVerify(i_isolate1, one_byte);
  Handle<String> shared_two_byte = ShareAndVerify(i_isolate1, two_byte);
  // Internalize copies, s.t. internalizing the original strings creates a
  // forwarding entry.
  factory1->InternalizeString(
      factory1->NewStringFromAsciiChecked(raw_one_byte));
  factory1->InternalizeString(
      factory1->NewStringFromTwoByte(two_byte_vec).ToHandleChecked());
  DirectHandle<String> one_byte_intern =
      factory1->InternalizeString(shared_one_byte);
  DirectHandle<String> two_byte_intern =
      factory1->InternalizeString(shared_two_byte);
  CHECK_NE(*one_byte_intern, *shared_one_byte);
  CHECK_NE(*two_byte_intern, *shared_two_byte);
  CHECK(String::IsHashFieldComputed(one_byte_intern->raw_hash_field()));
  CHECK(String::IsHashFieldComputed(two_byte_intern->raw_hash_field()));
  CHECK(shared_one_byte->HasInternalizedForwardingIndex(kAcquireLoad));
  CHECK(shared_two_byte->HasInternalizedForwardingIndex(kAcquireLoad));

  OneByteResource* one_byte_res = resource_factory.CreateOneByte(raw_one_byte);
  TwoByteResource* two_byte_res = resource_factory.CreateTwoByte(two_byte_vec);
  CHECK(shared_one_byte->MakeExternal(i_isolate1, one_byte_res));
  CHECK(shared_two_byte->MakeExternal(i_isolate1, two_byte_res));
  CHECK(shared_one_byte->HasExternalForwardingIndex(kAcquireLoad));
  CHECK(shared_two_byte->HasExternalForwardingIndex(kAcquireLoad));
  CHECK(shared_one_byte->HasInternalizedForwardingIndex(kAcquireLoad));
  CHECK(shared_two_byte->HasInternalizedForwardingIndex(kAcquireLoad));

  // Check that API calls return the resource from the forwarding table.
  CheckExternalStringResource(shared_one_byte, one_byte_res);
  CheckExternalStringResource(shared_two_byte, two_byte_res);
}

UNINITIALIZED_TEST(InternalizeMissAndExternalizeSharedString) {
  if (v8_flags.single_generation) return;

  v8_flags.shared_string_table = true;
  i::FlagList::EnforceFlagImplications();

  ExternalResourceFactory resource_factory;
  MultiClientIsolateTest test;
  Isolate* i_isolate1 = test.i_main_isolate();
  Factory* factory1 = i_isolate1->factory();

  HandleScope handle_scope(i_isolate1);

  const char raw_one_byte[] = "external string";
  base::uc16 raw_two_byte[] = {2001, 2002, 2003};
  base::Vector<base::uc16> two_byte_vec(raw_two_byte, 3);

  Handle<String> one_byte =
      factory1->NewStringFromAsciiChecked(raw_one_byte, AllocationType::kOld);
  Handle<String> two_byte =
      factory1->NewStringFromTwoByte(two_byte_vec, AllocationType::kOld)
          .ToHandleChecked();
  Handle<String> shared_one_byte = ShareAndVerify(i_isolate1, one_byte);
  Handle<String> shared_two_byte = ShareAndVerify(i_isolate1, two_byte);
  DirectHandle<String> one_byte_intern =
      factory1->InternalizeString(shared_one_byte);
  DirectHandle<String> two_byte_intern =
      factory1->InternalizeString(shared_two_byte);
  CHECK_EQ(*one_byte_intern, *shared_one_byte);
  CHECK_EQ(*two_byte_intern, *shared_two_byte);
  CHECK(!shared_one_byte->HasInternalizedForwardingIndex(kAcquireLoad));
  CHECK(!shared_two_byte->HasInternalizedForwardingIndex(kAcquireLoad));

  OneByteResource* one_byte_res = resource_factory.CreateOneByte(raw_one_byte);
  TwoByteResource* two_byte_res = resource_factory.CreateTwoByte(two_byte_vec);
  CHECK(shared_one_byte->MakeExternal(i_isolate1, one_byte_res));
  CHECK(shared_two_byte->MakeExternal(i_isolate1, two_byte_res));
  CHECK(shared_one_byte->HasExternalForwardingIndex(kAcquireLoad));
  CHECK(shared_two_byte->HasExternalForwardingIndex(kAcquireLoad));
  CHECK(one_byte_intern->HasExternalForwardingIndex(kAcquireLoad));
  CHECK(two_byte_intern->HasExternalForwardingIndex(kAcquireLoad));

  // Check that API calls return the resource from the forwarding table.
  CheckExternalStringResource(shared_one_byte, one_byte_res);
  CheckExternalStringResource(shared_two_byte, two_byte_res);
}

class ConcurrentExternalizationThread final
    : public ConcurrentStringThreadBase {
 public:
  ConcurrentExternalizationThread(MultiClientIsolateTest* test,
                                  IndirectHandle<FixedArray> shared_strings,
                                  std::vector<OneByteResource*> resources,
                                  bool share_resources,
                                  ParkingSemaphore* sema_ready,
                                  ParkingSemaphore* sema_execute_start,
                                  ParkingSemaphore* sema_execute_complete)
      : ConcurrentStringThreadBase("ConcurrentExternalizationThread", test,
                                   shared_strings, sema_ready,
                                   sema_execute_start, sema_execute_complete),
        resources_(resources),
        share_resources_(share_resources) {}

  void RunForString(Handle<String> input_string, int counter) override {
    CHECK(input_string->IsShared());
    OneByteResource* resource = Resource(counter);
    if (!input_string->MakeExternal(i_isolate, resource)) {
      if (!share_resources_) {
        resource->Unaccount(reinterpret_cast<v8::Isolate*>(i_isolate));
        resource->Dispose();
      }
    }
    CHECK(input_string->HasForwardingIndex(kAcquireLoad));
  }

  OneByteResource* Resource(int index) const { return resources_[index]; }

 private:
  std::vector<OneByteResource*> resources_;
  const bool share_resources_;
};

namespace {

void CreateExternalResources(Isolate* i_isolate,
                             DirectHandle<FixedArray> strings,
                             std::vector<OneByteResource*>& resources,
                             ExternalResourceFactory& resource_factory) {
  HandleScope scope(i_isolate);
  resources.reserve(strings->length());
  for (int i = 0; i < strings->length(); i++) {
    DirectHandle<String> input_string(Cast<String>(strings->get(i)), i_isolate);
    CHECK(Utils::ToLocal(input_string)
              ->CanMakeExternal(v8::String::Encoding::ONE_BYTE_ENCODING));
    const int length = input_string->length();
    char* buffer = new char[length + 1];
    String::WriteToFlat(*input_string, reinterpret_cast<uint8_t*>(buffer), 0,
                        length);
    resources.push_back(resource_factory.CreateOneByte(buffer, length, false));
  }
}

void CheckStringAndResource(
    Tagged<String> string, int index, bool should_be_alive,
    Tagged<String> deleted_string, bool check_transition, bool shared_resources,
    const std::vector<std::unique_ptr<ConcurrentExternalizationThread>>&
        threads) {
  if (check_transition) {
    if (should_be_alive) {
      CHECK(IsExternalString(string));
    } else {
      CHECK_EQ(string, deleted_string);
    }
  }
  int alive_resources = 0;
  for (size_t t = 0; t < threads.size(); t++) {
    ConcurrentExternalizationThread* thread = threads[t].get();
    if (!thread->Resource(index)->IsDisposed()) {
      alive_resources++;
    }
  }

  // Check exact alive resources only if the string has transitioned, otherwise
  // there can still be multiple resource instances in the forwarding table.
  // Only check no resource is alive if the string is dead.
  const bool check_alive = check_transition || !should_be_alive;
  if (check_alive) {
    size_t expected_alive;
    if (should_be_alive) {
      if (shared_resources) {
        // Since we share the same resource for all threads, we accounted for it
        // in every thread.
        expected_alive = threads.size();
      } else {
        // Check that exactly one resource is alive.
        expected_ali
```