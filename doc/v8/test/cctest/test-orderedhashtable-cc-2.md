Response:
The user wants a summary of the provided C++ code snippet, which is part of the V8 JavaScript engine's test suite. The code specifically tests the functionality of ordered hash tables.

Here's a breakdown of the thought process to generate the response:

1. **Identify the Core Subject:** The file name `test-orderedhashtable.cc` and the repeated use of terms like `OrderedNameDictionary`, `SmallOrderedNameDictionary`, `OrderedHashMap`, and `OrderedHashSet` clearly indicate the code is about testing ordered hash table implementations within V8.

2. **Recognize the Testing Context:**  The code uses the `TEST()` macro, which is a common way to define test cases in C++ testing frameworks (likely Google Test in V8's case). This means the code consists of individual test functions, each focused on a specific aspect of the ordered hash table functionality.

3. **Analyze Individual Tests:** Go through each `TEST()` block and understand its purpose:
    * `SmallOrderedNameDictionarySetDetails`: Tests setting and retrieving property details within a small ordered name dictionary.
    * `SmallOrderedNameDictionarySetAndMigrateHash`: Checks if setting the hash value and adding elements works correctly for small dictionaries.
    * `OrderedNameDictionarySetAndMigrateHash`: Similar to the previous test but for larger ordered name dictionaries.
    * `OrderedNameDictionaryHandlerInsertion`: Focuses on adding new key-value pairs to an `OrderedNameDictionaryHandler`.
    * `OrderedNameDictionaryHandlerDeletion`: Checks the removal of key-value pairs from an `OrderedNameDictionaryHandler`.
    * `OrderedNameDictionarySetEntry`: Tests modifying the value and details associated with an existing entry in an `OrderedNameDictionary`.
    * `SmallOrderedNameDictionarySetEntry`:  Similar to the previous test, but for `SmallOrderedNameDictionary`.
    * `OrderedNameDictionaryDeleteEntry`: Tests the removal of entries from an `OrderedNameDictionary`.
    * `SmallOrderedNameDictionaryDeleteEntry`: Similar to the previous test, but for `SmallOrderedNameDictionary`.
    * `ZeroSizeOrderedHashMap`, `ZeroSizeOrderedHashSet`, `ZeroSizeOrderedNameDictionary`:  These tests specifically deal with the behavior of empty (zero-sized) ordered hash table variations. They check operations like adding, deleting, ensuring capacity, rehashing, and shrinking on empty structures.

4. **Group Common Functionality:**  Notice that many tests revolve around similar operations: adding elements, deleting elements, finding elements, setting details, and checking the hash. Group these conceptually. The distinction between "Small" and regular dictionaries is also important.

5. **Identify Data Structures:** Note the different types of ordered hash tables being tested: `SmallOrderedNameDictionary`, `OrderedNameDictionary`, `OrderedHashMap`, and `OrderedHashSet`. Understand the general purpose of each (e.g., dictionaries store key-value pairs, sets store unique keys).

6. **Infer Javascript Relevance:**  Ordered hash tables in V8 are fundamental to how JavaScript objects are implemented. Object properties are essentially stored in hash tables. Therefore, the tests are directly relevant to how JavaScript objects work. Think about common JavaScript operations that would interact with these underlying data structures (property access, adding properties, deleting properties).

7. **Create Javascript Examples:**  For the operations identified in the previous step, construct simple JavaScript code snippets that demonstrate the equivalent functionality. Focus on the user-facing aspects.

8. **Consider Potential Errors:** Think about common mistakes developers might make when working with objects and their properties in JavaScript. These errors are often related to incorrect assumptions about the existence of properties, trying to modify read-only properties, etc.

9. **Structure the Summary:** Organize the findings logically:
    * Start with a general statement about the file's purpose.
    * Address the `.tq` file name possibility.
    * Explain the connection to JavaScript.
    * Provide concrete JavaScript examples.
    * Include examples of potential programming errors.
    * Finally, offer a concise overall归纳 (summarization).

10. **Refine and Elaborate:** Review the draft and add details where necessary. For instance, explicitly mention the testing of insertion, deletion, lookup, and iteration (implied by the ordered nature). Highlight the focus on boundary conditions (like zero-sized tables).

By following these steps, we can systematically analyze the C++ test code and generate a comprehensive and informative summary for the user.
这是第3部分，对`v8/test/cctest/test-orderedhashtable.cc` 的功能进行归纳总结：

总的来说，`v8/test/cctest/test-orderedhashtable.cc` 这个 C++ 文件是 V8 JavaScript 引擎的测试文件，专门用于测试各种**有序哈希表**的实现及其相关操作。它包含了多个独立的测试用例，每个测试用例都针对有序哈希表的特定功能或边界情况进行验证。

**核心功能归纳:**

1. **测试不同类型的有序哈希表:** 文件中测试了多种有序哈希表的实现，包括：
    * `SmallOrderedNameDictionary`: 用于存储少量属性的优化版本。
    * `OrderedNameDictionary`: 用于存储较多属性的通用版本。
    * `OrderedNameDictionaryHandler`:  处理 `SmallOrderedNameDictionary` 和 `OrderedNameDictionary` 的通用接口。
    * `OrderedHashMap`:  键值对都是 HeapObject 的有序哈希表。
    * `OrderedHashSet`:  只存储键的有序哈希集合。

2. **测试基本操作:**  每个测试用例都针对有序哈希表的核心操作进行验证，例如：
    * **添加元素 (`Add`)**:  测试向哈希表中添加新的键值对或键。
    * **查找元素 (`FindEntry`, `HasKey`)**: 测试能否正确地找到已存在的元素。
    * **删除元素 (`Delete`, `DeleteEntry`)**: 测试从哈希表中删除元素的功能。
    * **设置/修改元素 (`SetEntry`, `DetailsAtPut`)**: 测试修改现有元素的值或属性详情。
    * **设置和迁移哈希值 (`SetHash`)**: 测试设置哈希表哈希值的功能，并确保在扩容等操作后哈希值仍然正确。
    * **扩容和收缩**: 虽然没有直接的测试函数名称，但从添加大量元素和删除元素的测试中可以推断出对哈希表动态调整大小的测试。
    * **属性详情 (`PropertyDetails`)**: 测试与哈希表条目关联的属性详情的设置和获取。

3. **测试边界情况:** 特别是 `ZeroSizeOrderedHashMap`, `ZeroSizeOrderedHashSet`, 和 `ZeroSizeOrderedNameDictionary` 这些测试用例，专门用于验证当哈希表初始大小为零时的行为，例如添加、删除、确保容量等操作是否正确。

4. **验证数据一致性:**  每个测试用例中都使用了 `Verify(isolate, dict)` 这样的函数，这表明测试框架会检查哈希表在操作后的内部状态是否一致且有效。

**关于代码逻辑推理的归纳:**

文件中的代码逻辑主要是通过一系列的断言 (`CHECK_EQ`, `CHECK_NE`, `CHECK`, `DCHECK`) 来验证哈希表操作后的状态是否符合预期。  我们可以通过假设输入和观察断言来理解其逻辑。

**示例：`TEST(SmallOrderedNameDictionarySetDetails)`**

* **假设输入:**  一个空的 `SmallOrderedNameDictionary`，一个键 `key1`，一个用于存储属性详情的对象 `other`。
* **操作步骤:**
    1. 尝试查找 `key1`，应该找不到。
    2. 将 `other` 存储为 `key1` 的属性详情。
    3. 再次查找 `key1` 的属性详情，应该能找到，并且等于 `other`。
    4. 添加一个新的键 `key2`。
    5. 再次查找 `key1` 和 `key2`，验证它们是否存在。
    6. 再次设置和检查 `key1` 和 `key2` 的属性详情。
* **预期输出 (体现在断言中):** 每次断言都会验证操作后的状态是否符合预期，例如：添加元素后元素数量增加，查找到的属性详情与设置的属性详情一致。

**用户常见的编程错误 (基于测试内容推断):**

虽然这是 V8 内部的测试代码，但从中可以推断出与哈希表相关的常见编程错误：

* **假设键存在但实际不存在:**  在 JavaScript 中访问一个不存在的对象属性会返回 `undefined`，但在 V8 的底层实现中，需要正确处理查找失败的情况。测试用例中多次使用 `FindEntry(...).is_not_found()` 来验证这种情况。
* **修改只读属性:**  测试用例中使用了 `PropertyDetails(PropertyKind::kAccessor, READ_ONLY, ...)`，这模拟了 JavaScript 中设置对象属性为只读的情况。用户可能尝试修改这样的属性而导致错误。
* **哈希表容量溢出:** 虽然现代哈希表通常会自动扩容，但在某些情况下，过度添加元素可能导致性能问题或者在极端的资源受限环境下出现错误。测试中通过循环添加大量元素来间接测试扩容机制。
* **删除不存在的元素:** 尝试删除哈希表中不存在的键不会引发错误，但测试用例会验证删除操作在这种情况下不会产生副作用。
* **对哈希表状态的错误假设:**  例如，假设哈希表的元素顺序固定不变（虽然 `OrderedHashTable` 保留插入顺序，但在某些操作后顺序可能会改变，或者在不同实现中行为可能不同）。

**总结归纳:**

`v8/test/cctest/test-orderedhashtable.cc` 是 V8 引擎中一个至关重要的测试文件，它细致地测试了各种有序哈希表实现的添加、删除、查找、修改等核心功能，并覆盖了边界情况，确保这些数据结构在 V8 中能够正确高效地工作。这直接关系到 JavaScript 对象的属性存储和访问等核心机制的稳定性和性能。 通过这些测试，V8 开发者可以确保底层数据结构的可靠性，从而为上层 JavaScript 代码的正确执行提供保障。

Prompt: 
```
这是目录为v8/test/cctest/test-orderedhashtable.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-orderedhashtable.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
 dict->FindEntry(isolate, *key1);
  PropertyDetails found = dict->DetailsAt(entry);
  CHECK_EQ(PropertyDetails::Empty().AsSmi(), found.AsSmi());

  PropertyDetails other = PropertyDetails(PropertyKind::kAccessor, READ_ONLY,
                                          PropertyCellType::kNoCell);
  dict->DetailsAtPut(entry, other);

  found = dict->DetailsAt(entry);
  CHECK_NE(PropertyDetails::Empty().AsSmi(), found.AsSmi());
  CHECK_EQ(other.AsSmi(), found.AsSmi());

  DirectHandle<Symbol> key2 = factory->NewSymbol();
  CHECK(dict->FindEntry(isolate, *key2).is_not_found());
  dict = SmallOrderedNameDictionary::Add(isolate, dict, key2, value, details)
             .ToHandleChecked();
  Verify(isolate, dict);
  CHECK_EQ(2, dict->NumberOfBuckets());
  CHECK_EQ(2, dict->NumberOfElements());
  CHECK_EQ(InternalIndex(0), dict->FindEntry(isolate, *key1));
  CHECK_EQ(InternalIndex(1), dict->FindEntry(isolate, *key2));

  entry = dict->FindEntry(isolate, *key1);
  found = dict->DetailsAt(entry);
  CHECK_NE(PropertyDetails::Empty().AsSmi(), found.AsSmi());
  CHECK_EQ(other.AsSmi(), found.AsSmi());

  entry = dict->FindEntry(isolate, *key2);
  dict->DetailsAtPut(entry, other);

  found = dict->DetailsAt(entry);
  CHECK_NE(PropertyDetails::Empty().AsSmi(), found.AsSmi());
  CHECK_EQ(other.AsSmi(), found.AsSmi());
}

TEST(SmallOrderedNameDictionarySetAndMigrateHash) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);
  Handle<SmallOrderedNameDictionary> dict =
      factory->NewSmallOrderedNameDictionary();
  DirectHandle<String> value = isolate->factory()->InternalizeUtf8String("bar");
  PropertyDetails details = PropertyDetails::Empty();

  CHECK_EQ(PropertyArray::kNoHashSentinel, dict->Hash());
  dict->SetHash(100);
  CHECK_EQ(100, dict->Hash());

  char buf[10];
  for (int i = 0; i < SmallOrderedNameDictionary::kMaxCapacity; i++) {
    CHECK_LT(0, snprintf(buf, sizeof(buf), "foo%d", i));
    DirectHandle<String> key = isolate->factory()->InternalizeUtf8String(buf);
    dict = SmallOrderedNameDictionary::Add(isolate, dict, key, value, details)
               .ToHandleChecked();
    Verify(isolate, dict);
    CHECK_EQ(100, dict->Hash());
  }
}

TEST(OrderedNameDictionarySetAndMigrateHash) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  HandleScope scope(isolate);
  Handle<OrderedNameDictionary> dict =
      OrderedNameDictionary::Allocate(isolate, 2).ToHandleChecked();
  DirectHandle<String> value = isolate->factory()->InternalizeUtf8String("bar");
  PropertyDetails details = PropertyDetails::Empty();

  CHECK_EQ(PropertyArray::kNoHashSentinel, dict->Hash());
  dict->SetHash(100);
  CHECK_EQ(100, dict->Hash());

  char buf[10];
  for (int i = 0; i <= 1024; i++) {
    CHECK_LT(0, snprintf(buf, sizeof(buf), "foo%d", i));
    DirectHandle<String> key = isolate->factory()->InternalizeUtf8String(buf);
    dict = OrderedNameDictionary::Add(isolate, dict, key, value, details)
               .ToHandleChecked();
    Verify(isolate, dict);
    CHECK_EQ(100, dict->Hash());
  }
}

TEST(OrderedNameDictionaryHandlerInsertion) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  HandleScope scope(isolate);

  Handle<HeapObject> table =
      OrderedNameDictionaryHandler::Allocate(isolate, 4).ToHandleChecked();
  CHECK(IsSmallOrderedNameDictionary(*table));
  Verify(isolate, table);

  // Add a new key.
  DirectHandle<String> value = isolate->factory()->InternalizeUtf8String("bar");
  DirectHandle<String> key = isolate->factory()->InternalizeUtf8String("foo");
  PropertyDetails details = PropertyDetails::Empty();

  table = OrderedNameDictionaryHandler::Add(isolate, table, key, value, details)
              .ToHandleChecked();
  DCHECK(IsUniqueName(*key));
  Verify(isolate, table);
  CHECK(IsSmallOrderedNameDictionary(*table));
  CHECK(OrderedNameDictionaryHandler::FindEntry(isolate, *table, *key)
            .is_found());

  char buf[10];
  for (int i = 0; i < 1024; i++) {
    CHECK_LT(0, snprintf(buf, sizeof(buf), "foo%d", i));
    key = isolate->factory()->InternalizeUtf8String(buf);
    table =
        OrderedNameDictionaryHandler::Add(isolate, table, key, value, details)
            .ToHandleChecked();
    DCHECK(IsUniqueName(*key));
    Verify(isolate, table);

    for (int j = 0; j <= i; j++) {
      CHECK_LT(0, snprintf(buf, sizeof(buf), "foo%d", j));
      DirectHandle<Name> key_j = isolate->factory()->InternalizeUtf8String(buf);
      CHECK(OrderedNameDictionaryHandler::FindEntry(isolate, *table, *key_j)
                .is_found());
    }

    for (int j = i + 1; j < 1024; j++) {
      CHECK_LT(0, snprintf(buf, sizeof(buf), "foo%d", j));
      DirectHandle<Name> key_j = isolate->factory()->InternalizeUtf8String(buf);
      CHECK(OrderedNameDictionaryHandler::FindEntry(isolate, *table, *key_j)
                .is_not_found());
    }
  }

  CHECK(IsOrderedNameDictionary(*table));
}

TEST(OrderedNameDictionaryHandlerDeletion) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  HandleScope scope(isolate);

  Handle<HeapObject> table =
      OrderedNameDictionaryHandler::Allocate(isolate, 4).ToHandleChecked();
  CHECK(IsSmallOrderedNameDictionary(*table));
  Verify(isolate, table);

  // Add a new key.
  DirectHandle<String> value = isolate->factory()->InternalizeUtf8String("bar");
  DirectHandle<String> key = isolate->factory()->InternalizeUtf8String("foo");
  DirectHandle<String> key2 = isolate->factory()->InternalizeUtf8String("foo2");
  PropertyDetails details = PropertyDetails::Empty();

  table = OrderedNameDictionaryHandler::Add(isolate, table, key, value, details)
              .ToHandleChecked();
  DCHECK(IsUniqueName(*key));
  Verify(isolate, table);
  CHECK(IsSmallOrderedNameDictionary(*table));
  CHECK(OrderedNameDictionaryHandler::FindEntry(isolate, *table, *key)
            .is_found());

  // Remove a non-existing key.
  OrderedNameDictionaryHandler::Delete(isolate, table, key2);
  Verify(isolate, table);
  CHECK(IsSmallOrderedNameDictionary(*table));
  CHECK(OrderedNameDictionaryHandler::FindEntry(isolate, *table, *key2)
            .is_not_found());
  CHECK(OrderedNameDictionaryHandler::FindEntry(isolate, *table, *key)
            .is_found());

  // Remove an existing key.
  OrderedNameDictionaryHandler::Delete(isolate, table, key);
  Verify(isolate, table);
  CHECK(IsSmallOrderedNameDictionary(*table));
  CHECK(OrderedNameDictionaryHandler::FindEntry(isolate, *table, *key)
            .is_not_found());

  CHECK(IsSmallOrderedNameDictionary(*table));
}

TEST(OrderedNameDictionarySetEntry) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<OrderedNameDictionary> dict =
      OrderedNameDictionary::Allocate(isolate, 2).ToHandleChecked();
  Verify(isolate, dict);
  CHECK_EQ(2, dict->NumberOfBuckets());
  CHECK_EQ(0, dict->NumberOfElements());
  CHECK_EQ(0, dict->NumberOfDeletedElements());

  DirectHandle<String> key = factory->InternalizeUtf8String("foo");
  DirectHandle<String> value = factory->InternalizeUtf8String("bar");
  CHECK(dict->FindEntry(isolate, *key).is_not_found());
  PropertyDetails details = PropertyDetails::Empty();
  dict = OrderedNameDictionary::Add(isolate, dict, key, value, details)
             .ToHandleChecked();
  Verify(isolate, dict);
  CHECK_EQ(2, dict->NumberOfBuckets());
  CHECK_EQ(1, dict->NumberOfElements());

  InternalIndex entry = dict->FindEntry(isolate, *key);
  CHECK_EQ(InternalIndex(0), entry);
  DirectHandle<Object> found(dict->ValueAt(entry), isolate);
  CHECK_EQ(*found, *value);

  // Change the value
  DirectHandle<String> other_value =
      isolate->factory()->InternalizeUtf8String("baz");
  PropertyDetails other_details = PropertyDetails(
      PropertyKind::kAccessor, READ_ONLY, PropertyCellType::kNoCell);
  dict->SetEntry(entry, *key, *other_value, other_details);

  entry = dict->FindEntry(isolate, *key);
  CHECK_EQ(InternalIndex(0), entry);
  found = direct_handle(dict->ValueAt(entry), isolate);
  CHECK_EQ(*found, *other_value);
  found = direct_handle(dict->KeyAt(entry), isolate);
  CHECK_EQ(*found, *key);
  PropertyDetails found_details = dict->DetailsAt(entry);
  CHECK_EQ(found_details.AsSmi(), other_details.AsSmi());
}

TEST(SmallOrderedNameDictionarySetEntry) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<SmallOrderedNameDictionary> dict =
      factory->NewSmallOrderedNameDictionary();
  Verify(isolate, dict);
  CHECK_EQ(2, dict->NumberOfBuckets());
  CHECK_EQ(0, dict->NumberOfElements());

  DirectHandle<String> key = factory->InternalizeUtf8String("foo");
  DirectHandle<String> value = factory->InternalizeUtf8String("bar");
  CHECK(dict->FindEntry(isolate, *key).is_not_found());
  PropertyDetails details = PropertyDetails::Empty();
  dict = SmallOrderedNameDictionary::Add(isolate, dict, key, value, details)
             .ToHandleChecked();
  Verify(isolate, dict);
  CHECK_EQ(2, dict->NumberOfBuckets());
  CHECK_EQ(1, dict->NumberOfElements());
  CHECK_EQ(0, dict->NumberOfDeletedElements());

  InternalIndex entry = dict->FindEntry(isolate, *key);
  CHECK_EQ(InternalIndex(0), entry);
  DirectHandle<Object> found(dict->ValueAt(entry), isolate);
  CHECK_EQ(*found, *value);

  // Change the value
  DirectHandle<String> other_value = factory->InternalizeUtf8String("baz");
  PropertyDetails other_details = PropertyDetails(
      PropertyKind::kAccessor, READ_ONLY, PropertyCellType::kNoCell);
  dict->SetEntry(entry, *key, *other_value, other_details);

  entry = dict->FindEntry(isolate, *key);
  CHECK_EQ(InternalIndex(0), entry);
  found = direct_handle(dict->ValueAt(entry), isolate);
  CHECK_EQ(*found, *other_value);
  found = direct_handle(dict->KeyAt(entry), isolate);
  CHECK_EQ(*found, *key);
  PropertyDetails found_details = dict->DetailsAt(entry);
  CHECK_EQ(found_details.AsSmi(), other_details.AsSmi());
}

TEST(OrderedNameDictionaryDeleteEntry) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<OrderedNameDictionary> dict =
      OrderedNameDictionary::Allocate(isolate, 2).ToHandleChecked();
  Verify(isolate, dict);
  CHECK_EQ(2, dict->NumberOfBuckets());
  CHECK_EQ(0, dict->NumberOfElements());

  DirectHandle<String> key = factory->InternalizeUtf8String("foo");
  DirectHandle<String> value = factory->InternalizeUtf8String("bar");
  CHECK(dict->FindEntry(isolate, *key).is_not_found());
  PropertyDetails details = PropertyDetails::Empty();
  dict = OrderedNameDictionary::Add(isolate, dict, key, value, details)
             .ToHandleChecked();
  Verify(isolate, dict);
  CHECK_EQ(2, dict->NumberOfBuckets());
  CHECK_EQ(1, dict->NumberOfElements());
  CHECK_EQ(0, dict->NumberOfDeletedElements());

  InternalIndex entry = dict->FindEntry(isolate, *key);
  CHECK_EQ(InternalIndex(0), entry);
  dict = OrderedNameDictionary::DeleteEntry(isolate, dict, entry);
  entry = dict->FindEntry(isolate, *key);
  CHECK(entry.is_not_found());
  CHECK_EQ(0, dict->NumberOfElements());

  char buf[10];
  // Make sure we grow at least once.
  CHECK_LT(OrderedNameDictionaryHandler::Capacity(*dict), 100);
  for (int i = 0; i < 100; i++) {
    CHECK_LT(0, snprintf(buf, sizeof(buf), "foo%d", i));
    key = factory->InternalizeUtf8String(buf);
    dict = OrderedNameDictionary::Add(isolate, dict, key, value, details)
               .ToHandleChecked();
    DCHECK(IsUniqueName(*key));
    Verify(isolate, dict);
  }

  CHECK_EQ(100, dict->NumberOfElements());
  // Initial dictionary has grown.
  CHECK_EQ(0, dict->NumberOfDeletedElements());

  for (int i = 0; i < 100; i++) {
    CHECK_LT(0, snprintf(buf, sizeof(buf), "foo%d", i));
    key = factory->InternalizeUtf8String(buf);
    entry = dict->FindEntry(isolate, *key);

    dict = OrderedNameDictionary::DeleteEntry(isolate, dict, entry);
    Verify(isolate, dict);

    entry = dict->FindEntry(isolate, *key);
    CHECK(entry.is_not_found());
  }
  CHECK_EQ(0, dict->NumberOfElements());
  // Dictionary shrunk again.
  CHECK_EQ(0, dict->NumberOfDeletedElements());
}

TEST(SmallOrderedNameDictionaryDeleteEntry) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<SmallOrderedNameDictionary> dict =
      factory->NewSmallOrderedNameDictionary();
  Verify(isolate, dict);
  CHECK_EQ(2, dict->NumberOfBuckets());
  CHECK_EQ(0, dict->NumberOfElements());

  DirectHandle<String> key = factory->InternalizeUtf8String("foo");
  DirectHandle<String> value = factory->InternalizeUtf8String("bar");
  CHECK(dict->FindEntry(isolate, *key).is_not_found());
  PropertyDetails details = PropertyDetails::Empty();
  dict = SmallOrderedNameDictionary::Add(isolate, dict, key, value, details)
             .ToHandleChecked();
  Verify(isolate, dict);
  CHECK_EQ(2, dict->NumberOfBuckets());
  CHECK_EQ(1, dict->NumberOfElements());
  CHECK_EQ(0, dict->NumberOfDeletedElements());

  InternalIndex entry = dict->FindEntry(isolate, *key);
  CHECK_EQ(InternalIndex(0), entry);
  dict = SmallOrderedNameDictionary::DeleteEntry(isolate, dict, entry);
  entry = dict->FindEntry(isolate, *key);
  CHECK(entry.is_not_found());

  char buf[10];
  // Make sure we grow at least once.
  CHECK_LT(dict->Capacity(), SmallOrderedNameDictionary::kMaxCapacity);

  for (int i = 0; i < SmallOrderedNameDictionary::kMaxCapacity; i++) {
    CHECK_LT(0, snprintf(buf, sizeof(buf), "foo%d", i));
    key = factory->InternalizeUtf8String(buf);
    dict = SmallOrderedNameDictionary::Add(isolate, dict, key, value, details)
               .ToHandleChecked();
    DCHECK(IsUniqueName(*key));
    Verify(isolate, dict);
  }

  CHECK_EQ(SmallOrderedNameDictionary::kMaxCapacity, dict->NumberOfElements());
  // Dictionary has grown.
  CHECK_EQ(0, dict->NumberOfDeletedElements());

  for (int i = 0; i < SmallOrderedNameDictionary::kMaxCapacity; i++) {
    CHECK_LT(0, snprintf(buf, sizeof(buf), "foo%d", i));
    key = factory->InternalizeUtf8String(buf);

    entry = dict->FindEntry(isolate, *key);
    dict = SmallOrderedNameDictionary::DeleteEntry(isolate, dict, entry);
    Verify(isolate, dict);

    entry = dict->FindEntry(isolate, *key);
    CHECK(entry.is_not_found());
  }

  CHECK_EQ(0, dict->NumberOfElements());
  // Dictionary shrunk.
  CHECK_EQ(0, dict->NumberOfDeletedElements());
}

template <typename T>
void TestEmptyOrderedHashTable(Isolate* isolate, Factory* factory,
                               Handle<T> table) {
  CHECK_EQ(0, table->NumberOfElements());

  PropertyDetails details = PropertyDetails::Empty();

  Handle<String> key1 = isolate->factory()->InternalizeUtf8String("key1");
  Handle<String> value1 = isolate->factory()->InternalizeUtf8String("value1");
  table = Add(isolate, table, key1, value1, details);
  Verify(isolate, table);
  CHECK_EQ(1, table->NumberOfElements());
  CHECK(HasKey(isolate, table, *key1));

  Handle<String> key2 = factory->InternalizeUtf8String("key2");
  Handle<String> value2 = factory->InternalizeUtf8String("value2");
  CHECK(!HasKey(isolate, table, *key2));
  table = Add(isolate, table, key2, value2, details);
  Verify(isolate, table);
  CHECK_EQ(2, table->NumberOfElements());
  CHECK(HasKey(isolate, table, *key1));
  CHECK(HasKey(isolate, table, *key2));

  Handle<String> key3 = factory->InternalizeUtf8String("key3");
  Handle<String> value3 = factory->InternalizeUtf8String("value3");
  CHECK(!HasKey(isolate, table, *key3));
  table = Add(isolate, table, key3, value3, details);
  Verify(isolate, table);
  CHECK_EQ(3, table->NumberOfElements());
  CHECK(HasKey(isolate, table, *key1));
  CHECK(HasKey(isolate, table, *key2));
  CHECK(HasKey(isolate, table, *key3));

  Handle<String> key4 = factory->InternalizeUtf8String("key4");
  Handle<String> value4 = factory->InternalizeUtf8String("value4");
  CHECK(!HasKey(isolate, table, *key4));
  table = Delete(isolate, table, *key4);
  Verify(isolate, table);
  CHECK_EQ(3, table->NumberOfElements());
  CHECK_EQ(0, table->NumberOfDeletedElements());
  CHECK(!HasKey(isolate, table, *key4));

  table = Add(isolate, table, key4, value4, details);
  Verify(isolate, table);
  CHECK_EQ(4, table->NumberOfElements());
  CHECK_EQ(0, table->NumberOfDeletedElements());
  CHECK(HasKey(isolate, table, *key4));

  CHECK(HasKey(isolate, table, *key4));
  table = Delete(isolate, table, *key4);
  Verify(isolate, table);
  CHECK_EQ(3, table->NumberOfElements());
  CHECK_EQ(1, table->NumberOfDeletedElements());
  CHECK(!HasKey(isolate, table, *key4));
}

TEST(ZeroSizeOrderedHashMap) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);
  ReadOnlyRoots ro_roots(isolate);

  DirectHandle<Smi> key1(Smi::FromInt(1), isolate);
  DirectHandle<Smi> value1(Smi::FromInt(1), isolate);

  Handle<OrderedHashMap> empty =
      Handle<OrderedHashMap>(ro_roots.empty_ordered_hash_map(), isolate);
  {
    Handle<OrderedHashMap> map = empty;

    CHECK_EQ(0, map->NumberOfBuckets());
    CHECK_EQ(0, map->NumberOfElements());
    CHECK(!OrderedHashMap::HasKey(isolate, *map, *key1));

    TestEmptyOrderedHashTable(isolate, factory, map);
  }
  {
    Handle<OrderedHashMap> map = empty;

    map =
        OrderedHashMap::EnsureCapacityForAdding(isolate, map).ToHandleChecked();

    CHECK_LT(0, map->NumberOfBuckets());
    CHECK_EQ(0, map->NumberOfElements());
  }
  {
    Handle<OrderedHashMap> map = empty;

    CHECK(map->FindEntry(isolate, *key1).is_not_found());

    TestEmptyOrderedHashTable(isolate, factory, map);
  }
  {
    Handle<OrderedHashMap> map = empty;

    map = OrderedHashMap::Add(isolate, map, key1, value1).ToHandleChecked();

    CHECK_EQ(1, map->NumberOfElements());
    CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));
  }
  {
    Handle<OrderedHashMap> map = empty;

    map = OrderedHashMap::Clear(isolate, map);

    TestEmptyOrderedHashTable(isolate, factory, map);
  }
  {
    Handle<OrderedHashMap> map = empty;

    map = OrderedHashMap::Rehash(isolate, map).ToHandleChecked();

    TestEmptyOrderedHashTable(isolate, factory, map);
  }
  {
    Handle<OrderedHashMap> map = empty;

    map = OrderedHashMap::Shrink(isolate, map);

    TestEmptyOrderedHashTable(isolate, factory, map);
  }
  {
    Handle<OrderedHashMap> map = empty;

    OrderedHashMap::Delete(isolate, *map, *key1);

    TestEmptyOrderedHashTable(isolate, factory, map);
  }
}

TEST(ZeroSizeOrderedHashSet) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);
  ReadOnlyRoots ro_roots(isolate);

  DirectHandle<Smi> key1(Smi::FromInt(1), isolate);
  DirectHandle<Smi> value1(Smi::FromInt(1), isolate);

  Handle<OrderedHashSet> empty =
      Handle<OrderedHashSet>(ro_roots.empty_ordered_hash_set(), isolate);

  {
    Handle<OrderedHashSet> set = empty;

    CHECK_EQ(0, set->NumberOfBuckets());
    CHECK_EQ(0, set->NumberOfElements());
    CHECK(!OrderedHashSet::HasKey(isolate, *set, *key1));

    TestEmptyOrderedHashTable(isolate, factory, set);
  }
  {
    Handle<OrderedHashSet> set = empty;

    set =
        OrderedHashSet::EnsureCapacityForAdding(isolate, set).ToHandleChecked();

    CHECK_LT(0, set->NumberOfBuckets());
    CHECK_EQ(0, set->NumberOfElements());
  }
  {
    Handle<OrderedHashSet> set = empty;

    CHECK(set->FindEntry(isolate, *key1).is_not_found());

    TestEmptyOrderedHashTable(isolate, factory, set);
  }
  {
    Handle<OrderedHashSet> set = empty;

    set = OrderedHashSet::Add(isolate, set, key1).ToHandleChecked();

    CHECK_EQ(1, set->NumberOfElements());
    CHECK(OrderedHashSet::HasKey(isolate, *set, *key1));
  }
  {
    Handle<OrderedHashSet> set = empty;

    set = OrderedHashSet::Clear(isolate, set);

    TestEmptyOrderedHashTable(isolate, factory, set);
  }
  {
    Handle<OrderedHashSet> set = empty;

    set = OrderedHashSet::Rehash(isolate, set).ToHandleChecked();

    TestEmptyOrderedHashTable(isolate, factory, set);
  }
  {
    Handle<OrderedHashSet> set = empty;

    set = OrderedHashSet::Shrink(isolate, set);

    TestEmptyOrderedHashTable(isolate, factory, set);
  }
  {
    Handle<OrderedHashSet> set = empty;

    OrderedHashSet::Delete(isolate, *set, *key1);

    TestEmptyOrderedHashTable(isolate, factory, set);
  }
}

TEST(ZeroSizeOrderedNameDictionary) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);
  ReadOnlyRoots ro_roots(isolate);

  DirectHandle<String> key1 = isolate->factory()->InternalizeUtf8String("key1");
  DirectHandle<String> value1 =
      isolate->factory()->InternalizeUtf8String("value1");
  PropertyDetails details = PropertyDetails::Empty();

  Handle<OrderedNameDictionary> empty = Handle<OrderedNameDictionary>(
      ro_roots.empty_ordered_property_dictionary(), isolate);

  {
    Handle<OrderedNameDictionary> dict = empty;

    CHECK_EQ(0, dict->NumberOfBuckets());
    CHECK_EQ(0, dict->NumberOfElements());
    CHECK(!HasKey(isolate, dict, *key1));

    TestEmptyOrderedHashTable(isolate, factory, dict);
  }
  {
    Handle<OrderedNameDictionary> dict = empty;

    CHECK(dict->FindEntry(isolate, *key1).is_not_found());

    TestEmptyOrderedHashTable(isolate, factory, dict);
  }
  {
    Handle<OrderedNameDictionary> dict = empty;

    dict = OrderedNameDictionary::Add(isolate, dict, key1, value1, details)
               .ToHandleChecked();
    CHECK_EQ(1, dict->NumberOfElements());
    CHECK(HasKey(isolate, dict, *key1));
  }
  {
    Handle<OrderedNameDictionary> dict = empty;

    dict = OrderedNameDictionary::Rehash(isolate, dict, 0).ToHandleChecked();

    TestEmptyOrderedHashTable(isolate, factory, dict);
  }
  {
    Handle<OrderedNameDictionary> dict = empty;

    dict = OrderedNameDictionary::Shrink(isolate, dict);

    TestEmptyOrderedHashTable(isolate, factory, dict);
  }
}

}  // namespace test_orderedhashtable
}  // namespace internal
}  // namespace v8

"""


```