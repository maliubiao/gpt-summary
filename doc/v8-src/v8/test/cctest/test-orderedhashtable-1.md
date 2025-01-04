Response: The user wants a summary of the C++ code provided. This is the second part of a larger file testing the functionality of `OrderedHashTable` related data structures in V8.

The tests focus on:
- **`DetailsAtPut`**: Setting and retrieving property details associated with keys in `SmallOrderedNameDictionary`.
- **Hash Migration**: Verifying that the hash value of `SmallOrderedNameDictionary` and `OrderedNameDictionary` persists even after adding multiple elements and potentially triggering internal resizing or migration.
- **`OrderedNameDictionaryHandler`**: Testing adding and deleting entries in dictionaries managed by the `OrderedNameDictionaryHandler`, which can handle both small and large dictionaries.
- **`SetEntry`**: Modifying existing key-value pairs and their associated details in both `OrderedNameDictionary` and `SmallOrderedNameDictionary`.
- **`DeleteEntry`**: Removing entries from both `OrderedNameDictionary` and `SmallOrderedNameDictionary` and verifying the number of elements and deleted elements.
- **Empty HashTable Tests**:  A template function `TestEmptyOrderedHashTable` is used to test basic operations (add, delete, hasKey) on various empty ordered hash table implementations.
- **Zero-Size Hash Table Tests**: Specific tests for `OrderedHashMap`, `OrderedHashSet`, and `OrderedNameDictionary` when they are initially created with zero capacity, ensuring they can handle basic operations like adding, deleting, and checking for keys.

If there's a relationship with JavaScript, it will likely be in how these data structures are used to implement JavaScript objects and their properties.
```cpp
TEST(SmallOrderedNameDictionaryDetailsAtPut) {
  // ... (code from the input)
}

TEST(SmallOrderedNameDictionarySetAndMigrateHash) {
  // ... (code from the input)
}

TEST(OrderedNameDictionarySetAndMigrateHash) {
  // ... (code from the input)
}

TEST(OrderedNameDictionaryHandlerInsertion) {
  // ... (code from the input)
}

TEST(OrderedNameDictionaryHandlerDeletion) {
  // ... (code from the input)
}

TEST(OrderedNameDictionarySetEntry) {
  // ... (code from the input)
}

TEST(SmallOrderedNameDictionarySetEntry) {
  // ... (code from the input)
}

TEST(OrderedNameDictionaryDeleteEntry) {
  // ... (code from the input)
}

TEST(SmallOrderedNameDictionaryDeleteEntry) {
  // ... (code from the input)
}

template <typename T>
void TestEmptyOrderedHashTable(Isolate* isolate, Factory* factory,
                               Handle<T> table) {
  // ... (code from the input)
}

TEST(ZeroSizeOrderedHashMap) {
  // ... (code from the input)
}

TEST(ZeroSizeOrderedHashSet) {
  // ... (code from the input)
}

TEST(ZeroSizeOrderedNameDictionary) {
  // ... (code from the input)
}
```

这个C++代码文件（作为第二部分）继续测试V8引擎中用于实现有序哈希表的几种不同变体的功能。它主要关注以下几个方面：

1. **属性细节 (Property Details) 的设置和获取:**  测试了 `SmallOrderedNameDictionary` 中与键关联的属性细节的存储和检索功能，例如属性的类型（数据属性或访问器属性）、可写性等。

2. **哈希值的持久性:**  测试了在 `SmallOrderedNameDictionary` 和 `OrderedNameDictionary` 中设置哈希值后，即使在添加多个元素导致内部结构调整（例如扩容）后，该哈希值仍然保持不变。

3. **`OrderedNameDictionaryHandler` 的插入和删除:**  测试了使用 `OrderedNameDictionaryHandler` 来管理键值对的插入和删除操作。`OrderedNameDictionaryHandler` 能够根据需要选择使用更小或更大的哈希表实现。

4. **设置条目 (Set Entry):**  测试了修改已存在于 `OrderedNameDictionary` 和 `SmallOrderedNameDictionary` 中的键值对的功能，包括修改值和属性细节。

5. **删除条目 (Delete Entry):**  测试了从 `OrderedNameDictionary` 和 `SmallOrderedNameDictionary` 中删除键值对的功能，并验证了删除后哈希表的状态（元素数量、已删除元素数量等）。

6. **空哈希表的测试:**  定义了一个模板函数 `TestEmptyOrderedHashTable`，用于对不同类型的空有序哈希表执行一系列基本操作（添加、删除、查找键）。

7. **零大小哈希表的测试:**  专门测试了当 `OrderedHashMap`、`OrderedHashSet` 和 `OrderedNameDictionary` 被创建时初始大小为零的情况下的行为，例如能否正常添加、删除元素等。

**与 JavaScript 的关系和示例:**

这些有序哈希表是 V8 引擎在底层实现 JavaScript 对象和 Map 等数据结构的关键组件。JavaScript 对象的属性本质上是以键值对的形式存储的，而属性的顺序在某些情况下（例如 ES6 的 `Map` 对象或对象字面量的属性顺序）是需要被保留的。

* **JavaScript 对象属性存储:**  当在 JavaScript 中创建一个对象并添加属性时，V8 引擎可能会使用这些有序哈希表来存储这些属性。属性名作为键，属性值作为值，属性的特性（如可枚举性、可配置性等）可能对应于 C++ 代码中的 `PropertyDetails`。

```javascript
// JavaScript 示例

const obj = {
  a: 1,
  b: 2
};

console.log(obj.a); // 访问属性

obj.b = 3; // 修改属性值

delete obj.a; // 删除属性
```

在上面的 JavaScript 代码中，`obj` 对象的属性 `a` 和 `b` 在 V8 引擎内部很可能就存储在类似 `OrderedNameDictionary` 的数据结构中。

* **JavaScript `Map` 对象:** ES6 引入的 `Map` 对象明确要求保持键值对的插入顺序。V8 引擎会使用有序哈希表（例如 `OrderedHashMap`）来高效地实现 `Map` 的功能。

```javascript
// JavaScript 示例

const map = new Map();
map.set('key1', 'value1');
map.set('key2', 'value2');

console.log(map.get('key1')); // 获取值

map.set('key2', 'new value2'); // 修改值

map.delete('key1'); // 删除键值对

for (let [key, value] of map) {
  console.log(key, value); // 遍历时保持插入顺序
}
```

在这个例子中，`Map` 对象的键值对以及它们的插入顺序会由 V8 引擎的 `OrderedHashMap` 或类似的结构来维护。

总而言之，这个 C++ 测试文件验证了 V8 引擎中用于实现有序键值存储的核心数据结构的正确性和效率，这些数据结构对于 JavaScript 对象的属性管理和 ES6 `Map` 等特性的实现至关重要。

Prompt: 
```
这是目录为v8/test/cctest/test-orderedhashtable.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能

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