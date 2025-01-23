Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/test/cctest/test-orderedhashtable.cc`. This is part 2 of 3. I need to summarize the functionality demonstrated in this part of the code.

The code contains several C++ TEST macros, which indicate that this file contains unit tests for V8's ordered hash table implementation. The tests cover:

- Deletion of elements from `OrderedHashMap` and `SmallOrderedHashMap`.
- Deletion of elements from `OrderedHashSet` and `SmallOrderedHashSet`.
- Handling of duplicate hash codes during deletion in both Maps and Sets.
- Insertion and deletion using `OrderedHashSetHandler` and `OrderedHashMapHandler`. These handlers likely provide an interface for interacting with the hash tables at a lower level.
- Insertion and manipulation of elements in `OrderedNameDictionary` and `SmallOrderedNameDictionary`, including finding entries, getting and setting values, and getting and setting details (likely metadata).
- Testing the maximum capacity of `SmallOrderedNameDictionary`.

Therefore, the main functionality demonstrated in this part is **testing the deletion and manipulation of elements in various ordered hash table implementations in V8, including handling edge cases like duplicate hash codes and interactions through handlers.**
这是目录为 `v8/test/cctest/test-orderedhashtable.cc` 的 V8 源代码的第二部分。

**功能归纳:**

这部分代码主要集中在测试 V8 中各种有序哈希表（`OrderedHashMap`, `SmallOrderedHashMap`, `OrderedHashSet`, `SmallOrderedHashSet`, `OrderedNameDictionary`, `SmallOrderedNameDictionary`）的**删除操作**和**元素查找与修改**等功能。具体来说，它测试了：

1. **从 `OrderedHashMap` 和 `SmallOrderedHashMap` 中删除键值对**:
   - 测试删除已存在的键和不存在的键。
   - 测试删除后哈希表的内部状态（桶的数量、元素数量、已删除元素数量）。
   - 测试尝试删除具有相同哈希码但不是同一个对象的键的情况。

2. **从 `OrderedHashSet` 和 `SmallOrderedHashSet` 中删除元素**:
   - 测试从空哈希集合中删除。
   - 测试删除单个已存在的元素。
   - 测试删除多个已存在的元素。
   - 测试删除不存在的元素。
   - 测试删除后哈希集合的内部状态。
   - 测试尝试删除具有相同哈希码但不是同一个对象的元素的情况。

3. **使用 Handler 进行插入和删除操作**:
   - 测试使用 `OrderedHashSetHandler` 和 `OrderedHashMapHandler` 进行元素的插入和删除。这可能用于测试在更底层的抽象层面上操作哈希表。

4. **`OrderedNameDictionary` 和 `SmallOrderedNameDictionary` 的操作**:
   - 测试插入新的键值对 (`Add`)。
   - 测试查找键对应的条目 (`FindEntry`)。
   - 测试获取和设置指定条目的值 (`ValueAt`, `ValueAtPut`)。
   - 测试获取和设置指定条目的详细信息 (`DetailsAt`, `DetailsAtPut`)，这些详细信息可能包含属性的元数据。
   - 测试 `SmallOrderedNameDictionary` 的最大容量限制。

**关于代码特征的分析:**

- **以 `.tq` 结尾？**:  `v8/test/cctest/test-orderedhashtable.cc` 以 `.cc` 结尾，这意味着它是 **C++ 源代码**，而不是 Torque 源代码。Torque 源代码通常以 `.tq` 结尾。
- **与 Javascript 的功能关系**:  有序哈希表是 JavaScript 中 `Map` 和 `Set` 等数据结构的基础实现之一。它们用于存储和检索键值对或唯一值，并保持插入顺序。`OrderedNameDictionary` 更像是 JavaScript 对象的属性存储结构，能够存储属性的细节信息。

**JavaScript 示例 (与 `OrderedHashMap` 和 `OrderedHashSet` 类似):**

```javascript
// 模拟 OrderedHashMap 的行为
const orderedMap = new Map();

// 添加键值对
orderedMap.set('a', 1);
orderedMap.set('b', 2);

// 删除键
orderedMap.delete('a');

// 检查是否存在键
console.log(orderedMap.has('a')); // 输出: false
console.log(orderedMap.has('b')); // 输出: true

// 模拟 OrderedHashSet 的行为
const orderedSet = new Set();

// 添加元素
orderedSet.add(1);
orderedSet.add(2);

// 删除元素
orderedSet.delete(1);

// 检查是否存在元素
console.log(orderedSet.has(1)); // 输出: false
console.log(orderedSet.has(2)); // 输出: true
```

**代码逻辑推理 (以 `OrderedHashMapDeletion` 为例):**

**假设输入:**

1. 创建一个新的 `OrderedHashMap`。
2. 添加键 `key1` 和 `key2`。

**预期输出:**

1. 成功删除 `key1`，哈希表中不再包含 `key1`，但仍然包含 `key2`。
2. 尝试删除不存在的键 `key3`，操作失败，哈希表状态不变。

**用户常见的编程错误 (与哈希表相关):**

1. **假设哈希表的迭代顺序**: 在某些编程语言中，标准哈希表的迭代顺序是不确定的。V8 的 `OrderedHashMap` 保证了插入顺序，但用户可能在不保证顺序的哈希表上编写了依赖于特定顺序的代码，移植到 V8 的代码时可能会出现问题。
2. **使用对象作为键但不重写 `hashCode` 和 `equals` 方法**: 在 JavaScript 中，如果使用对象作为 `Map` 或 `Set` 的键，默认情况下只有当两个对象是同一个引用时才被认为是相同的键。用户可能期望内容相同的对象被认为是相同的键，这会导致意外的行为。

**总结这部分代码的功能:**

这部分代码是 V8 针对其有序哈希表实现进行的单元测试，重点验证了各种哈希表类型的**删除操作**的正确性，包括删除已存在和不存在的元素，以及处理具有相同哈希码的元素的情况。此外，还测试了 `OrderedNameDictionary` 的**插入、查找和修改功能**。这些测试确保了 V8 的哈希表能够在各种场景下正确地管理键值对和元素，并保持预期的内部状态。

### 提示词
```
这是目录为v8/test/cctest/test-orderedhashtable.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/test-orderedhashtable.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
te the key!
  CHECK(!OrderedHashMap::Delete(isolate, *map, *key2));
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key2));
}

TEST(SmallOrderedHashMapDuplicateHashCodeDeletion) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<SmallOrderedHashMap> map = factory->NewSmallOrderedHashMap();
  DirectHandle<JSObject> key1 = factory->NewJSObjectWithNullProto();
  DirectHandle<JSObject> value = factory->NewJSObjectWithNullProto();
  map = SmallOrderedHashMap::Add(isolate, map, key1, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  CHECK(map->HasKey(isolate, key1));

  DirectHandle<JSObject> key2 = factory->NewJSObjectWithNullProto();
  CopyHashCode(key1, key2);

  // We shouldn't be able to delete the key!
  CHECK(!SmallOrderedHashMap::Delete(isolate, *map, *key2));
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  CHECK(map->HasKey(isolate, key1));
  CHECK(!map->HasKey(isolate, key2));
}

TEST(OrderedHashSetDeletion) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<OrderedHashSet> set = factory->NewOrderedHashSet();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(0, set->NumberOfElements());
  CHECK_EQ(0, set->NumberOfDeletedElements());

  // Delete from an empty hash table
  DirectHandle<Smi> key1(Smi::FromInt(1), isolate);
  CHECK(!OrderedHashSet::Delete(isolate, *set, *key1));
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(0, set->NumberOfElements());
  CHECK_EQ(0, set->NumberOfDeletedElements());
  CHECK(!OrderedHashSet::HasKey(isolate, *set, *key1));

  set = OrderedHashSet::Add(isolate, set, key1).ToHandleChecked();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(1, set->NumberOfElements());
  CHECK_EQ(0, set->NumberOfDeletedElements());
  CHECK(OrderedHashSet::HasKey(isolate, *set, *key1));

  // Delete single existing key
  CHECK(OrderedHashSet::Delete(isolate, *set, *key1));
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(0, set->NumberOfElements());
  CHECK_EQ(1, set->NumberOfDeletedElements());
  CHECK(!OrderedHashSet::HasKey(isolate, *set, *key1));

  set = OrderedHashSet::Add(isolate, set, key1).ToHandleChecked();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(1, set->NumberOfElements());
  CHECK_EQ(1, set->NumberOfDeletedElements());
  CHECK(OrderedHashSet::HasKey(isolate, *set, *key1));

  DirectHandle<String> key2 = factory->NewStringFromAsciiChecked("foo");
  CHECK(!OrderedHashSet::HasKey(isolate, *set, *key2));
  set = OrderedHashSet::Add(isolate, set, key2).ToHandleChecked();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(2, set->NumberOfElements());
  CHECK_EQ(1, set->NumberOfDeletedElements());
  CHECK(OrderedHashSet::HasKey(isolate, *set, *key2));

  DirectHandle<Symbol> key3 = factory->NewSymbol();
  CHECK(!OrderedHashSet::HasKey(isolate, *set, *key3));
  set = OrderedHashSet::Add(isolate, set, key3).ToHandleChecked();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(3, set->NumberOfElements());
  CHECK_EQ(1, set->NumberOfDeletedElements());
  CHECK(OrderedHashSet::HasKey(isolate, *set, *key1));
  CHECK(OrderedHashSet::HasKey(isolate, *set, *key2));
  CHECK(OrderedHashSet::HasKey(isolate, *set, *key3));

  // Delete multiple existing keys
  CHECK(OrderedHashSet::Delete(isolate, *set, *key1));
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(2, set->NumberOfElements());
  CHECK_EQ(2, set->NumberOfDeletedElements());
  CHECK(!OrderedHashSet::HasKey(isolate, *set, *key1));
  CHECK(OrderedHashSet::HasKey(isolate, *set, *key2));
  CHECK(OrderedHashSet::HasKey(isolate, *set, *key3));

  CHECK(OrderedHashSet::Delete(isolate, *set, *key2));
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(1, set->NumberOfElements());
  CHECK_EQ(3, set->NumberOfDeletedElements());
  CHECK(!OrderedHashSet::HasKey(isolate, *set, *key1));
  CHECK(!OrderedHashSet::HasKey(isolate, *set, *key2));
  CHECK(OrderedHashSet::HasKey(isolate, *set, *key3));

  CHECK(OrderedHashSet::Delete(isolate, *set, *key3));
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(0, set->NumberOfElements());
  CHECK_EQ(4, set->NumberOfDeletedElements());
  CHECK(!OrderedHashSet::HasKey(isolate, *set, *key1));
  CHECK(!OrderedHashSet::HasKey(isolate, *set, *key2));
  CHECK(!OrderedHashSet::HasKey(isolate, *set, *key3));

  // Delete non existent key from non new hash table
  CHECK(!OrderedHashSet::Delete(isolate, *set, *key3));
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(0, set->NumberOfElements());
  CHECK_EQ(4, set->NumberOfDeletedElements());
  CHECK(!OrderedHashSet::HasKey(isolate, *set, *key1));
  CHECK(!OrderedHashSet::HasKey(isolate, *set, *key2));
  CHECK(!OrderedHashSet::HasKey(isolate, *set, *key3));

  // Delete non existent key from non empty hash table
  set = OrderedHashSet::Shrink(isolate, set);
  set = OrderedHashSet::Add(isolate, set, key1).ToHandleChecked();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(1, set->NumberOfElements());
  CHECK_EQ(0, set->NumberOfDeletedElements());
  CHECK(OrderedHashSet::HasKey(isolate, *set, *key1));
  CHECK(!OrderedHashSet::HasKey(isolate, *set, *key2));
  CHECK(!OrderedHashSet::HasKey(isolate, *set, *key3));
  CHECK(!OrderedHashSet::Delete(isolate, *set, *key2));
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(1, set->NumberOfElements());
  CHECK_EQ(0, set->NumberOfDeletedElements());
  CHECK(OrderedHashSet::HasKey(isolate, *set, *key1));
  CHECK(!OrderedHashSet::HasKey(isolate, *set, *key2));
  CHECK(!OrderedHashSet::HasKey(isolate, *set, *key3));
}

TEST(SmallOrderedHashSetDeletion) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<SmallOrderedHashSet> set = factory->NewSmallOrderedHashSet();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(0, set->NumberOfElements());
  CHECK_EQ(0, set->NumberOfDeletedElements());

  // Delete from an empty hash table
  DirectHandle<Smi> key1(Smi::FromInt(1), isolate);
  CHECK(!SmallOrderedHashSet::Delete(isolate, *set, *key1));
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(0, set->NumberOfElements());
  CHECK_EQ(0, set->NumberOfDeletedElements());
  CHECK(!set->HasKey(isolate, key1));

  set = SmallOrderedHashSet::Add(isolate, set, key1).ToHandleChecked();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(1, set->NumberOfElements());
  CHECK_EQ(0, set->NumberOfDeletedElements());
  CHECK(set->HasKey(isolate, key1));

  // Delete single existing key
  CHECK(SmallOrderedHashSet::Delete(isolate, *set, *key1));
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(0, set->NumberOfElements());
  CHECK_EQ(1, set->NumberOfDeletedElements());
  CHECK(!set->HasKey(isolate, key1));

  set = SmallOrderedHashSet::Add(isolate, set, key1).ToHandleChecked();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(1, set->NumberOfElements());
  CHECK_EQ(1, set->NumberOfDeletedElements());
  CHECK(set->HasKey(isolate, key1));

  DirectHandle<String> key2 = factory->NewStringFromAsciiChecked("foo");
  CHECK(!set->HasKey(isolate, key2));
  set = SmallOrderedHashSet::Add(isolate, set, key2).ToHandleChecked();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(2, set->NumberOfElements());
  CHECK_EQ(1, set->NumberOfDeletedElements());
  CHECK(set->HasKey(isolate, key2));

  DirectHandle<Symbol> key3 = factory->NewSymbol();
  CHECK(!set->HasKey(isolate, key3));
  set = SmallOrderedHashSet::Add(isolate, set, key3).ToHandleChecked();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(3, set->NumberOfElements());
  CHECK_EQ(1, set->NumberOfDeletedElements());
  CHECK(set->HasKey(isolate, key1));
  CHECK(set->HasKey(isolate, key2));
  CHECK(set->HasKey(isolate, key3));

  // Delete multiple existing keys
  CHECK(SmallOrderedHashSet::Delete(isolate, *set, *key1));
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(2, set->NumberOfElements());
  CHECK_EQ(2, set->NumberOfDeletedElements());
  CHECK(!set->HasKey(isolate, key1));
  CHECK(set->HasKey(isolate, key2));
  CHECK(set->HasKey(isolate, key3));

  CHECK(SmallOrderedHashSet::Delete(isolate, *set, *key2));
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(1, set->NumberOfElements());
  CHECK_EQ(3, set->NumberOfDeletedElements());
  CHECK(!set->HasKey(isolate, key1));
  CHECK(!set->HasKey(isolate, key2));
  CHECK(set->HasKey(isolate, key3));

  CHECK(SmallOrderedHashSet::Delete(isolate, *set, *key3));
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(0, set->NumberOfElements());
  CHECK_EQ(4, set->NumberOfDeletedElements());
  CHECK(!set->HasKey(isolate, key1));
  CHECK(!set->HasKey(isolate, key2));
  CHECK(!set->HasKey(isolate, key3));

  // Delete non existent key from non new hash table
  CHECK(!SmallOrderedHashSet::Delete(isolate, *set, *key3));
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(0, set->NumberOfElements());
  CHECK_EQ(4, set->NumberOfDeletedElements());
  CHECK(!set->HasKey(isolate, key1));
  CHECK(!set->HasKey(isolate, key2));
  CHECK(!set->HasKey(isolate, key3));

  // Delete non existent key from non empty hash table
  set = SmallOrderedHashSet::Add(isolate, set, key1).ToHandleChecked();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(1, set->NumberOfElements());
  CHECK_EQ(0, set->NumberOfDeletedElements());
  CHECK(set->HasKey(isolate, key1));
  CHECK(!set->HasKey(isolate, key2));
  CHECK(!set->HasKey(isolate, key3));
  CHECK(!SmallOrderedHashSet::Delete(isolate, *set, *key2));
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(1, set->NumberOfElements());
  CHECK_EQ(0, set->NumberOfDeletedElements());
  CHECK(set->HasKey(isolate, key1));
  CHECK(!set->HasKey(isolate, key2));
  CHECK(!set->HasKey(isolate, key3));
}

TEST(OrderedHashSetDuplicateHashCodeDeletion) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<OrderedHashSet> set = factory->NewOrderedHashSet();
  DirectHandle<JSObject> key1 = factory->NewJSObjectWithNullProto();
  set = OrderedHashSet::Add(isolate, set, key1).ToHandleChecked();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(1, set->NumberOfElements());
  CHECK_EQ(0, set->NumberOfDeletedElements());
  CHECK(OrderedHashSet::HasKey(isolate, *set, *key1));

  DirectHandle<JSObject> key2 = factory->NewJSObjectWithNullProto();
  CopyHashCode(key1, key2);

  // We shouldn't be able to delete the key!
  CHECK(!OrderedHashSet::Delete(isolate, *set, *key2));
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(1, set->NumberOfElements());
  CHECK_EQ(0, set->NumberOfDeletedElements());
  CHECK(OrderedHashSet::HasKey(isolate, *set, *key1));
  CHECK(!OrderedHashSet::HasKey(isolate, *set, *key2));
}

TEST(SmallOrderedHashSetDuplicateHashCodeDeletion) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<SmallOrderedHashSet> set = factory->NewSmallOrderedHashSet();
  DirectHandle<JSObject> key1 = factory->NewJSObjectWithNullProto();
  set = SmallOrderedHashSet::Add(isolate, set, key1).ToHandleChecked();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(1, set->NumberOfElements());
  CHECK_EQ(0, set->NumberOfDeletedElements());
  CHECK(set->HasKey(isolate, key1));

  DirectHandle<JSObject> key2 = factory->NewJSObjectWithNullProto();
  CopyHashCode(key1, key2);

  // We shouldn't be able to delete the key!
  CHECK(!SmallOrderedHashSet::Delete(isolate, *set, *key2));
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(1, set->NumberOfElements());
  CHECK_EQ(0, set->NumberOfDeletedElements());
  CHECK(set->HasKey(isolate, key1));
  CHECK(!set->HasKey(isolate, key2));
}

TEST(OrderedHashSetHandlerInsertion) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  HandleScope scope(isolate);

  Handle<HeapObject> set =
      OrderedHashSetHandler::Allocate(isolate, 4).ToHandleChecked();
  Verify(isolate, set);

  // Add a new key.
  Handle<Smi> key1(Smi::FromInt(1), isolate);
  CHECK(!OrderedHashSetHandler::HasKey(isolate, set, key1));
  set = OrderedHashSetHandler::Add(isolate, set, key1).ToHandleChecked();
  Verify(isolate, set);
  CHECK(OrderedHashSetHandler::HasKey(isolate, set, key1));

  // Add existing key.
  set = OrderedHashSetHandler::Add(isolate, set, key1).ToHandleChecked();
  Verify(isolate, set);
  CHECK(OrderedHashSetHandler::HasKey(isolate, set, key1));
  CHECK(SmallOrderedHashSet::Is(set));

  for (int i = 0; i < 1024; i++) {
    DirectHandle<Smi> key_i(Smi::FromInt(i), isolate);
    set = OrderedHashSetHandler::Add(isolate, set, key_i).ToHandleChecked();
    Verify(isolate, set);
    for (int j = 0; j <= i; j++) {
      Handle<Smi> key_j(Smi::FromInt(j), isolate);
      CHECK(OrderedHashSetHandler::HasKey(isolate, set, key_j));
    }
  }
  CHECK(OrderedHashSet::Is(set));
}

TEST(OrderedHashMapHandlerInsertion) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  HandleScope scope(isolate);

  Handle<HeapObject> map =
      OrderedHashMapHandler::Allocate(isolate, 4).ToHandleChecked();
  Verify(isolate, map);

  // Add a new key.
  Handle<Smi> key1(Smi::FromInt(1), isolate);
  DirectHandle<Smi> value1(Smi::FromInt(1), isolate);
  CHECK(!OrderedHashMapHandler::HasKey(isolate, map, key1));
  map =
      OrderedHashMapHandler::Add(isolate, map, key1, value1).ToHandleChecked();
  Verify(isolate, map);
  CHECK(OrderedHashMapHandler::HasKey(isolate, map, key1));

  // Add existing key.
  map =
      OrderedHashMapHandler::Add(isolate, map, key1, value1).ToHandleChecked();
  Verify(isolate, map);
  CHECK(OrderedHashMapHandler::HasKey(isolate, map, key1));
  CHECK(SmallOrderedHashMap::Is(map));

  for (int i = 0; i < 1024; i++) {
    DirectHandle<Smi> key_i(Smi::FromInt(i), isolate);
    DirectHandle<Smi> value_i(Smi::FromInt(i), isolate);
    map = OrderedHashMapHandler::Add(isolate, map, key_i, value_i)
              .ToHandleChecked();
    Verify(isolate, map);
    for (int j = 0; j <= i; j++) {
      Handle<Smi> key_j(Smi::FromInt(j), isolate);
      CHECK(OrderedHashMapHandler::HasKey(isolate, map, key_j));
    }
  }
  CHECK(OrderedHashMap::Is(map));
}

TEST(OrderedHashSetHandlerDeletion) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  HandleScope scope(isolate);

  Handle<HeapObject> set =
      OrderedHashSetHandler::Allocate(isolate, 4).ToHandleChecked();
  Verify(isolate, set);

  // Add a new key.
  Handle<Smi> key1(Smi::FromInt(1), isolate);
  CHECK(!OrderedHashSetHandler::HasKey(isolate, set, key1));
  set = OrderedHashSetHandler::Add(isolate, set, key1).ToHandleChecked();
  Verify(isolate, set);
  CHECK(OrderedHashSetHandler::HasKey(isolate, set, key1));

  // Add existing key.
  set = OrderedHashSetHandler::Add(isolate, set, key1).ToHandleChecked();
  Verify(isolate, set);
  CHECK(OrderedHashSetHandler::HasKey(isolate, set, key1));
  CHECK(SmallOrderedHashSet::Is(set));

  // Remove a non-existing key.
  Handle<Smi> key2(Smi::FromInt(2), isolate);
  OrderedHashSetHandler::Delete(isolate, set, key2);
  Verify(isolate, set);
  CHECK(OrderedHashSetHandler::HasKey(isolate, set, key1));
  CHECK(!OrderedHashSetHandler::HasKey(isolate, set, key2));
  CHECK(SmallOrderedHashSet::Is(set));

  // Remove an existing key.
  OrderedHashSetHandler::Delete(isolate, set, key1);
  Verify(isolate, set);
  CHECK(!OrderedHashSetHandler::HasKey(isolate, set, key1));
  CHECK(SmallOrderedHashSet::Is(set));
}

TEST(OrderedHashMapHandlerDeletion) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  HandleScope scope(isolate);

  Handle<HeapObject> map =
      OrderedHashMapHandler::Allocate(isolate, 4).ToHandleChecked();
  Verify(isolate, map);

  // Add a new key.
  Handle<Smi> key1(Smi::FromInt(1), isolate);
  DirectHandle<Smi> value1(Smi::FromInt(1), isolate);
  CHECK(!OrderedHashMapHandler::HasKey(isolate, map, key1));
  map =
      OrderedHashMapHandler::Add(isolate, map, key1, value1).ToHandleChecked();
  Verify(isolate, map);
  CHECK(OrderedHashMapHandler::HasKey(isolate, map, key1));

  // Add existing key.
  map =
      OrderedHashMapHandler::Add(isolate, map, key1, value1).ToHandleChecked();
  Verify(isolate, map);
  CHECK(OrderedHashMapHandler::HasKey(isolate, map, key1));
  CHECK(SmallOrderedHashMap::Is(map));

  // Remove a non-existing key.
  Handle<Smi> key2(Smi::FromInt(2), isolate);
  OrderedHashMapHandler::Delete(isolate, map, key2);
  Verify(isolate, map);
  CHECK(OrderedHashMapHandler::HasKey(isolate, map, key1));
  CHECK(!OrderedHashMapHandler::HasKey(isolate, map, key2));
  CHECK(SmallOrderedHashMap::Is(map));

  // Remove an existing key.
  OrderedHashMapHandler::Delete(isolate, map, key1);
  Verify(isolate, map);
  CHECK(!OrderedHashMapHandler::HasKey(isolate, map, key1));
  CHECK(SmallOrderedHashMap::Is(map));
}

TEST(OrderedNameDictionaryInsertion) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<OrderedNameDictionary> dict =
      OrderedNameDictionary::Allocate(isolate, 2).ToHandleChecked();
  Verify(isolate, dict);
  CHECK_EQ(2, dict->NumberOfBuckets());
  CHECK_EQ(0, dict->NumberOfElements());

  DirectHandle<String> key1 = isolate->factory()->InternalizeUtf8String("foo");
  DirectHandle<String> value = isolate->factory()->InternalizeUtf8String("bar");
  CHECK(dict->FindEntry(isolate, *key1).is_not_found());
  PropertyDetails details = PropertyDetails::Empty();
  dict = OrderedNameDictionary::Add(isolate, dict, key1, value, details)
             .ToHandleChecked();
  Verify(isolate, dict);
  CHECK_EQ(2, dict->NumberOfBuckets());
  CHECK_EQ(1, dict->NumberOfElements());

  CHECK_EQ(InternalIndex(0), dict->FindEntry(isolate, *key1));

  DirectHandle<Symbol> key2 = factory->NewSymbol();
  CHECK(dict->FindEntry(isolate, *key2).is_not_found());
  dict = OrderedNameDictionary::Add(isolate, dict, key2, value, details)
             .ToHandleChecked();
  Verify(isolate, dict);
  CHECK_EQ(2, dict->NumberOfBuckets());
  CHECK_EQ(2, dict->NumberOfElements());
  CHECK_EQ(InternalIndex(0), dict->FindEntry(isolate, *key1));
  CHECK_EQ(InternalIndex(1), dict->FindEntry(isolate, *key2));
}

TEST(OrderedNameDictionaryFindEntry) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<OrderedNameDictionary> dict =
      OrderedNameDictionary::Allocate(isolate, 2).ToHandleChecked();
  Verify(isolate, dict);
  CHECK_EQ(2, dict->NumberOfBuckets());
  CHECK_EQ(0, dict->NumberOfElements());

  DirectHandle<String> key1 = isolate->factory()->InternalizeUtf8String("foo");
  DirectHandle<String> value = isolate->factory()->InternalizeUtf8String("bar");
  PropertyDetails details = PropertyDetails::Empty();
  dict = OrderedNameDictionary::Add(isolate, dict, key1, value, details)
             .ToHandleChecked();
  Verify(isolate, dict);
  CHECK_EQ(2, dict->NumberOfBuckets());
  CHECK_EQ(1, dict->NumberOfElements());

  InternalIndex entry = dict->FindEntry(isolate, *key1);
  CHECK_EQ(entry, InternalIndex(0));
  CHECK(entry.is_found());

  DirectHandle<Symbol> key2 = factory->NewSymbol();
  dict = OrderedNameDictionary::Add(isolate, dict, key2, value, details)
             .ToHandleChecked();
  Verify(isolate, dict);
  CHECK_EQ(2, dict->NumberOfBuckets());
  CHECK_EQ(2, dict->NumberOfElements());

  entry = dict->FindEntry(isolate, *key1);
  CHECK(entry.is_found());
  CHECK_EQ(entry, InternalIndex(0));

  entry = dict->FindEntry(isolate, *key2);
  CHECK(entry.is_found());
  CHECK_EQ(entry, InternalIndex(1));
}

TEST(OrderedNameDictionaryValueAtAndValueAtPut) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<OrderedNameDictionary> dict =
      OrderedNameDictionary::Allocate(isolate, 2).ToHandleChecked();
  Verify(isolate, dict);
  CHECK_EQ(2, dict->NumberOfBuckets());
  CHECK_EQ(0, dict->NumberOfElements());

  DirectHandle<String> key1 = isolate->factory()->InternalizeUtf8String("foo");
  DirectHandle<String> value = isolate->factory()->InternalizeUtf8String("bar");
  CHECK(dict->FindEntry(isolate, *key1).is_not_found());
  PropertyDetails details = PropertyDetails::Empty();
  dict = OrderedNameDictionary::Add(isolate, dict, key1, value, details)
             .ToHandleChecked();
  Verify(isolate, dict);
  CHECK_EQ(2, dict->NumberOfBuckets());
  CHECK_EQ(1, dict->NumberOfElements());
  CHECK_EQ(InternalIndex(0), dict->FindEntry(isolate, *key1));

  InternalIndex entry = dict->FindEntry(isolate, *key1);
  DirectHandle<Object> found(dict->ValueAt(entry), isolate);
  CHECK_EQ(*found, *value);

  // Change the value
  DirectHandle<String> other_value =
      isolate->factory()->InternalizeUtf8String("baz");
  dict->ValueAtPut(entry, *other_value);

  entry = dict->FindEntry(isolate, *key1);
  found = direct_handle(dict->ValueAt(entry), isolate);
  CHECK_EQ(*found, *other_value);

  DirectHandle<Symbol> key2 = factory->NewSymbol();
  CHECK(dict->FindEntry(isolate, *key2).is_not_found());
  dict = OrderedNameDictionary::Add(isolate, dict, key2, value, details)
             .ToHandleChecked();
  Verify(isolate, dict);
  CHECK_EQ(2, dict->NumberOfBuckets());
  CHECK_EQ(2, dict->NumberOfElements());
  CHECK_EQ(InternalIndex(0), dict->FindEntry(isolate, *key1));
  CHECK_EQ(InternalIndex(1), dict->FindEntry(isolate, *key2));

  entry = dict->FindEntry(isolate, *key1);
  found = direct_handle(dict->ValueAt(entry), isolate);
  CHECK_EQ(*found, *other_value);

  entry = dict->FindEntry(isolate, *key2);
  found = direct_handle(dict->ValueAt(entry), isolate);
  CHECK_EQ(*found, *value);

  // Change the value
  dict->ValueAtPut(entry, *other_value);

  entry = dict->FindEntry(isolate, *key1);
  found = direct_handle(dict->ValueAt(entry), isolate);
  CHECK_EQ(*found, *other_value);
}

TEST(OrderedNameDictionaryDetailsAtAndDetailsAtPut) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<OrderedNameDictionary> dict =
      OrderedNameDictionary::Allocate(isolate, 2).ToHandleChecked();
  Verify(isolate, dict);
  CHECK_EQ(2, dict->NumberOfBuckets());
  CHECK_EQ(0, dict->NumberOfElements());

  DirectHandle<String> key1 = isolate->factory()->InternalizeUtf8String("foo");
  DirectHandle<String> value = isolate->factory()->InternalizeUtf8String("bar");
  CHECK(dict->FindEntry(isolate, *key1).is_not_found());
  PropertyDetails details = PropertyDetails::Empty();
  dict = OrderedNameDictionary::Add(isolate, dict, key1, value, details)
             .ToHandleChecked();
  Verify(isolate, dict);
  CHECK_EQ(2, dict->NumberOfBuckets());
  CHECK_EQ(1, dict->NumberOfElements());
  CHECK_EQ(InternalIndex(0), dict->FindEntry(isolate, *key1));

  InternalIndex entry = dict->FindEntry(isolate, *key1);
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
  dict = OrderedNameDictionary::Add(isolate, dict, key2, value, details)
             .ToHandleChecked();
  Verify(isolate, dict);
  CHECK_EQ(2, dict->NumberOfBuckets());
  CHECK_EQ(2, dict->NumberOfElements());
  CHECK_EQ(InternalIndex(0), dict->FindEntry(isolate, *key1));
  CHECK_EQ(InternalIndex(1), dict->FindEntry(isolate, *key2));

  entry = dict->FindEntry(isolate, *key1);
  found = dict->DetailsAt(entry);
  CHECK_EQ(other.AsSmi(), found.AsSmi());
  CHECK_NE(PropertyDetails::Empty().AsSmi(), found.AsSmi());

  entry = dict->FindEntry(isolate, *key2);
  dict->DetailsAtPut(entry, other);

  found = dict->DetailsAt(entry);
  CHECK_NE(PropertyDetails::Empty().AsSmi(), found.AsSmi());
  CHECK_EQ(other.AsSmi(), found.AsSmi());
}

TEST(SmallOrderedNameDictionaryInsertion) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<SmallOrderedNameDictionary> dict =
      factory->NewSmallOrderedNameDictionary();
  Verify(isolate, dict);
  CHECK_EQ(2, dict->NumberOfBuckets());
  CHECK_EQ(0, dict->NumberOfElements());

  DirectHandle<String> key1 = isolate->factory()->InternalizeUtf8String("foo");
  DirectHandle<String> value = isolate->factory()->InternalizeUtf8String("bar");
  CHECK(dict->FindEntry(isolate, *key1).is_not_found());
  PropertyDetails details = PropertyDetails::Empty();
  dict = SmallOrderedNameDictionary::Add(isolate, dict, key1, value, details)
             .ToHandleChecked();
  Verify(isolate, dict);
  CHECK_EQ(2, dict->NumberOfBuckets());
  CHECK_EQ(1, dict->NumberOfElements());
  CHECK_EQ(InternalIndex(0), dict->FindEntry(isolate, *key1));

  DirectHandle<Symbol> key2 = factory->NewSymbol();
  CHECK(dict->FindEntry(isolate, *key2).is_not_found());
  dict = SmallOrderedNameDictionary::Add(isolate, dict, key2, value, details)
             .ToHandleChecked();
  Verify(isolate, dict);
  CHECK_EQ(2, dict->NumberOfBuckets());
  CHECK_EQ(2, dict->NumberOfElements());
  CHECK_EQ(InternalIndex(0), dict->FindEntry(isolate, *key1));
  CHECK_EQ(InternalIndex(1), dict->FindEntry(isolate, *key2));
}

TEST(SmallOrderedNameDictionaryInsertionMax) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);
  Handle<SmallOrderedNameDictionary> dict =
      factory->NewSmallOrderedNameDictionary();
  DirectHandle<String> value = isolate->factory()->InternalizeUtf8String("bar");
  PropertyDetails details = PropertyDetails::Empty();

  char buf[10];
  for (int i = 0; i < SmallOrderedNameDictionary::kMaxCapacity; i++) {
    CHECK_LT(0, snprintf(buf, sizeof(buf), "foo%d", i));
    DirectHandle<String> key = isolate->factory()->InternalizeUtf8String(buf);
    dict = SmallOrderedNameDictionary::Add(isolate, dict, key, value, details)
               .ToHandleChecked();
    Verify(isolate, dict);
  }

  CHECK_EQ(SmallOrderedNameDictionary::kMaxCapacity /
               SmallOrderedNameDictionary::kLoadFactor,
           dict->NumberOfBuckets());
  CHECK_EQ(SmallOrderedNameDictionary::kMaxCapacity, dict->NumberOfElements());

  // This should overflow and fail.
  CHECK(SmallOrderedNameDictionary::Add(isolate, dict, value, value, details)
            .is_null());
}

TEST(SmallOrderedNameDictionaryFindEntry) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<SmallOrderedNameDictionary> dict =
      factory->NewSmallOrderedNameDictionary();
  Verify(isolate, dict);
  CHECK_EQ(2, dict->NumberOfBuckets());
  CHECK_EQ(0, dict->NumberOfElements());

  DirectHandle<String> key1 = isolate->factory()->InternalizeUtf8String("foo");
  DirectHandle<String> value = isolate->factory()->InternalizeUtf8String("bar");
  CHECK(dict->FindEntry(isolate, *key1).is_not_found());
  PropertyDetails details = PropertyDetails::Empty();

  dict = SmallOrderedNameDictionary::Add(isolate, dict, key1, value, details)
             .ToHandleChecked();
  Verify(isolate, dict);
  CHECK_EQ(2, dict->NumberOfBuckets());
  CHECK_EQ(1, dict->NumberOfElements());
  CHECK_EQ(InternalIndex(0), dict->FindEntry(isolate, *key1));

  InternalIndex entry = dict->FindEntry(isolate, *key1);
  CHECK(entry.is_found());

  DirectHandle<Symbol> key2 = factory->NewSymbol();
  CHECK(dict->FindEntry(isolate, *key2).is_not_found());
  dict = SmallOrderedNameDictionary::Add(isolate, dict, key2, value, details)
             .ToHandleChecked();
  Verify(isolate, dict);
  CHECK_EQ(2, dict->NumberOfBuckets());
  CHECK_EQ(2, dict->NumberOfElements());

  CHECK_EQ(InternalIndex(0), dict->FindEntry(isolate, *key1));
  CHECK_EQ(InternalIndex(1), dict->FindEntry(isolate, *key2));
}

TEST(SmallOrderedNameDictionaryValueAtAndValueAtPut) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<SmallOrderedNameDictionary> dict =
      factory->NewSmallOrderedNameDictionary();
  Verify(isolate, dict);
  CHECK_EQ(2, dict->NumberOfBuckets());
  CHECK_EQ(0, dict->NumberOfElements());

  DirectHandle<String> key1 = isolate->factory()->InternalizeUtf8String("foo");
  DirectHandle<String> value = isolate->factory()->InternalizeUtf8String("bar");
  CHECK(dict->FindEntry(isolate, *key1).is_not_found());
  PropertyDetails details = PropertyDetails::Empty();
  dict = SmallOrderedNameDictionary::Add(isolate, dict, key1, value, details)
             .ToHandleChecked();
  Verify(isolate, dict);
  CHECK_EQ(2, dict->NumberOfBuckets());
  CHECK_EQ(1, dict->NumberOfElements());
  CHECK_EQ(InternalIndex(0), dict->FindEntry(isolate, *key1));

  InternalIndex entry = dict->FindEntry(isolate, *key1);
  DirectHandle<Object> found(dict->ValueAt(entry), isolate);
  CHECK_EQ(*found, *value);

  // Change the value
  DirectHandle<String> other_value =
      isolate->factory()->InternalizeUtf8String("baz");
  dict->ValueAtPut(entry, *other_value);

  entry = dict->FindEntry(isolate, *key1);
  found = direct_handle(dict->ValueAt(entry), isolate);
  CHECK_EQ(*found, *other_value);

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
  found = direct_handle(dict->ValueAt(entry), isolate);
  CHECK_EQ(*found, *other_value);

  entry = dict->FindEntry(isolate, *key2);
  found = direct_handle(dict->ValueAt(entry), isolate);
  CHECK_EQ(*found, *value);

  // Change the value
  dict->ValueAtPut(entry, *other_value);

  entry = dict->FindEntry(isolate, *key1);
  found = direct_handle(dict->ValueAt(entry), isolate);
  CHECK_EQ(*found, *other_value);
}

TEST(SmallOrderedNameDictionaryDetailsAtAndDetailsAtPut) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<SmallOrderedNameDictionary> dict =
      factory->NewSmallOrderedNameDictionary();
  Verify(isolate, dict);
  CHECK_EQ(2, dict->NumberOfBuckets());
  CHECK_EQ(0, dict->NumberOfElements());

  DirectHandle<String> key1 = isolate->factory()->InternalizeUtf8String("foo");
  DirectHandle<String> value = isolate->factory()->InternalizeUtf8String("bar");
  CHECK(dict->FindEntry(isolate, *key1).is_not_found());
  PropertyDetails details = PropertyDetails::Empty();
  dict = SmallOrderedNameDictionary::Add(isolate, dict, key1, value, details)
             .ToHandleChecked();
  Verify(isolate, dict);
  CHECK_EQ(2, dict->NumberOfBuckets());
  CHECK_EQ(1, dict->NumberOfElements());
  CHECK_EQ(InternalIndex(0), dict->FindEntry(isolate, *key1));

  InternalIndex entry =
```