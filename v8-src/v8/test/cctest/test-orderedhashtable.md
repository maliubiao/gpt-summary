Response: The user provided a C++ source code file for testing ordered hash tables in the V8 JavaScript engine. The request is to summarize the functionality of this code and illustrate its connection to JavaScript using examples.

**Plan:**

1. **Analyze the C++ code:** Identify the data structures being tested (e.g., `OrderedHashMap`, `OrderedHashSet`, `OrderedNameDictionary`, their "Small" variants).
2. **Identify the test scenarios:**  Look for `TEST(...)` macros and the operations being performed within each test (insertion, deletion, finding elements, handling duplicate hash codes, growing the table).
3. **Relate the C++ concepts to JavaScript:** Explain how these ordered hash tables are used internally to implement JavaScript objects and their properties.
4. **Provide JavaScript examples:** Demonstrate JavaScript code that uses objects and their properties, and explain how the underlying C++ data structures are involved.
这个C++源代码文件是V8 JavaScript引擎的一部分，专门用于测试**有序哈希表**的实现。更具体地说，它测试了以下几种有序哈希表：

* **`OrderedHashMap`**:  一个存储键值对的哈希表，它会记住插入的顺序。
* **`OrderedHashSet`**: 一个存储唯一值的哈希集合，它也会记住插入的顺序。
* **`OrderedNameDictionary`**:  一种专门用于存储对象属性的有序字典，除了键值对，还存储属性的详细信息 (PropertyDetails)。
* **`SmallOrderedHashMap`**, **`SmallOrderedHashSet`**, **`SmallOrderedNameDictionary`**:  这些是针对少量元素优化的、基于内联存储的有序哈希表变体。
* **`OrderedHashMapHandler`**, **`OrderedHashSetHandler`**:  用于管理`OrderedHashMap`和`OrderedHashSet`的句柄，允许在必要时进行增长。

**总而言之，这个文件的主要功能是：**

1. **验证不同有序哈希表类型的基本操作**：包括插入新元素、插入已存在的元素、查找元素是否存在、删除元素。
2. **测试哈希表的增长机制**：验证当元素数量超过初始容量时，哈希表能否正确地扩展其内部存储。
3. **测试处理哈希冲突的情况**：特别是当不同的对象具有相同的哈希值时，哈希表是否能正确处理。
4. **验证`SmallOrdered*` 类型的优化**：确保针对少量元素的优化工作正常。
5. **测试`OrderedNameDictionary` 特有的功能**：例如，存储和修改 `PropertyDetails`。
6. **测试使用 `OrderedHashMapHandler` 和 `OrderedHashSetHandler` 进行动态分配和管理的能力。**

**与 JavaScript 的功能关系：**

有序哈希表在 V8 引擎中扮演着至关重要的角色，它们是 JavaScript **对象（Object）** 的核心实现机制之一。

* **存储对象属性**：当你在 JavaScript 中创建一个对象并为其添加属性时，V8 内部很可能会使用有序哈希表来存储这些属性的键（属性名）和值。**保持插入顺序对于某些语言特性很重要，例如 `for...in` 循环遍历属性的顺序。**
* **实现 Set 和 Map 数据结构**：JavaScript 的 `Set` 和 `Map` 数据结构在 V8 内部也是基于哈希表实现的，并且需要保持元素的插入顺序。`OrderedHashSet` 和 `OrderedHashMap` 的 C++ 实现与此直接相关。

**JavaScript 举例说明：**

```javascript
// 创建一个 JavaScript 对象
const myObject = {};

// 添加属性（插入操作）
myObject.a = 1;
myObject.b = "hello";
myObject.c = true;

// 检查属性是否存在（查找操作）
console.log("a" in myObject); // 输出: true

// 删除属性（删除操作）
delete myObject.b;

// 遍历属性 (保持插入顺序)
for (let key in myObject) {
  console.log(key); // 输出顺序可能为: a, c (因为 b 被删除了)
}

// 使用 Set 数据结构
const mySet = new Set();
mySet.add(10);
mySet.add("world");
mySet.add(true);

for (let item of mySet) {
  console.log(item); // 输出顺序会保持插入顺序: 10, "world", true
}

// 使用 Map 数据结构
const myMap = new Map();
myMap.set("name", "Alice");
myMap.set("age", 30);

for (let [key, value] of myMap) {
  console.log(key, value); // 输出顺序会保持插入顺序: name Alice, age 30
}
```

**解释:**

* 当你在 `myObject` 中添加属性 `a`，`b`，`c` 时，V8 内部的有序哈希表（例如，基于 `OrderedHashMap` 的实现）会按照这个顺序存储 "a": 1, "b": "hello", "c": true。
* `console.log("a" in myObject)` 操作实际上会调用 V8 内部的哈希表查找机制来检查键 "a" 是否存在。
* `delete myObject.b` 操作会从内部哈希表中删除键为 "b" 的条目。
* `for...in` 循环遍历 `myObject` 的属性时，由于底层使用了有序哈希表，所以遍历的顺序通常会保持属性插入的顺序。
* `Set` 和 `Map` 数据结构在 JavaScript 中的行为也依赖于 V8 内部的有序哈希表实现，以保证元素的唯一性和插入顺序。

因此，`v8/test/cctest/test-orderedhashtable.cc` 文件中的测试直接关系到 JavaScript 中对象属性的存储、`Set` 和 `Map` 数据结构的行为等核心功能。确保这些有序哈希表的实现是正确和高效的，对于 V8 引擎的性能和 JavaScript 语言特性的正确运行至关重要。

Prompt: 
```
这是目录为v8/test/cctest/test-orderedhashtable.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include <utility>

#include "src/objects/objects-inl.h"
#include "src/objects/ordered-hash-table-inl.h"
#include "test/cctest/cctest.h"

namespace v8 {
namespace internal {
namespace test_orderedhashtable {

static Isolate* GetIsolateFrom(LocalContext* context) {
  return reinterpret_cast<Isolate*>((*context)->GetIsolate());
}

void CopyHashCode(DirectHandle<JSReceiver> from, DirectHandle<JSReceiver> to) {
  int hash = Smi::ToInt(Object::GetHash(*from));
  to->SetIdentityHash(hash);
}

void Verify(Isolate* isolate, DirectHandle<HeapObject> obj) {
#if VERIFY_HEAP
  Object::ObjectVerify(*obj, isolate);
#endif
}

// Helpers to abstract over differences in interfaces of the different ordered
// datastructures

template <typename T>
Handle<T> Add(Isolate* isolate, Handle<T> table, Handle<String> key1,
              Handle<String> value1, PropertyDetails details);

template <>
Handle<OrderedHashMap> Add(Isolate* isolate, Handle<OrderedHashMap> table,
                           Handle<String> key, Handle<String> value,
                           PropertyDetails details) {
  return OrderedHashMap::Add(isolate, table, key, value).ToHandleChecked();
}

template <>
Handle<OrderedHashSet> Add(Isolate* isolate, Handle<OrderedHashSet> table,
                           Handle<String> key, Handle<String> value,
                           PropertyDetails details) {
  return OrderedHashSet::Add(isolate, table, key).ToHandleChecked();
}

template <>
Handle<OrderedNameDictionary> Add(Isolate* isolate,
                                  Handle<OrderedNameDictionary> table,
                                  Handle<String> key, Handle<String> value,
                                  PropertyDetails details) {
  return OrderedNameDictionary::Add(isolate, table, key, value, details)
      .ToHandleChecked();
}

// version for
// OrderedHashMap, OrderedHashSet
template <typename T>
bool HasKey(Isolate* isolate, Handle<T> table, Tagged<Object> key) {
  return T::HasKey(isolate, *table, key);
}

template <>
bool HasKey(Isolate* isolate, Handle<OrderedNameDictionary> table,
            Tagged<Object> key) {
  return table->FindEntry(isolate, key).is_found();
}

// version for
// OrderedHashTable, OrderedHashSet
template <typename T>
Handle<T> Delete(Isolate* isolate, Handle<T> table, Tagged<Object> key) {
  T::Delete(isolate, *table, key);
  return table;
}

template <>
Handle<OrderedNameDictionary> Delete(Isolate* isolate,
                                     Handle<OrderedNameDictionary> table,
                                     Tagged<Object> key) {
  // OrderedNameDictionary doesn't have Delete, but only DeleteEntry, which
  // requires the key to be deleted to be present
  InternalIndex entry = table->FindEntry(isolate, key);
  if (entry.is_not_found()) return table;

  return OrderedNameDictionary::DeleteEntry(isolate, table, entry);
}

TEST(SmallOrderedHashSetInsertion) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<SmallOrderedHashSet> set = factory->NewSmallOrderedHashSet();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(0, set->NumberOfElements());

  // Add a new key.
  DirectHandle<Smi> key1(Smi::FromInt(1), isolate);
  CHECK(!set->HasKey(isolate, key1));
  set = SmallOrderedHashSet::Add(isolate, set, key1).ToHandleChecked();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(1, set->NumberOfElements());
  CHECK(set->HasKey(isolate, key1));

  // Add existing key.
  set = SmallOrderedHashSet::Add(isolate, set, key1).ToHandleChecked();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(1, set->NumberOfElements());
  CHECK(set->HasKey(isolate, key1));

  DirectHandle<String> key2 = factory->NewStringFromAsciiChecked("foo");
  CHECK(!set->HasKey(isolate, key2));
  set = SmallOrderedHashSet::Add(isolate, set, key2).ToHandleChecked();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(2, set->NumberOfElements());
  CHECK(set->HasKey(isolate, key1));
  CHECK(set->HasKey(isolate, key2));

  set = SmallOrderedHashSet::Add(isolate, set, key2).ToHandleChecked();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(2, set->NumberOfElements());
  CHECK(set->HasKey(isolate, key1));
  CHECK(set->HasKey(isolate, key2));

  DirectHandle<Symbol> key3 = factory->NewSymbol();
  CHECK(!set->HasKey(isolate, key3));
  set = SmallOrderedHashSet::Add(isolate, set, key3).ToHandleChecked();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(3, set->NumberOfElements());
  CHECK(set->HasKey(isolate, key1));
  CHECK(set->HasKey(isolate, key2));
  CHECK(set->HasKey(isolate, key3));

  set = SmallOrderedHashSet::Add(isolate, set, key3).ToHandleChecked();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(3, set->NumberOfElements());
  CHECK(set->HasKey(isolate, key1));
  CHECK(set->HasKey(isolate, key2));
  CHECK(set->HasKey(isolate, key3));

  DirectHandle<Object> key4 = factory->NewHeapNumber(42.0);
  CHECK(!set->HasKey(isolate, key4));
  set = SmallOrderedHashSet::Add(isolate, set, key4).ToHandleChecked();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(4, set->NumberOfElements());
  CHECK(set->HasKey(isolate, key1));
  CHECK(set->HasKey(isolate, key2));
  CHECK(set->HasKey(isolate, key3));
  CHECK(set->HasKey(isolate, key4));

  set = SmallOrderedHashSet::Add(isolate, set, key4).ToHandleChecked();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(4, set->NumberOfElements());
  CHECK(set->HasKey(isolate, key1));
  CHECK(set->HasKey(isolate, key2));
  CHECK(set->HasKey(isolate, key3));
  CHECK(set->HasKey(isolate, key4));
}

TEST(SmallOrderedHashMapInsertion) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<SmallOrderedHashMap> map = factory->NewSmallOrderedHashMap();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfElements());

  // Add a new key.
  DirectHandle<Smi> key1(Smi::FromInt(1), isolate);
  DirectHandle<Smi> value1(Smi::FromInt(1), isolate);
  CHECK(!map->HasKey(isolate, key1));
  map = SmallOrderedHashMap::Add(isolate, map, key1, value1).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK(map->HasKey(isolate, key1));

  // Add existing key.
  map = SmallOrderedHashMap::Add(isolate, map, key1, value1).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK(map->HasKey(isolate, key1));

  DirectHandle<String> key2 = factory->NewStringFromAsciiChecked("foo");
  DirectHandle<String> value = factory->NewStringFromAsciiChecked("foo");
  CHECK(!map->HasKey(isolate, key2));
  map = SmallOrderedHashMap::Add(isolate, map, key2, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(2, map->NumberOfElements());
  CHECK(map->HasKey(isolate, key1));
  CHECK(map->HasKey(isolate, key2));

  map = SmallOrderedHashMap::Add(isolate, map, key2, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(2, map->NumberOfElements());
  CHECK(map->HasKey(isolate, key1));
  CHECK(map->HasKey(isolate, key2));

  DirectHandle<Symbol> key3 = factory->NewSymbol();
  CHECK(!map->HasKey(isolate, key3));
  map = SmallOrderedHashMap::Add(isolate, map, key3, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(3, map->NumberOfElements());
  CHECK(map->HasKey(isolate, key1));
  CHECK(map->HasKey(isolate, key2));
  CHECK(map->HasKey(isolate, key3));

  map = SmallOrderedHashMap::Add(isolate, map, key3, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(3, map->NumberOfElements());
  CHECK(map->HasKey(isolate, key1));
  CHECK(map->HasKey(isolate, key2));
  CHECK(map->HasKey(isolate, key3));

  DirectHandle<Object> key4 = factory->NewHeapNumber(42.0);
  CHECK(!map->HasKey(isolate, key4));
  map = SmallOrderedHashMap::Add(isolate, map, key4, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(4, map->NumberOfElements());
  CHECK(map->HasKey(isolate, key1));
  CHECK(map->HasKey(isolate, key2));
  CHECK(map->HasKey(isolate, key3));
  CHECK(map->HasKey(isolate, key4));

  map = SmallOrderedHashMap::Add(isolate, map, key4, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(4, map->NumberOfElements());
  CHECK(map->HasKey(isolate, key1));
  CHECK(map->HasKey(isolate, key2));
  CHECK(map->HasKey(isolate, key3));
  CHECK(map->HasKey(isolate, key4));
}

TEST(SmallOrderedHashSetDuplicateHashCode) {
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
  CHECK(set->HasKey(isolate, key1));

  DirectHandle<JSObject> key2 = factory->NewJSObjectWithNullProto();
  CopyHashCode(key1, key2);

  set = SmallOrderedHashSet::Add(isolate, set, key2).ToHandleChecked();
  Verify(isolate, set);
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(2, set->NumberOfElements());
  CHECK(set->HasKey(isolate, key1));
  CHECK(set->HasKey(isolate, key2));
}

TEST(SmallOrderedHashMapDuplicateHashCode) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<SmallOrderedHashMap> map = factory->NewSmallOrderedHashMap();
  DirectHandle<JSObject> value = factory->NewJSObjectWithNullProto();
  DirectHandle<JSObject> key1 = factory->NewJSObjectWithNullProto();
  map = SmallOrderedHashMap::Add(isolate, map, key1, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK(map->HasKey(isolate, key1));

  DirectHandle<JSObject> key2 = factory->NewJSObjectWithNullProto();
  CopyHashCode(key1, key2);

  CHECK(!Object::SameValue(*key1, *key2));
  Tagged<Object> hash1 = Object::GetHash(*key1);
  Tagged<Object> hash2 = Object::GetHash(*key2);
  CHECK_EQ(hash1, hash2);

  map = SmallOrderedHashMap::Add(isolate, map, key2, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(2, map->NumberOfElements());
  CHECK(map->HasKey(isolate, key1));
  CHECK(map->HasKey(isolate, key2));
}

TEST(SmallOrderedHashSetGrow) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<SmallOrderedHashSet> set = factory->NewSmallOrderedHashSet();
  std::vector<Handle<Object>> keys;
  for (int i = 0; i < 254; i++) {
    Handle<Smi> key(Smi::FromInt(i), isolate);
    keys.push_back(key);
  }

  for (size_t i = 0; i < 4; i++) {
    set = SmallOrderedHashSet::Add(isolate, set, keys[i]).ToHandleChecked();
    Verify(isolate, set);
  }

  for (size_t i = 0; i < 4; i++) {
    CHECK(set->HasKey(isolate, keys[i]));
    Verify(isolate, set);
  }

  CHECK_EQ(4, set->NumberOfElements());
  CHECK_EQ(2, set->NumberOfBuckets());
  CHECK_EQ(0, set->NumberOfDeletedElements());
  Verify(isolate, set);

  for (size_t i = 4; i < 8; i++) {
    set = SmallOrderedHashSet::Add(isolate, set, keys[i]).ToHandleChecked();
    Verify(isolate, set);
  }

  for (size_t i = 0; i < 8; i++) {
    CHECK(set->HasKey(isolate, keys[i]));
    Verify(isolate, set);
  }

  CHECK_EQ(8, set->NumberOfElements());
  CHECK_EQ(4, set->NumberOfBuckets());
  CHECK_EQ(0, set->NumberOfDeletedElements());
  Verify(isolate, set);

  for (size_t i = 8; i < 16; i++) {
    set = SmallOrderedHashSet::Add(isolate, set, keys[i]).ToHandleChecked();
    Verify(isolate, set);
  }

  for (size_t i = 0; i < 16; i++) {
    CHECK(set->HasKey(isolate, keys[i]));
    Verify(isolate, set);
  }

  CHECK_EQ(16, set->NumberOfElements());
  CHECK_EQ(8, set->NumberOfBuckets());
  CHECK_EQ(0, set->NumberOfDeletedElements());
  Verify(isolate, set);

  for (size_t i = 16; i < 32; i++) {
    set = SmallOrderedHashSet::Add(isolate, set, keys[i]).ToHandleChecked();
    Verify(isolate, set);
  }

  for (size_t i = 0; i < 32; i++) {
    CHECK(set->HasKey(isolate, keys[i]));
    Verify(isolate, set);
  }

  CHECK_EQ(32, set->NumberOfElements());
  CHECK_EQ(16, set->NumberOfBuckets());
  CHECK_EQ(0, set->NumberOfDeletedElements());
  Verify(isolate, set);

  for (size_t i = 32; i < 64; i++) {
    set = SmallOrderedHashSet::Add(isolate, set, keys[i]).ToHandleChecked();
    Verify(isolate, set);
  }

  for (size_t i = 0; i < 64; i++) {
    CHECK(set->HasKey(isolate, keys[i]));
    Verify(isolate, set);
  }

  CHECK_EQ(64, set->NumberOfElements());
  CHECK_EQ(32, set->NumberOfBuckets());
  CHECK_EQ(0, set->NumberOfDeletedElements());
  Verify(isolate, set);

  for (size_t i = 64; i < 128; i++) {
    set = SmallOrderedHashSet::Add(isolate, set, keys[i]).ToHandleChecked();
    Verify(isolate, set);
  }

  for (size_t i = 0; i < 128; i++) {
    CHECK(set->HasKey(isolate, keys[i]));
    Verify(isolate, set);
  }

  CHECK_EQ(128, set->NumberOfElements());
  CHECK_EQ(64, set->NumberOfBuckets());
  CHECK_EQ(0, set->NumberOfDeletedElements());
  Verify(isolate, set);

  for (size_t i = 128; i < 254; i++) {
    set = SmallOrderedHashSet::Add(isolate, set, keys[i]).ToHandleChecked();
    Verify(isolate, set);
  }

  for (size_t i = 0; i < 254; i++) {
    CHECK(set->HasKey(isolate, keys[i]));
    Verify(isolate, set);
  }

  CHECK_EQ(254, set->NumberOfElements());
  CHECK_EQ(127, set->NumberOfBuckets());
  CHECK_EQ(0, set->NumberOfDeletedElements());
  Verify(isolate, set);
}

TEST(SmallOrderedHashMapGrow) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<SmallOrderedHashMap> map = factory->NewSmallOrderedHashMap();
  std::vector<Handle<Object>> keys;
  for (int i = 0; i < 254; i++) {
    Handle<Smi> key(Smi::FromInt(i), isolate);
    keys.push_back(key);
  }

  for (size_t i = 0; i < 4; i++) {
    map = SmallOrderedHashMap::Add(isolate, map, keys[i], keys[i])
              .ToHandleChecked();
    Verify(isolate, map);
  }

  for (size_t i = 0; i < 4; i++) {
    CHECK(map->HasKey(isolate, keys[i]));
    Verify(isolate, map);
  }

  CHECK_EQ(4, map->NumberOfElements());
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  Verify(isolate, map);

  for (size_t i = 4; i < 8; i++) {
    map = SmallOrderedHashMap::Add(isolate, map, keys[i], keys[i])
              .ToHandleChecked();
    Verify(isolate, map);
  }

  for (size_t i = 0; i < 8; i++) {
    CHECK(map->HasKey(isolate, keys[i]));
    Verify(isolate, map);
  }

  CHECK_EQ(8, map->NumberOfElements());
  CHECK_EQ(4, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  Verify(isolate, map);

  for (size_t i = 8; i < 16; i++) {
    map = SmallOrderedHashMap::Add(isolate, map, keys[i], keys[i])
              .ToHandleChecked();
    Verify(isolate, map);
  }

  for (size_t i = 0; i < 16; i++) {
    CHECK(map->HasKey(isolate, keys[i]));
    Verify(isolate, map);
  }

  CHECK_EQ(16, map->NumberOfElements());
  CHECK_EQ(8, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  Verify(isolate, map);

  for (size_t i = 16; i < 32; i++) {
    map = SmallOrderedHashMap::Add(isolate, map, keys[i], keys[i])
              .ToHandleChecked();
    Verify(isolate, map);
  }

  for (size_t i = 0; i < 32; i++) {
    CHECK(map->HasKey(isolate, keys[i]));
    Verify(isolate, map);
  }

  CHECK_EQ(32, map->NumberOfElements());
  CHECK_EQ(16, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  Verify(isolate, map);

  for (size_t i = 32; i < 64; i++) {
    map = SmallOrderedHashMap::Add(isolate, map, keys[i], keys[i])
              .ToHandleChecked();
    Verify(isolate, map);
  }

  for (size_t i = 0; i < 64; i++) {
    CHECK(map->HasKey(isolate, keys[i]));
    Verify(isolate, map);
  }

  CHECK_EQ(64, map->NumberOfElements());
  CHECK_EQ(32, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  Verify(isolate, map);

  for (size_t i = 64; i < 128; i++) {
    map = SmallOrderedHashMap::Add(isolate, map, keys[i], keys[i])
              .ToHandleChecked();
    Verify(isolate, map);
  }

  for (size_t i = 0; i < 128; i++) {
    CHECK(map->HasKey(isolate, keys[i]));
    Verify(isolate, map);
  }

  CHECK_EQ(128, map->NumberOfElements());
  CHECK_EQ(64, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  Verify(isolate, map);

  for (size_t i = 128; i < 254; i++) {
    map = SmallOrderedHashMap::Add(isolate, map, keys[i], keys[i])
              .ToHandleChecked();
    Verify(isolate, map);
  }

  for (size_t i = 0; i < 254; i++) {
    CHECK(map->HasKey(isolate, keys[i]));
    Verify(isolate, map);
  }

  CHECK_EQ(254, map->NumberOfElements());
  CHECK_EQ(127, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  Verify(isolate, map);
}

TEST(OrderedHashTableInsertion) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<OrderedHashMap> map = factory->NewOrderedHashMap();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfElements());

  // Add a new key.
  DirectHandle<Smi> key1(Smi::FromInt(1), isolate);
  DirectHandle<Smi> value1(Smi::FromInt(1), isolate);
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key1));
  map = OrderedHashMap::Add(isolate, map, key1, value1).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));

  // Add existing key.
  map = OrderedHashMap::Add(isolate, map, key1, value1).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));

  DirectHandle<String> key2 = factory->NewStringFromAsciiChecked("foo");
  DirectHandle<String> value = factory->NewStringFromAsciiChecked("bar");
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key2));
  map = OrderedHashMap::Add(isolate, map, key2, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(2, map->NumberOfElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key2));

  map = OrderedHashMap::Add(isolate, map, key2, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(2, map->NumberOfElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key2));

  DirectHandle<Symbol> key3 = factory->NewSymbol();
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key3));
  map = OrderedHashMap::Add(isolate, map, key3, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(3, map->NumberOfElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key2));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key3));

  map = OrderedHashMap::Add(isolate, map, key3, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(3, map->NumberOfElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key2));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key3));

  DirectHandle<Object> key4 = factory->NewHeapNumber(42.0);
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key4));
  map = OrderedHashMap::Add(isolate, map, key4, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(4, map->NumberOfElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key2));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key3));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key4));

  map = OrderedHashMap::Add(isolate, map, key4, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(4, map->NumberOfElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key2));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key3));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key4));
}

TEST(OrderedHashMapDuplicateHashCode) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<OrderedHashMap> map = factory->NewOrderedHashMap();
  DirectHandle<JSObject> key1 = factory->NewJSObjectWithNullProto();
  DirectHandle<JSObject> value = factory->NewJSObjectWithNullProto();
  map = OrderedHashMap::Add(isolate, map, key1, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));

  DirectHandle<JSObject> key2 = factory->NewJSObjectWithNullProto();
  CopyHashCode(key1, key2);

  map = OrderedHashMap::Add(isolate, map, key2, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(2, map->NumberOfElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key2));
}

TEST(OrderedHashMapDeletion) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);
  DirectHandle<Smi> value1(Smi::FromInt(1), isolate);
  DirectHandle<String> value = factory->NewStringFromAsciiChecked("bar");

  Handle<OrderedHashMap> map = factory->NewOrderedHashMap();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfElements());
  CHECK_EQ(0, map->NumberOfDeletedElements());

  // Delete from an empty hash table
  DirectHandle<Smi> key1(Smi::FromInt(1), isolate);
  CHECK(!OrderedHashMap::Delete(isolate, *map, *key1));
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfElements());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key1));

  map = OrderedHashMap::Add(isolate, map, key1, value1).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));

  // Delete single existing key
  CHECK(OrderedHashMap::Delete(isolate, *map, *key1));
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfElements());
  CHECK_EQ(1, map->NumberOfDeletedElements());
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key1));

  map = OrderedHashMap::Add(isolate, map, key1, value1).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK_EQ(1, map->NumberOfDeletedElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));

  DirectHandle<String> key2 = factory->NewStringFromAsciiChecked("foo");
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key2));
  map = OrderedHashMap::Add(isolate, map, key2, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(2, map->NumberOfElements());
  CHECK_EQ(1, map->NumberOfDeletedElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key2));

  DirectHandle<Symbol> key3 = factory->NewSymbol();
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key3));
  map = OrderedHashMap::Add(isolate, map, key3, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(3, map->NumberOfElements());
  CHECK_EQ(1, map->NumberOfDeletedElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key2));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key3));

  // Delete multiple existing keys
  CHECK(OrderedHashMap::Delete(isolate, *map, *key1));
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(2, map->NumberOfElements());
  CHECK_EQ(2, map->NumberOfDeletedElements());
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key1));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key2));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key3));

  CHECK(OrderedHashMap::Delete(isolate, *map, *key2));
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK_EQ(3, map->NumberOfDeletedElements());
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key1));
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key2));
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key3));

  CHECK(OrderedHashMap::Delete(isolate, *map, *key3));
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfElements());
  CHECK_EQ(4, map->NumberOfDeletedElements());
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key1));
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key2));
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key3));

  // Delete non existent key from non new hash table
  CHECK(!OrderedHashMap::Delete(isolate, *map, *key3));
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfElements());
  CHECK_EQ(4, map->NumberOfDeletedElements());
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key1));
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key2));
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key3));

  // Delete non existent key from non empty hash table
  map = OrderedHashMap::Shrink(isolate, map);
  map = OrderedHashMap::Add(isolate, map, key1, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key2));
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key3));
  CHECK(!OrderedHashMap::Delete(isolate, *map, *key2));
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key2));
  CHECK(!OrderedHashMap::HasKey(isolate, *map, *key3));
}

TEST(SmallOrderedHashMapDeletion) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);
  DirectHandle<Smi> value1(Smi::FromInt(1), isolate);
  DirectHandle<String> value = factory->NewStringFromAsciiChecked("bar");

  Handle<SmallOrderedHashMap> map = factory->NewSmallOrderedHashMap();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfElements());
  CHECK_EQ(0, map->NumberOfDeletedElements());

  // Delete from an empty hash table
  DirectHandle<Smi> key1(Smi::FromInt(1), isolate);
  CHECK(!SmallOrderedHashMap::Delete(isolate, *map, *key1));
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfElements());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  CHECK(!map->HasKey(isolate, key1));

  map = SmallOrderedHashMap::Add(isolate, map, key1, value1).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  CHECK(map->HasKey(isolate, key1));

  // Delete single existing key
  CHECK(SmallOrderedHashMap::Delete(isolate, *map, *key1));
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfElements());
  CHECK_EQ(1, map->NumberOfDeletedElements());
  CHECK(!map->HasKey(isolate, key1));

  map = SmallOrderedHashMap::Add(isolate, map, key1, value1).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK_EQ(1, map->NumberOfDeletedElements());
  CHECK(map->HasKey(isolate, key1));

  DirectHandle<String> key2 = factory->NewStringFromAsciiChecked("foo");
  CHECK(!map->HasKey(isolate, key2));
  map = SmallOrderedHashMap::Add(isolate, map, key2, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(2, map->NumberOfElements());
  CHECK_EQ(1, map->NumberOfDeletedElements());
  CHECK(map->HasKey(isolate, key2));

  DirectHandle<Symbol> key3 = factory->NewSymbol();
  CHECK(!map->HasKey(isolate, key3));
  map = SmallOrderedHashMap::Add(isolate, map, key3, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(3, map->NumberOfElements());
  CHECK_EQ(1, map->NumberOfDeletedElements());
  CHECK(map->HasKey(isolate, key1));
  CHECK(map->HasKey(isolate, key2));
  CHECK(map->HasKey(isolate, key3));

  // Delete multiple existing keys
  CHECK(SmallOrderedHashMap::Delete(isolate, *map, *key1));
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(2, map->NumberOfElements());
  CHECK_EQ(2, map->NumberOfDeletedElements());
  CHECK(!map->HasKey(isolate, key1));
  CHECK(map->HasKey(isolate, key2));
  CHECK(map->HasKey(isolate, key3));

  CHECK(SmallOrderedHashMap::Delete(isolate, *map, *key2));
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK_EQ(3, map->NumberOfDeletedElements());
  CHECK(!map->HasKey(isolate, key1));
  CHECK(!map->HasKey(isolate, key2));
  CHECK(map->HasKey(isolate, key3));

  CHECK(SmallOrderedHashMap::Delete(isolate, *map, *key3));
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfElements());
  CHECK_EQ(4, map->NumberOfDeletedElements());
  CHECK(!map->HasKey(isolate, key1));
  CHECK(!map->HasKey(isolate, key2));
  CHECK(!map->HasKey(isolate, key3));

  // Delete non existent key from non new hash table
  CHECK(!SmallOrderedHashMap::Delete(isolate, *map, *key3));
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(0, map->NumberOfElements());
  CHECK_EQ(4, map->NumberOfDeletedElements());
  CHECK(!map->HasKey(isolate, key1));
  CHECK(!map->HasKey(isolate, key2));
  CHECK(!map->HasKey(isolate, key3));

  // Delete non existent key from non empty hash table
  map = SmallOrderedHashMap::Add(isolate, map, key1, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  CHECK(map->HasKey(isolate, key1));
  CHECK(!map->HasKey(isolate, key2));
  CHECK(!map->HasKey(isolate, key3));
  CHECK(!SmallOrderedHashMap::Delete(isolate, *map, *key2));
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  CHECK(map->HasKey(isolate, key1));
  CHECK(!map->HasKey(isolate, key2));
  CHECK(!map->HasKey(isolate, key3));
}

TEST(OrderedHashMapDuplicateHashCodeDeletion) {
  LocalContext context;
  Isolate* isolate = GetIsolateFrom(&context);
  Factory* factory = isolate->factory();
  HandleScope scope(isolate);

  Handle<OrderedHashMap> map = factory->NewOrderedHashMap();
  DirectHandle<JSObject> key1 = factory->NewJSObjectWithNullProto();
  DirectHandle<JSObject> value = factory->NewJSObjectWithNullProto();
  map = OrderedHashMap::Add(isolate, map, key1, value).ToHandleChecked();
  Verify(isolate, map);
  CHECK_EQ(2, map->NumberOfBuckets());
  CHECK_EQ(1, map->NumberOfElements());
  CHECK_EQ(0, map->NumberOfDeletedElements());
  CHECK(OrderedHashMap::HasKey(isolate, *map, *key1));

  DirectHandle<JSObject> key2 = factory->NewJSObjectWithNullProto();
  CopyHashCode(key1, key2);

  // We shouldn't be able to delete the key!
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
"""


```